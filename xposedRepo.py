#!/usr/bin/env python3
"""
repoXpose.py — parallel .git exposure scanner (camelCase + state resume + colored output)

Features:
 - camelCase naming
 - thread-safe .state file with timestamp for resuming progress (format: STATUS,STATUS_CODE_OR_MSG,URL)
 - prints only VULNERABLE / SUSPICIOUS lines (colorized)
 - simple remaining counter with print(..., end='\r', flush=True)
 - graceful handling of KeyboardInterrupt and thread exceptions
 - optional CSV report named: DD-Mmm-YYYY-RepoXpose.csv (uses 'Sept' for September)
"""

from __future__ import annotations
import argparse
import concurrent.futures
import csv
import gc
import re
import threading
import time
import sys
import os
import socket
import urllib.parse
from datetime import datetime
from typing import List, Optional, Tuple, Set, Deque
import collections
import itertools
import sqlite3
import requests # type: ignore
from requests.adapters import HTTPAdapter, Retry # type: ignore
try:
    import modules.dumper
except ImportError:
    # If running directly not as module, or path issues
    pass

# -------------------------
# Config / constants
# -------------------------
VULN = "VULNERABLE"
SUSPICIOUS = "SUSPICIOUS"
OK = "OK"
ERROR = "ERROR"

INDEX_PAT = re.compile(r'Index of /.git', re.IGNORECASE)
# A real .git/HEAD is exactly a symbolic ref or a bare 40-hex object ID.
# Anchored and whole-body: the previous r'[a-f0-9]{4,40}' search matched CSS
# hex colours, webpack asset hashes and even the letters in "access".
GIT_HEAD_VALID_PAT = re.compile(r'^(ref:\s*refs/\S+|[0-9a-f]{40})$', re.IGNORECASE)
GIT_CONFIG_PAT = re.compile(r'\[core\]', re.IGNORECASE)
# objects/info/packs lines and pack directory listings name packs explicitly.
PACK_NAME_PAT = re.compile(r'pack-[0-9a-f]{40}\.(pack|idx)', re.IGNORECASE)

ANSI_RED = "\033[91m"  # Bright red
ANSI_GREEN = "\033[92m"
ANSI_RESET = "\033[0m"

DEFAULT_THREADS = 50
DEFAULT_TIMEOUT = 5.0
DEFAULT_STATE_FILE = None  # Will be generated with timestamp

# month mapping with 'Sept' for September to match your example
MONTH_MAP = {
    1: "Jan", 2: "Feb", 3: "Mar", 4: "Apr", 5: "May", 6: "Jun",
    7: "Jul", 8: "Aug", 9: "Sept", 10: "Oct", 11: "Nov", 12: "Dec"
}

# -------------------------
# Global runtime state
# -------------------------
totalTargets = 0
remainingLock = threading.Lock()
remaining = 0
lastChecked = ""
stateLock = threading.Lock()
progressLock = threading.Lock()  # rich.Progress is NOT thread-safe


# -------------------------
# Disk-backed dedup + rate limit (dnsx-inspired)
# -------------------------
class TokenBucket:
    """Thread-safe token bucket for rate limiting.

    Implemented as a reservation clock rather than a running token count:
    each caller claims the next free slot under the lock, then sleeps until
    that slot arrives with the lock released. Sleeping while holding the lock
    both blocks unrelated workers and double-credits the waited-out interval
    -- once by resetting the token count and again as elapsed time on the
    next call -- which let the limiter run at several times the configured
    rate. The clock is allowed to trail `per` seconds behind real time, which
    preserves an initial burst of up to `rate` requests.
    """
    def __init__(self, rate: int, per: float = 1.0):
        self.rate = max(rate, 1)
        self.per = per
        self.interval = per / self.rate
        self.lock = threading.Lock()
        # Trailing the clock by this much grants an opening burst of exactly
        # `rate` requests; request rate+1 then waits one interval.
        self.burstWindow = per - self.interval
        self.nextFree = time.monotonic() - self.burstWindow

    def take(self):
        with self.lock:
            now = time.monotonic()
            earliest = now - self.burstWindow
            if self.nextFree < earliest:
                # Idle long enough that the backlog expired; re-anchor so the
                # burst allowance does not accumulate without bound.
                self.nextFree = earliest
            wait = self.nextFree - now
            self.nextFree += self.interval
        if wait > 0:
            time.sleep(wait)


class DedupStore:
    """SQLite-backed deduplication store with WAL mode and batched writes."""
    def __init__(self, db_path: str, flush_interval: float = 2.0, batch_size: int = 500):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.execute("CREATE TABLE IF NOT EXISTS seen(url TEXT PRIMARY KEY)")
        self.conn.commit()
        self._pending: List[str] = []
        # Membership mirror of _pending. The list preserves insert order for
        # the batched write; this answers has() in O(1) instead of scanning a
        # buffer that can now outlive a failed flush.
        self._pendingSet: Set[str] = set()
        self._lock = threading.Lock()
        self._last_flush = time.monotonic()
        self._flush_interval = flush_interval
        self._batch_size = batch_size
        self._warned = False
        # Cap on URLs held back for retry after failed writes. The .state file
        # is written before dedup.add, so it stays the authoritative record and
        # loadState can rebuild from it; this bound keeps a persistently broken
        # database from growing the retry buffer without limit.
        self._max_pending = max(batch_size * 100, batch_size)

    def has(self, url: str) -> bool:
        with self._lock:
            if url in self._pendingSet:
                return True
        # _maybe_flush takes the lock itself, so call it before re-acquiring.
        self._maybe_flush()
        with self._lock:
            # One connection is shared by every worker thread. SQLite rejects
            # concurrent use of a single connection with SQLITE_MISUSE ("bad
            # parameter or other API misuse"), so every statement on it --
            # reads included -- has to be serialized here, not just the writes.
            cur = self.conn.execute("SELECT 1 FROM seen WHERE url=?", (url,))
            return cur.fetchone() is not None

    def add(self, url: str):
        with self._lock:
            self._pending.append(url)
            self._pendingSet.add(url)
            should_flush = (
                len(self._pending) >= self._batch_size
                or (time.monotonic() - self._last_flush) > self._flush_interval
            )
        if should_flush:
            self._flush()

    def add_many(self, urls: List[str]):
        if not urls:
            return
        with self._lock:
            self._pending.extend(urls)
            self._pendingSet.update(urls)
        self._flush()

    def _maybe_flush(self):
        with self._lock:
            should_flush = (
                len(self._pending) >= self._batch_size
                or (time.monotonic() - self._last_flush) > self._flush_interval
            )
        if should_flush:
            self._flush()

    def _flush(self):
        with self._lock:
            if not self._pending:
                return
            try:
                self.conn.executemany(
                    "INSERT OR IGNORE INTO seen(url) VALUES (?)",
                    [(u,) for u in self._pending]
                )
                self.conn.commit()
            except Exception as e:
                # The write did not land, so the URLs are still unrecorded.
                # Keep them for the next flush instead of dropping them, which
                # would make a resumed scan re-probe targets it already hit.
                if not self._warned:
                    self._warned = True
                    print(
                        f"[WARN] dedup database write failed ({e}); "
                        f"retaining {len(self._pending)} URLs for retry. "
                        f"The .state file remains the authoritative record.",
                        file=sys.stderr,
                    )
                if len(self._pending) > self._max_pending:
                    dropped = len(self._pending) - self._max_pending
                    del self._pending[:dropped]
                    self._pendingSet = set(self._pending)
                    print(
                        f"[WARN] dedup retry buffer full; dropped {dropped} "
                        f"URLs. Resume from the .state file instead.",
                        file=sys.stderr,
                    )
                self._last_flush = time.monotonic()
                return
            self._pending.clear()
            self._pendingSet.clear()
            self._last_flush = time.monotonic()

    def close(self):
        self._flush()
        try:
            self.conn.close()
        except Exception:
            pass


# -------------------------
# Networking helpers
# -------------------------
def makeSession(timeout: int = 5, maxRetries: int = 1, poolConnections: int = 100, poolMaxSize: int = 100) -> requests.Session:
    s = requests.Session()
    retries = Retry(
        total=maxRetries,
        backoff_factor=0.25,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=frozenset(['GET', 'HEAD', 'OPTIONS'])
    )
    adapter = HTTPAdapter(max_retries=retries, pool_connections=poolConnections, pool_maxsize=poolMaxSize)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    s.headers.update({"User-Agent": "Mozilla/5.0 (compatible; repoXpose/1.0)"})
    return s


def normalizeUrl(u: str) -> Optional[str]:
    try:
        u = u.strip()
        if not u:
            return None
        # reject wildcard DNS patterns (e.g., *.example.com)
        if u.startswith("*.") or "/*." in u:
            return None
        if not re.match(r'^https?://', u):
            u = "https://" + u
        # remove trailing slash for consistency
        return u.rstrip('/')
    except Exception:
        return None


# -------------------------
# State file handling
# -------------------------
def loadState(stateFile: str, dedup: DedupStore) -> None:
    """
    Reads existing .state file and populates dedup store.
    State line format: STATUS,STATUS-CODE-OR-MSG,URL
    """
    if not os.path.exists(stateFile):
        return
    urls: List[str] = []
    try:
        with open(stateFile, "r", encoding="utf-8", errors="ignore", newline="") as fh:
            for row in csv.reader(fh):
                if len(row) < 3:
                    continue
                # The URL is always the last field. Reading it positionally from
                # the end also recovers legacy rows written before the status
                # message was quoted, where a comma in the message split it
                # across several fields.
                url = row[-1].strip()
                if url:
                    urls.append(url)
    except Exception as e:
        print(f"[WARN] Failed to read state file {stateFile}: {e}", file=sys.stderr)
        return
    if urls:
        dedup.add_many(urls)


def appendState(stateFile: str, dedup: DedupStore, status: str, codeOrMsg: str, url: str) -> None:
    """
    Thread-safe append to state file + dedup store.
    """
    try:
        with stateLock:
            with open(stateFile, "a", encoding="utf-8", newline="") as fh:
                # codeOrMsg carries str(exception) on the ERROR path, which
                # routinely contains commas, quotes and newlines. csv quotes
                # them so the URL stays in field 3 for loadState/writeFinalCsv.
                csv.writer(fh, lineterminator="\n").writerow([status, codeOrMsg, url])
        dedup.add(url)
    except Exception as e:
        # we must not crash on state write failure
        print(f"[ERROR] Failed to write to state file {stateFile}: {e}", file=sys.stderr)


# -------------------------
# Scanner logic
# -------------------------
MAX_PROBE_BYTES = 16384  # Only read first 16KB of any response


def _safeText(response: requests.Response, maxBytes: int = MAX_PROBE_BYTES) -> str:
    """Stream at most *maxBytes* from a response and close it to release the connection.
    Falls back to response.text for compatibility with test mocks."""
    try:
        raw = getattr(response, "raw", None)
        if raw is not None and hasattr(raw, "read"):
            chunk = raw.read(maxBytes)
            response.close()
            return chunk.decode("utf-8", errors="ignore")
        # Fallback for non-streaming responses / mocks
        text = response.text or ""
        response.close()
        return text[:maxBytes]
    except Exception:
        return getattr(response, "text", "")[:maxBytes]


def _contentTypeIsHtml(response: requests.Response) -> bool:
    """True if the response is an HTML document.

    A real .git/HEAD, .git/config or objects/info/packs is never HTML. Servers
    that answer unknown paths with a 200 soft-404 page are the single largest
    source of false positives, and this is what separates them.
    """
    ct = response.headers.get("Content-Type", "") or ""
    return "html" in ct.lower()


def checkGitExposure(session: requests.Session, baseUrl: str, timeout: float,
                     limiter: Optional[TokenBucket] = None) -> Optional[Tuple[str, str, str, str]]:
    """
    Probe git endpoints. Return (STATUS_LABEL, STATUS_CODE_OR_MSG, baseUrl, serverHeader) or None.

    VULNERABLE means a response only a real .git directory produces.
    SUSPICIOUS is reserved for a non-HTML 200 on .git/HEAD whose body is not
    valid HEAD content -- genuinely ambiguous, worth a human look.

    Redirects are never followed: a 3xx on these paths means the server is
    routing the request somewhere else, not serving .git. Following them, and
    accepting any hex-looking substring as an object ID, made every soft-404
    page look like a finding.

    Each request takes a token from *limiter* when one is supplied, so
    --rate-limit bounds requests rather than targets.
    All requests are streamed and capped to MAX_PROBE_BYTES to avoid OOM on huge responses.
    """
    serverHeader = "N/A"

    def get(path: str):
        if limiter:
            limiter.take()
        return session.get(baseUrl + path, timeout=timeout,
                           allow_redirects=False, stream=True)

    try:
        # /.git/ directory listing. This one is legitimately HTML.
        r = get("/.git/")
        serverHeader = r.headers.get("Server", "N/A")
        if r.status_code == 200:
            text = _safeText(r, MAX_PROBE_BYTES)
            if INDEX_PAT.search(text):
                return (VULN, str(r.status_code), baseUrl, serverHeader)
        else:
            r.close()

        # /.git/HEAD -- must be plain "ref: refs/..." or a bare 40-hex object ID
        r2 = get("/.git/HEAD")
        if serverHeader == "N/A":
            serverHeader = r2.headers.get("Server", "N/A")
        if r2.status_code == 200:
            isHtml = _contentTypeIsHtml(r2)
            body = _safeText(r2, MAX_PROBE_BYTES).strip()
            if not isHtml:
                if GIT_HEAD_VALID_PAT.match(body):
                    return (VULN, str(r2.status_code), baseUrl, serverHeader)
                # Non-HTML 200 that is not valid HEAD content: ambiguous.
                if body:
                    return (SUSPICIOUS, str(r2.status_code), baseUrl, serverHeader)
        else:
            r2.close()

        # /.git/config -- an INI file, never HTML
        r3 = get("/.git/config")
        if serverHeader == "N/A":
            serverHeader = r3.headers.get("Server", "N/A")
        if r3.status_code == 200:
            isHtml = _contentTypeIsHtml(r3)
            text = _safeText(r3, MAX_PROBE_BYTES)
            if not isHtml and GIT_CONFIG_PAT.search(text):
                return (VULN, str(r3.status_code), baseUrl, serverHeader)
        else:
            r3.close()

        # objects/info/packs and objects/pack/ -- require a real pack filename
        for p in ("/.git/objects/info/packs", "/.git/objects/pack/"):
            rp = get(p)
            if serverHeader == "N/A":
                serverHeader = rp.headers.get("Server", "N/A")
            if rp.status_code == 200:
                text = _safeText(rp, MAX_PROBE_BYTES)
                if PACK_NAME_PAT.search(text):
                    return (VULN, str(rp.status_code), baseUrl, serverHeader)
            else:
                rp.close()

    except requests.RequestException as e:
        # network error - record as ERROR with message
        return (ERROR, str(e), baseUrl, "Error")
    except Exception as e:
        return (ERROR, str(e), baseUrl, "Error")

    # not vulnerable / nothing conclusive
    return (OK, str(getattr(r, "status_code", "N/A")), baseUrl, serverHeader)


def worker(taskUrl: str, session: requests.Session, timeout: float, stateFile: str, dedup: DedupStore, limiter: Optional[TokenBucket] = None, dumpingExecutor: Optional[concurrent.futures.ThreadPoolExecutor] = None, outputDirArg: Optional[str] = None, progress: Optional[object] = None, scanTaskID: Optional[object] = None, feed: Optional[FindingsFeed] = None, resolve: bool = False) -> None:
    """
    Worker that runs checkGitExposure and appends to state. Handles exceptions.
    Trigger dump if vulnerable and dumpingExecutor is provided.
    """
    global remaining, lastChecked

    result = None
    try:
        # If already processed (from state resume), skip
        if dedup.has(taskUrl):
            with remainingLock:
                remaining -= 1
                lastChecked = taskUrl
            if progress and scanTaskID is not None:
                with progressLock:
                    progress.advance(scanTaskID, 1)
            return

        # The limiter is handed to checkGitExposure so each of its HTTP
        # requests takes a token; throttling once per target let a scan run
        # at up to 5x the configured rate.
        result = checkGitExposure(session, taskUrl, timeout, limiter=limiter)
    except KeyboardInterrupt:
        import os
        os._exit(1)  # Worker exit
    except Exception:
        pass

    try:
        if result:
            status, codeOrMsg, url, serverHeader = result
            appendState(stateFile, dedup, status, codeOrMsg, url)
            if status == VULN:
                timeStr = datetime.now().strftime("%H:%M:%S")

                # Resolve IP (optional — costs CPU and blocks threads)
                ip_addr = "N/A"
                if resolve:
                    try:
                        parsed = urllib.parse.urlparse(url)
                        domain = parsed.netloc.split(':')[0]
                        ip_addr = socket.gethostbyname(domain)
                    except Exception:
                        pass

                if dumpingExecutor:
                    # Add row to the feed instead of the table
                    if feed is not None:
                        feed.append((
                            f"[bold red]{status}[/bold red]",
                            url,
                            f"[blue]{ip_addr}[/blue]",
                            f"[magenta]{serverHeader}[/magenta]",
                            f"[dim white]{timeStr}[/dim white]",
                            "[cyan]Dumping...[/cyan]"
                        ))
                    else:
                        print(f"[VULNERABLE] {url} [Server: {serverHeader}] [DUMPING]")

                    try:
                        # Determine output directory
                        parsed = urllib.parse.urlparse(url)
                        domain = parsed.netloc.replace(':', '_')
                        if not domain:
                            domain = "unknown_target"

                        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                        defaultName = f"{domain}-xposed-{timestamp}"
                        finalOutputDir = outputDirArg if outputDirArg else defaultName

                        dumpUrl = url
                        if not dumpUrl.endswith("/.git/"):
                            dumpUrl = dumpUrl.rstrip("/")
                            if not dumpUrl.endswith("/.git"):
                                dumpUrl += "/.git/"

                        # Define a wrapper to handle the dump
                        def runDump():
                            taskID = None
                            try:
                                if progress:
                                    with progressLock:
                                        taskID = progress.add_task(f"[cyan]Dumping {domain}...", total=None)

                                def progressCallback(completed, total, currentFile):
                                    if progress and taskID is not None:
                                        with progressLock:
                                            progress.update(taskID, completed=completed, total=total if total > 0 else None)

                                commitCount = modules.dumper.dumpAndExtract(dumpUrl, finalOutputDir, progressCallback=progressCallback)

                                if progress and taskID is not None:
                                    # Keep it green on success
                                    if isinstance(commitCount, int) and commitCount > 0:
                                        statsMsg = f"({commitCount} commits)"
                                    else:
                                        statsMsg = ""
                                    with progressLock:
                                        progress.update(taskID, completed=100, total=100, description=f"[green]Dumped {domain} ✓ {statsMsg}")

                            except KeyboardInterrupt:
                                if progress and taskID is not None:
                                    with progressLock:
                                        progress.update(taskID, description=f"[yellow]Stopped {domain}")
                            except Exception as e:
                                if progress and taskID is not None:
                                    with progressLock:
                                        progress.update(taskID, description=f"[red]Failed {domain}: {str(e)}")

                        dumpingExecutor.submit(runDump)

                    except Exception as dumpErr:
                        err_msg = f"[red][ERROR] Failed to queue dump for {url}: {dumpErr}[/red]"
                        if progress:
                            with progressLock:
                                progress.console.print(err_msg)
                        else:
                            print(err_msg, file=sys.stderr)
                else:
                    # No dumping, just alert
                    if feed is not None:
                        feed.append((
                            f"[bold red]{status}[/bold red]",
                            url,
                            f"[blue]{ip_addr}[/blue]",
                            f"[magenta]{serverHeader}[/magenta]",
                            f"[dim white]{timeStr}[/dim white]",
                            "[yellow]Logged[/yellow]"
                        ))
                    else:
                        print(f"{ANSI_RED}[{status}]{ANSI_RESET} {url}")

            elif status == SUSPICIOUS:
                ip_addr = "N/A"
                if resolve:
                    try:
                        parsed = urllib.parse.urlparse(url)
                        domain = parsed.netloc.split(':')[0]
                        ip_addr = socket.gethostbyname(domain)
                    except Exception:
                        pass

                timeStr = datetime.now().strftime("%H:%M:%S")

                if feed is not None:
                    # Mapping: STATUS, URL, IP, SERVER, TIME, ACTION
                    feed.append((
                        f"[bold yellow]{status}[/bold yellow]",
                        url,
                        f"[blue]{ip_addr}[/blue]",
                        f"[magenta]{serverHeader}[/magenta]",
                        f"[dim white]{timeStr}[/dim white]",
                        f"[grey50]Status: {codeOrMsg}[/grey50]"
                    ))
                else:
                    print(f"{ANSI_GREEN}[{status}]{ANSI_RESET} {url}")

        with remainingLock:
            remaining -= 1
            lastChecked = taskUrl

        # Update main scan progress
        if progress and scanTaskID is not None:
            with progressLock:
                progress.advance(scanTaskID, 1)

    except KeyboardInterrupt:
        import os
        os._exit(1)
    except Exception as e:
        # Error handling
        appendState(stateFile, dedup, ERROR, str(e), taskUrl)
        with remainingLock:
            remaining -= 1
            lastChecked = taskUrl
        # Update main scan progress even on error
        if progress and scanTaskID is not None:
            with progressLock:
                progress.advance(scanTaskID, 1)


# -------------------------
# Utilities
# -------------------------
def writeFinalCsv(stateFile: str, outPrefix: str = "RepoXpose") -> None:
    """
    Reads the .state file and writes all entries into a CSV
    named like: DD-Mmm-YYYY-RepoXpose.csv
    """
    try:
        today = datetime.now()
        day = f"{today.day:02d}"
        month = MONTH_MAP.get(today.month, today.strftime("%b"))
        year = today.year
        filename = f"{day}-{month}-{year}-{outPrefix}.csv"
        # Read the .state file to include all entries in the same order
        lines = []
        if os.path.exists(stateFile):
            with open(stateFile, "r", encoding="utf-8", errors="ignore", newline="") as fh:
                for row in csv.reader(fh):
                    if len(row) < 3:
                        continue
                    # Status first, URL last. Anything between is the message,
                    # which legacy unquoted rows may have split across fields.
                    lines.append((
                        row[0].strip(),
                        ",".join(row[1:-1]),
                        row[-1].strip(),
                    ))
        # write csv header and rows
        with open(filename, "w", encoding="utf-8", newline="") as csvf:
            writer = csv.writer(csvf, lineterminator="\n")
            writer.writerow(["status", "code_or_message", "url"])
            writer.writerows(lines)
        print(f"\nWrote final CSV report: {filename}")
    except Exception as e:
        print(f"\n[ERROR] Failed to write final CSV: {e}", file=sys.stderr)


def stream_targets(path: str, dedup: DedupStore):
    """Yield normalized targets from a file, skipping already-seen URLs."""
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            u = normalizeUrl(line)
            if u and not dedup.has(u):
                yield u


def countTargets(path: str, dedup: DedupStore, maxTargets: int = 0) -> int:
    """Count the targets a scan will actually submit.

    Applies the same filter as stream_targets -- blank lines, wildcard
    patterns and already-seen URLs are all excluded -- so the progress bar
    total matches the number of workers that will run. Counting raw lines
    instead leaves the bar stuck short of 100%.
    """
    count = 0
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                u = normalizeUrl(line)
                if u and not dedup.has(u):
                    count += 1
                    if maxTargets and count >= maxTargets:
                        break
    except OSError as e:
        print(f"[ERROR] Could not read input file {path}: {e}", file=sys.stderr)
        return 0
    return count


# -------------------------
# Live dashboard
# -------------------------
# STATUS, TARGET URL, IP ADDRESS, SERVER, TIME, ACTION
FINDINGS_COLUMNS = 6


IP_FIELD_INDEX = 2


class FindingsFeed:
    """Bounded, thread-safe feed of findings for the live dashboard.

    Owns its own lock and a monotonic revision counter. The renderer
    throttles redraws and needs to know that new findings arrived; the
    window's length is not that signal, because a bounded deque stops
    growing once full, which froze the dashboard on the 10th finding.
    """

    def __init__(self, maxlen: int = 10):
        self._rows: Deque[Tuple] = collections.deque(maxlen=maxlen)
        self._lock = threading.Lock()
        self._revision = 0

    def append(self, row: Tuple) -> None:
        with self._lock:
            self._rows.append(row)
            self._revision += 1

    @property
    def revision(self) -> int:
        with self._lock:
            return self._revision

    def snapshot(self) -> List[Tuple]:
        """Return a copy, so rendering never races an append."""
        with self._lock:
            return list(self._rows)


def buildFindingsTable(rows, showIp: bool = False) -> "object":
    """Build the findings table for the live dashboard.

    Five fixed-width columns plus borders already exceed an 80-column
    terminal, so TARGET URL -- sized only by ratio -- used to be squeezed to
    zero width, hiding the one field the operator cannot reconstruct from the
    others. TARGET URL now gets a min_width floor, the secondary columns can
    shrink, and IP ADDRESS is omitted unless --resolve actually populated it
    (otherwise it is 15 columns of "N/A").
    """
    from rich.table import Table
    from rich.box import HEAVY_EDGE

    table = Table(
        box=HEAVY_EDGE,
        show_header=True,
        header_style="bold white on blue",
        title="[bold reverse cyan] TARGET EXPOSURE SYSTEMS [/bold reverse cyan]",
        expand=True,
        border_style="bright_blue",
        row_styles=["", "dim"],
    )
    table.add_column("STATUS", justify="center", min_width=10, style="bold", no_wrap=True)
    table.add_column("TARGET URL", style="cyan", ratio=1, min_width=24, overflow="fold")
    if showIp:
        table.add_column("IP ADDRESS", style="blue", min_width=11, justify="center", no_wrap=True)
    table.add_column("SERVER", style="magenta", min_width=8, max_width=20, overflow="ellipsis", no_wrap=True)
    table.add_column("TIME", style="dim white", min_width=8, justify="center", no_wrap=True)
    table.add_column("ACTION", style="grey70", min_width=8, max_width=15, justify="center", overflow="ellipsis", no_wrap=True)

    for row in rows:
        if not showIp and len(row) > IP_FIELD_INDEX:
            row = row[:IP_FIELD_INDEX] + row[IP_FIELD_INDEX + 1:]
        table.add_row(*row)
    return table


# -------------------------
# Main orchestration
# -------------------------
def main(argv: Optional[List[str]] = None) -> int:
    global totalTargets, remaining
    parser = argparse.ArgumentParser(description="repoXpose - parallel .git exposure scanner (resumable .state)")
    parser.add_argument("-i", "--input", help="File of targets (one per line). URLs can omit scheme", type=str)
    parser.add_argument("-u", "--url", help="Single target URL", type=str)
    parser.add_argument("-t", "--threads", help=f"Number of parallel workers (default: {DEFAULT_THREADS})", type=int, default=DEFAULT_THREADS)
    parser.add_argument("-T", "--timeout", help=f"Request timeout seconds (default: {DEFAULT_TIMEOUT})", type=float, default=DEFAULT_TIMEOUT)
    parser.add_argument("--rate-limit", help="Max requests per second (0 = unlimited)", type=int, default=0)
    parser.add_argument("--state-file", help="State file to resume from (default: auto-generated with timestamp)", type=str, default=None)
    parser.add_argument("--max", help="Max targets to process from input file (for testing)", type=int, default=0)
    parser.add_argument("--csv", help="Generate CSV report after scan completes", action="store_true")
    parser.add_argument("--dump", help="Automatically dump and recover artifacts from vulnerable targets", action="store_true")
    parser.add_argument("--output-dir", help="Output directory for dump (default: domain-xposed-datetime)", type=str)
    parser.add_argument("--resolve", help="Resolve IP addresses for findings (slower)", action="store_true")
    args = parser.parse_args(argv)

    if not args.input and not args.url:
        parser.error("Specify --input FILE or --url URL")

    # Generate state file name with timestamp if not provided
    if args.state_file is None:
        now = datetime.now()
        timestamp = now.strftime("%Y%m%d_%H%M%S")
        args.state_file = f".state_{timestamp}"

    # Disk-backed dedup store (sqlite) + optional rate limiter
    dedup = DedupStore(db_path=f"{args.state_file}.db")
    limiter: Optional[TokenBucket] = None
    if args.rate_limit > 0:
        limiter = TokenBucket(rate=args.rate_limit)

    # load previous state into dedup store
    try:
        loadState(args.state_file, dedup)
    except Exception as e:
        print(f"[WARN] Could not load state file: {e}", file=sys.stderr)

    # Build streaming target iterator and count for progress bar
    targetIter: iter = iter([])
    totalLines = 0
    if args.url:
        u = normalizeUrl(args.url)
        if not u:
            print("[ERROR] Invalid URL provided via --url", file=sys.stderr)
            dedup.close()
            return 2
        targetIter = iter([u])
        totalLines = 1
    else:
        # Count what will actually be submitted, not raw lines: blanks,
        # wildcards and resumed URLs are filtered out by stream_targets.
        totalLines = countTargets(args.input, dedup, maxTargets=max(args.max, 0))
        targetIter = stream_targets(args.input, dedup)
        if args.max and args.max > 0:
            targetIter = itertools.islice(targetIter, args.max)

    totalTargets = totalLines
    remaining = totalLines

    if totalTargets == 0:
        print("No remaining targets to process (state file indicates all done).")
        if args.csv:
            writeFinalCsv(args.state_file)
        dedup.close()
        return 0

    session = makeSession(timeout=int(args.timeout), maxRetries=1, poolConnections=args.threads+10, poolMaxSize=args.threads+10)

    # ensure state file exists (touch)
    try:
        with stateLock:
            open(args.state_file, "a").close()
    except Exception:
        pass

    # run thread pool
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeRemainingColumn, MofNCompleteColumn
    from rich.panel import Panel
    from rich.live import Live
    from rich.console import Group

    # 1. Findings feed, rendered by buildFindingsTable
    feed = FindingsFeed(maxlen=10)

    # 2. Create Progress Bar
    progress = Progress(
        SpinnerColumn(spinner_name="dots12", style="bold cyan"),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=None, complete_style="cyan", finished_style="green"),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        MofNCompleteColumn(),
        TimeRemainingColumn(),
        refresh_per_second=4
    )

    # 3. Create Group and Live View
    ui_group = Group(
        Panel(buildFindingsTable(feed.snapshot(), showIp=args.resolve), border_style="cyan"),
        progress
    )

    # Wrap execution in Live context
    with Live(ui_group, refresh_per_second=4, screen=False) as live:

        # Create the Overall Scan Progress bar
        scanTaskID = progress.add_task("[bold white]Scanning Targets[/bold white]", total=totalTargets)

        executor = concurrent.futures.ThreadPoolExecutor(max_workers=args.threads)

        dumpingExecutor = None
        if args.dump:
            # Cap dump workers to prevent OOM when many vulnerable targets are found
            dumpWorkers = min(5, args.threads)
            dumpingExecutor = concurrent.futures.ThreadPoolExecutor(max_workers=dumpWorkers)

        futures = set()
        try:
            def renderFindings():
                live.update(Group(
                    Panel(
                        buildFindingsTable(feed.snapshot(), showIp=args.resolve),
                        border_style="cyan",
                    ),
                    progress,
                ))

            maxInflight = args.threads * 2

            # Seed initial batch (bounded to prevent unbounded memory growth)
            for _ in range(maxInflight):
                try:
                    url = next(targetIter)
                    futures.add(executor.submit(
                        worker,
                        url,
                        session,
                        args.timeout,
                        args.state_file,
                        dedup,
                        limiter,
                        dumpingExecutor,
                        args.output_dir,
                        progress,
                        scanTaskID,
                        feed,
                        args.resolve
                    ))
                except StopIteration:
                    break

            # Track the feed's revision to avoid unnecessary table rebuilds.
            # Revision, not length: the window is bounded, so its length stops
            # changing once full and findings would stop being drawn.
            lastRevision = 0
            lastTableRebuild = 0.0
            TABLE_REBUILD_INTERVAL = 1.0  # seconds

            # Monitor completion and replenish
            while futures:
                done, futures = concurrent.futures.wait(futures, timeout=0.5, return_when=concurrent.futures.FIRST_COMPLETED)

                for future in done:
                    try:
                        future.result()
                    except Exception:
                        pass

                for _ in done:
                    try:
                        url = next(targetIter)
                        futures.add(executor.submit(
                            worker,
                            url,
                            session,
                            args.timeout,
                            args.state_file,
                            dedup,
                            limiter,
                            dumpingExecutor,
                            args.output_dir,
                            progress,
                            scanTaskID,
                            feed,
                            args.resolve
                        ))
                    except StopIteration:
                        break

                # Rebuild table only when new rows arrived AND throttled interval elapsed
                currentRevision = feed.revision
                now = time.monotonic()
                if currentRevision != lastRevision and (now - lastTableRebuild) >= TABLE_REBUILD_INTERVAL:
                    lastRevision = currentRevision
                    lastTableRebuild = now
                    renderFindings()
                    # Force GC to reclaim old Rich Table/Panel objects and prevent memory creep
                    gc.collect()

            # Final render: without it, any finding arriving inside the last
            # throttle window never reaches the screen.
            if feed.revision != lastRevision:
                lastRevision = feed.revision
                renderFindings()

            # Clean shutdown (non-interrupt case)
            if args.dump and dumpingExecutor:
                dumpingExecutor.shutdown(wait=True)
            executor.shutdown(wait=True)

        except KeyboardInterrupt:
            try:
                 live.stop()
            except:
                 pass
            import os
            from rich import print as rprint
            rprint("\n[bold yellow]Keyboard Interrupt! Exiting immediately...[/bold yellow]")
            os._exit(1)

        except Exception as e:
            try:
                 live.stop()
            except:
                 pass
            import os
            from rich import print as rprint
            rprint(f"[bold red]Fatal Error: {e}[/bold red]")
            os._exit(2)

    print("\nScan complete.")
    # The default state file is timestamped, so a bare restart begins a fresh
    # scan rather than resuming. Name the file the operator has to pass to
    # actually pick this run back up.
    print(f"Resume this scan with: --state-file {args.state_file}")
    if args.csv:
        writeFinalCsv(args.state_file)
    dedup.close()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SystemExit:
        # allow normal exits
        raise
    except Exception as e:
        print(f"[FATAL] Unhandled exception: {e}", file=sys.stderr)
        raise
    except KeyboardInterrupt:
        pass
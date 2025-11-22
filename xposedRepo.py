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
import re
import threading
import time
import sys
import os
import urllib.parse
from datetime import datetime
from typing import List, Optional, Tuple, Set
import requests # type: ignore
from requests.adapters import HTTPAdapter, Retry # type: ignore

# -------------------------
# Config / constants
# -------------------------
VULN = "VULNERABLE"
SUSPICIOUS = "SUSPICIOUS"
OK = "OK"
ERROR = "ERROR"

INDEX_PAT = re.compile(r'Index of /.git', re.IGNORECASE)
GIT_HEAD_PAT = re.compile(r'ref:\s+refs/', re.IGNORECASE)
GIT_CONFIG_PAT = re.compile(r'\[core\]', re.IGNORECASE)

ANSI_RED = "\033[31m"
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
processedUrls: Set[str] = set()  # urls we've recorded in state (resumed or live)
vulnResults: List[Tuple[str, str, str]] = []  # (STATUS, STATUS_CODE_OR_MSG, URL)


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
        if not re.match(r'^https?://', u):
            u = "https://" + u
        # remove trailing slash for consistency
        return u.rstrip('/')
    except Exception:
        return None


# -------------------------
# State file handling
# -------------------------
def loadState(stateFile: str) -> None:
    """
    Reads existing .state file and populates processedUrls and vulnResults accordingly.
    State line format: STATUS,STATUS-CODE-OR-MSG,URL
    """
    global processedUrls, vulnResults
    if not os.path.exists(stateFile):
        return
    try:
        with open(stateFile, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                # split only first two commas to allow commas in message (if any)
                parts = line.split(",", 2)
                if len(parts) < 3:
                    continue
                status, codeOrMsg, url = parts[0].strip(), parts[1].strip(), parts[2].strip()
                processedUrls.add(url)
                if status.upper() in (VULN, SUSPICIOUS):
                    vulnResults.append((status.upper(), codeOrMsg, url))
    except Exception as e:
        print(f"[WARN] Failed to read state file {stateFile}: {e}", file=sys.stderr)


def appendState(stateFile: str, status: str, codeOrMsg: str, url: str) -> None:
    """
    Thread-safe append to state file.
    """
    global processedUrls
    try:
        with stateLock:
            with open(stateFile, "a", encoding="utf-8") as fh:
                fh.write(f"{status},{codeOrMsg},{url}\n")
            processedUrls.add(url)
            if status.upper() in (VULN, SUSPICIOUS):
                vulnResults.append((status.upper(), codeOrMsg, url))
    except Exception as e:
        # we must not crash on state write failure
        print(f"[ERROR] Failed to write to state file {stateFile}: {e}", file=sys.stderr)


# -------------------------
# Scanner logic
# -------------------------
def checkGitExposure(session: requests.Session, baseUrl: str, timeout: float) -> Optional[Tuple[str, str, str]]:
    """
    Probe git endpoints. Return (STATUS_LABEL, STATUS_CODE_OR_MSG, baseUrl) or None.
    Returns VULNERABLE for confirmed exposure, SUSPICIOUS for 200 with ambiguous content.
    """
    try:
        # /.git/ directory listing
        urlGitDir = baseUrl + "/.git/"
        r = session.get(urlGitDir, timeout=timeout, allow_redirects=True)
        text = r.text or ""
        if r.status_code == 200 and INDEX_PAT.search(text):
            return (VULN, str(r.status_code), baseUrl)

        # /.git/HEAD
        urlHead = baseUrl + "/.git/HEAD"
        r2 = session.get(urlHead, timeout=timeout, allow_redirects=True)
        if r2.status_code == 200:
            body = r2.text.strip()
            if GIT_HEAD_PAT.search(body):
                return (VULN, str(r2.status_code), baseUrl)
            # Only mark as SUSPICIOUS if we got 200 with suspicious SHA-like content (but not confirmed)
            if len(body) > 0 and re.search(r'[a-f0-9]{4,40}', body, re.IGNORECASE):
                return (SUSPICIOUS, str(r2.status_code), baseUrl)

        # /.git/config
        urlConfig = baseUrl + "/.git/config"
        r3 = session.get(urlConfig, timeout=timeout, allow_redirects=True)
        if r3.status_code == 200 and GIT_CONFIG_PAT.search(r3.text or ""):
            return (VULN, str(r3.status_code), baseUrl)

        # objects/info/packs or objects/pack/
        for p in ("/.git/objects/info/packs", "/.git/objects/pack/"):
            rp = session.get(baseUrl + p, timeout=timeout, allow_redirects=True)
            # Only check for suspicious content if we got 200 OK
            if rp.status_code == 200:
                if "pack-" in (rp.text or "") or (rp.headers.get("Content-Type", "").startswith("text")):
                    return (SUSPICIOUS, str(rp.status_code), baseUrl)

    except requests.RequestException as e:
        # network error - record as ERROR with message
        return (ERROR, str(e), baseUrl)
    except Exception as e:
        return (ERROR, str(e), baseUrl)

    # not vulnerable / nothing conclusive
    return (OK, str(getattr(r, "status_code", "N/A")), baseUrl)


def worker(taskUrl: str, session: requests.Session, timeout: float, stateFile: str) -> None:
    """
    Worker that runs checkGitExposure and appends to state. Handles exceptions.
    """
    global remaining, lastChecked
    try:
        # If already processed (from state resume), skip
        if taskUrl in processedUrls:
            with remainingLock:
                remaining -= 1
                lastChecked = taskUrl
            return

        result = checkGitExposure(session, taskUrl, timeout)
        if result is None:
            # Don't record ERROR status
            pass
        else:
            status, codeOrMsg, url = result
            # Only record VULNERABLE or SUSPICIOUS
            if status in (VULN, SUSPICIOUS):
                appendState(stateFile, status, codeOrMsg, url)
                # Print the results
                if status == VULN:
                    print(f"{ANSI_RED}[{status}]{ANSI_RESET} {url}")
                elif status == SUSPICIOUS:
                    print(f"{ANSI_GREEN}[{status}]{ANSI_RESET} {url}")
        # decrement counter
        with remainingLock:
            remaining -= 1
            lastChecked = taskUrl
    except Exception as e:
        # Make sure unexpected exceptions do not kill the whole program
        appendState(stateFile, ERROR, str(e), taskUrl)
        with remainingLock:
            remaining -= 1
            lastChecked = taskUrl


def printRemaining() -> None:
    global remaining, totalTargets, lastChecked
    try:
        with remainingLock:
            print(f"Remaining: {remaining}/{totalTargets}  Last checked: {lastChecked:80}", end='\r', flush=True)
    except Exception:
        # non-fatal, ignore
        pass


# -------------------------
# Utilities
# -------------------------
def loadTargetsFromFile(path: str) -> List[str]:
    lst: List[str] = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                u = normalizeUrl(line)
                if u:
                    lst.append(u)
    except Exception as e:
        print(f"[ERROR] Could not load input file {path}: {e}", file=sys.stderr)
    return lst


def writeFinalCsv(stateFile: str, outPrefix: str = "RepoXpose") -> None:
    """
    Writes the vulnResults + ALL entries from state (processedUrls tracked separately)
    into a CSV named like: DD-Mmm-YYYY-RepoXpose.csv
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
            with open(stateFile, "r", encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        parts = line.split(",", 2)
                        if len(parts) == 3:
                            status, codeOrMsg, url = parts[0].strip(), parts[1].strip(), parts[2].strip()
                            lines.append((status, codeOrMsg, url))
        # write csv header and rows
        with open(filename, "w", encoding="utf-8") as csvf:
            csvf.write("status,code_or_message,url\n")
            for status, codeOrMsg, url in lines:
                # escape commas in codeOrMsg if any by wrapping in quotes
                if "," in codeOrMsg:
                    codeOrMsg = '"' + codeOrMsg.replace('"', '""') + '"'
                csvf.write(f"{status},{codeOrMsg},{url}\n")
        print(f"\nWrote final CSV report: {filename}")
    except Exception as e:
        print(f"\n[ERROR] Failed to write final CSV: {e}", file=sys.stderr)


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
    parser.add_argument("--state-file", help="State file to resume from (default: auto-generated with timestamp)", type=str, default=None)
    parser.add_argument("--max", help="Max targets to process from input file (for testing)", type=int, default=0)
    parser.add_argument("--csv", help="Generate CSV report after scan completes", action="store_true")
    args = parser.parse_args(argv)

    if not args.input and not args.url:
        parser.error("Specify --input FILE or --url URL")

    # Generate state file name with timestamp if not provided
    if args.state_file is None:
        now = datetime.now()
        timestamp = now.strftime("%Y%m%d_%H%M%S")
        args.state_file = f".state_{timestamp}"

    # load state if present
    try:
        loadState(args.state_file)
    except Exception as e:
        print(f"[WARN] Could not load state file: {e}", file=sys.stderr)

    targets: List[str] = []
    if args.url:
        u = normalizeUrl(args.url)
        if not u:
            print("[ERROR] Invalid URL provided via --url", file=sys.stderr)
            return 2
        targets = [u]
    else:
        targets = loadTargetsFromFile(args.input)
        if args.max and args.max > 0:
            targets = targets[:args.max]

    if not targets:
        print("[ERROR] No valid targets loaded.", file=sys.stderr)
        return 2

    # filter out already processed urls (resumed state)
    toProcess = [t for t in targets if t not in processedUrls]

    totalTargets = len(toProcess)
    remaining = totalTargets

    if totalTargets == 0:
        print("No remaining targets to process (state file indicates all done).")
        # write final CSV from state if flag is set
        if args.csv:
            writeFinalCsv(args.state_file)
        return 0

    session = makeSession(timeout=int(args.timeout), maxRetries=1, poolConnections=args.threads+10, poolMaxSize=args.threads+10)

    # ensure state file exists (touch)
    try:
        with stateLock:
            open(args.state_file, "a").close()
    except Exception:
        pass

    # run thread pool
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=args.threads)
    futures = set()  # Use set for O(1) removal
    try:
        for url in toProcess:
            futures.add(executor.submit(worker, url, session, args.timeout, args.state_file))

        # Monitor completion and print remaining
        while futures:
            done, futures = concurrent.futures.wait(futures, timeout=0.5, return_when=concurrent.futures.FIRST_COMPLETED)
            # Just print remaining, no need to check exceptions (worker handles them)
            if done:
                printRemaining()
        # No need for shutdown(wait=True) since all futures are already done
    except KeyboardInterrupt:
        print("\n[INFO] Keyboard interrupt received — saving progress and exiting gracefully...")
        executor.shutdown(wait=False, cancel_futures=True)
        # ensure state flushed (already appendState writes instantly)
        if args.csv:
            writeFinalCsv(args.state_file)
        return 1
    except Exception as e:
        print(f"\n[ERROR] Fatal exception in main thread: {e}", file=sys.stderr)
        try:
            executor.shutdown(wait=False, cancel_futures=True)
        except Exception:
            pass
        if args.csv:
            writeFinalCsv(args.state_file)
        return 2

    # finalize
    # ensure final printed newline
    print("\nScan complete.")
    # write final CSV if flag is set
    if args.csv:
        writeFinalCsv(args.state_file)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SystemExit as se:
        # allow normal exits
        raise
    except Exception as e:
        print(f"[FATAL] Unhandled exception: {e}", file=sys.stderr)
        raise
    except KeyboardInterrupt:
        pass
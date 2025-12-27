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
import socket
import urllib.parse
from datetime import datetime
from datetime import datetime
from typing import List, Optional, Tuple, Set, Deque
import collections
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
GIT_HEAD_PAT = re.compile(r'ref:\s+refs/', re.IGNORECASE)
GIT_CONFIG_PAT = re.compile(r'\[core\]', re.IGNORECASE)

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
def checkGitExposure(session: requests.Session, baseUrl: str, timeout: float) -> Optional[Tuple[str, str, str, str]]:
    """
    Probe git endpoints. Return (STATUS_LABEL, STATUS_CODE_OR_MSG, baseUrl, serverHeader) or None.
    Returns VULNERABLE for confirmed exposure, SUSPICIOUS for 200 with ambiguous content.
    """
    serverHeader = "N/A"
    try:
        # /.git/ directory listing
        urlGitDir = baseUrl + "/.git/"
        r = session.get(urlGitDir, timeout=timeout, allow_redirects=True)
        serverHeader = r.headers.get("Server", "N/A")
        text = r.text or ""
        if r.status_code == 200 and INDEX_PAT.search(text):
            return (VULN, str(r.status_code), baseUrl, serverHeader)

        # /.git/HEAD
        urlHead = baseUrl + "/.git/HEAD"
        r2 = session.get(urlHead, timeout=timeout, allow_redirects=True)
        if serverHeader == "N/A": serverHeader = r2.headers.get("Server", "N/A")
        if r2.status_code == 200:
            body = r2.text.strip()
            if GIT_HEAD_PAT.search(body):
                return (VULN, str(r2.status_code), baseUrl, serverHeader)
            # Only mark as SUSPICIOUS if we got 200 with suspicious SHA-like content (but not confirmed)
            if len(body) > 0 and re.search(r'[a-f0-9]{4,40}', body, re.IGNORECASE):
                return (SUSPICIOUS, str(r2.status_code), baseUrl, serverHeader)

        # /.git/config
        urlConfig = baseUrl + "/.git/config"
        r3 = session.get(urlConfig, timeout=timeout, allow_redirects=True)
        if serverHeader == "N/A": serverHeader = r3.headers.get("Server", "N/A")
        if r3.status_code == 200 and GIT_CONFIG_PAT.search(r3.text or ""):
            return (VULN, str(r3.status_code), baseUrl, serverHeader)

        # objects/info/packs or objects/pack/
        for p in ("/.git/objects/info/packs", "/.git/objects/pack/"):
            rp = session.get(baseUrl + p, timeout=timeout, allow_redirects=True)
            if serverHeader == "N/A": serverHeader = rp.headers.get("Server", "N/A")
            # Only check for suspicious content if we got 200 OK
            if rp.status_code == 200:
                if "pack-" in (rp.text or "") or (rp.headers.get("Content-Type", "").startswith("text")):
                    return (SUSPICIOUS, str(rp.status_code), baseUrl, serverHeader)

    except requests.RequestException as e:
        # network error - record as ERROR with message
        return (ERROR, str(e), baseUrl, "Error")
    except Exception as e:
        return (ERROR, str(e), baseUrl, "Error")

    # not vulnerable / nothing conclusive
    return (OK, str(getattr(r, "status_code", "N/A")), baseUrl, serverHeader)


def worker(taskUrl: str, session: requests.Session, timeout: float, stateFile: str, dumpingExecutor: Optional[concurrent.futures.ThreadPoolExecutor] = None, outputDirArg: Optional[str] = None, progress: Optional[object] = None, scanTaskID: Optional[object] = None, displayQueue: Optional[Deque] = None, queueLock: Optional[object] = None) -> None:
    """
    Worker that runs checkGitExposure and appends to state. Handles exceptions.
    Trigger dump if vulnerable and dumpingExecutor is provided.
    """
    global remaining, lastChecked
    # Late import to ensure it's available or assume top-level import
    from rich.panel import Panel
    
    try:
        # If already processed (from state resume), skip
        if taskUrl in processedUrls:
            with remainingLock:
                remaining -= 1
                lastChecked = taskUrl
            if progress and scanTaskID is not None:
                progress.advance(scanTaskID, 1)
            return

        result = checkGitExposure(session, taskUrl, timeout)
    except KeyboardInterrupt:
        import os
        os._exit(1) # Worker exit
        return
    except Exception:
        pass

    try:
        if result is None:
            pass
        else:
            status, codeOrMsg, url, serverHeader = result
            if status in (VULN, SUSPICIOUS):
                appendState(stateFile, status, codeOrMsg, url)
                if status == VULN:
                    timeStr = datetime.now().strftime("%H:%M:%S")
                    
                    # Resolve IP
                    try:
                        parsed = urllib.parse.urlparse(url)
                        domain = parsed.netloc.split(':')[0]
                        ip_addr = socket.gethostbyname(domain)
                    except:
                        ip_addr = "N/A"

                    if dumpingExecutor:
                         # Add row to queue instead of table
                         if displayQueue is not None and queueLock is not None:
                             with queueLock:
                                 displayQueue.append((
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
                                        taskID = progress.add_task(f"[cyan]Dumping {domain}...", total=None)

                                    def progressCallback(completed, total, currentFile):
                                        if progress and taskID is not None:
                                            progress.update(taskID, completed=completed, total=total if total > 0 else None)

                                    commitCount = modules.dumper.dumpAndExtract(dumpUrl, finalOutputDir, progressCallback=progressCallback)
                                    
                                    if progress and taskID is not None:
                                        # Keep it green on success
                                        if isinstance(commitCount, int) and commitCount > 0:
                                            statsMsg = f"({commitCount} commits)"
                                        else:
                                            statsMsg = ""
                                        progress.update(taskID, completed=100, total=100, description=f"[green]Dumped {domain} ✓ {statsMsg}")
                                        
                                except KeyboardInterrupt:
                                    if progress and taskID is not None:
                                        progress.update(taskID, description=f"[yellow]Stopped {domain}")
                                except Exception as e:
                                    if progress and taskID is not None:
                                        progress.update(taskID, description=f"[red]Failed {domain}: {str(e)}")
                                        # progress.console.print(f"[red][FAIL] {url} ({str(e)})") # Optional to reduce noise

                            dumpingExecutor.submit(runDump)
                            
                         except Exception as dumpErr:
                             err_msg = f"[red][ERROR] Failed to queue dump for {url}: {dumpErr}[/red]"
                             if progress:
                                 progress.console.print(err_msg)
                             else:
                                 print(err_msg, file=sys.stderr)
                    else:
                        # No dumping, just alert
                        if displayQueue is not None and queueLock is not None:
                             with queueLock:
                                 displayQueue.append((
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
                    # Resolve IP for suspicious too
                    try:
                        parsed = urllib.parse.urlparse(url)
                        domain = parsed.netloc.split(':')[0]
                        ip_addr = socket.gethostbyname(domain)
                    except:
                        ip_addr = "N/A"
                    
                    timeStr = datetime.now().strftime("%H:%M:%S")
                        
                    if displayQueue is not None and queueLock is not None:
                         with queueLock:
                             # Mapping: STATUS, URL, IP, SERVER, TIME, ACTION
                             displayQueue.append((
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
            progress.advance(scanTaskID, 1)
            
    except KeyboardInterrupt:
        import os
        os._exit(1)
    except Exception as e:
        # Error handling
        appendState(stateFile, ERROR, str(e), taskUrl)
        with remainingLock:
            remaining -= 1
            lastChecked = taskUrl
        # Update main scan progress even on error
        if progress and scanTaskID is not None:
            progress.advance(scanTaskID, 1)


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
    parser.add_argument("--dump", help="Automatically dump and recover artifacts from vulnerable targets", action="store_true")
    parser.add_argument("--output-dir", help="Output directory for dump (default: domain-xposed-datetime)", type=str)
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
    # Create a Rich Progress manager
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeRemainingColumn, TransferSpeedColumn, MofNCompleteColumn
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.live import Live
    from rich.console import Group
    from rich.box import HEAVY_EDGE
    
    # 1. Create the Findings Table
    findingsTable = Table(
        box=HEAVY_EDGE, 
        show_header=True, 
        header_style="bold white on blue", 
        title="[bold reverse cyan] TARGET EXPOSURE SYSTEMS [/bold reverse cyan]",
        # title_style="bold cyan", # Title style is handled in the text itself for reverse effect
        expand=True,
        border_style="bright_blue",
        row_styles=["", "dim"]
    )
    findingsTable.add_column("STATUS", justify="center", width=12, style="bold")
    findingsTable.add_column("TARGET URL", style="cyan")
    findingsTable.add_column("SERVER", style="magenta")
    findingsTable.add_column("TIME", style="dim white")
    findingsTable.add_column("ACTION", style="grey70")
    
    # Lock for table updates
    tableLock = threading.Lock()

    # 2. Create Progress Bar
    progress = Progress(
        SpinnerColumn(spinner_name="dots12", style="bold cyan"),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=None, complete_style="cyan", finished_style="green"),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        MofNCompleteColumn(),
        TimeRemainingColumn(),
        refresh_per_second=10
    )

    # 3. Create Group and Live View
    ui_group = Group(
        Panel(findingsTable, border_style="cyan"),
        progress
    )

    # Wrap execution in Live context
    # Note: We pass the table and lock to the worker
    with Live(ui_group, refresh_per_second=10, screen=False) as live:
        
        # Create the Overall Scan Progress bar
        scanTaskID = progress.add_task("[bold white]Scanning Targets[/bold white]", total=totalTargets)
        
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=args.threads)
        
        dumpingExecutor = None
        if args.dump:
            dumpingExecutor = concurrent.futures.ThreadPoolExecutor(max_workers=args.threads)

        futures = set()
        try:
            # Fixed-size queue for sliding window effect
            displayQueue: Deque[Tuple] = collections.deque(maxlen=10)
            queueLock = threading.Lock()

            # Helper to rebuild table
            def rebuildTable(queue):
                newTable = Table(
                    box=HEAVY_EDGE, 
                    show_header=True, 
                    header_style="bold white on blue", 
                    title="[bold reverse cyan] TARGET EXPOSURE SYSTEMS [/bold reverse cyan]",
                    expand=True,
                    border_style="bright_blue",
                    row_styles=["", "dim"]
                )
                newTable.add_column("STATUS", justify="center", width=12, style="bold", no_wrap=True)
                newTable.add_column("TARGET URL", style="cyan", ratio=1, overflow="fold")
                newTable.add_column("IP ADDRESS", style="blue", width=15, justify="center")
                newTable.add_column("SERVER", style="magenta", width=20, overflow="ellipsis", no_wrap=True)
                newTable.add_column("TIME", style="dim white", width=10, justify="center", no_wrap=True)
                newTable.add_column("ACTION", style="grey70", width=15, justify="center", no_wrap=True)
                
                with queueLock:
                    for row in queue:
                        # Handle variable length rows (SUSPICIOUS vs VULN)
                        if len(row) == 4: # Suspicous might be shorter? No, we padded it.
                             # But check just in case. Old suspicious was 3 elements for table. 
                             # We added IP, so it should be 6 elements total for full row, or handling differently
                             
                             # Full row is: STATUS, URL, IP, SERVER, TIME, ACTION (6 cols)
                             # SUSPICIOUS we added: STATUS, URL, IP, MSG, "", "" (6 items)
                             newTable.add_row(*row)
                        else:
                             newTable.add_row(*row)
                return newTable

            for url in toProcess:
                futures.add(executor.submit(
                    worker, 
                    url, 
                    session, 
                    args.timeout, 
                    args.state_file, 
                    dumpingExecutor, 
                    args.output_dir,
                    progress,      # Rich progress object
                    scanTaskID,    # Task ID to advance
                    displayQueue,  # Pass queue
                    queueLock      # Pass lock
                ))

            # Monitor completion
            while futures:
                done, futures = concurrent.futures.wait(futures, timeout=0.5, return_when=concurrent.futures.FIRST_COMPLETED)
                
                # Rebuild and update live view
                live.update(Group(
                    Panel(rebuildTable(displayQueue), border_style="cyan"),
                    progress
                ))
                
            if args.dump and dumpingExecutor:
                # We can print to console, but it might jump around with Live view. 
                # Better to use a transient task or just let it finish.
                pass

            # Clean shutdown (non-interrupt case)
            if args.dump and dumpingExecutor:
                dumpingExecutor.shutdown(wait=True)
            executor.shutdown(wait=True)
                
        except KeyboardInterrupt:
            # FORCE EXIT to prevent traceback spam from threading shutdown
            try:
                 live.stop()
            except:
                 pass
            import os
            from rich import print as rprint
            rprint("\n[bold yellow]Keyboard Interrupt! Exiting immediately...[/bold yellow]")
            os._exit(1)
            
        except Exception as e:
            # Use progress console to print error cleanly
            # But normally we just exit
            try:
                 live.stop()
            except:
                 pass
            import os
            from rich import print as rprint
            rprint(f"[bold red]Fatal Error: {e}[/bold red]")
            os._exit(2)

    print("\nScan complete.")
    if args.csv:
        writeFinalCsv(args.state_file)
    return 0

    print("\nScan complete.")
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
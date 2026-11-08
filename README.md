# xposedRepo.py

🚨 **Parallel .git Exposure Scanner & Dumper** (Military-Grade UI + Resumable State)

`xposedRepo.py` is a high-performance tool that scans targets in parallel for **exposed `.git` repositories** and optionally **dumps** their contents. It features a "Hardcore Tech" dashboard with industrial aesthetics for real-time reconnaissance.

---

## ✨ Key Features

### 🛡️ **Military-Grade Dashboard**
*   **Industrial UI**: Heavy-duty tables with high-contrast headers (White on Blue).
*   **Live Intel**: Real-time progress bars with "M of N" counters (e.g., `15/45`).
*   **Recon Columns**: Instantly see critical intel:
    *   **STATUS**: `VULNERABLE` (Red) / `SUSPICIOUS` (Yellow)
    *   **SERVER**: `nginx`, `Apache`, `Cloudflare` (Magenta)
    *   **TIME**: Discovery timestamp (Dim White)
*   **Clean Exit**: `Ctrl+C` exits immediately without leaving terminal artifacts. Results already written to the `.state` file are kept; in-flight probes and dumps are abandoned.

### ⚡ **High-Performance Scanning**
*   **Parallel Execution**: Scans hundreds of targets concurrently (default: 50 threads).
*   **Resumable**: Progress is saved to the `.state` file immediately. The default state file is timestamped per run, so pass `--state-file <file>` to resume a previous scan (the path is printed when a scan ends).
*   **Smart Detection**: Checks `/.git/`, `HEAD`, `config` and pack files. Redirects are not followed, HTML responses are rejected on paths that are never HTML, and `HEAD` must contain a real symbolic ref or a bare 40-hex object ID -- so 200-status "soft 404" pages are not reported as findings.

### 📦 **Auto-Dump Integration**
*   **--dump**: Automatically triggers the standard `git-dumper` logic for vulnerable targets.
*   **Artifact Recovery**: Extracts commits and objects to a local directory.
*   **Commit Counting**: Displays the number of extracted commits (e.g., `Dumped target.com ✓ (120 commits)`).

---

## 📦 Installation

1.  **Clone the repository**:
    ```bash
    git clone https://github.com/your-repo/xposed.git
    cd xposed
    ```
2.  **Install Dependencies**:
    ```bash
    pip3 install -r requirements.txt
    ```
    *   Requires `rich`, `requests`, `dulwich` (for dumper).

---

## 🚀 Usage

### 1. Basic Scan (Recon Only)
Scan a list of targets and see the live dashboard.
```bash
python3 xposedRepo.py -i targets.txt
```

### 2. Scan & Auto-Dump (Full Attack)
Scan targets and automatically dump the source code of vulnerable ones.
```bash
python3 xposedRepo.py -i targets.txt --dump
```
> **Note**: Dumps are saved to the current directory (or `--output-dir`) with a timestamped folder name.

### 3. Single Target Dump
Dump a specific target immediately.
```bash
python3 xposedRepo.py -u http://target.com --dump
```

### 4. Advanced Options
```bash
python3 xposedRepo.py -i targets.txt -t 100 --timeout 10 --state-file operation_alpha.state
```

| Flag | Description | Default |
| :--- | :--- | :--- |
| `-i / --input` | List of targets (one per line) | - |
| `-u / --url` | Single target URL | - |
| `--dump` | Enable auto-dumping of artifacts | False |
| `-t / --threads` | Number of worker threads | 50 |
| `-T / --timeout` | Request timeout (seconds) | 5 |
| `--output-dir` | Directory to save dumps | `./<domain>-xposed-<time>` |
| `--csv` | Write a CSV report when the scan finishes | False |
| `--rate-limit` | Cap HTTP requests per second across all workers (0 = unlimited). Each target costs up to 5 requests. | 0 |
| `--resolve` | Resolve IPs for findings and show the IP column | False |
| `--state-file` | State file to resume from | `.state_<timestamp>` |
| `--max` | Stop after N targets from the input file | 0 (all) |

---

## 📂 Output Formats

### 1. Live Dashboard (Console)
A heavy-duty terminal UI showing:
*   **Target Status**: `VULNERABLE` / `SUSPICIOUS`
*   **Server Tech**: e.g., `nginx/1.18`
*   **Action**: `Dumping...` or `Logged`

### 2. CSV Report
With `--csv`, results are written to a CSV file (e.g., `28-Dec-2025-RepoXpose.csv`).
Fields containing commas or quotes are properly quoted, so the `url` column is
always the third field.
```csv
status,code_or_message,url
VULNERABLE,200,https://victim.com
SUSPICIOUS,403,https://example.org
```

### 3. State File (`.state`)
Raw log for resuming scans.
```text
VULNERABLE,200,https://victim.com
OK,404,https://safe.com
```

---

## ⚠️ Disclaimer
This tool is for **security research and authorized testing only**. Usage against systems without permission is illegal. The author assumes no liability for misuse.

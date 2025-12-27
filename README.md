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
*   **Clean Exit**: Graceful shutdown on `Ctrl+C` without terminal artifacts.

### ⚡ **High-Performance Scanning**
*   **Parallel Execution**: Scans hundreds of targets concurrently (default: 50 threads).
*   **Resumable**: Progress is saved to `.state` file immediately. Restarting resumes where you left off.
*   **Smart Detection**: Checks `/.git/`, `HEAD`, `config`, and Pack files for accurate validation.

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

---

## 📂 Output Formats

### 1. Live Dashboard (Console)
A heavy-duty terminal UI showing:
*   **Target Status**: `VULNERABLE` / `SUSPICIOUS`
*   **Server Tech**: e.g., `nginx/1.18`
*   **Action**: `Dumping...` or `Logged`

### 2. CSV Report
Final results are saved to a CSV file (e.g., `28-Dec-2025-xposedRepo.csv`).
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

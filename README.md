# xposedRepo.py

🚨 **Parallel .git Exposure Scanner** (with resumable state + colored output)

`xposedRepo.py` is a Python tool that scans multiple targets in parallel for **exposed `.git` repositories** — a common but critical security misconfiguration.

It supports resuming interrupted scans, colored output for quick results triage, error handling, and generates a final CSV report.

---

## ✨ Features

* **Parallel scanning** with configurable threads (default: 50).
* **Resumable state file** (`.state`) — progress is saved as it runs.
* **Thread-safe logging** — each result is recorded immediately.
* **Error handling & retries** — gracefully continues on failures.
* **Colorized output**:

  * 🟥 **VULNERABLE**
  * 🟩 **MAYBE VULNERABLE**
* **Remaining counter** with live updates (lightweight, no progress bars).
* **CSV reporting** — results are exported as `DD-Mmm-YYYY-xposedRepo.csv`
  (e.g. `04-Oct-2025-xposedRepo.csv`).
* **Custom month mapping** (`Sept` instead of `Sep`).
* **KeyboardInterrupt safe** — exits gracefully and saves progress.

---

## 📦 Installation

1. Clone/download this repository.
2. Ensure Python **3.7+** is installed.
3. Install dependencies:

```bash
pip install -r requirements.txt
```

> Minimal dependencies:
>
> * `requests`

---

## 🚀 Usage

### Single target scan

```bash
python3 xposedRepo.py -u example.com
```

### Multiple targets (from file)

```bash
python3 xposedRepo.py -i targets.txt
```

### Custom options

```bash
python3 xposedRepo.py -i targets.txt -t 100 -T 10 --state-file myscan.state
```

Options:

* `-i / --input` → file of domains/URLs (one per line).
* `-u / --url` → single target domain/URL.
* `-t / --threads` → number of parallel workers (default: 50).
* `-T / --timeout` → request timeout in seconds (default: 5).
* `--state-file` → path to `.state` file (default: `.state`).
* `--max` → limit number of targets (for testing/debugging).

---

## 📂 Output

### Console

* Prints **only vulnerable / maybe vulnerable** results (colored).
* Live counter for progress:

  ```
  Remaining: 37/100  Last checked: https://example.com
  ```

### State file

* Stored in `.state` (or custom path).
* Format:

  ```
  STATUS,CODE_OR_MESSAGE,URL
  ```

Example:

```
VULNERABLE,200,https://example.com
OK,404,https://another.com
ERROR,Timeout,https://slow.com
```

### Final CSV

* Written at the end (or on interruption).
* Named: `DD-Mmm-YYYY-xposedRepo.csv`

Columns:

* `status`
* `code_or_message`
* `url`

---

## 🛠️ Detection Logic

`xposedRepo.py` checks the following for each target:

* `/.git/` → directory listing (`Index of /.git`).
* `/.git/HEAD` → looks for `ref: refs/` or SHA-like strings.
* `/.git/config` → looks for `[core]`.
* `/.git/objects/info/packs` & `/.git/objects/pack/` → indicators of Git packs.
* Status codes `401/403` → flagged as **MAYBE VULNERABLE**.
* Redirects pointing to `.git`.

Results:

* 🟥 **VULNERABLE** → confirmed Git exposure.
* 🟩 **MAYBE VULNERABLE** → suspicious, needs manual review.
* ✅ **OK** → not vulnerable.
* ❌ **ERROR** → request/connection issues.

---

## 🔄 State & Resume

* Progress is written **per target** into `.state`.
* If the scan is interrupted, restarting with the same state file will **skip already processed URLs**.
* Results are **always appended**, not overwritten.

---

## ⚡ Examples

### Resume an interrupted scan

```bash
python3 xposedRepo.py -i biglist.txt --state-file .state
```

### Limit to 50 targets for quick testing

```bash
python3 xposedRepo.py -i biglist.txt --max 50
```

### Scan with more threads & higher timeout

```bash
python3 xposedRepo.py -i govsites.txt -t 200 -T 15
```

---

## 📖 Example Output

Console:

```
[VULNERABLE] https://victim.com -- 200
[MAYBE VULNERABLE] https://weirdtarget.net -- 403
```

CSV (04-Oct-2025-xposedRepo.csv):

```csv
status,code_or_message,url
VULNERABLE,200,https://victim.com
MAYBE VULNERABLE,403,https://weirdtarget.net
OK,404,https://safe.org
```

---

## ⚠️ Disclaimer

This tool is intended for **security research & educational purposes only**.
Do not use it against systems without **explicit authorization**.

---

## 💡 Future Improvements

* AsyncIO-based scanner for higher scalability.
* JSON output mode.
* Target deduplication & normalization improvements.
* Plugin system for additional exposures.

---

## 👨‍💻 Author

* Developed by **Suman Roy** (Security Researcher).
* Contributions and PRs welcome!

---

### Made with ❤️ by Suman Roy

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-blue?style=flat-square\&logo=linkedin)](https://www.linkedin.com/in/sumanrox/)

**My bio:**
[https://linktr.ee/sumanroy.official](https://linktr.ee/sumanroy.official)

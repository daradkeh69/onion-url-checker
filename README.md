
<h1 align="center">🧅 Onion URL Checker</h1>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.7%2B-blue.svg" alt="Python">
  <img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT">
  <img src="https://img.shields.io/github/last-commit/daradkeh69/websec-scanner" alt="Last Commit">
</p>

A small, professional Python tool to check `.onion` URLs over the Tor network. It tests whether each URL is Alive, Timeout, or Dead and records HTTP status codes and load times.

---

## Features

- Read `.onion` URLs from a CSV file (one URL per row, first column)
- Send HTTP requests via Tor SOCKS5 proxy (default: `127.0.0.1:9050`)
- Concurrent checks using threads (configurable number of workers)
- Retry/backoff logic and optional Tor circuit renewal (NEWNYM) via `stem`
- CSV or JSON output, progress bar, logging, and summary report

---

## Requirements

- Python 3.8+
- Tor running locally (for SOCKS proxy and optional control port)

Recommended Python packages (see `requirements.txt`):

- requests[socks]
- tqdm
- stem

---

## Installation

1. Create and activate a virtual environment (recommended):

```
python3 -m venv venv
source venv/bin/activate
```

2. Install dependencies:

```
pip install -r requirements.txt
```

3. Ensure Tor is running. On macOS/Homebrew:

```
brew install tor
tor &
```

   On Linux (Debian/Ubuntu):

```
sudo apt install tor
sudo systemctl start tor
```

If you want the script to request new Tor circuits (NEWNYM), enable Tor's control port in your torrc (e.g. `ControlPort 9051`) and set a hashed control password (or use `CookieAuthentication 1`).

---
## Running in Docker

1. Build the image:

```
docker build -t onion-checker .
```

2. Run the container (mounting your current directory):

```
docker run --rm -v $(pwd):/app onion-checker
```

---
## Usage

Basic:

```
python3 main.py urls.csv
```

Options (examples):

- Save JSON results:

```
python3 main.py urls.csv -o results.json
```

- Increase concurrency and timeout:

```
python3 main.py urls.csv -w 20 -t 20
```

- Renew Tor circuit every 10 checks (requires control port and stem):

```
python3 main.py urls.csv --renew-every 10 --control-port 9051 --control-password your_password
```

---

## Notes

- The script treats any HTTP response as "Alive" (including 301/404). Timeouts are reported as "Timeout". Connection errors and other exceptions are reported as "Dead".
- Run Tor locally and verify the SOCKS port (default 9050) before running the checker.
- For large lists, increase `--workers` but avoid overwhelming the Tor network.

---
## ⚠️ Disclaimer & License

> **This tool is for educational and authorized security testing only.**
> - **Do NOT scan targets without explicit permission.**
> - **You may NOT copy, redistribute, or claim credit for this code.**
> - Commercial use, code reuse, or derivative works are strictly prohibited.

---
## License

MIT
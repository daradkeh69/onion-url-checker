#!/usr/bin/env python3
import csv
import requests
import sys
import time
import argparse
import json
import logging
import socket
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

try:
    from tqdm import tqdm
except Exception:
    tqdm = None

# Optional: stem for renewing Tor circuits
try:
    from stem import Signal
    from stem.control import Controller
    STEM_AVAILABLE = True
except Exception:
    STEM_AVAILABLE = False

TOR_SOCKS_PROXY = "socks5h://127.0.0.1:9050"


def validate_proxy(proxy, timeout=3):
    """Quickly check that the proxy host:port is reachable via TCP.

    Returns (True, None) on success or (False, reason) on failure.
    """
    if not proxy:
        return False, "no proxy configured"

    try:
        p = urlparse(proxy)
    except Exception as e:
        return False, f"invalid proxy URL: {e}"

    host = p.hostname
    port = p.port
    if not port:
        port = 9050 if p.scheme and p.scheme.startswith("socks") else 80

    try:
        socket.create_connection((host, port), timeout=timeout)
        return True, None
    except Exception as e:
        return False, str(e)


def load_urls(csv_file):
    urls = []
    with open(csv_file, "r") as f:
        reader = csv.reader(f)
        for row in reader:
            if row:
                u = row[0].strip()
                if not u.startswith(("http://", "https://")):
                    u = "http://" + u
                urls.append(u)
    return urls


def create_session(proxy=TOR_SOCKS_PROXY, retries=2, backoff_factor=0.5, status_forcelist=(429, 500, 502, 503, 504)):
    session = requests.Session()
    session.trust_env = False
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0 Safari/537.36"
    })

    retry = Retry(
        total=retries,
        read=retries,
        connect=retries,
        backoff_factor=backoff_factor,
        status_forcelist=status_forcelist,
        allowed_methods=("GET", "HEAD", "OPTIONS"),
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    if proxy:
        session.proxies = {"http": proxy, "https": proxy}

    return session


def check_url(url, timeout=15, proxy=TOR_SOCKS_PROXY, retries=2, backoff_factor=0.5):
    try:
        session = create_session(proxy=proxy, retries=retries, backoff_factor=backoff_factor)
    except requests.exceptions.InvalidSchema as e:
        return {"url": url, "status": "Dead", "http_status": None, "load_time": None, "error": f"Invalid proxy schema: {e}. Install pysocks via 'pip install requests[socks]'"}
    except Exception as e:
        return {"url": url, "status": "Dead", "http_status": None, "load_time": None, "error": str(e)}

    try:
        start = time.time()
        response = session.get(url, timeout=timeout)
        elapsed = round(time.time() - start, 2)
        return {"url": url, "status": "Alive", "http_status": response.status_code, "load_time": elapsed, "error": None}

    except requests.exceptions.Timeout:
        return {"url": url, "status": "Timeout", "http_status": None, "load_time": None, "error": "timeout"}

    except requests.exceptions.ProxyError as e:
        msg = str(e)
        suggestion = ""
        if "General SOCKS server failure" in msg:
            suggestion = " (Tor SOCKS proxy returned 'General SOCKS server failure' — check Tor logs, correct SOCKS port (9050 vs 9150), and ensure the proxy accepts connections)"

        if STEM_AVAILABLE:
            if renew_tor_circuit(quiet=True):
                try:
                    start = time.time()
                    response = session.get(url, timeout=timeout)
                    elapsed = round(time.time() - start, 2)
                    return {"url": url, "status": "Alive", "http_status": response.status_code, "load_time": elapsed, "error": None}
                except Exception as e2:
                    msg = f"{msg} | retry after NEWNYM failed: {e2}"
            else:
                msg = f"{msg} | NEWNYM request failed"

        return {"url": url, "status": "Dead", "http_status": None, "load_time": None, "error": msg + suggestion}

    except requests.exceptions.ConnectionError as e:
        msg = str(e)
        suggestion = ""
        if "Failed to establish a new connection" in msg or "Connection refused" in msg:
            suggestion = " (connection failed — is Tor running and listening on the configured SOCKS port?)"

        if STEM_AVAILABLE:
            if renew_tor_circuit(quiet=True):
                try:
                    start = time.time()
                    response = session.get(url, timeout=timeout)
                    elapsed = round(time.time() - start, 2)
                    return {"url": url, "status": "Alive", "http_status": response.status_code, "load_time": elapsed, "error": None}
                except Exception as e2:
                    msg = f"{msg} | retry after NEWNYM failed: {e2}"
            else:
                msg = f"{msg} | NEWNYM request failed"

        return {"url": url, "status": "Dead", "http_status": None, "load_time": None, "error": msg + suggestion}

    except requests.exceptions.InvalidSchema as e:
        return {"url": url, "status": "Dead", "http_status": None, "load_time": None, "error": f"Invalid proxy schema: {e}. Install pysocks via 'pip install requests[socks]'"}

    except Exception as e:
        return {"url": url, "status": "Dead", "http_status": None, "load_time": None, "error": str(e)}


def save_results(results, output_file="results.csv", output_format="csv"):
    if output_format == "json":
        with open(output_file, "w") as f:
            json.dump(results, f, indent=2)
    else:
        with open(output_file, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["url", "status", "http_status", "load_time_sec", "error"])
            for r in results:
                writer.writerow([r.get("url"), r.get("status"), r.get("http_status"), r.get("load_time"), r.get("error")])


def color(text, code):
    return f"\033[{code}m{text}\033[0m"


def renew_tor_circuit(control_port=9051, password=None, quiet=True):
    if not STEM_AVAILABLE:
        logging.debug("stem not available; cannot renew Tor circuit")
        return False

    try:
        with Controller.from_port(port=control_port) as controller:
            if password:
                controller.authenticate(password=password)
            else:
                controller.authenticate()
            controller.signal(Signal.NEWNYM)
        if not quiet:
            logging.info("Requested new Tor circuit (NEWNYM)")
        return True
    except Exception as e:
        logging.warning(f"Failed to renew Tor circuit: {e}")
        return False


def run_checks(urls, workers=10, timeout=15, proxy=TOR_SOCKS_PROXY, retries=2, backoff_factor=0.5, renew_every=0, control_port=9051, control_password=None, show_progress=True):
    results = []
    total = len(urls)

    iterator = urls
    if show_progress and tqdm:
        iterator = tqdm(urls, desc="Checking", unit="url", bar_format="{l_bar}{bar} | {n_fmt}/{total_fmt} [{percentage:3.0f}%]")

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(check_url, url, timeout, proxy, retries, backoff_factor): url for url in urls}

        completed = 0
        for fut in as_completed(futures):
            res = fut.result()
            results.append(res)
            completed += 1

            if show_progress and tqdm:
                iterator.update(1)

            if renew_every and completed % renew_every == 0:
                renew_tor_circuit(control_port=control_port, password=control_password, quiet=True)

    if show_progress and tqdm:
        iterator.close()

    return results


def print_summary(results):
    total = len(results)
    alive = sum(1 for r in results if r.get("status") == "Alive")
    timeout = sum(1 for r in results if r.get("status") == "Timeout")
    dead = sum(1 for r in results if r.get("status") == "Dead")

    print()
    print(color("--- Summary ---", "34"))
    print(color(f"Total: {total}", "34"))
    print(color(f"Alive: {alive}", "32"))
    print(color(f"Timeout: {timeout}", "33"))
    print(color(f"Dead: {dead}", "31"))


def setup_logging(verbose=False):
    logging.basicConfig(format="%(asctime)s %(levelname)s: %(message)s", level=logging.CRITICAL)


def main():
    parser = argparse.ArgumentParser(description="Onion URL Health Checker — checks .onion URLs over Tor")
    parser.add_argument("input", help="CSV file with one URL per row (first column)")
    parser.add_argument("-o", "--output", help="Output file (CSV or JSON by extension)", default="results.csv")
    parser.add_argument("-w", "--workers", type=int, help="Number of concurrent workers", default=10)
    parser.add_argument("-t", "--timeout", type=int, help="Request timeout in seconds", default=15)
    parser.add_argument("--retries", type=int, help="Per-request retry attempts", default=2)
    parser.add_argument("--backoff", type=float, help="Backoff factor for retries", default=0.5)
    parser.add_argument("--proxy", help=f"SOCKS proxy URL (default: {TOR_SOCKS_PROXY})", default=TOR_SOCKS_PROXY)
    parser.add_argument("--renew-every", type=int, help="Request new Tor circuit every N checks (requires Tor control port and stem)", default=0)
    parser.add_argument("--control-port", type=int, help="Tor control port (for NEWNYM)", default=9051)
    parser.add_argument("--control-password", help="Tor control port password (if set)", default=None)
    parser.add_argument("--no-progress", action="store_true", help="Disable progress bar")
    parser.add_argument("--filter", choices=["all", "alive", "dead", "timeout"], default="all", help="Filter output rows")
    parser.add_argument("--verbose", action="store_true", help="Verbose logging")

    args = parser.parse_args()

    setup_logging(args.verbose)

    try:
        urls = load_urls(args.input)
    except Exception as e:
        logging.error(f"Failed to read input CSV: {e}")
        sys.exit(1)

    if not urls:
        logging.info("No URLs found in input file")
        sys.exit(0)

    ok, reason = validate_proxy(args.proxy)
    if not ok:
        logging.warning(f"Proxy {args.proxy} appears unreachable: {reason}. Ensure Tor is running and the SOCKS port is correct (9050 or 9150). Also ensure 'pysocks' is installed: pip install requests[socks]")

    print(color("\n--- Onion URL Checker ---\n", "34"))

    proxies_to_try = [args.proxy]
    if args.proxy == TOR_SOCKS_PROXY:
        proxies_to_try.extend(["socks5h://127.0.0.1:9150", "socks5h://localhost:9050"])

    results = None
    used_proxy = None
    for p in proxies_to_try:
        logging.info(f"Attempting checks using proxy {p}")
        ok, reason = validate_proxy(p)
        if not ok:
            logging.debug(f"Skipping proxy {p}: {reason}")
            continue

        results = run_checks(urls, workers=args.workers, timeout=args.timeout, proxy=p, retries=args.retries, backoff_factor=args.backoff, renew_every=args.renew_every, control_port=args.control_port, control_password=args.control_password, show_progress=not args.no_progress)

        if any(r.get("status") == "Alive" for r in results):
            used_proxy = p
            logging.info(f"Using proxy {p} — some hosts responded")
            break
        else:
            logging.info(f"No hosts responded via proxy {p}, trying next candidate if available")

    if results is None:
        logging.error("No valid SOCKS proxy available; aborting")
        sys.exit(1)

    if args.filter != "all":
        filtered = [r for r in results if r.get("status").lower() == args.filter]
    else:
        filtered = results

    out_fmt = "json" if args.output.lower().endswith(".json") else "csv"
    save_results(filtered, output_file=args.output, output_format=out_fmt)

    print(color(f"Saved results to {args.output}\n", "35"))

    print_summary(results)


if __name__ == "__main__":
    main()

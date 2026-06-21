#!/usr/bin/env python3
"""
bench.py v1.0 — VPN split-tunnel performance benchmark
Run on the VICTIM machine before and after DHCP poisoning.

Workflow:
  1. Connect victim to VPN normally, then:
       python bench.py run baseline

  2. Trigger DHCP poisoning from attacker, then:
       python bench.py run split

  3. Compare:
       python bench.py compare bench_baseline.json bench_split.json

Measures: ICMP latency, TCP connect time, DNS resolution time, HTTP throughput.
No third-party libraries required — stdlib only.
"""

import argparse
import json
import re
import socket
import statistics
import subprocess
import sys
import time
import urllib.request
from datetime import datetime

VERSION = "1.0"

DEFAULT_INTERNET_TARGETS = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
DEFAULT_TCP_PORT         = 80
DEFAULT_DNS_HOSTS        = ["google.com", "cloudflare.com", "github.com"]
DEFAULT_DOWNLOAD_URL     = "http://ipv4.download.thinkbroadband.com/5MB.zip"
DOWNLOAD_CHUNK           = 65536


# ── Test: ICMP ping ────────────────────────────────────────────────────────────

def ping_host(host: str, count: int) -> dict:
    """Return RTT stats (ms) parsed from platform ping summary line."""
    if sys.platform == "win32":
        cmd = ["ping", "-n", str(count), host]
    else:
        cmd = ["ping", "-c", str(count), "-W", "2", "-q", host]

    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=count * 3 + 5)
        out = r.stdout + r.stderr
    except subprocess.TimeoutExpired:
        return {"error": "timeout"}

    if sys.platform == "win32":
        m_loss = re.search(r"\((\d+)% loss\)", out)
        m_min  = re.search(r"Minimum = (\d+)ms", out)
        m_max  = re.search(r"Maximum = (\d+)ms", out)
        m_avg  = re.search(r"Average = (\d+)ms", out)
        if not m_avg:
            return {"error": "no replies"}
        return {
            "min":      float(m_min.group(1)),
            "avg":      float(m_avg.group(1)),
            "max":      float(m_max.group(1)),
            "stddev":   None,
            "loss_pct": float(m_loss.group(1)) if m_loss else 100.0,
        }
    else:
        m_loss = re.search(r"(\d+)% packet loss", out)
        m_rtt  = re.search(r"rtt .* = ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+) ms", out)
        if not m_rtt:
            return {"error": "no replies",
                    "loss_pct": float(m_loss.group(1)) if m_loss else 100.0}
        return {
            "min":      float(m_rtt.group(1)),
            "avg":      float(m_rtt.group(2)),
            "max":      float(m_rtt.group(3)),
            "stddev":   float(m_rtt.group(4)),
            "loss_pct": float(m_loss.group(1)) if m_loss else 0.0,
        }


# ── Test: TCP connect time ─────────────────────────────────────────────────────

def tcp_connect_time(host: str, port: int, count: int) -> dict:
    """Measure TCP handshake time in ms (excludes DNS — uses raw IP or pre-resolved)."""
    times  = []
    errors = 0
    for _ in range(count):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            t0 = time.perf_counter()
            s.connect((host, port))
            times.append((time.perf_counter() - t0) * 1000)
            s.close()
        except OSError:
            errors += 1
        time.sleep(0.05)

    if not times:
        return {"error": f"all {errors} connections failed"}
    return {
        "min":    round(min(times), 2),
        "avg":    round(statistics.mean(times), 2),
        "max":    round(max(times), 2),
        "stddev": round(statistics.stdev(times) if len(times) > 1 else 0.0, 2),
        "errors": errors,
    }


# ── Test: DNS resolution time ──────────────────────────────────────────────────

def dns_resolve_time(host: str, count: int) -> dict:
    """Measure time for getaddrinfo() to resolve a hostname (ms)."""
    times  = []
    errors = 0
    for _ in range(count):
        try:
            t0 = time.perf_counter()
            socket.getaddrinfo(host, None)
            times.append((time.perf_counter() - t0) * 1000)
        except OSError:
            errors += 1
        time.sleep(0.05)

    if not times:
        return {"error": f"all {errors} lookups failed"}
    return {
        "min":    round(min(times), 2),
        "avg":    round(statistics.mean(times), 2),
        "max":    round(max(times), 2),
        "stddev": round(statistics.stdev(times) if len(times) > 1 else 0.0, 2),
        "errors": errors,
    }


# ── Test: HTTP download throughput ─────────────────────────────────────────────

def http_download(url: str, duration_s: float) -> dict:
    """Download from URL for up to duration_s seconds; return Mbps."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "bench/1.0"})
        total = 0
        t0    = time.perf_counter()
        with urllib.request.urlopen(req, timeout=15) as resp:
            while True:
                chunk = resp.read(DOWNLOAD_CHUNK)
                if not chunk:
                    break
                total += len(chunk)
                if time.perf_counter() - t0 >= duration_s:
                    break
        elapsed = time.perf_counter() - t0
        mbps    = (total * 8) / (elapsed * 1_000_000)
        return {
            "mbps":      round(mbps, 2),
            "bytes":     total,
            "elapsed_s": round(elapsed, 2),
        }
    except Exception as e:
        return {"error": str(e)}


# ── Run all tests ──────────────────────────────────────────────────────────────

def run_benchmark(args) -> dict:
    results = {
        "label":     args.label,
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "version":   VERSION,
        "tests":     {},
    }
    T = results["tests"]

    targets = list(args.targets) if args.targets else list(DEFAULT_INTERNET_TARGETS)
    if args.vpn_host:
        targets.append(args.vpn_host)

    # ICMP ping
    for host in targets:
        print(f"  ping {host} x{args.count} ...", end="  ", flush=True)
        r = ping_host(host, args.count)
        T[f"ping_{host}"] = r
        if "avg" in r:
            print(f"avg={r['avg']} ms  loss={r['loss_pct']}%")
        else:
            print(r.get("error", "?"))

    # TCP connect (internet hosts only — not the VPN host, which may not have open ports)
    inet_targets = list(args.targets) if args.targets else DEFAULT_INTERNET_TARGETS
    for host in inet_targets:
        print(f"  tcp {host}:{DEFAULT_TCP_PORT} x{args.count} ...", end="  ", flush=True)
        r = tcp_connect_time(host, DEFAULT_TCP_PORT, args.count)
        T[f"tcp_{host}:{DEFAULT_TCP_PORT}"] = r
        if "avg" in r:
            print(f"avg={r['avg']} ms")
        else:
            print(r.get("error", "?"))

    # DNS resolution
    for host in DEFAULT_DNS_HOSTS:
        print(f"  dns {host} x{args.count} ...", end="  ", flush=True)
        r = dns_resolve_time(host, args.count)
        T[f"dns_{host}"] = r
        if "avg" in r:
            print(f"avg={r['avg']} ms")
        else:
            print(r.get("error", "?"))

    # HTTP download
    if not args.no_download:
        url = args.download or DEFAULT_DOWNLOAD_URL
        print(f"  download ({args.download_secs}s cap) ...", end="  ", flush=True)
        r = http_download(url, args.download_secs)
        T["http_download"] = r
        if "mbps" in r:
            print(f"{r['mbps']} Mbps  ({r['bytes'] // 1024} KB in {r['elapsed_s']}s)")
        else:
            print(r.get("error", "?"))

    return results


# ── Compare two result files ───────────────────────────────────────────────────

def compare(path_a: str, path_b: str) -> None:
    with open(path_a) as f:
        a = json.load(f)
    with open(path_b) as f:
        b = json.load(f)

    la, lb = a["label"], b["label"]
    ta, tb = a["tests"], b["tests"]
    all_keys = sorted(set(ta) | set(tb))

    col = max(len(k) for k in all_keys) + 2
    hdr = f"{'Test':<{col}}  {la:>10}  {lb:>10}  {'Delta':>10}  {'Change':>8}"
    print(f"\n{hdr}")
    print("─" * len(hdr))

    for key in all_keys:
        va = ta.get(key, {})
        vb = tb.get(key, {})

        if key == "http_download":
            metric, unit, higher_better = "mbps", "Mbps", True
        else:
            metric, unit, higher_better = "avg", "ms", False

        try:
            fa = float(va[metric])
            fb = float(vb[metric])
        except (KeyError, TypeError, ValueError):
            ea = va.get("error", "?")[:12] if isinstance(va, dict) else "?"
            eb = vb.get("error", "?")[:12] if isinstance(vb, dict) else "?"
            print(f"{key:<{col}}  {ea:>10}  {eb:>10}  {'N/A':>10}  {'':>8}")
            continue

        delta = fb - fa
        pct   = (delta / fa * 100) if fa else float("nan")

        if higher_better:
            symbol = "▲ faster" if delta > 1 else ("▼ slower" if delta < -1 else "≈ same")
        else:
            symbol = "▼ faster" if delta < -1 else ("▲ slower" if delta > 1 else "≈ same")

        print(f"{key:<{col}}  {fa:>9.2f}  {fb:>9.2f}  {delta:>+9.2f}  {pct:>+6.1f}% {symbol}")

    print()
    print(f"  {la}: {a['timestamp']}    {lb}: {b['timestamp']}")
    print()


# ── Entry point ────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description=f"VPN split-tunnel benchmark v{VERSION}"
    )
    sub = parser.add_subparsers(dest="cmd")

    # ── run ──────────────────────────────────────────────────────────────────
    rp = sub.add_parser("run", help="Run benchmark and save results to JSON")
    rp.add_argument("label",
                    help="Label for this run: 'baseline' (full VPN) or 'split' (after poisoning)")
    rp.add_argument("-o", "--out", default=None,
                    help="Output file (default: bench_<label>.json)")
    rp.add_argument("--targets", nargs="+", metavar="IP", default=None,
                    help=f"Internet IPs to ping/connect (default: {DEFAULT_INTERNET_TARGETS})")
    rp.add_argument("--vpn-host", default=None, metavar="IP",
                    help="VPN internal host to also ping (e.g. 10.8.0.1)")
    rp.add_argument("--count", type=int, default=10,
                    help="Iterations per ping/TCP/DNS test (default: 10)")
    rp.add_argument("--download", default=None, metavar="URL",
                    help=f"URL for throughput test (default: {DEFAULT_DOWNLOAD_URL})")
    rp.add_argument("--download-secs", type=float, default=10.0,
                    help="Seconds to run download test (default: 10)")
    rp.add_argument("--no-download", action="store_true",
                    help="Skip the HTTP download throughput test")

    # ── compare ───────────────────────────────────────────────────────────────
    cp = sub.add_parser("compare", help="Compare two saved result files")
    cp.add_argument("baseline", help="Baseline result JSON (full VPN)")
    cp.add_argument("split",    help="Split-tunnel result JSON (after poisoning)")

    args = parser.parse_args()

    if args.cmd == "compare":
        compare(args.baseline, args.split)
        return

    if args.cmd != "run":
        parser.print_help()
        sys.exit(1)

    out = args.out or f"bench_{args.label}.json"
    print(f"[bench] Running '{args.label}'  ({datetime.now().strftime('%H:%M:%S')})")
    print(f"[bench] Output  → {out}\n")

    results = run_benchmark(args)

    with open(out, "w") as f:
        json.dump(results, f, indent=2)

    print(f"\n[bench] Saved → {out}")
    print(f"[bench] Compare: python bench.py compare bench_baseline.json {out}\n")


if __name__ == "__main__":
    main()

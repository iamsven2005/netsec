#!/usr/bin/env python3
from __future__ import annotations
import argparse
import ipaddress
import platform
import socket
import subprocess
import sys
import threading
import time
from ospf_route_addition import prompt_and_add_router_stub_route

try:
    from scapy.all import Ether, IP, conf as scapy_conf, get_if_addr, sendp, sniff
    from scapy.contrib.ospf import (
        OSPF_DBDesc,
        OSPF_Hdr,
        OSPF_Hello,
        OSPF_LSA_Hdr,
        OSPF_LSAck,
        OSPF_LSReq,
        OSPF_LSUpd,
        OSPF_Link,
        OSPF_Router_LSA,
    )
except ImportError:
    sys.exit("[!] pip install scapy  (Windows: also install Npcap)")

ALL_SPF_MULTICAST = "224.0.0.5"
ALL_DR_MULTICAST = "224.0.0.6"
ALL_SPF_MAC = "01:00:5e:00:00:05"
ALL_DR_MAC = "01:00:5e:00:00:06"
OSPF_PROTO = getattr(socket, "IPPROTO_OSPF", 89)
OSPF_OPTIONS = 0x02
DEAD_INTERVAL = 40
HELLO_INTERVAL = 10
INITIAL_DBD_SEQ = 1000
BASE_LSA_SEQUENCE = 0x80000001
BACKBONE_AREA = "0.0.0.0"
DEFAULT_ROUTER_ID = "99.99.99.99"
OSPF_NBR_ROUTES_DB = {}

DOWN = "DOWN"
INIT = "INIT"
TWO_WAY = "TWO_WAY"
EXSTART = "EXSTART"
EXCHANGE = "EXCHANGE"
LOADING = "LOADING"
FULL = "FULL"

ACTIVE_NEIGHBOR_STATES = (INIT, TWO_WAY, EXSTART, EXCHANGE, LOADING, FULL)
DBD_READY_STATES = (EXSTART, EXCHANGE, LOADING, FULL)
MENU_HELP_TEXT = (
    "[MENU] Available commands: '1' adds a Router-LSA route, '2' shows neighbours, "
    "'3' shows the LSDB, '4' shows OSPF_NBR_ROUTES_DB, 'q' hides the menu prompt, and "
    "'m' shows it again."
)
MENU_PROMPT = "ospf-menu> "
MENU_HIDDEN_PROMPT = "ospf-menu(hidden)> "
MENU_HIDDEN_TEXT = "[MENU] The menu prompt is hidden. Type 'm' to show it again."


def log_message(message):
    sys.stdout.write(f"[{time.strftime('%H:%M:%S')}] {message}\n")
    sys.stdout.flush()


def default_iface():
    try:
        interface_name = getattr(scapy_conf.iface, "name", str(scapy_conf.iface))
        if interface_name and interface_name != "None":
            return interface_name
    except Exception:
        pass
    return "Ethernet" if platform.system() == "Windows" else "eth0"


def read_interface_ip(interface_name):
    try:
        address = get_if_addr(interface_name)
        if address and address != "0.0.0.0":
            return address
    except Exception:
        pass
    if platform.system() == "Windows":
        try:
            if interface_name.startswith("\\Device\\"):
                alias = scapy_conf.ifaces.dev_from_networkname(interface_name).name
                address = get_if_addr(alias)
            else:
                network_name = scapy_conf.ifaces.dev_from_name(interface_name).network_name
                address = get_if_addr(network_name)
            if address and address != "0.0.0.0":
                return address
        except Exception:
            pass
    return None


def read_interface_netmask(interface_name):
    try:
        if platform.system() == "Windows":
            alias = interface_name
            try:
                if interface_name.startswith("\\Device\\"):
                    alias = scapy_conf.ifaces.dev_from_networkname(interface_name).name
                else:
                    alias = scapy_conf.ifaces.dev_from_name(interface_name).name
            except Exception:
                pass
            result = subprocess.run(
                [
                    "netsh",
                    "interface",
                    "ipv4",
                    "show",
                    "addresses",
                    f"name={alias}",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            prefix_text = ""
            for line in result.stdout.splitlines():
                if "(mask " in line:
                    prefix_text = line.split("(mask ", 1)[1].split(")", 1)[0].strip()
                    break
                if "Subnet Mask" in line:
                    prefix_text = line.split(":", 1)[1].strip()
                    break
        else:
            result = subprocess.run(
                ["ip", "-o", "-f", "inet", "addr", "show", "dev", interface_name],
                capture_output=True,
                text=True,
                check=False,
            )
            prefix_text = ""
            for token in result.stdout.split():
                if "/" in token and token.count(".") == 3:
                    prefix_text = token.split("/", 1)[1]
                    break
        if prefix_text.count(".") == 3:
            return prefix_text
        if prefix_text.isdigit():
            return str(ipaddress.IPv4Network(f"0.0.0.0/{prefix_text}", strict=False).netmask)
    except Exception:
        pass
    return None


def read_interface_state(interface_name):
    address = read_interface_ip(interface_name)
    netmask = read_interface_netmask(interface_name) if address else None
    if address and netmask:
        return address, netmask
    return None, None


def make_neighbor(router_id, ip_address):
    return {
        "router_id": router_id,
        "ip_address": ip_address,
        "mac_address": "ff:ff:ff:ff:ff:ff",
        "state": DOWN,
        "priority": 0,
        "designated_router": "0.0.0.0",
        "backup_designated_router": "0.0.0.0",
        "database_sequence": 0,
        "is_master": False,
        "last_seen": time.time(),
        "requested_lsas": [],
    }


def make_context(interface_name, source_ip, network_mask, hello_interval):
    return {
        "interface_name": interface_name,
        "source_ip": source_ip,
        "router_id": DEFAULT_ROUTER_ID,
        "network_mask": network_mask,
        "designated_router": "0.0.0.0",
        "backup_designated_router": "0.0.0.0",
        "hello_interval": hello_interval,
        "local_lsdb": [],
        "neighbors": {},
        "lock": threading.RLock(),
        "manual_router_links": [],
        "adjacency_ready_event": threading.Event(),
        "stop_event": threading.Event(),
        "menu_suppressed": False,
        "source_ip_available": True,
        "ospf_raw_socket": None,
        "ospf_raw_socket_warning_logged": False,
    }


def close_ospf_raw_socket(context):
    with context["lock"]:
        raw_socket = context["ospf_raw_socket"]
        context["ospf_raw_socket"] = None
    if raw_socket is None:
        return
    try:
        raw_socket.close()
    except OSError:
        pass


def drain_ospf_raw_socket(context, raw_socket):
    while not context["stop_event"].is_set():
        try:
            raw_socket.recv(65535)
        except socket.timeout:
            continue
        except OSError:
            break
    with context["lock"]:
        if context["ospf_raw_socket"] is raw_socket:
            context["ospf_raw_socket"] = None
    try:
        raw_socket.close()
    except OSError:
        pass


def ensure_ospf_raw_socket(context):
    with context["lock"]:
        if context["ospf_raw_socket"] is not None or not context["source_ip_available"]:
            return
        source_ip = context["source_ip"]
    try:
        raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, OSPF_PROTO)
        raw_socket.bind((source_ip, 0))
        raw_socket.settimeout(1.0)
    except OSError as exc:
        with context["lock"]:
            if context["ospf_raw_socket_warning_logged"]:
                return
            context["ospf_raw_socket_warning_logged"] = True
        log_message(
            f"[WARN] Could not bind a raw IP protocol {OSPF_PROTO} receiver on {source_ip}: {exc}. "
            "Inbound OSPF may still trigger ICMP protocol-unreachable replies from the host."
        )
        return
    with context["lock"]:
        context["ospf_raw_socket"] = raw_socket
        context["ospf_raw_socket_warning_logged"] = False
    threading.Thread(target=drain_ospf_raw_socket, args=(context, raw_socket), daemon=True).start()


def send_packet(context, payload, destination=ALL_SPF_MULTICAST):
    if not payload.haslayer(OSPF_Hdr):
        raise ValueError("send_packet() expected an OSPF payload that already contains OSPF_Hdr.")
    if payload[OSPF_Hdr].type == 1 and destination != ALL_SPF_MULTICAST:
        raise ValueError("OSPF Hello packets in this broadcast-segment script must be sent to 224.0.0.5.")
    if destination == ALL_SPF_MULTICAST:
        ethernet_destination = ALL_SPF_MAC
    elif destination == ALL_DR_MULTICAST:
        ethernet_destination = ALL_DR_MAC
    else:
        ethernet_destination = "ff:ff:ff:ff:ff:ff"
        with context["lock"]:
            for neighbor in context["neighbors"].values():
                if neighbor["ip_address"] == destination:
                    ethernet_destination = neighbor["mac_address"]
                    break
    frame = Ether(dst=ethernet_destination) / IP(src=context["source_ip"], dst=destination, proto=OSPF_PROTO, ttl=1) / payload
    sendp(frame, iface=context["interface_name"], verbose=False)


def build_header(context, packet_type):
    return OSPF_Hdr(version=2, type=packet_type, src=context["router_id"], area=BACKBONE_AREA)


def build_ls_update(context, lsa_packets):
    return build_header(context, 4) / OSPF_LSUpd(lsalist=[lsa_packet.copy() for lsa_packet in lsa_packets])


def local_lsdb_entries(context, copy_packets=False):
    with context["lock"]:
        lsa_packets = context["local_lsdb"]
        if copy_packets:
            return [lsa_packet.copy() for lsa_packet in lsa_packets]
        return list(lsa_packets)


def build_hello(context):
    with context["lock"]:
        neighbor_ids = [
            neighbor["router_id"]
            for neighbor in context["neighbors"].values()
            if neighbor["state"] in ACTIVE_NEIGHBOR_STATES
        ]
    return build_header(context, 1) / OSPF_Hello(
        mask=context["network_mask"],
        hellointerval=context["hello_interval"],
        options=OSPF_OPTIONS,
        prio=0,
        deadinterval=DEAD_INTERVAL,
        router=context["designated_router"],
        backup=context["backup_designated_router"],
        neighbors=neighbor_ids,
    )


def build_dbd(context, _neighbor_entry, is_initial_packet=False, has_more_packets=False, is_master_packet=True, sequence_number=0, lsa_headers=None):
    database_description_flags = (0x04 if is_initial_packet else 0) | (0x02 if has_more_packets else 0) | (0x01 if is_master_packet else 0)
    database_description_packet = build_header(context, 2) / OSPF_DBDesc(mtu=1500, options=OSPF_OPTIONS, dbdescr=database_description_flags, ddseq=sequence_number)
    for lsa_header in (lsa_headers or []):
        database_description_packet = database_description_packet / lsa_header
    return database_description_packet


def build_router_lsa(context, sequence_number=BASE_LSA_SEQUENCE):
    with context["lock"]:
        if context["designated_router"] != "0.0.0.0":
            attached_link = OSPF_Link(type=2, id=context["designated_router"], data=context["source_ip"], metric=1)
        else:
            network_prefix, network_mask = normalize_network(context["source_ip"], context["network_mask"])
            attached_link = OSPF_Link(type=3, id=network_prefix, data=network_mask, metric=1)
        link_list = [attached_link]
        link_list.extend(link.copy() for link in context["manual_router_links"])
    return OSPF_Router_LSA(
        age=1,
        options=OSPF_OPTIONS,
        type=1,
        id=context["router_id"],
        adrouter=context["router_id"],
        seq=sequence_number,
        linklist=link_list,
    )


def get_lsa_key(lsa_packet):
    return (lsa_packet.type, lsa_packet.id, lsa_packet.adrouter)


def rebuild_ospf_nbr_routes_db(context):
    global OSPF_NBR_ROUTES_DB
    route_map = {}
    full_neighbor_ids = {
        neighbor["router_id"]
        for neighbor in context["neighbors"].values()
        if neighbor["state"] == FULL
    }
    for lsa_packet in context["local_lsdb"]:
        if getattr(lsa_packet, "type", None) != 1:
            continue
        advertising_router = str(getattr(lsa_packet, "adrouter", "0.0.0.0"))
        if advertising_router not in full_neighbor_ids:
            continue
        routes = []
        for link in getattr(lsa_packet, "linklist", []):
            if int(getattr(link, "type", 0)) != 3:
                continue
            network, netmask = normalize_network(
                str(getattr(link, "id", "0.0.0.0")),
                str(getattr(link, "data", "0.0.0.0")),
            )
            routes.append({
                "network": network,
                "netmask": netmask,
                "metric": int(getattr(link, "metric", 0)),
                "lsa_id": str(getattr(lsa_packet, "id", "0.0.0.0")),
                "advertising_router": advertising_router,
                "sequence": f"0x{getattr(lsa_packet, 'seq', 0):08x}",
            })
        if routes:
            route_map[advertising_router] = routes
    OSPF_NBR_ROUTES_DB = route_map


def format_neighbor_status(neighbor):
    status_message = f"[STATUS] {neighbor['router_id']} state={neighbor['state']} ip={neighbor['ip_address']}"
    if neighbor["designated_router"] != "0.0.0.0" and neighbor["ip_address"] == neighbor["designated_router"]:
        status_message += f" dr={neighbor['designated_router']}"
    return status_message


def is_dr_or_bdr_neighbor(neighbor):
    return neighbor["ip_address"] in {neighbor["designated_router"], neighbor["backup_designated_router"]} and neighbor["ip_address"] != "0.0.0.0"


def find_lsa(context, lsa_type, lsa_id, advertising_router):
    for lsa_packet in context["local_lsdb"]:
        if get_lsa_key(lsa_packet) == (lsa_type, lsa_id, advertising_router):
            return lsa_packet
    return None


def upsert_lsa(context, lsa_packet):
    lsa_key = get_lsa_key(lsa_packet)
    for index, existing_lsa in enumerate(context["local_lsdb"]):
        if get_lsa_key(existing_lsa) != lsa_key:
            continue
        if getattr(lsa_packet, "seq", 0) >= getattr(existing_lsa, "seq", 0):
            context["local_lsdb"][index] = lsa_packet.copy()
            rebuild_ospf_nbr_routes_db(context)
            return True
        return False
    context["local_lsdb"].append(lsa_packet.copy())
    rebuild_ospf_nbr_routes_db(context)
    return True


def next_lsa_sequence(context, lsa_type, lsa_id, advertising_router):
    existing_lsa = find_lsa(context, lsa_type, lsa_id, advertising_router)
    if existing_lsa is None:
        return BASE_LSA_SEQUENCE
    return max(getattr(existing_lsa, "seq", BASE_LSA_SEQUENCE - 1) + 1, BASE_LSA_SEQUENCE)


def normalize_network(prefix, mask):
    network = ipaddress.IPv4Network(f"{prefix}/{mask}", strict=False)
    return str(network.network_address), str(network.netmask)


def flood_lsa_packets(context, lsa_packets):
    with context["lock"]:
        full_neighbor_ids = [
            neighbor["router_id"]
            for neighbor in context["neighbors"].values()
            if neighbor["state"] == FULL
        ]
    if not full_neighbor_ids:
        return False
    send_packet(context, build_ls_update(context, lsa_packets), destination=ALL_DR_MULTICAST)
    return True


def should_fight_back_self_lsa(context, received_lsa):
    with context["lock"]:
        existing_lsa = find_lsa(context, 1, context["router_id"], context["router_id"])
        existing_sequence = getattr(existing_lsa, "seq", BASE_LSA_SEQUENCE - 1) if existing_lsa is not None else BASE_LSA_SEQUENCE - 1
    if getattr(received_lsa, "seq", BASE_LSA_SEQUENCE - 1) > existing_sequence:
        return True
    desired_lsa = build_router_lsa(context, sequence_number=getattr(received_lsa, "seq", BASE_LSA_SEQUENCE))
    received_links = [
        (int(getattr(link, "type", 0)), str(getattr(link, "id", "0.0.0.0")), str(getattr(link, "data", "0.0.0.0")), int(getattr(link, "metric", 0)))
        for link in getattr(received_lsa, "linklist", [])
    ]
    desired_links = [
        (int(getattr(link, "type", 0)), str(getattr(link, "id", "0.0.0.0")), str(getattr(link, "data", "0.0.0.0")), int(getattr(link, "metric", 0)))
        for link in getattr(desired_lsa, "linklist", [])
    ]
    return received_links != desired_links


def reorigin_self_router_lsa(context, sequence_number):
    with context["lock"]:
        router_lsa = build_router_lsa(context, sequence_number=sequence_number)
        upsert_lsa(context, router_lsa)
    flood_lsa_packets(context, [router_lsa])
    return router_lsa


def refresh_local_router_lsa(context, bump_sequence=False):
    with context["lock"]:
        if bump_sequence:
            sequence_number = next_lsa_sequence(context, 1, context["router_id"], context["router_id"])
        else:
            existing_lsa = find_lsa(context, 1, context["router_id"], context["router_id"])
            sequence_number = getattr(existing_lsa, "seq", BASE_LSA_SEQUENCE)
        upsert_lsa(context, build_router_lsa(context, sequence_number=sequence_number))


def reset_adjacency_state(context, reason):
    with context["lock"]:
        context["neighbors"].clear()
        context["designated_router"] = "0.0.0.0"
        context["backup_designated_router"] = "0.0.0.0"
        context["adjacency_ready_event"].clear()
        context["menu_suppressed"] = False
        rebuild_ospf_nbr_routes_db(context)
    log_message(f"[RESET] {reason}")


def refresh_runtime_source_ip(context):
    current_ip, current_mask = read_interface_state(context["interface_name"])
    with context["lock"]:
        previous_ip = context["source_ip"]
        previous_mask = context["network_mask"]
        ip_was_available = context["source_ip_available"]

    if not current_ip or not current_mask:
        if ip_was_available:
            with context["lock"]:
                context["source_ip_available"] = False
            close_ospf_raw_socket(context)
            reset_adjacency_state(
                context,
                f"Interface {context['interface_name']} lost its usable IPv4 address or netmask. Pausing hellos until a valid address returns.",
            )
        return False

    if not ip_was_available:
        with context["lock"]:
            context["source_ip"] = current_ip
            context["network_mask"] = current_mask
            context["source_ip_available"] = True
        close_ospf_raw_socket(context)
        ensure_ospf_raw_socket(context)
        refresh_local_router_lsa(context, bump_sequence=True)
        reset_adjacency_state(
            context,
            f"Interface {context['interface_name']} recovered with IPv4 address {current_ip}. Restarting adjacency discovery.",
        )
        return True

    if current_ip == previous_ip and current_mask == previous_mask:
        return True

    with context["lock"]:
        context["source_ip"] = current_ip
        context["network_mask"] = current_mask
    close_ospf_raw_socket(context)
    ensure_ospf_raw_socket(context)
    refresh_local_router_lsa(context, bump_sequence=True)
    if current_ip != previous_ip:
        reason = (
            f"Interface {context['interface_name']} changed IPv4 address {previous_ip} -> {current_ip}. "
            "Refreshing self-originated Router-LSA."
        )
    else:
        reason = (
            f"Interface {context['interface_name']} changed IPv4 netmask {previous_mask} -> {current_mask}. "
            "Refreshing self-originated Router-LSA."
        )
    reset_adjacency_state(context, reason)
    return True


def show_neighbors(context):
    with context["lock"]:
        lines = [
            format_neighbor_status(neighbor)
            for neighbor in sorted(context["neighbors"].values(), key=lambda neighbor: neighbor["router_id"])
        ]
    if not lines:
        log_message("[STATUS] No OSPF neighbors discovered yet.")
        return
    for line in lines:
        log_message(line)


def update_full_adjacency_gate(context):
    ready_message = None
    lost_message = None
    with context["lock"]:
        neighbors = [neighbor for neighbor in context["neighbors"].values() if is_dr_or_bdr_neighbor(neighbor)]
        everyone_full = bool(neighbors) and all(neighbor["state"] == FULL for neighbor in neighbors)
        if everyone_full and not context["adjacency_ready_event"].is_set():
            context["adjacency_ready_event"].set()
            ready_message = "[MENU] FULL adjacency is ready. Type 'help' to view the available menu commands."
        else:
            if context["adjacency_ready_event"].is_set():
                lost_message = "[MENU] FULL adjacency is no longer stable. Manual Router-LSA flooding is paused."
            context["adjacency_ready_event"].clear()
            context["menu_suppressed"] = False
    if ready_message:
        show_neighbors(context)
        log_message(ready_message)
    if lost_message:
        log_message(lost_message)


# Adjacency forms in protocol order before any manual route advertisement is allowed.
def transition_neighbor(context, neighbor, new_state):
    previous_state = neighbor["state"]
    neighbor["state"] = new_state
    if previous_state == FULL and new_state != FULL:
        rebuild_ospf_nbr_routes_db(context)
    if new_state == FULL:
        state_full(context, neighbor)


def state_down(context, neighbor):
    if neighbor["state"] == DOWN:
        transition_neighbor(context, neighbor, INIT)


def state_init(context, neighbor, hello_packet):
    if neighbor["state"] == INIT and context["router_id"] in (hello_packet.neighbors or []):
        transition_neighbor(context, neighbor, TWO_WAY)


def state_two_way(context, neighbor, packet, hello_packet):
    if neighbor["state"] != TWO_WAY:
        return
    if not is_dr_or_bdr_neighbor(neighbor):
        return
    transition_neighbor(context, neighbor, EXSTART)
    neighbor["database_sequence"] = INITIAL_DBD_SEQ
    neighbor["is_master"] = True
    send_packet(
        context,
        build_dbd(
            context,
            neighbor,
            is_initial_packet=True,
            has_more_packets=True,
            is_master_packet=True,
            sequence_number=neighbor["database_sequence"],
        ),
        destination=neighbor["ip_address"],
    )


def state_exstart(context, neighbor, router_id, master_bit, sequence_number):
    if neighbor["state"] != EXSTART:
        return False
    try:
        neighbor_is_master = int(ipaddress.IPv4Address(router_id)) > int(ipaddress.IPv4Address(context["router_id"]))
    except Exception:
        neighbor_is_master = False
    if neighbor_is_master:
        neighbor["is_master"] = False
        neighbor["database_sequence"] = sequence_number
        send_packet(context, build_dbd(context, neighbor, is_master_packet=False, sequence_number=sequence_number), destination=neighbor["ip_address"])
        transition_neighbor(context, neighbor, EXCHANGE)
        send_lsdb_summary(context, neighbor)
    elif not master_bit and sequence_number == neighbor["database_sequence"]:
        transition_neighbor(context, neighbor, EXCHANGE)
        send_lsdb_summary(context, neighbor)
    return True


def state_exchange(context, neighbor, packet, more_bit):
    if neighbor["state"] != EXCHANGE:
        return False
    neighbor["requested_lsas"] = collect_unknown_lsas(context, packet)
    if not more_bit:
        if neighbor["requested_lsas"]:
            transition_neighbor(context, neighbor, LOADING)
            ls_request_packet = build_header(context, 3)
            for lsa_type, lsa_id, adv_router in neighbor["requested_lsas"]:
                ls_request_packet = ls_request_packet / OSPF_LSReq(type=lsa_type, id=lsa_id, adrouter=adv_router)
            send_packet(context, ls_request_packet, destination=neighbor["ip_address"])
        else:
            transition_neighbor(context, neighbor, FULL)
        return True
    if neighbor["is_master"]:
        neighbor["database_sequence"] += 1
    send_packet(
        context,
        build_dbd(context, neighbor, is_master_packet=neighbor["is_master"], sequence_number=neighbor["database_sequence"]),
        destination=neighbor["ip_address"],
    )
    return True


def state_loading(context, neighbor, packet):
    if neighbor["state"] != LOADING:
        return None
    neighbor["mac_address"] = packet[Ether].src
    neighbor["requested_lsas"].clear()
    transition_neighbor(context, neighbor, FULL)
    refresh_local_router_lsa(context)
    self_lsa = find_lsa(context, 1, context["router_id"], context["router_id"])
    if self_lsa is None:
        self_lsa = build_router_lsa(context)
    return self_lsa


def state_full(context, neighbor):
    rebuild_ospf_nbr_routes_db(context)
    log_message(format_neighbor_status(neighbor))


def collect_unknown_lsas(context, packet):
    requested_lsas = []
    lsa_layer = packet[OSPF_DBDesc].payload
    while lsa_layer and lsa_layer.name != "NoPayload":
        if not hasattr(lsa_layer, "adrouter"):
            lsa_layer = lsa_layer.payload
            continue
        lsa_type = getattr(lsa_layer, "type", 1)
        lsa_id = getattr(lsa_layer, "id", "0.0.0.0")
        advertising_router = lsa_layer.adrouter
        local_lsa = find_lsa(context, lsa_type, lsa_id, advertising_router)
        remote_sequence = getattr(lsa_layer, "seq", 0)
        if local_lsa is None or getattr(local_lsa, "seq", 0) < remote_sequence:
            requested_lsas.append((lsa_type, lsa_id, advertising_router))
        lsa_layer = lsa_layer.payload
    return requested_lsas

def send_lsdb_summary(context, neighbor):
    refresh_local_router_lsa(context)
    if neighbor["is_master"]:
        neighbor["database_sequence"] += 1
    lsa_packets = local_lsdb_entries(context)
    send_packet(
        context,
        build_dbd(
            context,
            neighbor,
            is_master_packet=neighbor["is_master"],
            sequence_number=neighbor["database_sequence"],
            lsa_headers=[OSPF_LSA_Hdr(bytes(lsa_packet)[:20]) for lsa_packet in lsa_packets],
        ),
        destination=neighbor["ip_address"],
    )


def handle_hello(context, packet):
    ospf_header = packet[OSPF_Hdr]
    hello_packet = packet[OSPF_Hello]
    router_id = ospf_header.src
    if router_id == context["router_id"]:
        return

    with context["lock"]:
        neighbor = context["neighbors"].setdefault(router_id, make_neighbor(router_id, packet[IP].src))
        neighbor["ip_address"] = packet[IP].src
        neighbor["mac_address"] = packet[Ether].src
        neighbor["last_seen"] = time.time()
        neighbor["priority"] = hello_packet.prio
        neighbor["designated_router"] = hello_packet.router
        neighbor["backup_designated_router"] = hello_packet.backup
        if hello_packet.router != "0.0.0.0":
            context["designated_router"] = hello_packet.router
        if hello_packet.backup != "0.0.0.0":
            context["backup_designated_router"] = hello_packet.backup
        state_down(context, neighbor)
        state_init(context, neighbor, hello_packet)
        state_two_way(context, neighbor, packet, hello_packet)

    send_packet(context, build_hello(context))


def handle_dbd(context, packet):
    ospf_header = packet[OSPF_Hdr]
    database_description = packet[OSPF_DBDesc]
    router_id = ospf_header.src

    with context["lock"]:
        neighbor = context["neighbors"].get(router_id)
        if not neighbor or neighbor["state"] not in DBD_READY_STATES:
            return
        neighbor["mac_address"] = packet[Ether].src

        flags = database_description.dbdescr
        more_bit = flags & 0x02
        master_bit = flags & 0x01
        sequence_number = database_description.ddseq

        if state_exstart(context, neighbor, router_id, master_bit, sequence_number):
            return
        state_exchange(context, neighbor, packet, more_bit)


def handle_lsupd(context, packet):
    router_id = packet[OSPF_Hdr].src
    lsa_list = getattr(packet[OSPF_LSUpd], "lsalist", []) if packet.haslayer(OSPF_LSUpd) else []
    if lsa_list:
        fight_back_lsa = None
        with context["lock"]:
            for lsa_packet in lsa_list:
                if (
                    getattr(lsa_packet, "type", None) == 1
                    and getattr(lsa_packet, "id", None) == context["router_id"]
                    and getattr(lsa_packet, "adrouter", None) == context["router_id"]
                    and should_fight_back_self_lsa(context, lsa_packet)
                ):
                    if fight_back_lsa is None or getattr(lsa_packet, "seq", BASE_LSA_SEQUENCE - 1) > getattr(fight_back_lsa, "seq", BASE_LSA_SEQUENCE - 1):
                        fight_back_lsa = lsa_packet.copy()
                upsert_lsa(context, lsa_packet)
            refresh_local_router_lsa(context)
        send_packet(
            context,
            build_header(context, 5) / OSPF_LSAck(lsaheaders=[OSPF_LSA_Hdr(bytes(lsa_packet)[:20]) for lsa_packet in lsa_list]),
        )
        if fight_back_lsa is not None:
            reorigin_self_router_lsa(
                context,
                sequence_number=max(getattr(fight_back_lsa, "seq", BASE_LSA_SEQUENCE - 1) + 1, BASE_LSA_SEQUENCE),
            )

    self_lsa = None
    with context["lock"]:
        neighbor = context["neighbors"].get(router_id)
        if not neighbor:
            return
        self_lsa = state_loading(context, neighbor, packet)
    if self_lsa is not None:
        send_packet(context, build_ls_update(context, [self_lsa]), destination=ALL_DR_MULTICAST)


def handle_lsreq(context, packet):
    with context["lock"]:
        refresh_local_router_lsa(context)
        neighbor = context["neighbors"].get(packet[OSPF_Hdr].src)
        if neighbor:
            neighbor["mac_address"] = packet[Ether].src
        requested_lsa_packets = []
        request_layer = packet[OSPF_LSReq]
        while request_layer and request_layer.name != "NoPayload":
            if hasattr(request_layer, "adrouter"):
                local_lsa = find_lsa(context, request_layer.type, request_layer.id, request_layer.adrouter)
                if local_lsa is not None:
                    requested_lsa_packets.append(local_lsa.copy())
            request_layer = request_layer.payload
    send_packet(context, build_ls_update(context, requested_lsa_packets), destination=packet[IP].src)


def dispatch_packet(context, packet):
    if not packet.haslayer(OSPF_Hdr):
        return
    if packet[OSPF_Hdr].area != BACKBONE_AREA:
        return
    if packet.haslayer(IP) and packet[IP].src == context["source_ip"] and packet[OSPF_Hdr].src == context["router_id"]:
        return
    ospf_packet_type = packet[OSPF_Hdr].type
    if ospf_packet_type == 1:
        handle_hello(context, packet)
    elif ospf_packet_type == 2:
        handle_dbd(context, packet)
    elif ospf_packet_type == 3:
        handle_lsreq(context, packet)
    elif ospf_packet_type == 4:
        handle_lsupd(context, packet)


def runtime_console(context):
    log_message("[MENU] Waiting for FULL adjacency before enabling manual actions.")
    while not context["stop_event"].is_set():
        if not context["adjacency_ready_event"].wait(timeout=1):
            continue
        with context["lock"]:
            suppress_menu = context["menu_suppressed"]
        try:
            command = input(MENU_HIDDEN_PROMPT if suppress_menu else MENU_PROMPT).strip().lower()
        except EOFError:
            continue
        except KeyboardInterrupt:
            context["stop_event"].set()
            return
        if suppress_menu:
            if command == "" or command == "q":
                continue
            if command == "m":
                with context["lock"]:
                    context["menu_suppressed"] = False
                log_message("[MENU] The menu prompt is enabled again. Type 'help' to view the available commands.")
                continue
            log_message(MENU_HIDDEN_TEXT)
            continue
        if command == "":
            continue
        if command == "help":
            log_message(MENU_HELP_TEXT)
            continue
        if command == "m":
            log_message("[MENU] The menu prompt is already enabled. Type 'help' to view the available commands.")
            continue
        if command == "1":
            if not context["adjacency_ready_event"].is_set():
                log_message("[MENU] Wait until all discovered neighbors reach FULL before flooding a manual Router-LSA.")
                continue
            prompt_and_add_router_stub_route(context, input, log_message, normalize_network=normalize_network, ospf_link_cls=OSPF_Link, next_lsa_sequence=next_lsa_sequence, build_router_lsa=build_router_lsa, upsert_lsa=upsert_lsa,flood_lsa_packets=flood_lsa_packets)
            continue
        if command == "2":
            show_neighbors(context)
            continue
        if command == "3":
            lsa_packets = local_lsdb_entries(context)
            if not lsa_packets:
                log_message("[LSDB] Local LSDB is empty.")
                continue
            for lsa_packet in lsa_packets:
                log_message(
                    f"[LSDB] type={lsa_packet.type} id={lsa_packet.id} adv={lsa_packet.adrouter} "
                    f"seq=0x{getattr(lsa_packet, 'seq', 0):08x}"
                )
            continue
        if command == "4":
            route_map = {
                advertising_router: [route.copy() for route in routes]
                for advertising_router, routes in OSPF_NBR_ROUTES_DB.items()
            }
            if not route_map:
                log_message("[ROUTES] OSPF_NBR_ROUTES_DB is empty.")
                continue
            for advertising_router in sorted(route_map):
                for route in route_map[advertising_router]:
                    log_message(
                        f"[ROUTES] adv={advertising_router} net={route['network']} "
                        f"mask={route['netmask']} metric={route['metric']} seq={route['sequence']}"
                    )
            continue
        if command == "q":
            with context["lock"]:
                context["menu_suppressed"] = True
            log_message(MENU_HIDDEN_TEXT)
            continue
        log_message(f"[MENU] Unknown command '{command}'. Type 'help' to view the available commands.")


def run_engine(context):
    ensure_ospf_raw_socket(context)
    threading.Thread(
        target=sniff,
        kwargs=dict(iface=context["interface_name"], filter="proto 89", prn=lambda packet: dispatch_packet(context, packet), store=0),
        daemon=True,
    ).start()
    threading.Thread(target=runtime_console, args=(context,), daemon=True).start()
    log_message(f"[*] Sniffer on {context['interface_name']}")
    log_message("[*] Hellos sending -- Ctrl+C to stop.\n")

    try:
        while True:
            if not refresh_runtime_source_ip(context):
                update_full_adjacency_gate(context)
                time.sleep(context["hello_interval"])
                continue
            send_packet(context, build_hello(context))

            with context["lock"]:
                expired = [
                    router_id
                    for router_id, neighbor in context["neighbors"].items()
                    if time.time() - neighbor["last_seen"] > DEAD_INTERVAL
                ]
                for router_id in expired:
                    del context["neighbors"][router_id]
                if expired:
                    rebuild_ospf_nbr_routes_db(context)
            for router_id in expired:
                log_message(f"[DEAD] {router_id} expired.")

            update_full_adjacency_gate(context)
            time.sleep(context["hello_interval"])
    except KeyboardInterrupt:
        context["stop_event"].set()
        close_ospf_raw_socket(context)
        log_message("\n[*] Exiting.")


def main():
    parser = argparse.ArgumentParser(prog="ospf_full_adjacency.py")
    parser.add_argument("--iface", default=default_iface())
    parser.add_argument("--interval", default=HELLO_INTERVAL, type=int)
    args = parser.parse_args()

    source_ip, network_mask = read_interface_state(args.iface)
    if not source_ip or not network_mask:
        sys.exit(f"[!] No usable IPv4 address or netmask for '{args.iface}'.")
    log_message("=" * 52)
    log_message("  OSPFv2 Full Adjacency Engine")
    log_message(f"  iface={args.iface}  src={source_ip}  rid={DEFAULT_ROUTER_ID}")
    log_message("=" * 52)

    context = make_context(args.iface, source_ip, network_mask, args.interval)
    refresh_local_router_lsa(context)
    run_engine(context)


if __name__ == "__main__":
    main()

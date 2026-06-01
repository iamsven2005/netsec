#!/usr/bin/env python3
from __future__ import annotations
import argparse
import ipaddress
import platform
import socket
import sys
import threading
import time

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
OSPF_PROTO = 89
OSPF_OPTIONS = 0x02
DEFAULT_PRIORITY = 255
DEAD_INTERVAL = 40
HELLO_INTERVAL = 10
INITIAL_DBD_SEQ = 1000

DOWN = "DOWN"
INIT = "INIT"
TWO_WAY = "TWO_WAY"
EXSTART = "EXSTART"
EXCHANGE = "EXCHANGE"
LOADING = "LOADING"
FULL = "FULL"


def log_message(message):
    sys.stdout.write(f"[{time.strftime('%H:%M:%S')}] {message}\n")
    sys.stdout.flush()


def router_id_gt(left, right):
    try:
        return int(ipaddress.IPv4Address(left)) > int(ipaddress.IPv4Address(right))
    except Exception:
        return False


def default_iface():
    try:
        interface_name = str(scapy_conf.iface)
        if interface_name and interface_name != "None":
            return interface_name
    except Exception:
        pass
    return {"Windows": "Ethernet", "Darwin": "en0"}.get(platform.system(), "eth0")


def get_local_ip(interface_name):
    try:
        address = get_if_addr(interface_name)
        if address and address != "0.0.0.0":
            return address
    except Exception:
        pass
    try:
        socket_obj = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        socket_obj.connect(("8.8.8.8", 80))
        address = socket_obj.getsockname()[0]
        socket_obj.close()
        if address and address != "0.0.0.0":
            return address
    except Exception:
        pass
    sys.exit(f"[!] No usable IP for '{interface_name}'. Use --router-id.")


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


def make_context(interface_name, source_ip, router_id, area, mask, hello_interval, verbose):
    return {
        "interface_name": interface_name,
        "source_ip": source_ip,
        "router_id": router_id,
        "ospf_area": area,
        "network_mask": mask,
        "designated_router": "0.0.0.0",
        "backup_designated_router": "0.0.0.0",
        "hello_interval": hello_interval,
        "verbose": verbose,
        "local_lsdb": [],
        "neighbors": {},
        "lock": threading.RLock(),
    }


def resolve_ethernet_destination(context, destination_ip):
    if destination_ip == ALL_SPF_MULTICAST:
        return ALL_SPF_MAC
    if destination_ip == ALL_DR_MULTICAST:
        return ALL_DR_MAC
    with context["lock"]:
        for neighbor in context["neighbors"].values():
            if neighbor["ip_address"] == destination_ip:
                return neighbor["mac_address"]
    return "ff:ff:ff:ff:ff:ff"


def send_packet(context, payload, destination=ALL_SPF_MULTICAST):
    ethernet_destination = resolve_ethernet_destination(context, destination)
    frame = Ether(dst=ethernet_destination) / IP(src=context["source_ip"], dst=destination, proto=OSPF_PROTO, ttl=1) / payload
    if context["verbose"]:
        frame.show2()
    sendp(frame, iface=context["interface_name"], verbose=False)


def build_header(context, packet_type):
    return OSPF_Hdr(version=2, type=packet_type, src=context["router_id"], area=context["ospf_area"])


def build_hello(context):
    with context["lock"]:
        neighbor_ids = [
            neighbor["router_id"]
            for neighbor in context["neighbors"].values()
            if neighbor["state"] in (INIT, TWO_WAY, EXSTART, EXCHANGE, LOADING, FULL)
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


def describe_dbd_flags(flag_value):
    return "".join([
        "I" if flag_value & 0x04 else "-",
        "M" if flag_value & 0x02 else "-",
        "S" if flag_value & 0x01 else "-",
    ])


def build_router_lsa(context):
    return OSPF_Router_LSA(
        age=1,
        options=OSPF_OPTIONS,
        type=1,
        id=context["router_id"],
        adrouter=context["router_id"],
        seq=0x80000001,
        linklist=[OSPF_Link(type=3, id=context["source_ip"], data=context["network_mask"], metric=1)],
    )


def get_lsa_key(lsa_packet):
    return (lsa_packet.type, lsa_packet.id, lsa_packet.adrouter)


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
            return True
        return False
    context["local_lsdb"].append(lsa_packet.copy())
    return True


def refresh_local_router_lsa(context):
    upsert_lsa(context, build_router_lsa(context))


def sync_local_lsdb(context):
    refresh_local_router_lsa(context)


def transition_neighbor(neighbor, new_state):
    log_message(f"[STATE] {neighbor['router_id']}  {neighbor['state']} -> {new_state}")
    neighbor["state"] = new_state


def collect_unknown_lsas(context, packet):
    requested_lsas = []
    lsa_layer = packet[OSPF_DBDesc].payload
    while lsa_layer and lsa_layer.name != "NoPayload":
        if hasattr(lsa_layer, "adrouter"):
            lsa_type = getattr(lsa_layer, "type", 1)
            lsa_id = getattr(lsa_layer, "id", "0.0.0.0")
            advertising_router = lsa_layer.adrouter
            local_lsa = find_lsa(context, lsa_type, lsa_id, advertising_router)
            remote_sequence = getattr(lsa_layer, "seq", 0)
            if local_lsa is None or getattr(local_lsa, "seq", 0) < remote_sequence:
                requested_lsas.append((lsa_type, lsa_id, advertising_router))
        lsa_layer = lsa_layer.payload
    return requested_lsas


def send_lsreq(context, neighbor):
    if not neighbor["requested_lsas"]:
        return
    log_message(f"[LOADING] LSReq -> {neighbor['router_id']}  ({len(neighbor['requested_lsas'])} LSA(s))")
    ls_request_packet = build_header(context, 3)
    for lsa_type, lsa_id, adv_router in neighbor["requested_lsas"]:
        ls_request_packet = ls_request_packet / OSPF_LSReq(type=lsa_type, id=lsa_id, adrouter=adv_router)
    send_packet(context, ls_request_packet, destination=neighbor["ip_address"])


def send_lsdb_summary(context, neighbor):
    log_message(f"[EXCHANGE] Summary -> {neighbor['router_id']}")
    sync_local_lsdb(context)
    if neighbor["is_master"]:
        neighbor["database_sequence"] += 1
    send_packet(
        context,
        build_dbd(
            context,
            neighbor,
            is_master_packet=neighbor["is_master"],
            sequence_number=neighbor["database_sequence"],
            lsa_headers=[OSPF_LSA_Hdr(bytes(lsa_packet)[:20]) for lsa_packet in context["local_lsdb"]],
        ),
        destination=neighbor["ip_address"],
    )


def start_exstart(context, neighbor):
    transition_neighbor(neighbor, EXSTART)
    neighbor["database_sequence"] = INITIAL_DBD_SEQ
    neighbor["is_master"] = True
    log_message(f"[EXSTART] -> {neighbor['router_id']}  seq={neighbor['database_sequence']}")
    log_message(f"[DBD-OUT] {neighbor['router_id']}  state=EXSTART  flags={describe_dbd_flags(0x07)}  seq={neighbor['database_sequence']}  mtu=1500")
    send_packet(context, build_dbd(context, neighbor, is_initial_packet=True, has_more_packets=True, is_master_packet=True, sequence_number=neighbor["database_sequence"]), destination=neighbor["ip_address"])


def handle_hello(context, packet):
    ospf_header = packet[OSPF_Hdr]
    hello_packet = packet[OSPF_Hello]
    router_id = ospf_header.src
    if router_id == context["router_id"]:
        return

    with context["lock"]:
        neighbor = context["neighbors"].setdefault(router_id, make_neighbor(router_id, packet[IP].src))
        neighbor["mac_address"] = packet[Ether].src
        neighbor["last_seen"] = time.time()
        neighbor["priority"] = hello_packet.prio
        neighbor["designated_router"] = hello_packet.router
        neighbor["backup_designated_router"] = hello_packet.backup
        if hello_packet.router != "0.0.0.0":
            context["designated_router"] = hello_packet.router
        if hello_packet.backup != "0.0.0.0":
            context["backup_designated_router"] = hello_packet.backup
        if neighbor["state"] == DOWN:
            transition_neighbor(neighbor, INIT)
        if neighbor["state"] == INIT and context["router_id"] in (hello_packet.neighbors or []):
            transition_neighbor(neighbor, TWO_WAY)
        neighbor_is_dr_or_bdr = packet[IP].src in {hello_packet.router, hello_packet.backup} and packet[IP].src != "0.0.0.0"
        if neighbor["state"] == TWO_WAY and neighbor_is_dr_or_bdr:
            start_exstart(context, neighbor)

    send_packet(context, build_hello(context))


def handle_dbd(context, packet):
    ospf_header = packet[OSPF_Hdr]
    database_description = packet[OSPF_DBDesc]
    router_id = ospf_header.src

    with context["lock"]:
        neighbor = context["neighbors"].get(router_id)
        if not neighbor or neighbor["state"] not in (EXSTART, EXCHANGE, LOADING, FULL):
            return
        neighbor["mac_address"] = packet[Ether].src

        flags = database_description.dbdescr
        more_bit = flags & 0x02
        master_bit = flags & 0x01
        sequence_number = database_description.ddseq
        log_message(
            f"[DBD-IN] {router_id}  state={neighbor['state']}  flags={describe_dbd_flags(flags)}  "
            f"seq={sequence_number}  mtu={database_description.mtu}"
        )

        if neighbor["state"] == EXSTART:
            if router_id_gt(router_id, context["router_id"]):
                neighbor["is_master"] = False
                neighbor["database_sequence"] = sequence_number
                log_message(f"[EXSTART] {router_id}=Master  We=Slave")
                log_message(f"[DBD-OUT] {router_id}  state=EXSTART  flags={describe_dbd_flags(0x01)}  seq={sequence_number}  mtu=1500")
                send_packet(context, build_dbd(context, neighbor, is_master_packet=False, sequence_number=sequence_number), destination=neighbor["ip_address"])
                transition_neighbor(neighbor, EXCHANGE)
                send_lsdb_summary(context, neighbor)
            elif not master_bit and sequence_number == neighbor["database_sequence"]:
                log_message(f"[EXSTART] We=Master  {router_id}=Slave")
                transition_neighbor(neighbor, EXCHANGE)
                send_lsdb_summary(context, neighbor)
            return

        if neighbor["state"] == EXCHANGE:
            neighbor["requested_lsas"] = collect_unknown_lsas(context, packet)
            if not more_bit:
                if neighbor["requested_lsas"]:
                    transition_neighbor(neighbor, LOADING)
                    send_lsreq(context, neighbor)
                else:
                    transition_neighbor(neighbor, FULL)
                    log_message(f"[FULL] {router_id} -- DR claimed.")
            else:
                if neighbor["is_master"]:
                    neighbor["database_sequence"] += 1
                log_message(
                    f"[DBD-OUT] {router_id}  state=EXCHANGE  flags={describe_dbd_flags(0x01 if neighbor['is_master'] else 0x00)}  "
                    f"seq={neighbor['database_sequence']}  mtu=1500"
                )
                send_packet(context, build_dbd(context, neighbor, is_master_packet=neighbor["is_master"], sequence_number=neighbor["database_sequence"]), destination=neighbor["ip_address"])


def handle_lsupd(context, packet):
    router_id = packet[OSPF_Hdr].src
    lsa_list = getattr(packet[OSPF_LSUpd], "lsalist", []) if packet.haslayer(OSPF_LSUpd) else []
    if lsa_list:
        log_message(f"[LSUPD] {len(lsa_list)} LSA(s) from {router_id}. ACK.")
        with context["lock"]:
            for lsa_packet in lsa_list:
                upsert_lsa(context, lsa_packet)
            sync_local_lsdb(context)
        acknowledgment_packet = build_header(context, 5) / OSPF_LSAck(lsaheaders=[OSPF_LSA_Hdr(bytes(lsa_packet)[:20]) for lsa_packet in lsa_list])
        send_packet(context, acknowledgment_packet)

    with context["lock"]:
        neighbor = context["neighbors"].get(router_id)
        if neighbor and neighbor["state"] == LOADING:
            neighbor["mac_address"] = packet[Ether].src
            neighbor["requested_lsas"].clear()
            transition_neighbor(neighbor, FULL)
            log_message(f"[FULL] {router_id} -- Local LSDB synchronized.")
            refresh_local_router_lsa(context)
            self_lsa = find_lsa(context, 1, context["router_id"], context["router_id"])
            if self_lsa is None:
                self_lsa = build_router_lsa(context)
            send_packet(context, build_header(context, 4) / OSPF_LSUpd(lsalist=[self_lsa.copy()]), destination=ALL_DR_MULTICAST)


def handle_lsreq(context, packet):
    log_message(f"[LSREQ] {packet[OSPF_Hdr].src} -- Responding.")
    with context["lock"]:
        sync_local_lsdb(context)
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
        response_lsa_packets = [lsa.copy() for lsa in context["local_lsdb"]]
    log_message(
        f"[LSREQ] requested={len(requested_lsa_packets)}  replying_with={len(response_lsa_packets)} LSA(s)"
    )
    send_packet(context, build_header(context, 4) / OSPF_LSUpd(lsalist=response_lsa_packets), destination=packet[IP].src)


def dispatch_packet(context, packet):
    if not packet.haslayer(OSPF_Hdr):
        return
    ospf_packet_type = packet[OSPF_Hdr].type
    handlers = {
        1: handle_hello,
        2: handle_dbd,
        3: handle_lsreq,
        4: handle_lsupd,
        5: lambda _context, received_packet: log_message(f"[LSACK] {received_packet[OSPF_Hdr].src}"),
    }
    handlers.get(ospf_packet_type, lambda _context, _packet: None)(context, packet)


def run_engine(context):
    threading.Thread(
        target=sniff,
        kwargs=dict(iface=context["interface_name"], filter="proto 89", prn=lambda packet: dispatch_packet(context, packet), store=0),
        daemon=True,
    ).start()
    log_message(f"[*] Sniffer on {context['interface_name']}")
    log_message("[*] Hellos sending -- Ctrl+C to stop.\n")

    hello_count = 0
    try:
        while True:
            send_packet(context, build_hello(context))
            hello_count += 1
            log_message(f"[Hello #{hello_count}] -> {ALL_SPF_MULTICAST}")

            if hello_count % 3 == 0:
                with context["lock"]:
                    for router_id, neighbor in context["neighbors"].items():
                        log_message(f"[STATUS] {router_id}  state={neighbor['state']}  dr={neighbor['designated_router']}")

            with context["lock"]:
                expired = [
                    router_id
                    for router_id, neighbor in context["neighbors"].items()
                    if time.time() - neighbor["last_seen"] > DEAD_INTERVAL
                ]
            for router_id in expired:
                del context["neighbors"][router_id]
                log_message(f"[DEAD] {router_id} expired.")

            time.sleep(context["hello_interval"])
    except KeyboardInterrupt:
        log_message("\n[*] Stopped.")


def main():
    parser = argparse.ArgumentParser(prog="ospf_full_adjacency.py")
    parser.add_argument("--iface", default=default_iface())
    parser.add_argument("--router-id", default=None)
    parser.add_argument("--area", default="0.0.0.0")
    parser.add_argument("--mask", default="255.255.255.0")
    parser.add_argument("--interval", default=HELLO_INTERVAL, type=int)
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    source_ip = get_local_ip(args.iface)
    router_id = args.router_id or source_ip
    log_message("=" * 52)
    log_message("  OSPFv2 Full Adjacency Engine")
    log_message(f"  iface={args.iface}  src={source_ip}  rid={router_id}  area={args.area}")
    log_message("=" * 52)

    context = make_context(args.iface, source_ip, router_id, args.area, args.mask, args.interval, args.verbose)
    refresh_local_router_lsa(context)
    run_engine(context)


if __name__ == "__main__":
    main()

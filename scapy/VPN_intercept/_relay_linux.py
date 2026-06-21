#!/usr/bin/env python3
"""Linux forwarding backend for vpn_relay.py — iptables + ip route + tun."""

import glob
import os
import re
import subprocess
import time

# ── Module-level state (mutated by setup/teardown) ────────────────────────────

_orig_ip_forward: str | None = None
_rules_installed  = False
_phys_iface: str | None = None
_tun_iface:  str | None = None

# ── Search paths ──────────────────────────────────────────────────────────────

OVPN_SEARCH_PATHS = [
    "/usr/sbin/openvpn",
    "/usr/bin/openvpn",
    "/usr/local/sbin/openvpn",
    "/usr/local/bin/openvpn",
]

PROFILE_SEARCH_DIRS = [
    # OpenVPN Connect for Access Server
    os.path.expanduser("~/.config/OpenVPN Connect/profiles"),
    # Community OpenVPN client
    "/etc/openvpn",
    "/etc/openvpn/client",
    os.path.expanduser("~/.config/openvpn"),
    os.path.expanduser("~/openvpn"),
    ".",
]


# ── Physical interface discovery ─────────────────────────────────────────────

_SKIP_PREFIXES = re.compile(
    r"^(lo|docker|virbr|br-|veth|dummy|bond|team|vlan|tun|tap)"
)


def list_phys_ifaces() -> list[tuple[str, str, str]]:
    """Return [(name, type, state), ...] for all non-virtual interfaces."""
    result = []
    try:
        ifaces = sorted(os.listdir("/sys/class/net/"))
    except OSError:
        return result
    for iface in ifaces:
        if _SKIP_PREFIXES.match(iface):
            continue
        try:
            with open(f"/sys/class/net/{iface}/operstate") as f:
                state = f.read().strip()
        except OSError:
            state = "unknown"
        is_wireless = (
            os.path.isdir(f"/sys/class/net/{iface}/wireless")
            or bool(re.match(r"^(wlan|wlp|wls)", iface))
        )
        itype = "wifi" if is_wireless else "eth"
        result.append((iface, itype, state))
    return result


def detect_phys_iface() -> str | None:
    """Return best physical iface: ethernet first, wifi fallback; lower index preferred."""
    candidates: list[tuple[int, int, str]] = []
    for name, itype, state in list_phys_ifaces():
        if state not in ("up", "unknown"):
            continue
        priority = 0 if itype == "eth" else 1
        m = re.search(r"(\d+)$", name)
        num = int(m.group(1)) if m else 999
        candidates.append((priority, num, name))
    candidates.sort()
    return candidates[0][2] if candidates else None


# ── Tun interface detection ───────────────────────────────────────────────────

def find_tun_iface() -> str | None:
    """Return the name of the first up tun*/tap* interface, or None."""
    patterns = ["/sys/class/net/tun*/operstate", "/sys/class/net/tap*/operstate"]
    for state_path in (p for pat in patterns for p in glob.glob(pat)):
        try:
            with open(state_path) as f:
                if f.read().strip() == "up":
                    return state_path.split("/")[4]
        except OSError:
            continue
    return None


def wait_for_tun(timeout: int = 30) -> str | None:
    """Poll until a tun interface comes up; return its name or None on timeout."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        iface = find_tun_iface()
        if iface:
            return iface
        time.sleep(0.5)
    return None


# ── OpenVPN binary + profile discovery ───────────────────────────────────────

def find_ovpn_path() -> str:
    for p in OVPN_SEARCH_PATHS:
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    result = subprocess.run(["which", "openvpn"], capture_output=True, text=True)
    if result.returncode == 0:
        return result.stdout.strip()
    raise FileNotFoundError("openvpn binary not found — install openvpn package")


def find_profiles(extra_dirs: tuple = ()) -> list[tuple[str, float]]:
    """Return [(abs_path, mtime), ...] sorted newest-first."""
    dirs = list(PROFILE_SEARCH_DIRS) + list(extra_dirs)
    found: dict[str, float] = {}
    for d in dirs:
        if not d:
            continue
        for p in glob.glob(os.path.join(d, "**", "*.ovpn"), recursive=True):
            found[os.path.abspath(p)] = os.path.getmtime(p)
    return sorted(found.items(), key=lambda x: x[1], reverse=True)


# ── Route management ──────────────────────────────────────────────────────────

def snapshot_routes() -> set[str]:
    out = subprocess.check_output(["ip", "route", "show"], text=True)
    return set(out.strip().splitlines())


def remove_pushed_routes(pre_routes: set[str]) -> None:
    """Delete redirect-gateway routes that OpenVPN pushed after connecting."""
    try:
        current = set(subprocess.check_output(["ip", "route", "show"], text=True).strip().splitlines())
    except subprocess.CalledProcessError:
        return
    new_routes = current - pre_routes
    # OpenVPN redirect-gateway pushes 0.0.0.0/1 and 128.0.0.0/1
    conflict_prefixes = ("0.0.0.0/1", "128.0.0.0/1")
    removed = []
    for route in new_routes:
        stripped = route.strip()
        if any(stripped.startswith(p) for p in conflict_prefixes):
            subprocess.run(["ip", "route", "del"] + stripped.split(), check=False)
            removed.append(stripped.split()[0])
    if removed:
        print(f"[relay] Removed pushed route(s): {', '.join(removed)}")


# ── Forward chain block/unblock ───────────────────────────────────────────────

def block_forward() -> None:
    """Insert a DROP rule at position 1 in FORWARD to hold traffic during VPN bring-up."""
    subprocess.run(
        ["iptables", "-I", "FORWARD", "1", "-j", "DROP"],
        check=True, capture_output=True,
    )


def unblock_forward() -> None:
    subprocess.run(
        ["iptables", "-D", "FORWARD", "-j", "DROP"],
        check=False, capture_output=True,
    )


# ── Forwarding setup / teardown ───────────────────────────────────────────────

def setup_forwarding(phys_iface: str, tun_iface: str) -> None:
    global _orig_ip_forward, _rules_installed, _phys_iface, _tun_iface
    _phys_iface = phys_iface
    _tun_iface  = tun_iface

    # Preserve original ip_forward value so teardown restores it
    with open("/proc/sys/net/ipv4/ip_forward") as f:
        _orig_ip_forward = f.read().strip()
    with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
        f.write("1\n")

    rules = [
        ["iptables", "-t", "nat", "-A", "POSTROUTING", "-o", tun_iface, "-j", "MASQUERADE"],
        ["iptables", "-A", "FORWARD", "-i", phys_iface, "-o", tun_iface, "-j", "ACCEPT"],
        ["iptables", "-A", "FORWARD", "-i", tun_iface, "-o", phys_iface,
         "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"],
    ]
    for rule in rules:
        subprocess.run(rule, check=True)
    _rules_installed = True
    print(f"[relay] Forwarding: {phys_iface} → {tun_iface} (MASQUERADE on tun)")


def teardown_forwarding() -> None:
    global _orig_ip_forward, _rules_installed
    if _rules_installed and _phys_iface and _tun_iface:
        rules = [
            ["iptables", "-t", "nat", "-D", "POSTROUTING", "-o", _tun_iface, "-j", "MASQUERADE"],
            ["iptables", "-D", "FORWARD", "-i", _phys_iface, "-o", _tun_iface, "-j", "ACCEPT"],
            ["iptables", "-D", "FORWARD", "-i", _tun_iface, "-o", _phys_iface,
             "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"],
        ]
        for rule in rules:
            subprocess.run(rule, check=False, capture_output=True)
        _rules_installed = False

    if _orig_ip_forward is not None:
        try:
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                f.write(_orig_ip_forward + "\n")
        except OSError:
            pass
        _orig_ip_forward = None

    print("[relay] Linux forwarding rules cleaned up")

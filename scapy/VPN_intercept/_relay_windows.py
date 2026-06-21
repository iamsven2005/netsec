#!/usr/bin/env python3
"""Windows forwarding backend for vpn_relay.py — netsh + PowerShell + route.exe."""

import glob
import ipaddress
import json
import os
import subprocess
import time

# ── Module-level state ────────────────────────────────────────────────────────

_ifaces_forwarding: list[str] = []
_nat_installed = False
_phys_iface: str | None = None
_tun_iface:  str | None = None
_NAT_NAME = "VPNRelayNAT"
_FW_RULE  = "VPNRelayForwardBlock"

# ── Search paths ──────────────────────────────────────────────────────────────

OVPN_SEARCH_PATHS = [
    # Community OpenVPN client (provides openvpn.exe CLI)
    r"C:\Program Files\OpenVPN\bin\openvpn.exe",
    r"C:\Program Files (x86)\OpenVPN\bin\openvpn.exe",
    # OpenVPN Connect for Access Server does NOT ship openvpn.exe —
    # install the community client alongside it to get the CLI binary.
]

PROFILE_SEARCH_DIRS = [
    # OpenVPN Connect for Access Server (primary target)
    os.path.join(os.environ.get("APPDATA", ""), "OpenVPN Connect", "profiles"),
    # Community OpenVPN client
    r"C:\Program Files\OpenVPN\config",
    r"C:\Program Files (x86)\OpenVPN\config",
    os.path.join(os.environ.get("USERPROFILE", ""), "OpenVPN", "config"),
    ".",
]


# ── PowerShell helper ─────────────────────────────────────────────────────────

def _ps(cmd: str) -> str:
    """Run a PowerShell command; return stdout, raise on non-zero exit."""
    return subprocess.check_output(
        ["powershell", "-NonInteractive", "-NoProfile", "-Command", cmd],
        text=True, stderr=subprocess.DEVNULL,
    ).strip()


def _ps_safe(cmd: str) -> str:
    """Run a PowerShell command; return stdout or '' on failure."""
    try:
        return _ps(cmd)
    except subprocess.CalledProcessError:
        return ""


# ── Physical interface discovery ─────────────────────────────────────────────

_SKIP_DESC = ("tap", "tun", "openvpn", "wireguard", "bluetooth",
              "virtual", "loopback", "teredo", "isatap", "pseudo")


def list_phys_ifaces() -> list[tuple[str, str, str]]:
    """Return [(name, type, state), ...] for non-virtual adapters."""
    raw = _ps_safe(
        "Get-NetAdapter"
        " | Select-Object Name, InterfaceDescription, Status, PhysicalMediaType"
        " | ConvertTo-Json -Depth 2"
    )
    if not raw:
        return []
    try:
        data = json.loads(raw)
        if isinstance(data, dict):
            data = [data]
    except Exception:
        return []
    result = []
    for item in data:
        name  = item.get("Name", "")
        desc  = (item.get("InterfaceDescription") or "").lower()
        state = (item.get("Status") or "Unknown").lower()
        media = str(item.get("PhysicalMediaType") or "")
        if any(x in desc for x in _SKIP_DESC):
            continue
        if "802.3" in media or "ethernet" in desc:
            itype = "eth"
        elif "802.11" in media or "wireless" in desc or "wi-fi" in desc:
            itype = "wifi"
        else:
            itype = "other"
        result.append((name, itype, state))
    return result


def detect_phys_iface() -> str | None:
    """Return best physical adapter: Ethernet first, then WiFi, lowest ifIndex."""
    raw = _ps_safe(
        "Get-NetAdapter"
        " | Where-Object {"
        "   $_.Status -eq 'Up' -and"
        "   $_.InterfaceDescription -notmatch"
        "   'TAP|TUN|OpenVPN|WireGuard|Bluetooth|Virtual|Loopback|Teredo|ISATAP'"
        " }"
        " | Sort-Object"
        "   @{Expression={ if ($_.PhysicalMediaType -eq '802.3') {0} else {1} }},"
        "   ifIndex"
        " | Select-Object -First 1 -ExpandProperty Name"
    )
    return raw or None


# ── Tun/TAP interface detection ───────────────────────────────────────────────

def find_tun_iface() -> str | None:
    """Return the friendly name of the first Up TAP/TUN/OpenVPN adapter, or None."""
    out = _ps_safe(
        "Get-NetAdapter | Where-Object {"
        "  ($_.InterfaceDescription -match 'TAP|TUN|OpenVPN|WireGuard') -and"
        "  $_.Status -eq 'Up'"
        "} | Select-Object -First 1 -ExpandProperty Name"
    )
    return out or None


def wait_for_tun(timeout: int = 30) -> str | None:
    """Poll until a TAP/TUN adapter comes Up; return its name or None on timeout."""
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
        if os.path.isfile(p):
            return p
    result = subprocess.run(["where", "openvpn"], capture_output=True, text=True)
    if result.returncode == 0:
        return result.stdout.strip().splitlines()[0]
    connect_gui = r"C:\Program Files\OpenVPN Connect\OpenVPNConnect.exe"
    if os.path.isfile(connect_gui):
        raise FileNotFoundError(
            "OpenVPN Connect is installed but does not ship a CLI openvpn.exe.\n"
            "Install the community client (which adds openvpn.exe) alongside it:\n"
            "  https://openvpn.net/community-downloads/\n"
            "Your profiles in AppData\\Roaming\\OpenVPN Connect\\profiles\\ are compatible."
        )
    raise FileNotFoundError(
        "openvpn.exe not found — install OpenVPN community client:\n"
        "  https://openvpn.net/community-downloads/"
    )


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
    """Return the IPv4 routing table as a set of raw lines."""
    try:
        out = subprocess.check_output(["route", "print", "-4"], text=True,
                                      stderr=subprocess.DEVNULL)
        return set(out.strip().splitlines())
    except subprocess.CalledProcessError:
        return set()


def remove_pushed_routes(pre_routes: set[str]) -> None:
    """Delete 0.0.0.0/1 and 128.0.0.0/1 routes added by OpenVPN.

    Rather than diffing (route print output has many volatile lines),
    we unconditionally search for the known pushed-route network+mask pairs.
    """
    targets = {
        ("0.0.0.0",   "128.0.0.0"),   # 0.0.0.0/1
        ("128.0.0.0", "128.0.0.0"),   # 128.0.0.0/1
    }
    try:
        out = subprocess.check_output(["route", "print", "-4"], text=True,
                                      stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        return
    removed = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 3 and (parts[0], parts[1]) in targets:
            net, mask, gw = parts[0], parts[1], parts[2]
            res = subprocess.run(["route", "delete", net, "mask", mask, gw],
                                 capture_output=True, check=False)
            if res.returncode == 0:
                removed.append(f"{net}/{mask}")
    if removed:
        print(f"[relay] Removed pushed route(s): {', '.join(set(removed))}")


# ── Forward chain block/unblock ───────────────────────────────────────────────

def block_forward() -> None:
    """Add a Windows Firewall block rule to drop forwarded traffic temporarily."""
    subprocess.run(
        ["netsh", "advfirewall", "firewall", "add", "rule",
         f"name={_FW_RULE}", "dir=in", "action=block", "protocol=any", "enable=yes"],
        check=False, capture_output=True,
    )


def unblock_forward() -> None:
    subprocess.run(
        ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={_FW_RULE}"],
        check=False, capture_output=True,
    )


# ── Forwarding setup / teardown ───────────────────────────────────────────────

def _get_iface_network(iface: str) -> str | None:
    """Return the CIDR network for the physical interface, e.g. '192.168.88.0/24'."""
    ip_out = _ps_safe(
        f"Get-NetIPAddress -InterfaceAlias '{iface}' -AddressFamily IPv4"
        " | Select-Object -First 1 IPAddress,PrefixLength"
        " | ConvertTo-Json"
    )
    if not ip_out:
        return None
    import json
    try:
        data = json.loads(ip_out)
        ip   = data.get("IPAddress") or data.get("value", {}).get("IPAddress")
        plen = data.get("PrefixLength") or data.get("value", {}).get("PrefixLength")
        if ip and plen:
            net = ipaddress.IPv4Interface(f"{ip}/{plen}").network
            return str(net)
    except Exception:
        pass
    return None


def setup_forwarding(phys_iface: str, tun_iface: str) -> None:
    global _ifaces_forwarding, _nat_installed, _phys_iface, _tun_iface
    _phys_iface = phys_iface
    _tun_iface  = tun_iface

    # Enable per-interface forwarding for both adapters
    for iface in (phys_iface, tun_iface):
        try:
            _ps(f"Set-NetIPInterface -InterfaceAlias '{iface}' -Forwarding Enabled")
            _ifaces_forwarding.append(iface)
        except subprocess.CalledProcessError as e:
            print(f"[relay] Warning: could not enable forwarding on '{iface}': {e}")

    # NAT via New-NetNat (requires Windows 10 1607+ / Server 2016+)
    net = _get_iface_network(phys_iface)
    if net:
        try:
            _ps(f"New-NetNat -Name '{_NAT_NAME}'"
                f" -InternalIPInterfaceAddressPrefix '{net}'"
                " -ErrorAction Stop")
            _nat_installed = True
            print(f"[relay] NAT: {net} → {tun_iface}  (New-NetNat)")
        except subprocess.CalledProcessError:
            print(
                "[relay] Warning: New-NetNat failed — Hyper-V feature may not be enabled.\n"
                "        Run in an elevated PowerShell: Enable-WindowsOptionalFeature"
                " -Online -FeatureName Microsoft-Hyper-V-All\n"
                "        Or enable Internet Connection Sharing on the TAP adapter manually."
            )
    else:
        print(f"[relay] Warning: could not determine subnet for '{phys_iface}'; NAT not configured")

    print(f"[relay] Forwarding: {phys_iface} → {tun_iface}")


def teardown_forwarding() -> None:
    global _nat_installed, _ifaces_forwarding
    for iface in _ifaces_forwarding:
        try:
            _ps(f"Set-NetIPInterface -InterfaceAlias '{iface}' -Forwarding Disabled")
        except subprocess.CalledProcessError:
            pass
    _ifaces_forwarding = []

    if _nat_installed:
        try:
            _ps(f"Remove-NetNat -Name '{_NAT_NAME}' -Confirm:$false")
        except subprocess.CalledProcessError:
            pass
        _nat_installed = False

    print("[relay] Windows forwarding rules cleaned up")

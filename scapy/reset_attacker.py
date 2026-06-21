#!/usr/bin/env python3
# v1.0
"""
reset_attacker.py — restore the attacker machine to baseline after main.py.

Undoes every persistent change the toolkit makes:

  Step 1  Kill  ospf_adjacency.py and openvpn processes
  Step 2  Flush iptables filter + nat tables
  Step 3  Restore default iptables chain policies to ACCEPT
  Step 4  Disable IPv4 forwarding
  Step 5  Delete toolkit-added /1 routes from any tun/tap interface
  Step 6  Delete VLAN subinterfaces  (e.g. eth0.10, eth0.20)
  Step 7  Remove non-127.x.x.x addresses from loopback
  Step 8  Bring parent physical interface up and request a fresh DHCP lease

Run as root on Linux / Kali.

The switch port (set to trunk by DTP) must be reset manually from the
Cisco CLI — this script cannot reach it.  Instructions are printed at the end.
"""

import glob
import os
import re
import subprocess
import sys
import time


# ── helpers ───────────────────────────────────────────────────────────────────

def _run(args, *, silent=False):
    if not silent:
        print("    $", " ".join(str(a) for a in args))
    r = subprocess.run(args, capture_output=True, text=True)
    if r.returncode != 0 and r.stderr.strip() and not silent:
        print(f"    ! {r.stderr.strip()}")
    return r


def _section(n, title):
    print(f"\n{'─' * 58}")
    print(f"  Step {n}  {title}")
    print(f"{'─' * 58}")


def _ok(msg):   print(f"  [OK]   {msg}")
def _skip(msg): print(f"  [SKIP] {msg}")
def _warn(msg): print(f"  [WARN] {msg}")


# ── 0. root check ─────────────────────────────────────────────────────────────

if os.geteuid() != 0:
    sys.exit("[!] Must be run as root:  sudo python3 reset_attacker.py")

print("=" * 58)
print("  reset_attacker.py  v1.0")
print("  Restoring attacker machine to baseline...")
print("=" * 58)


# ── Step 1: kill toolkit processes ────────────────────────────────────────────

_section(1, "Kill toolkit processes")

for pattern in ("ospf_adjacency.py", "ospf_full_adjacency.py", "main.py"):
    r = _run(["pkill", "-f", pattern], silent=True)
    if r.returncode == 0:
        _ok(f"Killed process(es) matching '{pattern}'")
    else:
        _skip(f"No process matching '{pattern}'")

# Give SIGTERM time to propagate before we flush iptables that atexit would clean
time.sleep(1)

r = _run(["pkill", "-x", "openvpn"], silent=True)
if r.returncode == 0:
    _ok("Killed openvpn")
    # Brief pause so tun interface teardown completes before route cleanup
    time.sleep(1)
else:
    _skip("openvpn not running")


# ── Step 2: flush iptables ────────────────────────────────────────────────────

_section(2, "Flush iptables rules")

for table in ("filter", "nat", "mangle"):
    r = _run(["iptables", "-t", table, "-F"], silent=True)
    _run(["iptables", "-t", table, "-X"], silent=True)
    if r.returncode == 0:
        _ok(f"Flushed table: {table}")
    else:
        _warn(f"Could not flush table '{table}' (iptables not available?)")


# ── Step 3: restore default chain policies ────────────────────────────────────

_section(3, "Restore default chain policies to ACCEPT")

for chain in ("INPUT", "FORWARD", "OUTPUT"):
    r = _run(["iptables", "-P", chain, "ACCEPT"], silent=True)
    if r.returncode == 0:
        _ok(f"Policy {chain} → ACCEPT")


# ── Step 4: disable ip_forward ────────────────────────────────────────────────

_section(4, "Disable IPv4 forwarding")

try:
    with open("/proc/sys/net/ipv4/ip_forward", "w") as fh:
        fh.write("0\n")
    _ok("ip_forward = 0")
except OSError as exc:
    _warn(f"Could not set ip_forward: {exc}")


# ── Step 5: remove toolkit-added /1 routes from tun/tap ───────────────────────

_section(5, "Remove /1 routes from tun/tap interfaces")

tun_ifaces = []
for state_path in (
    glob.glob("/sys/class/net/tun*/operstate")
    + glob.glob("/sys/class/net/tap*/operstate")
):
    tun_ifaces.append(state_path.split("/")[4])

if not tun_ifaces:
    _skip("No tun/tap interfaces present")
else:
    for tun in tun_ifaces:
        for prefix in ("0.0.0.0/1", "128.0.0.0/1"):
            r = _run(["ip", "route", "del", prefix, "dev", tun], silent=True)
            if r.returncode == 0:
                _ok(f"Removed  {prefix}  dev {tun}")


# ── Step 6: delete VLAN subinterfaces ─────────────────────────────────────────

_section(6, "Delete VLAN subinterfaces")

try:
    all_ifaces = os.listdir("/sys/class/net/")
except OSError:
    all_ifaces = []

# Any interface name containing a dot is a VLAN subinterface (eth0.10, ens3.20)
vlan_ifaces = sorted(i for i in all_ifaces if "." in i)

if not vlan_ifaces:
    _skip("No VLAN subinterfaces found")
else:
    for iface in vlan_ifaces:
        _run(["ip", "link", "set", iface, "down"], silent=True)
        r = _run(["ip", "link", "del", iface])
        if r.returncode == 0:
            _ok(f"Deleted {iface}  (removes stolen static IP with it)")
        else:
            _warn(f"Could not delete {iface}")


# ── Step 7: remove non-loopback IPs from lo ───────────────────────────────────

_section(7, "Remove stolen server IPs from loopback")

r = _run(["ip", "-o", "-4", "addr", "show", "dev", "lo"], silent=True)
removed = 0
for line in r.stdout.splitlines():
    m = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+/\d+)", line)
    if not m:
        continue
    cidr = m.group(1)
    if cidr.startswith("127."):
        continue
    _run(["ip", "addr", "del", cidr, "dev", "lo"])
    _ok(f"Removed  {cidr}  from lo")
    removed += 1

if removed == 0:
    _skip("No non-127.x.x.x addresses on lo")


# ── Step 8: restore DHCP on the parent physical interface ─────────────────────

_section(8, "Restore DHCP on parent physical interface")

# Detect the first up non-virtual, non-VLAN interface
_SKIP_RE = re.compile(r"^(lo|docker|virbr|br-|veth|dummy|bond|team|tun|tap)")

phys = None
try:
    candidates = []
    for iface in sorted(os.listdir("/sys/class/net/")):
        if _SKIP_RE.match(iface) or "." in iface:
            continue
        try:
            with open(f"/sys/class/net/{iface}/operstate") as fh:
                state = fh.read().strip()
        except OSError:
            continue
        # Prefer ethernet, then wifi; lower index preferred
        is_wifi = os.path.isdir(f"/sys/class/net/{iface}/wireless")
        num = int(re.search(r"(\d+)$", iface).group(1)) if re.search(r"\d+$", iface) else 999
        candidates.append((1 if is_wifi else 0, num, iface, state))
    candidates.sort()
    if candidates:
        phys = candidates[0][2]
except Exception as exc:
    _warn(f"Interface auto-detection failed: {exc}")

if phys is None:
    _warn("Could not auto-detect physical interface.")
    _warn("Run manually:  sudo dhclient -r eth0 && sudo dhclient eth0")
else:
    print(f"  Detected physical interface: {phys}")
    _run(["ip", "link", "set", phys, "up"])

    # Release any stale lease then request a fresh one
    _run(["dhclient", "-r", phys], silent=True)

    # Try dhclient; fall back to dhcpcd if missing
    r = _run(["dhclient", phys])
    if r.returncode == 0:
        _ok(f"DHCP lease obtained on {phys}")
    else:
        r2 = _run(["dhcpcd", phys])
        if r2.returncode == 0:
            _ok(f"DHCP lease obtained on {phys} (via dhcpcd)")
        else:
            _warn(f"DHCP request failed on {phys}.")
            _warn(f"Run manually:  sudo dhclient {phys}")

    # Show resulting address
    r = _run(["ip", "-4", "addr", "show", "dev", phys], silent=True)
    for line in r.stdout.splitlines():
        if "inet " in line:
            print(f"  Address now: {line.strip()}")


# ── done ──────────────────────────────────────────────────────────────────────

print(f"""
{'═' * 58}
  Reset complete.

  ┌─────────────────────────────────────────────────────┐
  │  MANUAL STEP — reset the switch port on Cisco CLI   │
  └─────────────────────────────────────────────────────┘

  The attacker's port is still in TRUNK mode from DTP.
  SSH to SW1 or SW2 and run:

    conf t
    interface <attacker-port>
      switchport mode access
      switchport access vlan <VLAN>
      no shutdown
    end
    write memory

  Then verify:
    show interfaces status
    show spanning-tree

  After the port is back in access mode, ARP tables on
  DSW1/DSW2 and other hosts should flush within ~5 min
  (or run "clear arp" on the DSW to force immediate).
{'═' * 58}
""")

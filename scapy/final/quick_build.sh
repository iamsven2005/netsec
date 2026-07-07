#!/bin/bash
# Quick build script for Linux executable

set -e

echo "════════════════════════════════════════════════════════════════"
echo "  Network Takeover Toolkit - Quick Build"
echo "════════════════════════════════════════════════════════════════"

# Check Python
echo "[*] Checking Python..."
if ! command -v python3 &> /dev/null; then
    echo "[!] Python 3 not found"
    exit 1
fi
PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
echo "[+] Python $PYTHON_VERSION found"

# Check PyInstaller
echo "[*] Checking PyInstaller..."
if ! python3 -c "import PyInstaller" 2>/dev/null; then
    echo "[!] PyInstaller not installed"
    echo "    Install with: pip install pyinstaller"
    exit 1
fi
echo "[+] PyInstaller found"

# Check UPX (optional)
if command -v upx &> /dev/null; then
    echo "[+] UPX found (binary will be compressed)"
    UPX_AVAILABLE=true
else
    echo "[~] UPX not found (optional, but recommended)"
    echo "    Install with: sudo apt install upx  (Linux)"
    UPX_AVAILABLE=false
fi

# Build
BUILD_DIR="build_toolkit"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo ""
echo "[*] Running build script..."
cd "$SCRIPT_DIR"
python3 build_executable.py

echo ""
echo "[*] Building with PyInstaller..."
cd "$BUILD_DIR"

if [ "$UPX_AVAILABLE" = true ]; then
    echo "    (with UPX compression)"
    pyinstaller netsec_toolkit.spec --onefile --upx-dir=/usr/bin
else
    echo "    (without compression)"
    pyinstaller netsec_toolkit.spec
fi

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "  BUILD COMPLETE"
echo "════════════════════════════════════════════════════════════════"

BINARY="$(pwd)/dist/netsec-toolkit"
if [ -f "$BINARY" ]; then
    SIZE=$(du -h "$BINARY" | cut -f1)
    echo ""
    echo "Executable: $BINARY"
    echo "Size:       $SIZE"
    echo ""
    echo "To run:"
    echo "  sudo $BINARY [--remote] [--demo]"
    echo ""
    echo "To deploy to another system:"
    echo "  scp $BINARY user@target:/tmp/"
    echo "  ssh user@target 'sudo /tmp/netsec-toolkit --demo'"
else
    echo "[!] Build failed - binary not found"
    exit 1
fi

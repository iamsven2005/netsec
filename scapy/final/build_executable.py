#!/usr/bin/env python3
"""
Build standalone executable for the network takeover toolkit.
Packages all modules except c2_server.py into a single binary.

Usage:
    python3 build_executable.py
"""

import os
import sys
import shutil
from pathlib import Path

def check_dependencies():
    """Check if required build tools are available."""
    try:
        import PyInstaller
        print("[OK] PyInstaller found")
    except ImportError:
        print("[!] PyInstaller not found. Install with: pip install pyinstaller")
        sys.exit(1)

def create_spec_file():
    """Create a PyInstaller spec file for the toolkit."""
    spec_content = '''# -*- mode: python ; coding: utf-8 -*-

import sys
from pathlib import Path

block_cipher = None

a = Analysis(
    ['main_executable.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('intercepted', 'intercepted'),
    ],
    hiddenimports=[
        'scapy',
        'scapy.all',
        'scapy.contrib.ospf',
        'scapy.layers.dns',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludedimports=[],
    win_console=True,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='netsec-toolkit',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
'''
    return spec_content

def create_wrapper():
    """Create main_executable.py that imports and runs main.py."""
    wrapper = '''#!/usr/bin/env python3
"""
Wrapper for standalone executable.
Imports and runs main.py from the packaged toolkit.
"""

import sys
import os

# Add current directory to path so imports work
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import and run main
try:
    import main
    main.main()
except KeyboardInterrupt:
    print("\\n[*] Interrupted by user")
    sys.exit(0)
except Exception as e:
    print(f"[!] Fatal error: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
'''
    return wrapper

def main():
    """Build the executable."""
    print("=" * 60)
    print("Network Takeover Toolkit - Executable Builder")
    print("=" * 60)

    # Check dependencies
    print("\n[*] Checking dependencies...")
    check_dependencies()

    build_dir = Path("build_toolkit")
    final_dir = Path(__file__).parent

    # Create build directory
    print(f"\n[*] Creating build directory: {build_dir}")
    if build_dir.exists():
        shutil.rmtree(build_dir)
    build_dir.mkdir(parents=True)

    # Copy source files (exclude c2_server.py)
    print("\n[*] Copying source files...")
    files_to_copy = [
        'main.py',
        'dhcp_takeover.py',
        'ospf_adjacency.py',
        'vpn_relay.py',
        'http_intercept.py',
        'dns_c2.py',
    ]

    for fname in files_to_copy:
        src = final_dir / fname
        dst = build_dir / fname
        if src.exists():
            shutil.copy2(src, dst)
            print(f"  [+] {fname}")
        else:
            print(f"  [!] {fname} not found")
            sys.exit(1)

    # Create wrapper
    print("\n[*] Creating wrapper...")
    wrapper_content = create_wrapper()
    wrapper_path = build_dir / "main_executable.py"
    wrapper_path.write_text(wrapper_content)
    print(f"  [+] main_executable.py created")

    # Create PyInstaller spec
    print("\n[*] Creating PyInstaller spec...")
    spec_content = create_spec_file()
    spec_path = build_dir / "netsec_toolkit.spec"
    spec_path.write_text(spec_content)
    print(f"  [+] netsec_toolkit.spec created")

    # Create intercepted directory
    print("\n[*] Creating data directories...")
    (build_dir / "intercepted").mkdir(exist_ok=True)
    print(f"  [+] intercepted/ created")

    # Build instructions
    print("\n" + "=" * 60)
    print("BUILD INSTRUCTIONS")
    print("=" * 60)
    print(f"""
Ready to build! Execute:

    cd {build_dir}
    pyinstaller netsec_toolkit.spec

This will create a standalone executable in dist/netsec-toolkit that can run
on any Linux system without Python or additional downloads.

Output will be in: {build_dir}/dist/netsec-toolkit

To run on a Linux system:
    sudo ./netsec-toolkit [--remote] [--demo]

The executable includes:
  - Python runtime
  - Scapy and all dependencies
  - All toolkit modules (except c2_server)
  - Pre-configured for Linux (Kali) deployment

Size: ~100-150MB (typical PyInstaller bundle)
Platform: Linux x86_64
Root required: Yes (raw sockets, iptables, routing)
    """)

if __name__ == '__main__':
    main()

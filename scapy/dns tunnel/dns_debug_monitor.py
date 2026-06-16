#!/usr/bin/env python3
"""
DNS Debug Monitor - Show all DNS queries received on UDP/53

Usage:
  python dns_debug_monitor.py

Displays all DNS queries (A, AAAA, TXT, MX, NS, etc.) received on port 53,
regardless of the destination domain. Useful for debugging and monitoring.
"""

import sys
from datetime import datetime
from scapy.all import sniff, conf, IP, UDP, DNS

VERSION = "v1.1"
conf.verb = 0  # suppress Scapy noise


def _format_qtype(qtype: int) -> str:
    """Convert DNS query type number to name."""
    type_map = {
        1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
        16: "TXT", 28: "AAAA", 33: "SRV", 41: "OPT"
    }
    return type_map.get(qtype, f"TYPE{qtype}")


def _dns_sniffer(pkt) -> None:
    """Callback for each packet received."""
    if not (pkt.haslayer(IP) and pkt.haslayer(UDP) and pkt.haslayer(DNS)):
        return

    dns = pkt[DNS]

    # Skip DNS responses (qr=1), only show queries
    if dns.qr != 0:
        return

    if dns.qdcount == 0:
        return

    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst
    src_port = pkt[UDP].sport
    qname = dns.qd.qname.decode("utf-8", errors="ignore").rstrip(".")
    qtype = _format_qtype(dns.qd.qtype)
    timestamp = datetime.now().strftime("%H:%M:%S")

    print(f"[{timestamp}] {src_ip}:{src_port} → {dst_ip}:53")
    print(f"  Query: {qname} ({qtype})")
    print()


if __name__ == "__main__":
    print("=" * 70)
    print(f"  DNS Debug Monitor - All Queries ({VERSION})")
    print("  Listening on UDP/53 for all DNS queries")
    print("=" * 70)
    print("[*] Sniffing DNS queries…  (Ctrl+C to stop)\n")

    try:
        sniff(filter="udp port 53", prn=_dns_sniffer, store=0)
    except PermissionError:
        print("[!] Permission denied — run as root/Administrator.")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[*] Monitor stopped.")

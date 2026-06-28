#!/usr/bin/env python3
"""
DNS Debug Client
Sends a DNS A query via tun0 to 8.8.8.8 matching dig's exact wire format:
  - Random non-zero transaction ID
  - RD + AD flags (0x0120)
  - EDNS0 OPT record (UDP payload size 1232, no COOKIE for simplicity)

Usage:
  sudo python3 dns_debug_client.py [qname]
  e.g. sudo python3 dns_debug_client.py command.d.lootforge.org
"""

import random
import sys
from scapy.all import IP, UDP, send, sr1, conf
from scapy.layers.dns import DNS, DNSQR, DNSRR

conf.verb = 0

DNS_SERVER = "8.8.8.8"
IFACE      = "tun0"


def _build_edns0_opt() -> DNSRR:
    """
    Build an EDNS0 OPT pseudo-RR matching dig's output:
      name=. type=OPT(41) rclass=1232 (UDP payload size) ttl=0
    """
    return DNSRR(
        rrname=b"\x00",   # root label "."
        type=41,          # OPT
        rclass=1232,      # advertised UDP payload size
        ttl=0,            # extended RCODE + EDNS version (both 0)
        rdata=b"",
    )


def send_query(qname: str) -> None:
    txid = random.randint(1, 65535)
    opt  = _build_edns0_opt()

    pkt = (
        IP(dst=DNS_SERVER)
        / UDP(sport=random.randint(1024, 65534), dport=53)
        / DNS(
            id=txid,
            qr=0,       # query
            opcode=0,
            rd=1,       # recursion desired
            ad=1,       # authenticated data (matches dig default)
            qd=DNSQR(qname=qname, qtype="A", qclass="IN"),
            ar=opt,
            arcount=1,
        )
    )

    print(f"[*] Sending DNS A query for '{qname}'")
    print(f"    → dst={DNS_SERVER}  iface={IFACE}  txid=0x{txid:04x}")
    print(f"    → flags=0x0120 (RD+AD)  additional=OPT(edns0 udp=1232)")

    resp = sr1(pkt, iface=IFACE, timeout=5, verbose=0)

    if resp is None:
        print("[!] No reply received within 5 seconds.")
        return

    dns = resp[DNS] if resp.haslayer(DNS) else None
    if dns is None:
        print(f"[!] Got a reply but it has no DNS layer: {resp.summary()}")
        return

    print(f"[+] Reply received! txid=0x{dns.id:04x}  rcode={dns.rcode}  ancount={dns.ancount}")
    if dns.ancount and dns.an:
        rr = dns.an
        while rr and rr.__class__.__name__ != "NoPayload":
            if hasattr(rr, "rdata"):
                print(f"    Answer: {rr.rrname.decode() if isinstance(rr.rrname, bytes) else rr.rrname}  "
                      f"type={rr.type}  rdata={rr.rdata}")
            rr = rr.payload if hasattr(rr, "payload") else None
    else:
        print("    (no answer records)")


if __name__ == "__main__":
    qname = sys.argv[1] if len(sys.argv) > 1 else "command.d.lootforge.org"
    send_query(qname)

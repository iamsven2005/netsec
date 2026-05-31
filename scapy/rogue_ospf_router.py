#!/usr/bin/env python3
from __future__ import annotations
import argparse, ipaddress, platform, socket, sys, threading, time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List

try:
    from scapy.all import Ether, IP, conf as scapy_conf, get_if_addr, sendp, sniff
    from scapy.contrib.ospf import (OSPF_DBDesc, OSPF_Hdr, OSPF_Hello, OSPF_LSReq, OSPF_LSUpd, OSPF_Router_LSA, OSPF_Link)
except ImportError:
    sys.exit("[!] pip install scapy  (Windows: also install Npcap)")

ALL_SPF = "224.0.0.5"; ALL_DR = "224.0.0.6"
MAC_SPF = "01:00:5e:00:00:05"; MAC_DR = "01:00:5e:00:00:06"
PROTO = 89; OPT = 0x02; PRIO = 255; DEAD = 40; HI = 10; ISEQ = 1000

class St(Enum):
    DOWN=auto(); INIT=auto(); TWO_WAY=auto(); EXSTART=auto()
    EXCHANGE=auto(); LOADING=auto(); FULL=auto()

@dataclass
class Nbr:
    rid: str; ip: str; state: St = St.DOWN; prio: int = 0
    dr: str = "0.0.0.0"; bdr: str = "0.0.0.0"; seq: int = 0; master: bool = False
    seen: float = field(default_factory=time.time); reqs: List = field(default_factory=list)

def log(m): sys.stdout.write(f"[{time.strftime('%H:%M:%S')}] {m}\n"); sys.stdout.flush()

def rid_gt(a, b):
    try: return int(ipaddress.IPv4Address(a)) > int(ipaddress.IPv4Address(b))
    except: return False

def default_iface():
    try:
        i = str(scapy_conf.iface)
        if i and i != "None": return i
    except: pass
    return {"Windows": "Ethernet", "Darwin": "en0"}.get(platform.system(), "eth0")

def local_ip(iface):
    try:
        a = get_if_addr(iface)
        if a and a != "0.0.0.0": return a
    except: pass
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80)); ip = s.getsockname()[0]; s.close()
        if ip and ip != "0.0.0.0": return ip
    except: pass
    sys.exit(f"[!] No usable IP for '{iface}'. Use --router-id.")

class OSPF:
    def __init__(self, iface, src, rid, area, mask, hi, verbose):
        self.iface = iface; self.src = src; self.rid = rid; self.area = area
        self.mask = mask; self.hi = hi; self.verbose = verbose
        self._seq = ISEQ; self.nbrs: Dict[str, Nbr] = {}; self._lk = threading.Lock()

    def _nseq(self): self._seq += 1; return self._seq

    def _send(self, payload, dst=ALL_SPF):
        p = Ether(dst=MAC_DR if dst == ALL_DR else MAC_SPF) / IP(src=self.src, dst=dst, proto=PROTO, ttl=1) / payload
        if self.verbose: p.show2()
        sendp(p, iface=self.iface, verbose=False)

    def _hdr(self, t): return OSPF_Hdr(version=2, type=t, src=self.rid, area=self.area)

    def _hello(self):
        with self._lk:
            nids = [n.rid for n in self.nbrs.values() if n.state.value >= St.INIT.value]
        return self._hdr(1) / OSPF_Hello(mask=self.mask, hellointerval=self.hi, options=OPT,
            prio=PRIO, deadinterval=DEAD, router=self.src, backup=self.src, neighbors=nids)

    def _dbd(self, n, init=False, more=False, ms=True, seq=0, lsas=None):
        f = (0x04 if init else 0) | (0x02 if more else 0) | (0x01 if ms else 0)
        p = self._hdr(2) / OSPF_DBDesc(mtu=1500, options=OPT, dbdescr=f, ddseq=seq)
        for h in (lsas or []): p = p / h
        return p

    def _rlsa(self):
        return OSPF_Router_LSA(age=1, options=OPT, type=1, id=self.rid, adrouter=self.rid,
            seq=0x80000001, linklist=[OSPF_Link(type=3, id=self.src, data=self.mask, metric=1)])

    def _trans(self, n, s): log(f"[STATE] {n.rid}  {n.state.name} -> {s.name}"); n.state = s

    def _on_hello(self, pkt):
        hdr = pkt[OSPF_Hdr]; h = pkt[OSPF_Hello]; rid = hdr.src
        if rid == self.rid: return
        with self._lk:
            n = self.nbrs.setdefault(rid, Nbr(rid=rid, ip=pkt[IP].src))
            n.seen = time.time(); n.prio = h.prio; n.dr = h.router; n.bdr = h.backup
            if n.state == St.DOWN: self._trans(n, St.INIT)
            if n.state == St.INIT and self.rid in (h.neighbors or []):
                self._trans(n, St.TWO_WAY); self._exstart(n)
        self._send(self._hello())

    def _exstart(self, n):
        self._trans(n, St.EXSTART); n.seq = self._nseq(); n.master = True
        log(f"[EXSTART] -> {n.rid}  seq={n.seq}")
        self._send(self._dbd(n, init=True, more=True, ms=True, seq=n.seq), dst=n.ip)

    def _on_dbd(self, pkt):
        hdr = pkt[OSPF_Hdr]; d = pkt[OSPF_DBDesc]; rid = hdr.src
        with self._lk:
            n = self.nbrs.get(rid)
            if not n or n.state.value < St.EXSTART.value: return
            f = d.dbdescr; m_bit = f & 0x02; ms_bit = f & 0x01; seq = d.ddseq
            if n.state == St.EXSTART:
                if rid_gt(rid, self.rid):
                    n.master = False; n.seq = seq
                    log(f"[EXSTART] {rid}=Master  We=Slave")
                    self._send(self._dbd(n, ms=False, seq=seq), dst=n.ip)
                    self._trans(n, St.EXCHANGE); self._lsdb_summary(n)
                elif not ms_bit and seq == n.seq:
                    log(f"[EXSTART] We=Master  {rid}=Slave")
                    self._trans(n, St.EXCHANGE); self._lsdb_summary(n)
            elif n.state == St.EXCHANGE:
                if n.master: n.seq = self._nseq()
                n.reqs = self._unknown(pkt)
                if not m_bit:
                    if n.reqs: self._trans(n, St.LOADING); self._lsreq(n)
                    else: self._trans(n, St.FULL); log(f"[FULL] {rid} -- DR claimed.")
                else:
                    self._send(self._dbd(n, ms=n.master, seq=n.seq), dst=n.ip)

    def _lsdb_summary(self, n):
        log(f"[EXCHANGE] Summary -> {n.rid}")
        self._send(self._dbd(n, ms=n.master, seq=n.seq, lsas=[self._rlsa()]), dst=n.ip)

    def _unknown(self, pkt):
        reqs = []; layer = pkt[OSPF_DBDesc].payload
        while layer and layer.name != "NoPayload":
            if hasattr(layer, "adrouter"):
                reqs.append((getattr(layer, "type", 1), getattr(layer, "id", "0.0.0.0"), layer.adrouter))
            layer = layer.payload
        return reqs

    def _lsreq(self, n):
        if not n.reqs: return
        log(f"[LOADING] LSReq -> {n.rid}  ({len(n.reqs)} LSA(s))")
        p = self._hdr(3)
        for t, i, a in n.reqs: p = p / OSPF_LSReq(type=t, id=i, adrouter=a)
        self._send(p, dst=n.ip)

    def _on_lsupd(self, pkt):
        rid = pkt[OSPF_Hdr].src
        lsas = getattr(pkt[OSPF_LSUpd], "lsalist", []) if pkt.haslayer(OSPF_LSUpd) else []
        if lsas:
            log(f"[LSUPD] {len(lsas)} LSA(s) from {rid}. ACK.")
            p = self._hdr(5)
            for l in lsas: p = p / l
            self._send(p)
        with self._lk:
            n = self.nbrs.get(rid)
            if n and n.state == St.LOADING:
                n.reqs.clear(); self._trans(n, St.FULL)
                log(f"[FULL] {rid} -- Flooding Router-LSA.")
                self._send(self._hdr(4) / OSPF_LSUpd(lsalist=[self._rlsa()]), dst=ALL_DR)

    def _on_lsreq(self, pkt):
        log(f"[LSREQ] {pkt[OSPF_Hdr].src} -- Responding.")
        self._send(self._hdr(4) / OSPF_LSUpd(lsalist=[self._rlsa()]), dst=pkt[IP].src)

    def _dispatch(self, pkt):
        if not pkt.haslayer(OSPF_Hdr): return
        {1: self._on_hello, 2: self._on_dbd, 3: self._on_lsreq, 4: self._on_lsupd,
         5: lambda p: log(f"[LSACK] {p[OSPF_Hdr].src}")}.get(pkt[OSPF_Hdr].type, lambda p: None)(pkt)

    def run(self):
        threading.Thread(target=sniff, kwargs=dict(iface=self.iface, filter="proto 89",
            prn=self._dispatch, store=0), daemon=True).start()
        log(f"[*] Sniffer on {self.iface}"); log("[*] Hellos sending -- Ctrl+C to stop.\n")
        tick = 0
        try:
            while True:
                self._send(self._hello()); tick += 1; log(f"[Hello #{tick}] -> {ALL_SPF}")
                if tick % 3 == 0:
                    with self._lk:
                        for r, n in self.nbrs.items():
                            log(f"[STATUS] {r}  state={n.state.name}  dr={n.dr}")
                with self._lk:
                    dead = [r for r, n in self.nbrs.items() if time.time() - n.seen > DEAD]
                for r in dead: del self.nbrs[r]; log(f"[DEAD] {r} expired.")
                time.sleep(self.hi)
        except KeyboardInterrupt: log("\n[*] Stopped.")

def main():
    p = argparse.ArgumentParser(prog="ospf_full_adjacency.py")
    p.add_argument("--iface",     default=default_iface())
    p.add_argument("--router-id", default=None)
    p.add_argument("--area",      default="0.0.0.0")
    p.add_argument("--mask",      default="255.255.255.0")
    p.add_argument("--interval",  default=HI, type=int)
    p.add_argument("--verbose",   action="store_true")
    a = p.parse_args(); src = local_ip(a.iface); rid = a.router_id or src
    log("=" * 52); log("  OSPFv2 Full Adjacency Engine")
    log(f"  iface={a.iface}  src={src}  rid={rid}  area={a.area}"); log("=" * 52)
    OSPF(a.iface, src, rid, a.area, a.mask, a.interval, a.verbose).run()

if __name__ == "__main__": main()
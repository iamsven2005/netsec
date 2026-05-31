from scapy.all import sniff
from scapy.contrib.ospf import OSPF_Hdr, OSPF_Hello

def show_hello(pkt):
    if pkt.haslayer(OSPF_Hello):
        h = pkt[OSPF_Hdr]
        hello = pkt[OSPF_Hello]
        print(f'Router ID: {h.src}')
        print(f'Area ID:   {h.area}')
        print(f'Hello int: {hello.hellointerval}s')
        print(f'Dead int:  {hello.deadinterval}s')
        print(f'DR:        {hello.router}')
        print(f'BDR:       {hello.backup}')
        print('---')

sniff(filter='proto 89', prn=show_hello, store=0)
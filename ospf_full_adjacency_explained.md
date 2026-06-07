# OSPFv2 Full Adjacency

This program lets your device join an OSPF broadcast segment as a `DROther` router. It listens for OSPF Hellos, negotiates adjacency with the DR and BDR, exchanges OSPF database information using Scapy, and can manually advertise a stub network through its self-originated Type-1 Router-LSA.

## What It Does

- Sends OSPF Hello packets with `priority = 0`, so the local device does not compete to become DR or BDR.
- Tracks neighbors and moves through the OSPF states from `Down` to `Full`.
- Uses a small local LSDB so the router can answer LSAs during database exchange.
- Replies to LSRequests and acknowledges LSUpdates using the correct OSPF packet types.
- Includes a runtime menu that can add a stub route by updating the local Router-LSA with a user-supplied network, mask, and metric.

## What To Expect

On a normal broadcast segment, your device should:

- reach `Full` adjacency only with the DR and BDR
- remain `Two-Way` with other DROther neighbors
- learn and answer the LSAs needed to complete adjacency
- keep a single self-originated local Router-LSA, even after adding a manual stub route

If the neighbor stays in `Loading` or drops back to `Down`, check the interface setup, DR/BDR election, and OSPF packet exchange.

## Requirements

- Linux or Windows with Scapy installed
- Administrator or root privileges
- Npcap on Windows
- A working OSPF broadcast network to join

## How To Run

```bash
sudo python3 scapy/ospf_full_adjacency.py --iface eth0
```

Useful options:

```bash
sudo python3 scapy/ospf_full_adjacency.py --iface eth0 --router-id 10.10.10.10
sudo python3 scapy/ospf_full_adjacency.py --iface eth0 --area 0.0.0.0
sudo python3 scapy/ospf_full_adjacency.py --iface eth0 --interval 10
sudo python3 scapy/ospf_full_adjacency.py --iface eth0 --verbose
```

## Command Line Flags

| Flag | Default | Meaning |
|------|---------|---------|
| `--iface` | auto-detected | Interface to sniff and send on |
| `--router-id` | interface IP | OSPF Router ID to advertise |
| `--area` | `0.0.0.0` | OSPF area ID |
| `--mask` | `255.255.255.0` | Network mask used in Hello packets |
| `--interval` | `10` | Hello interval in seconds |
| `--verbose` | off | Print detailed packet output |

## Quick Notes

- Use a broadcast OSPF segment with a real DR and BDR already elected.
- Set the local device to priority `0` so it stays a DROther.
- After FULL adjacency is stable for 2 hello intervals, use the runtime menu option `1` to advertise a stub network with a Type-1 Router-LSA.
- Option `1` updates the existing self Router-LSA; it does not create a Type-3 Summary-LSA.
- If the neighbor does not progress cleanly, verify MTU, interface IP settings, and OSPF packet flow in Wireshark.

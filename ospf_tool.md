# OSPFv2 Full Adjacency

This program lets your device join an OSPF broadcast segment as a `DROther` router. It listens for Hellos, forms adjacency with the DR or BDR, exchanges LSDB information with Scapy, and only after stable `FULL` adjacency lets you manually add a stub network into your self-originated Type-1 Router-LSA.

## What It Does

- Sends OSPF Hello packets with `priority = 0`, so the local device does not try to become DR or BDR.
- Uses backbone area `0.0.0.0` only and always uses router ID `99.99.99.99`.
- Keeps a local LSDB in `context["local_lsdb"]` for adjacency formation and LSA replies.
- Tracks neighbor routes separately in `OSPF_NBR_ROUTES_DB`.
- Lets you manually add a Type-1 Router-LSA stub link by entering a network, mask, and metric at runtime.

## Adjacency Flow

The adjacency code is now written in a direct state-by-state sequence.

`handle_hello()` updates neighbor information, then runs:

1. `state_down()`
2. `state_init()`
3. `state_two_way()`

`handle_dbd()` continues the sequence with:

1. `state_exstart()`
2. `state_exchange()`

`handle_lsupd()` completes the last adjacency step through:

1. `state_loading()`
2. `state_full()`

In simple terms:

- `Down -> Init`: we saw the neighbor.
- `Init -> Two-Way`: the neighbor also lists us.
- `Two-Way -> ExStart`: the neighbor is the DR or BDR, so we begin real adjacency setup.
- `ExStart -> Exchange`: master/slave and DBD sequence handling are agreed.
- `Exchange -> Loading`: we request LSAs we still need.
- `Loading -> Full`: LSDB synchronization is complete.

## Route Handling

There are now two different route-related stores in the script:

- `context["local_lsdb"]`: the raw local LSDB, containing self-originated and received LSAs used by adjacency logic.
- `OSPF_NBR_ROUTES_DB`: a simplified route view built only from Type-1 stub links advertised by neighbors that are currently in `FULL`.

That means `OSPF_NBR_ROUTES_DB` does not represent every LSA in the LSDB.
It is only for routes learned from full neighbors at runtime.

## Runtime Menu

The runtime console is intentionally simple now. It only checks for these commands:

- `1`: add a Router-LSA stub route
- `2`: show neighbors
- `3`: show local LSDB
- `4`: show `OSPF_NBR_ROUTES_DB`
- `q`: hide the menu prompt
- `m`: show the hidden menu prompt again
- `help`: show the command summary

There are no extra menu helper aliases.

## Adjacency Before Advertising

Manual route advertisement is still gated behind stable adjacency.

- The menu waits until all discovered neighbors stay `FULL` for `2 * hello_interval`.
- Only then does option `1` allow a manual Router-LSA stub route update.
- If there are no `FULL` neighbors, the route is still inserted into the local Router-LSA and local LSDB, but it is not flooded to neighbors.

So the program flow is:

1. form adjacency first
2. confirm stable `FULL`
3. allow manual route advertising after that

## What To Expect

On a normal broadcast segment, your device should:

- reach `FULL` adjacency only with the DR and BDR
- remain `Two-Way` with other DROther neighbors
- answer LSRequests and acknowledge LSUpdates during synchronization
- keep a self-originated Router-LSA that can be refreshed and updated with manual stub links

If adjacency drops, the script clears neighbor state, closes the stable-adjacency gate, and rebuilds `OSPF_NBR_ROUTES_DB` so it only reflects currently full neighbors.

## Interface and Runtime IP Behavior

The script auto-detects the interface IPv4 address and netmask.

If the interface loses its usable IPv4 address or netmask:

- Hellos pause
- adjacency state is reset
- the menu gate closes

If the interface IP or netmask changes:

- the local source values are updated
- the self Router-LSA sequence is bumped
- adjacency discovery starts again

The router ID stays fixed at `99.99.99.99`.

## Requirements

- Linux or Windows with Scapy installed
- Administrator or root privileges
- Npcap on Windows
- A working OSPF broadcast network with a DR or BDR to form adjacency with

## How To Run

```bash
sudo python3 scapy/OSPF/ospf_full_adjacency.py --iface eth0
```

## Command Line Flags

| Flag | Default | Meaning |
|------|---------|---------|
| `--iface` | auto-detected | Interface to sniff and send on |
| `--interval` | `10` | Hello interval in seconds |

## Quick Notes

- This script is area-0-only.
- This script is designed to behave like a DROther, not a DR.
- Manual route injection updates the existing self Type-1 Router-LSA; it does not create a Type-3 Summary-LSA.
- `OSPF_NBR_ROUTES_DB` is only a runtime neighbor-route view, not the authoritative LSDB.
- If adjacency does not progress cleanly, check DR/BDR presence, MTU, interface IPv4 settings, and packet flow in Wireshark.

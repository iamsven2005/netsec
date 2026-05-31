# OSPFv2 Full Adjacency — How Each Step Works

## The State Machine

```
Down → Init → 2-Way → ExStart → Exchange → Loading → Full
```

Each arrow is triggered by a specific packet exchange. The sections below trace exactly what the code does at each transition.

---

## Step 1 — Down → Init (Hello received)

**Trigger:** a Hello packet arrives from a previously unknown neighbour.

When `_on_hello` is called by the sniffer, it looks up the source Router ID in `self.nbrs`. If none exists, a new `Nbr` entry is created with state `DOWN`. Because a Hello was received, the neighbour immediately advances to `INIT`:

```python
if n.state == St.DOWN:
    self._trans(n, St.INIT)
```

A Hello is sent back so the neighbour learns about us. At this point both sides know the other exists, but neither has seen itself listed in the other's neighbour field yet.

---

## Step 2 — Init → 2-Way (bidirectional visibility confirmed)

**Trigger:** our own Router ID appears inside the neighbour's Hello packet.

OSPF Hellos carry a list of Router IDs the sender has already heard from. Once the neighbour includes our RID in that list, we have proof the link is bidirectional:

```python
if n.state == St.INIT and self.rid in (h.neighbors or []):
    self._trans(n, St.TWO_WAY)
    self._exstart(n)
```

This is also where the **DR election** begins. Every Hello we send advertises `prio=255` (maximum) and claims both the DR and BDR fields as our own IP. Since no other router can outbid 255, we win the election by default.

---

## Step 3 — 2-Way → ExStart (Master/Slave negotiation)

**Trigger:** `_exstart` is called immediately after reaching 2-Way.

ExStart opens the Database Exchange process. Its only goal is to agree on who is **Master** (controls the DD sequence number) and who is **Slave** (echoes it). The rule from RFC 2328: the router with the numerically higher Router ID is Master.

We always open by claiming Master, sending a DBDesc with all three control bits set:

```python
self._send(self._dbd(n, init=True, more=True, ms=True, seq=n.seq), dst=n.ip)
```

The three flag bits in `dbdescr`:

| Bit | Name | Meaning |
|-----|------|---------|
| `0x04` | I (Init) | This is the first DBDesc of the exchange |
| `0x02` | M (More) | More DBDesc packets to follow |
| `0x01` | MS (Master) | Sender claims to be Master |

When the reply arrives in `_on_dbd`, we compare Router IDs with `rid_gt()`:

- **Neighbour wins (higher RID):** we flip `n.master = False`, echo their sequence number back with MS=0, and move to Exchange as Slave.
- **We win (higher RID):** we wait for the neighbour to acknowledge by sending a DBDesc with MS=0 that echoes our sequence number. Once seen, we move to Exchange as Master.

---

## Step 4 — ExStart → Exchange (LSDB summaries)

**Trigger:** Master/Slave agreement is reached in `_on_dbd`.

Both sides now send a DBDesc containing the **headers** (not full bodies) of every LSA in their database. This tells the other side what LSAs exist so it can request anything it is missing.

We send our LSDB summary in `_lsdb_summary`:

```python
self._send(self._dbd(n, ms=n.master, seq=n.seq, lsas=[self._rlsa()]), dst=n.ip)
```

Our database contains exactly one LSA — a self-originated **Router-LSA** (`_rlsa`) that describes our stub link. The M-bit is cleared, signalling this is our only DBDesc.

When a DBDesc arrives from the neighbour, `_unknown` walks its payload and collects headers for any LSAs we do not hold locally. These are queued in `n.reqs` for the Loading phase.

If the neighbour's M-bit is also clear (no more summaries coming):
- `n.reqs` is empty → skip Loading, jump straight to **Full**.
- `n.reqs` has entries → transition to **Loading**.

---

## Step 5 — Exchange → Loading (requesting missing LSAs)

**Trigger:** the neighbour's DBDesc summary referenced LSAs we don't have.

`_lsreq` builds an LSRequest packet listing every `(type, id, adv_router)` tuple collected during Exchange:

```python
for t, i, a in n.reqs:
    p = p / OSPF_LSReq(type=t, id=i, adrouter=a)
self._send(p, dst=n.ip)
```

The neighbour responds with an LSUpdate (`_on_lsupd`) containing the full LSA bodies. We acknowledge every received LSA with an LSAck, then clear `n.reqs`. With nothing left outstanding, the state advances to Full.

If the neighbour sends us an LSRequest instead (`_on_lsreq`), we respond with an LSUpdate carrying our Router-LSA — identical to what we flood at Full state.

---

## Step 6 — Loading → Full (adjacency complete)

**Trigger:** LSUpdate received with all outstanding requests satisfied.

```python
n.reqs.clear()
self._trans(n, St.FULL)
self._send(self._hdr(4) / OSPF_LSUpd(lsalist=[self._rlsa()]), dst=ALL_DR)
```

Once Full is reached, we flood our Router-LSA to `224.0.0.6` (AllDRouters multicast). Only the DR and BDR listen on this address. Because we won the DR election in Step 2, we receive and re-flood it ourselves — completing our role as the elected DR on the segment.

---

## DR Election Summary

The election happens passively through Hello parameters. Every Hello we send carries:

```python
prio=255          # maximum possible priority
router=self.src   # DR field: claiming ourselves
backup=self.src   # BDR field: claiming ourselves
```

RFC 2328 §9.4 states that the router with the highest priority wins. Setting `prio=255` guarantees no other router can outbid us. The DR and BDR IP fields in our Hello advertise our claim, and once neighbours accept it (no one contests with an equal or higher priority), the election is settled by the time we reach Full state.

---

## Packet Type Reference

| Type | Name | Used in state |
|------|------|---------------|
| 1 | Hello | Down → Init → 2-Way (continuous keepalive) |
| 2 | DBDesc (DBD) | ExStart → Exchange |
| 3 | LSRequest | Loading |
| 4 | LSUpdate | Loading (response) + Full (flood) |
| 5 | LSAck | Loading (acknowledge LSUpdates) |

---

## Running the Script

```bash
# Linux / macOS
sudo python3 ospf_full_adjacency.py

# Specify interface and area
sudo python3 ospf_full_adjacency.py --iface eth1 --area 0.0.0.1

# Windows (run as Administrator, Npcap required)
python3 ospf_full_adjacency.py --iface "Ethernet"

# Override Router ID and enable verbose packet output
sudo python3 ospf_full_adjacency.py --router-id 10.0.0.1 --verbose
```

| Flag | Default | Purpose |
|------|---------|---------|
| `--iface` | auto-detected | Interface to send/sniff on |
| `--router-id` | interface IP | OSPF Router ID advertised |
| `--area` | `0.0.0.0` | OSPF Area ID |
| `--mask` | `255.255.255.0` | Subnet mask in Hello |
| `--interval` | `10` | Hello interval in seconds |
| `--verbose` | off | Print full packet breakdown per send |

# 🛡️ 1. Define key objects

```cisco
conf t

object network INSIDE-NET
 subnet 10.0.0.0 255.255.255.0

object network DNS-SERVER
 host 10.0.0.53
```

---

# 🚫 2. Block ALL direct DNS to the internet (critical)

This prevents clients from bypassing your resolver (key for stopping tunneling).

```cisco
access-list OUTSIDE-IN extended deny udp any any eq 53
access-list OUTSIDE-IN extended deny tcp any any eq 53
```

Then allow everything else you explicitly need:

```cisco
access-list OUTSIDE-IN extended permit ip any any
```

Apply it:

```cisco
access-group OUTSIDE-IN in interface outside
```

---

# ✅ 3. Force clients to use ONLY internal DNS

Allow DNS only to your DNS server:

```cisco
access-list INSIDE-IN extended permit udp any host 10.0.0.53 eq 53
access-list INSIDE-IN extended permit tcp any host 10.0.0.53 eq 53
```

Block everything else DNS from inside:

```cisco
access-list INSIDE-IN extended deny udp any any eq 53
access-list INSIDE-IN extended deny tcp any any eq 53
access-list INSIDE-IN extended permit ip any any
```

Apply:

```cisco
access-group INSIDE-IN in interface inside
```

---

# 🔍 4. Enable DNS inspection (MPF)

This helps ASA understand DNS behavior and enforce sanity checks.

```cisco
policy-map global_policy
 class inspection_default
  inspect dns preset_dns_map
```

Enable global policy:

```cisco
service-policy global_policy global
```

---

# ⚙️ 5. Strengthen DNS inspection (anti-tunneling behavior control)

Create a stricter DNS inspection map:

```cisco
policy-map DNS-POLICY
 class class-default
  inspect dns maximum-length 512
  inspect dns log
```

Apply it globally or to inside:

```cisco
service-policy DNS-POLICY interface inside
```

---

# 📊 6. Enable logging (very important for detection)

```cisco
logging enable
logging buffered warnings
logging trap warnings
logging console warnings
```

Optional remote SIEM logging:

```cisco
logging host inside 10.0.0.100
logging facility 16
```

---

# 🚨 7. Add DNS anomaly protection via rate limiting (basic ASA approach)

ASA doesn’t do full DNS entropy detection, but you can reduce abuse impact:

```cisco
threat-detection basic-threat
threat-detection statistics host
```

Enable:

```cisco
threat-detection scanning-threat
```

---

# 🌐 8. Restrict outbound traffic (important for C2 blocking)

Only allow necessary outbound traffic, not “any any”.

Example:

```cisco
access-list INSIDE-OUT extended permit ip 10.0.0.0 255.255.255.0 any
access-group INSIDE-OUT out interface inside
```

But better (tighter):

```cisco
access-list INSIDE-OUT extended permit tcp any any eq 80
access-list INSIDE-OUT extended permit tcp any any eq 443
access-list INSIDE-OUT extended permit udp any host 10.0.0.53 eq 53
access-list INSIDE-OUT extended deny udp any any eq 53
```

---

# 🧱 9. Block known DNS tunneling domains (like your PoC)

```cisco
access-list INSIDE-IN extended deny tcp any host cwmkaeg.duckdns.org eq 53
access-list INSIDE-IN extended deny udp any host cwmkaeg.duckdns.org eq 53
```

(You can generalize this using DNS filtering upstream instead.)

---

# 🔐 10. Optional: DNS rewrite / redirect (strong control)

Force all DNS to internal resolver (even if user manually sets 8.8.8.8):

```cisco
nat (inside,outside) source static any DNS-SERVER destination static any DNS-SERVER service udp 53 53
nat (inside,outside) source static any DNS-SERVER destination static any DNS-SERVER service tcp 53 53
```

---

# 🧪 11. Verification commands

Check ACL hits:

```cisco
show access-list
```

Check DNS inspection:

```cisco
show service-policy
```

Check logs:

```cisco
show logging
```

# S1 and S2 - OSPF Authentication

On every OSPF transit interface:

```cisco
router ospf 1
 router-id 1.1.1.1
```

S1:

```cisco
interface Gi0/1
 ip ospf authentication message-digest
 ip ospf message-digest-key 1 md5 CISCO123
```

S2:

```cisco
interface Gi0/1
 ip ospf authentication message-digest
 ip ospf message-digest-key 1 md5 CISCO123
```

Verify:

```cisco
show ip ospf neighbor
```

Result:

```text
Neighbor State = FULL
```

Attacker without key:

```text
No adjacency formed
```

---

# S1 and S2 - Passive Interfaces

Prevent clients from becoming OSPF neighbors.

```cisco
router ospf 1

 passive-interface default

 no passive-interface Gi0/1
 no passive-interface Gi0/2
```

Where:

```text
Gi0/1 = S1-S2 link
Gi0/2 = Router uplink
```

User VLAN interfaces remain passive.

Verify:

```cisco
show ip protocols
```

---

# S1 and S2 - Route Filtering

Accept only known routes.

```cisco
ip prefix-list VALID_ROUTES seq 5 permit 192.168.1.0/24
ip prefix-list VALID_ROUTES seq 10 permit 10.10.10.0/24
```

```cisco
router ospf 1
 distribute-list prefix VALID_ROUTES in
```

Result:

```text
Malicious OSPF routes rejected
```

---

# DHCP Snooping

Globally:

```cisco
ip dhcp snooping

ip dhcp snooping vlan 10,20
```

---

# Trust Only DHCP Server Port

If DHCP server is connected to Gi0/24:

```cisco
interface Gi0/24
 ip dhcp snooping trust
```

Everything else remains untrusted.

---

# Limit DHCP Packets

User ports:

```cisco
interface range Gi0/1-23

 ip dhcp snooping limit rate 10
```

Result:

```text
Rogue DHCP offers dropped
DHCP starvation mitigated
```

---

# Dynamic ARP Inspection

Uses DHCP Snooping database.

```cisco
ip arp inspection vlan 10,20
```

Trust uplinks:

```cisco
interface Gi0/24
 ip arp inspection trust
```

Verify:

```cisco
show ip arp inspection
```

---

# IP Source Guard

User-facing ports:

```cisco
interface range Gi0/1-23

 ip verify source
```

Result:

```text
Host cannot spoof another IP
```

---

# Port Security

User-facing interfaces:

```cisco
interface range Gi0/1-23

 switchport mode access

 switchport port-security

 switchport port-security maximum 1

 switchport port-security mac-address sticky

 switchport port-security violation shutdown
```

Verify:

```cisco
show port-security
```

---

# BPDU Guard

Stops rogue switches.

```cisco
spanning-tree portfast default

spanning-tree portfast bpduguard default
```

---

# DHCP Attack Detection Commands

```cisco
show ip dhcp snooping

show ip dhcp snooping binding
```

You should see:

```text
Trusted ports
Binding table
Dropped DHCP packets
```

---

# OSPF Attack Detection Commands

```cisco
show ip ospf neighbor

show ip ospf database

show ip route ospf
```

Before attack:

```text
Known neighbors only
```

Attack attempt:

```text
Neighbor fails authentication
```

---

# TunnelVision-Specific Defense

If you are using DHCP Option 121 for the demo:

Monitor:

```cisco
debug ip dhcp server packet
```

and ensure DHCP pools only advertise:

```cisco
default-router
dns-server
```


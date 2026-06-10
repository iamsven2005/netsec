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


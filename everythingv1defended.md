S1

en
conf t

ip dhcp snooping
ip dhcp snooping vlan 10,20,30,40

interface g1/0/24
 ip dhcp snooping trust

end






DSW1

en
conf t

router ospf 1
 area 0 authentication message-digest
 passive-interface default
 no passive-interface g1/0/1

interface g1/0/1
 ip ospf message-digest-key 1 md5 CISCO123

interface vlan10
 ip ospf message-digest-key 1 md5 CISCO123

interface vlan20
 ip ospf message-digest-key 1 md5 CISCO123

interface vlan30
 ip ospf message-digest-key 1 md5 CISCO123

interface vlan40
 ip ospf message-digest-key 1 md5 CISCO123


ip dhcp snooping
ip dhcp snooping vlan 10,20,30,40

interface g1/0/2
 ip dhcp snooping trust

interface g1/0/24
 ip dhcp snooping trust
end






R1

en
conf t

router ospf 1
 area 0 authentication message-digest

interface g0/1/0
 ip ospf message-digest-key 1 md5 CISCO123

end





show ip dhcp snooping
show ip dhcp snooping binding
show ip dhcp snooping statistics
show ip dhcp snooping database

show ip ospf neighbor























S1

en
conf t

interface g1/0/24
 no ip dhcp snooping trust

no ip dhcp snooping vlan 10,20,30,40
no ip dhcp snooping

end




DSW1

en
conf t


router ospf 1
 no area 0 authentication message-digest
 no passive-interface default

interface g1/0/1
 no ip ospf message-digest-key 1 md5 CISCO123

interface Vlan10
 no ip ospf message-digest-key 1 md5 CISCO123

interface Vlan20
 no ip ospf message-digest-key 1 md5 CISCO123

interface Vlan30
 no ip ospf message-digest-key 1 md5 CISCO123

interface Vlan40
 no ip ospf message-digest-key 1 md5 CISCO123



interface g1/0/2
 no ip dhcp snooping trust

interface g1/0/24
 no ip dhcp snooping trust

no ip dhcp snooping vlan 10,20,30,40
no ip dhcp snooping

end





R1

en
conf t

router ospf 1
 no area 0 authentication message-digest

interface g0/1/0
 no ip ospf message-digest-key 1 md5 CISCO123

end

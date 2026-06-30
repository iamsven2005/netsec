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

! Static host routes for critical infrastructure
ip route 192.168.100.6 255.255.255.255 192.168.100.6
ip route 192.168.100.1 255.255.255.255 10.10.10.6


ip dhcp snooping
ip dhcp snooping vlan 10,20,30,40


interface g1/0/24
 ip dhcp snooping trust
end






R1

en
conf t

router ospf 1
 area 0 authentication message-digest
 passive-interface default
 no passive-interface g0/1/0

interface g0/1/0
 ip ospf message-digest-key 1 md5 CISCO123

! Static host routes for critical infrastructure
ip route 192.168.100.6 255.255.255.255 10.10.10.5
ip route 192.168.100.1 255.255.255.255 192.168.100.1

end


R2
en
conf t
Ip dhcp relay information trust-all
end


show ip dhcp snooping
show ip dhcp snooping binding
show ip dhcp snooping statistics
show ip dhcp snooping database

show ip ospf neighbor















-- NO defences --







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

no ip route 192.168.100.6 255.255.255.255 192.168.100.6
no ip route 192.168.100.1 255.255.255.255 10.10.10.6




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
 no passive-interface default

interface g0/1/0
 no ip ospf message-digest-key 1 md5 CISCO123

no ip route 192.168.100.6 255.255.255.255 10.10.10.5
no ip route 192.168.100.1 255.255.255.255 192.168.100.1

end

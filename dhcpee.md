# DHCP Router Spoofing and Taking Over

The following program lets the device takeover the
DHCP server via IP Spoofing and becoming the DHCP
server itself

# How the takeover happens

The following steps have to occur for the DHCP takeover
to be success:

1. Forces trunk with a switchport by sending DTP packet.
2. Sniffs for PVST+ packets to discover the VLAns
   ~ Additionally, starts a thread to send DTP packets every 10s
3. Maps the VLANs discovered as well as their IP addresses.
4. Sends out DHCPDiscover packets with the corresponding VLAN tags
5. Starts a DHCPOffer sniffer thread to collect relevant information
6. Checks for the operating system that program is on
7. Removes all IP addresses previously set on the interface
8. Uses information collected to spoof DHCP server IP address
9. Start sniffing for DHCPDiscover and DHCPRequest packets
10. Returns an addresses and saves that address under "Used" so that there are no duplicates

# Tested Scenario

The program has been tested on the following topology with these tests:

- Restarted both laptops to test for proper IP address leasing
- Checking if DTP is still up

```
R1 --- DSW1 --- DSW2
|     /  |        |
|    ME PC A     PC B
DHCP
```

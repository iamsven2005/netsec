Q - For this case, lets assume the dhcp ip helpers on each vlan interface is pointing to the service-ip address aka the dhcp server ip address. The DHCP server is trunked to the L3 switch it is connected to so that it can respond to the DHCP request packets sent by each helper. And I added a route via our program in OSPF for the DHCP IP helpers to point to us. Will the DHCP server on our host be able to respond to the DHCP IP helpers and give the hosts an IP address?


A - Yes, in the design you described, it should work.

The important correction is: it works because of the DHCP relay path, not because the server is trunked by itself.

The packet flow is:

1. Client sends `DHCP Discover` as a broadcast on its VLAN.
2. The L3 switch SVI receives it.
3. `ip helper-address <service-ip>` makes the switch relay it as a unicast packet to your DHCP server.
4. OSPF routes that `service-ip` traffic toward your host.
5. Your DHCP server receives the relayed request, looks at `giaddr`, picks the right scope, and sends `Offer/Ack` back to the relay.
6. The relay forwards that reply to the client VLAN.
7. The client gets its lease.

So yes, your host can give the clients IP addresses if all of these are true:

- the `service-ip` is configured locally on your host
- your OSPF-injected `/32` route to that `service-ip` is installed by the routers
- each VLAN SVI helper-address points to that `service-ip`
- your DHCP server supports relayed DHCP
- your DHCP scopes match the relay `giaddr` subnets
- your host can route replies back to the relay IPs
- firewall allows DHCP traffic, especially UDP `67`

What is not required:
- your host does not need to directly receive client broadcasts from every VLAN
- your host does not need to be Layer-2 present in every client VLAN
- the trunk is not what makes relayed DHCP work

What the trunk does help with:
- carrying the VLAN/interface you use for OSPF connectivity to the L3 switch
- optionally carrying a server-facing VLAN if that is how your host reaches the switch

So in your exact setup, the safe conclusion is:

- if helper-addresses point to your `service-ip`
- and OSPF makes that `service-ip` reachable through your host
- and the DHCP server is correctly configured for relayed requests

then yes, the DHCP server on your host should be able to respond and clients should get leases.

One subtle note:
if you already rely on DHCP relay, you usually do not need the host to be trunked for every client VLAN. A simple routed path to the switch is enough. The relay handles the per-VLAN broadcast side.

Yes, you can still serve clients from a different VLAN, but only if the relay design already points traffic to you when the other server is down.

The key point is that DHCP clients do not need to be in your VLAN. The relay on each SVI receives the client broadcast, converts it to unicast, and sends it to the configured helper address or addresses. So being in a different VLAN is fine.

What decides whether you still work after the other server fails:

If the ip helper-address is configured only to the other DHCP server, then no. Clients will fail when that server is down.
If the ip helper-address includes your DHCP server IP as well, then yes, you can still serve clients from your VLAN.
If the network reroutes a shared service IP to you after the other host fails, then yes, that can also work, but failover timing matters.
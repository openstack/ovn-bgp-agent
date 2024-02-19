Traffic Redirection to/from OVN
+++++++++++++++++++++++++++++++

Besides the VM/LB IP being exposed in a specific node (either the one hosting
the VM/LB or the one with the OVN router gateway port), the OVN BGP Agent is in
charge of configuring the linux kernel networking and OVS so that the traffic
can be injected into the OVN overlay, and vice versa. To do that, when the
agent starts, it ensures that:

- ARP/NDP is enabled on OVS provider bridges by adding an IP to it

- There is a routing table associated to each OVS provider bridge
  (adds entry at /etc/iproute2/rt_tables)

- If the provider network is a VLAN network, a VLAN device connected
  to the bridge is created, and it has ARP and NDP enabled.

- Cleans up extra OVS flows at the OVS provider bridges

Then, either upon events or due to (re)sync (regularly or during start up), it:

- Adds an IP rule to apply specific routing table routes,
  in this case the one associated to the OVS provider bridge:

     .. code-block:: ini

      $ ip rule
      0:      from all lookup local
      1000:   from all lookup [l3mdev-table]
      *32000:  from all to IP lookup br-ex*  # br-ex is the OVS provider bridge
      *32000:  from all to CIDR lookup br-ex*  # for VMs in tenant networks
      32766:  from all lookup main
      32767:  from all lookup default


- Adds an IP route at the OVS provider bridge routing table so that the traffic is
  routed to the OVS provider bridge device:

     .. code-block:: ini

      $ ip route show table br-ex
      default dev br-ex scope link
      *CIDR via CR-LRP_IP dev br-ex*  # for VMs in tenant networks
      *CR-LRP_IP dev br-ex scope link*  # for the VM in tenant network redirection
      *IP dev br-ex scope link*  # IPs on provider or FIPs


- Adds a static ARP entry for the OVN Distributed Gateway Ports (cr-lrps) so
  that the traffic is steered to OVN via br-int -- this is because OVN does
  not reply to ARP requests outside its L2 network:

     .. code-block:: ini

      $ ip neigh
      ...
      CR-LRP_IP dev br-ex lladdr CR-LRP_MAC PERMANENT
      ...


- For IPv6, instead of the static ARP entry, an NDP proxy is added, same
  reasoning:

       .. code-block:: ini

        $ ip -6 neigh add proxy CR-LRP_IP dev br-ex


- Finally, in order for properly send the traffic out from the OVN overlay
  to kernel networking to be sent out of the node, the OVN BGP Agent needs
  to add a new flow at the OVS provider bridges so that the destination MAC
  address is changed to the MAC address of the OVS provider bridge
  (``actions=mod_dl_dst:OVN_PROVIDER_BRIDGE_MAC,NORMAL``):

       .. code-block:: ini

        $ sudo ovs-ofctl dump-flows br-ex
        cookie=0x3e7, duration=77.949s, table=0, n_packets=0, n_bytes=0, priority=900,ip,in_port="patch-provnet-1" actions=mod_dl_dst:3a:f7:e9:54:e8:4d,NORMAL
        cookie=0x3e7, duration=77.937s, table=0, n_packets=0, n_bytes=0, priority=900,ipv6,in_port="patch-provnet-1" actions=mod_dl_dst:3a:f7:e9:54:e8:4d,NORMAL

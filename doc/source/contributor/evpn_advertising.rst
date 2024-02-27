EVPN Advertisement (expose method ``vrf``)
++++++++++++++++++++++++++++++++++++++++++

When using expose method ``vrf``, the OVN BGP Agent is in charge of triggering
FRR (IP routing protocol suite for Linux which includes protocol daemons for
BGP, OSPF, RIP, among others) to advertise/withdraw directly connected and
kernel routes via BGP.

To do that, when the agent starts, it will search for all provider networks
and configure them.

In order to expose a provider network, each provider network must match these
criteria:

- The provider network can be matched to the bridge mappings as defined in the
  running OpenVSwitch instance (e.g. ``ovn-bridge-mappings="physnet1:br-ex"``)

- The provider network has been configured by an admin with at least a ``vni``,
  and the vpn type has been configured too with value ``l3``.

  For example (when using the OVN tools):

  .. code-block:: bash

    $ ovn-nbctl set logical-switch neutron-cd5d6fa7-3ed7-452b-8ce9-1490e2d377c8 external_ids:"neutron_bgpvpn\:type"=l3
    $ ovn-nbctl set logical-switch neutron-cd5d6fa7-3ed7-452b-8ce9-1490e2d377c8 external_ids:"neutron_bgpvpn\:vni"=100
    $ ovn-nbctl list logical-switch | less
    ...
    external_ids        : {.. "neutron_bgpvpn:type"=l3, "neutron_bgpvpn:vni"="1001" ..}
    name                : neutron-cd5d6fa7-3ed7-452b-8ce9-1490e2d377c8
    ...

  It is also possible to configure this using the Neutron BGP VPN API.

Initialization sequence per VRF
'''''''''''''''''''''''''''''''

Once the networks have been initialized, the driver waits for the first ip to be
exposed, before actually exposing the VRF on the host.

Once a VRF is exposed on the host, the following will be done (per VRF):

1. Create EVPN related devices

   - Create VRF device, using the VNI number as name suffix: vrf-1001

     .. code-block:: bash

       $ ip link add vrf-1001 type vrf table 1001

   - Create the VXLAN device, using the VNI number as the vxlan id, as well as
     for the name suffix: vxlan-1001

     .. code-block:: bash

       $ ip link add vxlan-1001 type vxlan id 1001 dstport 4789 local LOOPBACK_IP nolearning

   - Create the Bridge device, where the vxlan device is connected, and
     associate it to the created vrf, also using the VNI number as name suffix:
     br-1001

     .. code-block:: bash

       $ ip link add name br-1001 type bridge stp_state 0
       $ ip link set br-1001 master vrf-1001
       $ ip link set vxlan-1001 master br-1001

2. Reconfigure local FRR instance (``frr.conf``) to ensure the new VRF is
   exposed. To do that it uses ``vtysh shell``. It connects to the existing
   FRR socket (--vty_socket option) and executes the next commands, passing
   them through a file (-c FILE_NAME option):

   .. code-block:: jinja

     vrf {{ vrf_name }}
         vni {{ vni }}
     exit-vrf
     router bgp {{ bgp_as }} vrf {{ vrf_name }}
       bgp router-id {{ bgp_router_id }}
       address-family ipv4 unicast
       redistribute connected
       redistribute kernel
       exit-address-family

       address-family ipv6 unicast
         redistribute connected
         redistribute kernel
       exit-address-family
       address-family l2vpn evpn
         advertise ipv4 unicast
         advertise ipv6 unicast
         rd {{ local_ip }}:{{ vni }}
       exit-address-family

3. Connect EVPN to OVN overlay so that traffic can be redirected from the node
   to the OVN virtual networking. It needs to connect the VRF to the OVS
   provider bridge:

   - Create a veth device, that will be used for routing between the vrf and
     OVN, using the uuid of the localnet port in the logical-switch-port table
     and connect it to ovs (in this example the uuid of the localnet port is
     ``12345678-1234-1234-1234-123456789012``, and the first 11 chars will
     be used in the interface name):

     .. code-block:: bash

       $ ip link add name vrf12345678-12 type veth peer name ovs12345678-12
       $ ovs-vsctl add-port br-ex ovs12345678-12
       $ ip link set up dev ovs12345678-12

   - For EVPN l3 mode (only supported mode currently), it will attach the vrf
     side to the vrf:

     .. code-block:: bash

       $ ip link set vrf12345678-12 master vrf-1001
       $ ip link set up dev vrf12345678-12

     And it will add routing IPs on the veth interface, so the kernel is able
     to do L3 routing within the VRF. By default it will add a 169.254.x.x
     address based on the VNI/VLAN.

     If possible it will use the dhcp options to determine if it can use an
     actually configured router ip address, in addition to the 169.254.x.x
     address:

     .. code-block:: bash

       $ ip address add 10.0.0.1/32 dev vrf12345678-12  # router option from dhcp opts
       $ ip address add 169.254.0.123/32 dev vrf12345678-12  # generated 169.254.x.x address for vlan 123
       $ ip -6 address add fd53:d91e:400:7f17::7b/128 dev vrf12345678-12  # generated ipv6 address for vlan 123

4. Add needed OVS flows into the OVS provider bridge (e.g., br-ex) to redirect
   the traffic back from OVN to the proper VRF, based on the subnet CIDR and
   the router gateway port MAC address.

   .. code-block:: bash

      $ ovs-ofctl add-flow br-ex cookie=0x3e7,priority=900,ip,in_port=<OVN_PATCH_PORT_ID>,actions=mod_dl_dst:VETH|VLAN_MAC,NORMAL

5. If ``CONF.anycast_evpn_gateway_mode`` is enabled, it will make sure that the
   mac address on the vrf12345678-12 interface is equal on all nodes, using the
   VLAN id and VNI id as an offset while generating a MAC address.

   .. code-block:: bash

     $ ip link set address 02:00:03:e7:00:7b dev vrf12345678-12  # generated mac for vni 1001 and vlan 123

     # Replace link local address and update to generated vlan mac (used for ipv6 router advertisements)
     $ ip -6 address del <some fe80::/10 address> dev vrf12345678-12
     $ ip -6 address add fe80::200:3e7:65/64 dev vrf12345678-12

6. If IPv6 subnets are defined (checked in dhcp opts once again), then configure
   FRR to handle neighbor discovery (and do router advertisements for us)

   .. code-block:: jinja

     interface {{ vrf_intf }}
      {% if is_dhcpv6 %}
      ipv6 nd managed-config-flag
      {% endif %}
      {% for server in dns_servers %}
      ipv6 nd rdnss {{ server }}
      {% endfor %}
      ipv6 nd prefix {{ prefix }}
      no ipv6 nd suppress-ra
     exit

7. Then, finally, add the routes to expose to the VRF, since we use full
   kernel routing in this VRF, we also expose the MAC address that belongs
   to this route, so we do not rely on ARP proxies in OVN.

   .. code-block:: bash

     $ ip route add 10.0.0.5/32 dev vrf12345678-12
     $ ip route show table 1001 | grep veth
     local 10.0.0.1 dev vrf12345678-12 proto kernel scope host src 10.0.0.1
     10.0.0.5 dev vrf12345678-12 scope link
     local 169.254.0.123 dev vrf12345678-12 proto kernel scope host src 169.254.0.123

     $ ip neigh add 10.0.0.5 dev vrf12345678-12 lladdr fa:16:3e:7d:50:ad nud permanent
     $ ip neigh show vrf vrf-100 | grep veth
     10.0.0.5 dev vrf12345678-12 lladdr fa:16:3e:7d:50:ad PERMANENT
     fe80::f816:3eff:fe7d:50ad dev vrf12345678-12 lladdr fa:16:3e:7d:50:ad STALE


.. note::

  The VRF is not associated to one OpenStack tenant, but can be mixed with
  other provider networks too. When using VLAN provider networks, one can
  connect multiple networks to the same VNI, effectively placing them in the
  same VRF, routed and handled through kernel and FRR.

.. note::
  As we also want to be able to expose VM connected to tenant networks
  (when ``expose_tenant_networks`` or ``expose_ipv6_gua_tenant_networks``
  configuration options are enabled), there is a need to expose the Neutron
  router gateway port (cr-lrp on OVN) so that the traffic to VMs in tenant
  networks is injected into OVN overlay through the node that is hosting
  that port.

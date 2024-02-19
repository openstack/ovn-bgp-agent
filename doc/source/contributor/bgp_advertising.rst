BGP Advertisement
+++++++++++++++++

The OVN BGP Agent (both SB and NB drivers) is in charge of triggering FRR
(IP routing protocol suite for Linux which includes protocol daemons for BGP,
OSPF, RIP, among others) to advertise/withdraw directly connected routes via
BGP. To do that, when the agent starts, it ensures that:

- FRR local instance is reconfigured to leak routes for a new VRF. To do that
  it uses ``vtysh shell``. It connects to the existsing FRR socket (
  ``--vty_socket`` option) and executes the next commands, passing them through
  a file (``-c FILE_NAME`` option):

   .. code-block:: ini

        router bgp {{ bgp_as }}
          address-family ipv4 unicast
            import vrf {{ vrf_name }}
          exit-address-family

          address-family ipv6 unicast
            import vrf {{ vrf_name }}
          exit-address-family

        router bgp {{ bgp_as }} vrf {{ vrf_name }}
          bgp router-id {{ bgp_router_id }}
          address-family ipv4 unicast
            redistribute connected
          exit-address-family

          address-family ipv6 unicast
            redistribute connected
          exit-address-family


- There is a VRF created (the one leaked in the previous step), by default
  with name ``bgp-vrf``.

- There is a dummy interface type (by default named ``bgp-nic``), associated to
  the previously created VRF device.

- Ensure ARP/NDP is enabled at OVS provider bridges by adding an IP to it.


Then, to expose the VMs/LB IPs as they are created (or upon
initialization or re-sync), since the FRR configuration has the
``redistribute connected`` option enabled, the only action needed to expose it
(or withdraw it) is to add it (or remove it) from the ``bgp-nic`` dummy interface.
Then it relies on Zebra to do the BGP advertisement, as Zebra detects the
addition/deletion of the IP on the local interface and advertises/withdraws
the route:

   .. code-block:: ini

        $ ip addr add IPv4/32 dev bgp-nic
        $ ip addr add IPv6/128 dev bgp-nic


 .. note::

     As we also want to be able to expose VM connected to tenant networks
     (when ``expose_tenant_networks`` or ``expose_ipv6_gua_tenant_networks``
     configuration options are enabled), there is a need to expose the Neutron
     router gateway port (cr-lrp on OVN) so that the traffic to VMs in tenant
     networks is injected into OVN overlay through the node that is hosting
     that port.
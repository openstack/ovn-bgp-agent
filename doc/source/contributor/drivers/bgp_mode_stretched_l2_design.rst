..
      This work is licensed under a Creative Commons Attribution 3.0 Unported
      License.

      http://creativecommons.org/licenses/by/3.0/legalcode

      Convention for heading levels in Neutron devref:
      =======  Heading 0 (reserved for the title in a document)
      -------  Heading 1
      ~~~~~~~  Heading 2
      +++++++  Heading 3
      '''''''  Heading 4
      (Avoid deeper levels because they do not render well.)

====================================================
OVN BGP Agent: Design of the stretched L2 BGP Driver
====================================================

Purpose
-------

The main reason for adding the L2 BGP driver is to announce networks via BGP
that are not masqueraded (SNAT disabled) and can communicate directly via
routing. The driver requires that all routers to be announced are in a L2
provider network and that the BGP Neighbor and Speaker are also part of this
network. The whole tenant networks are announced via the external gateway IP
of the router, instead of as /32 (or /128 for IPv6). This means that the
tenant networks can be routed directly via the router IP and failover can run
completely via BFD in OVN. No additional BGP announcements are needed incase
of failover of routers, but only ARP/GARP in the respective L2 network.

The resulting routes are the same on all instances of the ovn-bgp-agent and
are not bound to the machine the agent is running on. For redundancy reasons
it is recommended to run multiple instances.

Overview
--------

The OVN BGP Agent is a Python-based daemon that can run on any node. However,
it is recommended to run the L2 BGP driver on the gateway node since all
requirements are already met there, e.g. connectivity to the L2 provider
network. The driver connects to the OVN SouthBound database (OVN SB DB) for
all information and responds to events via it. It uses a VRF to create the
routes locally and FRR to announce them to the BGP peer. The VRF is completely
isolated and is not used for anything else than announcing routes via FRR.
The tenant routers/networks cannot be reached from the VRF either.

 .. note::

     Note it is only intended for the N/S traffic, the E/W traffic will work
     exactly the same as before, i.e., VMs are connected through geneve
     tunnels.


The agent provides a multi-driver implementation that allows you to configure
it for specific infrastructure running on top of OVN, for instance OpenStack
or Kubernetes/OpenShift.
This simple design allows the agent to implement different drivers, depending
on what OVN SB DB events are being watched (watchers examples at
``ovn_bgp_agent/drivers/openstack/watchers/``), and what actions are
triggered in reaction to them (drivers examples at
``ovn_bgp_agent/drivers/openstack/XXXX_driver.py``, implementing the
``ovn_bgp_agent/drivers/driver_api.py``).

A common driver API is defined exposing the next methods:

- ``expose_ip`` and ``withdraw_ip``: used to expose/withdraw IPs/Networks for
  OVN ports.

- ``expose_subnet``, ``update_subnet`` and ``withdraw_subnet``: used to
  expose/withdraw subnets through the external router gateway ip.

OVN SB DB Events
~~~~~~~~~~~~~~~~

The watcher associated to this BGP driver detect the relevant events on the
OVN SB DB to call the driver functions to configure BGP and linux kernel
networking accordingly.

The BGP watcher detects OVN Southbound Database events at the ``Port_Binding``
and ``Load_Balancer`` tables. It creates new event classes named
``PortBindingChassisEvent`` and ``OVNLBEvent``, that all the events
watched for BGP use as the base (inherit from).

The driver react specifically to the following events:

- ``PortBindingChassisCreatedEvent``: Detects when a port of type
  ``""`` (empty double-qoutes), ``virtual``, or ``chassisredirect`` gets
  attached to the OVN chassis where the agent is running. This is the case for
  VM or amphora LB ports on the provider networks, VM or amphora LB ports on
  tenant networks with a FIP associated, and neutron gateway router ports
  (cr-lrps). It calls ``expose_ip`` driver method to perform the needed
  actions to expose it.

- ``PortBindingChassisDeletedEvent``: Detects when a port of type
  ``""`` (empty double-quotes), ``virtual``, or ``chassisredirect`` gets
  detached from the OVN chassis where the agent is running. This is the case
  for VM or amphora LB ports on the provider networks, VM or amphora LB ports
  on tenant networks with a FIP associated, and neutron gateway router ports
  (cr-lrps). It calls ``withdraw_ip`` driver method to perform the needed
  actions to withdraw the exposed BGP route.

- ``SubnetRouterAttachedEvent``: Detects when a patch port gets created.
  This means a subnet is attached to a router. If this port is associated to
  a cr-lrp port, the subnet will get announced.

- ``SubnetRouterDetachedEvent``: Same as previous one, but for the deletion
  of the port. It calls ``withdraw_subnet``.

- ``SubnetRouterUpdateEvent``: Detects when a subnet/IP is added to an
  existing patch port. This can happen when multiple subnets are generated
  from an address pool and added to the same router.
  It calls ``update_subnet``.

Driver Logic
~~~~~~~~~~~~

The stretched L2 BGP driver is responsible for announcing all tenant networks
that match the corresponding address scope (if used for filtering subnets).
If the config option ``address_scopes`` is not set, all tenant networks will
be announced via the corresponding provider network router IP.

BGP Advertisement
+++++++++++++++++

The OVN BGP Agent is in charge of triggering FRR (IP routing protocol
suite for Linux which includes protocol daemons for BGP, OSPF, RIP,
among others) to advertise/withdraw directly connected routes via BGP.
To do that, when the agent starts, it ensures that:

- FRR local instance is reconfigured to leak routes for a new VRF. To do that
  it uses ``vtysh shell``. It connects to the existing FRR socket (
  ``--vty_socket`` option) and executes the next commands, passing them through
  a file (``-c FILE_NAME`` option):

   .. code-block:: ini

        LEAK_VRF_TEMPLATE = '''
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
            redistribute kernel
          exit-address-family

          address-family ipv6 unicast
            redistribute kernel
          exit-address-family

        '''


- There is a VRF created (the one leaked in the previous step) by default
  with name ``bgp_vrf``.

- There is a dummy interface type (by default named ``bgp-nic``), associated to
  the previously created VRF device.


Then, to expose the tenant networks as they are created (or upon
initialization or re-sync), since the FRR configuration has the
``redistribute kernel`` option enabled, the only action needed to
expose/withdraw the tenant networks is to add/remove the routes in
the ``bgp_vrf_table_id`` table. Then it relies on Zebra to do the BGP
advertisement, as Zebra detects the addition/deletion of the routes in the
table and advertises/withdraw the route. In order to add these routes we have
to make the Linux kernel believe that it can reach the respective router IPs.
For this we use link-local routes pointing to the interface of the VRF. If we
use the provider network ``111.111.111.0/24``, a router with the IP
``111.111.111.17/24`` on the gateway port and the tenant subnet ``192.168.0.0/24``,
the route would be added like this (same logic applies to IPv6):

   .. code-block:: ini

        $ ip route add 111.111.111.0/24 dev bgp-nic table 10
        $ ip route add 192.168.0.0/24 via 111.111.111.17 table 10


 .. note::

     The link-local route for the provider network is also announced and is
     only removed when no router to be announced has a gateway port on the
     network. Since all BGP peers should also be on this network, the BGP
     neighbor will prefer its connected route over the announced link-local
     route.

On the BGP neighbor side, the route should look like this:

   .. code-block:: ini

        $ ip route show 
        192.168.0.0/24 via 111.111.111.17

Driver API
++++++++++

The BGP driver needs to implement the ``driver_api.py`` interface with the
following functions:

- ``expose_ip``: Creates the routes for all tenant networks and announces
  them via FRR. If no subnets are connected to this port, nothing is
  announced.

- ``withdraw_ip``: Removes all routes for the tenant networks and withdraws
  them from FRR.

- ``expose_subnet``: Announces the tenant network via the router IP if this
  router has an external gateway port.

- ``withdraw_subnet``: Withdraws the tenant network if this
  router has an external gateway port.

- ``update_subnet``: Does the same as ``expose_subnet`` / ``withdraw_subnet``
  and is called when a subnet is added or removed from the port.


Agent deployment
~~~~~~~~~~~~~~~~

The agent can be deployed anywhere as long as it is in the respective L2
network that is to be announced. In addition, OVS agent must be installed on
the machine (from which it reads SB DB address) and it must be possible to
connect to the Southbound Database. The L2 network can be filtered via the
address scope, so it is not necessary that the agent has access to all L2
provider networks, but only the one in which it is to peer. Unlike the
``ovn_bgp_driver``, it announces all routes regardless of which chassis they
are on.

As an example of how to start the OVN BGP Agent on the nodes, see the commands
below:

   .. code-block:: ini

      $ python setup.py install
      $ cat bgp-agent.conf
      # sample configuration that can be adapted based on needs
      [DEFAULT]
      debug=True
      reconcile_interval=120
      driver=ovn_stretched_l2_bgp_driver
      address_scopes=2237917c7b12489a84de4ef384a2bcae

      $ sudo bgp-agent --config-dir bgp-agent.conf
      ....


Note that the OVN BGP Agent operates under the next assumptions:

- A dynamic routing solution, in this case FRR, is deployed and
  advertises/withdraws routes added/deleted to/from the vrf routing table.
  A sample config for FRR is:

   .. code-block:: ini

        frr version 7.0
        frr defaults traditional
        hostname cmp-1-0
        log file /var/log/frr/frr.log debugging
        log timestamp precision 3
        service integrated-vtysh-config
        line vty

        debug bgp neighbor-events
        debug bgp updates

        router bgp 64999
          bgp router-id 172.30.1.1
          neighbor pg peer-group
          neighbor 172.30.1.2 remote-as 64998
          address-family ipv6 unicast
            redistribute kernel
            neighbor pg activate
            neighbor pg route-map IMPORT in
            neighbor pg route-map EXPORT out
          exit-address-family

          address-family ipv4 unicast
            redistribute kernel
            neighbor pg activate
            neighbor pg route-map IMPORT in
            neighbor pg route-map EXPORT out
          exit-address-family

        route-map EXPORT deny 100

        route-map EXPORT permit 1
          match interface bgp-nic

        route-map IMPORT deny 1

        line vty

Limitations
-----------

- TBD
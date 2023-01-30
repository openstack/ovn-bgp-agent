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

=======================================
OVN BGP Agent: Design of the BGP Driver
=======================================

Purpose
-------

The purpose of this document is to present the design decision behind
the BGP Driver for the Networking OVN BGP agent.

The main purpose of adding support for BGP is to be able to expose Virtual
Machines (VMs) and Load Balancers (LBs) IPs through  BGP dynamic protocol
when they either have a Floating IP (FIP) associated or are booted/created
on a provider network -- also in tenant networks if a flag is enabled.


Overview
--------

With the increment of virtualized/containerized workloads it is becoming more
and more common to use pure layer-3 Spine and Leaf network deployments at
datacenters. There are several benefits of this, such as reduced complexity at
scale, reduced failures domains, limiting broadcast traffic, among others.

The OVN BGP Agent is a Python based daemon that runs on each node
(e.g., OpenStack controllers and/or compute nodes). It connects to the OVN
SouthBound DataBase (OVN SB DB) to detect the specific events it needs to
react to, and then leverages FRR to expose the routes towards the VMs, and
kernel networking capabilities to redirect the traffic arriving on the nodes
to the OVN overlay.

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

A driver implements the support for BGP capabilities. It ensures both VMs and
LBs on providers networks or with Floating IPs associated can be
exposed throug BGP. In addition, VMs on tenant networks can be also exposed
if the ``expose_tenant_network`` configuration option is enabled.
To control what tenant networks are exposed another flag can be used:
``address_scopes``. If not set, all the tenant networks will be exposed, while
if it is configured with a (set of) address_scopes, only the tenant networks
whose address_scope matches will be exposed.

A common driver API is defined exposing the next methods:

- ``expose_ip`` and ``withdraw_ip``: used to expose/withdraw IPs for local
  OVN ports.

- ``expose_remote_ip`` and ``withdraw_remote_ip``: use to expose/withdraw IPs
  through another node when the VM/Pod are running on a different node.
  For example for VMs on tenant networks where the traffic needs to be
  injected through the OVN router gateway port.

- ``expose_subnet`` and ``withdraw_subnet``: used to expose/withdraw subnets through
  the local node.


Proposed Solution
-----------------

To support BGP functionality the OVN BGP Agent includes a driver
that performs the extra steps required for exposing the IPs through BGP on
the right nodes and steering the traffic to/from the node from/to the OVN
overlay. In order to configure which driver to use, one should set the
``driver`` configuration option in the ``bgp-agent.conf`` file.

This driver requires a watcher to react to the BGP-related events.
In this case, the BGP actions will be trigger by events related to
``Port_Binding`` and ``Load_Balancer`` OVN SB DB tables.
The information in those tables gets modified by actions related to VMs or LBs
creation/deletion, as well as FIPs association/disassociation to/from them.

Then, the agent performs some actions in order to ensure those VMs are
reachable through BGP:

- Traffic between nodes or BGP Advertisement: These are the actions needed to
  expose the BGP routes and make sure all the nodes know how to reach the
  VM/LB IP on the nodes.

- Traffic within a node or redirecting traffic to/from OVN overlay: These are
  the actions needed to redirect the traffic to/from a VM to the OVN neutron
  networks, when traffic reaches the node where the VM is or in their way
  out of the node.

The code for the BGP driver is located at
``drivers/openstack/ovn_bgp_driver.py``, and its associated watcher can be
found at ``drivers/openstack/watchers/bgp_watcher.py``.


OVN SB DB Events
~~~~~~~~~~~~~~~~

The watcher associated to the BGP driver detect the relevant events on the
OVN SB DB to call the driver functions to configure BGP and linux kernel
networking accordingly.
The folloging events are watched and handled by the BGP watcher:

- VMs or LBs created/deleted on provider networks

- FIPs association/disassociation to VMs or LBs

- VMs or LBs created/deleted on tenant networks (if the
  ``expose_tenant_networks`` configuration option is enabled, or if the
  ``expose_ipv6_gua_tenant_networks`` for only exposing IPv6 GUA ranges)

  .. note::

     If ``expose_tenant_networks`` flag is enabled, it does not matter the
     status of ``expose_ipv6_gua_tenant_networks``, as all the tenant IPs
     will be advertized.


The BGP watcher detects OVN Southbound Database events at the ``Port_Binding``
and ``Load_Balancer`` tables. It creates new event classes named
``PortBindingChassisEvent`` and ``OVNLBMemberEvent``, that all the events
watched for BGP use as the base (inherit from).

The specific defined events to react to are:

- ``PortBindingChassisCreatedEvent``: Detects when a port of type
  ``""`` (empty double-qoutes), ``virtual``, or ``chassisredirect`` gets
  attached to the OVN chassis where the agent is running. This is the case for
  VM or amphora LB ports on the provider networks, VM or amphora LB ports on
  tenant networks with a FIP associated, and neutron gateway router ports
  (CR-LRPs). It calls ``expose_ip`` driver method to perform the needed
  actions to expose it.

- ``PortBindingChassisDeletedEvent``: Detects when a port of type
  ``""`` (empty double-quotes), ``virtual``, or ``chassisredirect`` gets
  detached from the OVN chassis where the agent is running. This is the case
  for VM or amphora LB ports on the provider networks, VM or amphora LB ports
  on tenant networks with a FIP associated, and neutron gateway router ports
  (CR-LRPs). It calls ``withdraw_ip`` driver method to perform the needed
  actions to withdraw the exposed BGP route.

- ``FIPSetEvent``: Detects when a patch port gets its nat_addresses field
  updated (e.g., action related to FIPs NATing). If that so, and the associated
  VM port is on the local chassis the event is processed by the agent and the
  required ip rule gets created and also the IP is (BGP) exposed. It calls
  ``expose_ip`` driver method, including the associated_port information, to
  perform the required actions.

- ``FIPUnsetEvent``: Same as previous, but when the nat_address field get an
  IP deleted. It calls ``withdraw_ip`` driver method to perform the required
  actions.

- ``SubnetRouterAttachedEvent``: Detects when a patch port gets created.
  This means a subnet is attached to a router. In the ``expose_tenant_network``
  case, if the chassis is the one having the cr-lrp port for that router where
  the port is getting created, then the event is processed by the agent and the
  needed actions (ip rules and routes, and ovs rules) for exposing the IPs on
  that network are performed. This event calls the driver_api
  ``expose_subnet``. The same happens if ``expose_ipv6_gua_tenant_networks``
  is used, but then, the IPs are only exposed if they are IPv6 global.

- ``SubnetRouterDetachedEvent``: Same as previous one, but for the deletion
  of the port. It calls ``withdraw_subnet``.

- ``TenantPortCreateEvent``: Detects when a port of type ``""`` (empty
  double-quotes) or ``virtual`` gets updated. If that port is not on a
  provider network, and the chasis where the event is processed has the
  LogicalRouterPort for the network and the OVN router gateway port where the
  network is connected to, then the event is processed and the actions to
  expose it through BGP are triggered. It calls the ``expose_remote_ip`` as in
  this case the IPs are exposed through the node with the OVN router gateway
  port, instead of where the VM is.

- ``TenantPortDeleteEvent``: Same as previous one, but for the deletion of the
  port. It calls ``withdraw_remote_ip``.

- ``OVNLBMemberUpdateEvent``:  This event is required to handle the OVN load
  balancers created on the provider networks. It detects when new datapaths
  are added/removed to/from the ``Load_Balancer`` entries. This happens when
  members are added/removed -- their respective datapaths are added into the
  ``Load_Balancer`` table entry. The event is only processed in the nodes with the
  relevant OVN router gateway ports, as it is where it needs to get exposed to
  be injected into OVN overlay. It calls ``expose_ovn_lb_on_provider`` when the
  second datapath is added (first one is the one belonging to the VIP (i.e.,
  the provider network), while the second one belongs to the load balancer
  member -- note all the load balancer members are expected to be connected
  through the same router to the provider network). And it calls
  ``withdraw_ovn_lb_on_provider`` when that member gets deleted (only one
  datapath left) or the event type is ROW_DELETE, meaning the whole
  load balancer is deleted.


Driver Logic
~~~~~~~~~~~~

The BGP driver is in charge of the networking configuration ensuring that
VMs and LBs on provider networks or with FIPs can be reached through BGP
(N/S traffic). In addition, if ``expose_tenant_networks`` flag is enabled,
VMs in tenant networks should be reachable too -- although instead of directly
in the node they are created, through one of the network gateway chassis nodes.
The same happens with ``expose_ipv6_gua_tenant_networks`` but only for IPv6
GUA ranges. In addition, if the config option ``address_scopes`` is set only
the tenant networks with matching corresponding address_scope will be exposed.

To accomplish this, it needs to ensure that:

- VM and LBs IPs can be advertized in a node where the traffic could be
  injected into the OVN overlay, in this case either the node hosting the VM
  or the node where the router gateway port is scheduled (see limitations
  subsection).

- Once the traffic reaches the specific node, the traffic is redirected to the
  OVN overlay by leveraging kernel networking.


BGP Advertisement
+++++++++++++++++

The OVN BGP Agent is in charge of triggering FRR (ip routing protocol
suite for Linux which includes protocol daemons for BGP, OSPF, RIP,
among others) to advertise/withdraw directly connected routes via BGP.
To do that, when the agent starts, it ensures that:

- FRR local instance is reconfigured to leak routes for a new VRF. To do that
  it uses ``vtysh shell``. It connects to the existsing FRR socket (
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
            redistribute connected
          exit-address-family

          address-family ipv6 unicast
            redistribute connected
          exit-address-family

        '''


- There is a VRF created (the one leaked in the previous step), by default
  with name ``bgp_vrf``.

- There is a dummy interface type (by default named ``bgp-nic``), associated to
  the previously created VRF device.

- Ensure ARP/NDP is enabled at OVS provider bridges by adding an IP to it


Then, to expose the VMs/LB IPs as they are created (or upon
initialization or re-sync), since the FRR configuration has the
``redistribute connected`` option enabled, the only action needed to expose it
(or withdraw it) is to add it (or remove it) from the ``bgp-nic`` dummy interface.
Then it relies on Zebra to do the BGP advertisemant, as Zebra detects the
addition/deletion of the IP on the local interface and advertises/withdraw
the route:

   .. code-block:: ini

        $ ip addr add IPv4/32 dev bgp-nic
        $ ip addr add IPv6/128 dev bgp-nic


 .. note::

     As we also want to be able to expose VM connected to tenant networks
     (when ``expose_tenant_networks`` or ``expose_ipv6_gua_tenant_networks``
     configuration options are enabled), there is a need to expose the Neutron
     router gateway port (CR-LRP on OVN) so that the traffic to VMs on tenant
     networks is injected into OVN overlay through the node that is hosting
     that port.


Traffic Redirection to/from OVN
+++++++++++++++++++++++++++++++

Once the VM/LB IP is exposed in an specific node (either the one hosting the
VM/LB or the one with the OVN router gateway port), the OVN BGP Agent is in
charge of configuring the linux kernel networking and OVS so that the traffic
can be injected into the OVN overlay, and vice versa. To do that, when the
agent starts, it ensures that:

- ARP/NDP is enabled at OVS provider bridges by adding an IP to it

- There is a routing table associated to each OVS provider bridge
  (adds entry at /etc/iproute2/rt_tables)

- If provider network is a VLAN network, a VLAN device connected
  to the bridge is created, and it has ARP and NDP enabed.

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


- Adds a static ARP entry for the OVN router gateway ports (CR-LRP) so that the
  traffic is steered to OVN via br-int -- this is because OVN does not reply
  to ARP requests outside its L2 network:

     .. code-block:: ini

      $ ip nei
      ...
      CR-LRP_IP dev br-ex lladdr CR-LRP_MAC PERMANENT
      ...


- For IPv6, instead of the static ARP entry, and NDP proxy is added, same
  reasoning:

       .. code-block:: ini

        $ ip -6 nei add proxy CR-LRP_IP dev br-ex


- Finally, in order for properly send the traffic out from the OVN overlay
  to kernel networking to be sent out of the node, the OVN BGP Agent needs
  to add a new flow at the OVS provider bridges so that the destination MAC
  address is changed to the MAC address of the OVS provider bridge
  (``actions=mod_dl_dst:OVN_PROVIDER_BRIDGE_MAC,NORMAL``):

       .. code-block:: ini

        $ sudo ovs-ofctl dump-flows br-ex
        cookie=0x3e7, duration=77.949s, table=0, n_packets=0, n_bytes=0, priority=900,ip,in_port="patch-provnet-1" actions=mod_dl_dst:3a:f7:e9:54:e8:4d,NORMAL
        cookie=0x3e7, duration=77.937s, table=0, n_packets=0, n_bytes=0, priority=900,ipv6,in_port="patch-provnet-1" actions=mod_dl_dst:3a:f7:e9:54:e8:4d,NORMAL



Driver API
++++++++++

The BGP driver needs to implement the ``driver_api.py`` interface with the
following functions:

- ``expose_ip``: creates all the ip rules and routes, and ovs flows needed
  to redirect the traffic to OVN overlay. It also ensure FRR exposes through
  BGP the required IP.

- ``withdraw_ip``: removes the above configuration to withdraw the exposed IP.

- ``expose_subnet``: add kernel networking configuration (ip rules and route)
  to ensure traffic can go from the node to the OVN overlay, and viceversa,
  for IPs within the tenant subnet CIDR.

- ``withdraw_subnet``: removes the above kernel networking configuration.

- ``expose_remote_ip``: BGP expose VM tenant network IPs through the chassis
  hosting the OVN gateway port for the router where the VM is connected.
  It ensures traffic destinated to the VM IP arrives to this node by exposing
  the IP through BGP locally. The previous steps in ``expose_subnet`` ensure
  the traffic is redirected to the OVN overlay once on the node.

- ``withdraw_remote_ip``: removes the above steps to stop advertizing the IP
  through BGP from the node.

And in addition, it also implements these 2 extra ones for the OVN load
balancers on the provider networks

- ``expose_ovn_lb_on_provider``: adds kernel networking configuration to ensure
  traffic is forwarded from the node to the OVN overlay as well as to expose
  the VIP through BGP.

- ``withdraw_ovn_lb_on_provider``: removes the above steps to stop advertising
  the load balancer VIP.


Agent deployment
~~~~~~~~~~~~~~~~

The BGP mode exposes the VMs and LBs in provider networks or with
FIPs, as well as VMs on tenant networks if ``expose_tenant_networks`` or
``expose_ipv6_gua_tenant_networks`` configuration options are enabled.

There is a need to deploy the agent in all the nodes where VMs can be created
as well as in the networker nodes (i.e., where OVN router gateway ports can be
allocated):

- For VMs and Amphora load balancers on provider networks or with FIPs,
  the IP is exposed on the node where the VM (or amphora) is deployed.
  Therefore the agent needs to be running on the compute nodes.

- For VMs on tenant networks (with ``expose_tenant_networks`` or
  ``expose_ipv6_gua_tenant_networks`` configuration options enabled), the agent
  needs to be running on the networker nodes. In OpenStack, with OVN
  networking, the N/S traffic to the tenant VMs (without FIPs) needs to go
  through the networking nodes, more specifically the one hosting the
  chassisredirect ovn port (cr-lrp), connecting the provider network to the
  OVN virtual router. Hence, the VM IPs is advertised through BGP in that
  node, and from there it follows the normal path to the OpenStack compute
  node where the VM is located — the Geneve tunnel.

- Similarly, for OVN load balancer the IPs are exposed on the networker node.
  In this case the ARP request for the VIP is replied by the OVN router
  gateway port, therefore the traffic needs to be injected into OVN overlay
  at that point too.
  Therefore the agent needs to be running on the networker nodes for OVN
  load balancers.

As an example of how to start the OVN BGP Agent on the nodes, see the commands
below:

   .. code-block:: ini

      $ python setup.py install
      $ cat bgp-agent.conf
      # sample configuration that can be adapted based on needs
      [DEFAULT]
      debug=True
      reconcile_interval=120
      expose_tenant_networks=True
      # expose_ipv6_gua_tenant_networks=True
      driver=osp_bgp_driver
      address_scopes=2237917c7b12489a84de4ef384a2bcae

      $ sudo bgp-agent --config-dir bgp-agent.conf
      Starting BGP Agent...
      Loaded chassis 51c8480f-c573-4c1c-b96e-582f9ca21e70.
      BGP Agent Started...
      Ensuring VRF configuration for advertising routes
      Configuring br-ex default rule and routing tables for each provider network
      Found routing table for br-ex with: ['201', 'br-ex']
      Sync current routes.
      Add BGP route for logical port with ip 172.24.4.226
      Add BGP route for FIP with ip 172.24.4.199
      Add BGP route for CR-LRP Port 172.24.4.221
      ....


   .. note::

    If you only want to expose the IPv6 GUA tenant IPs, then remove the option
    ``expose_tenant_networks`` and add ``expose_ipv6_gua_tenant_networks=True``
    instead.


   .. note::

    If you what to filter the tenant networks to be exposed by some specific
    address scopes, add the list of address scopes to ``addresss_scope=XXX``
    section. If no filtering should be applied, just remove the line.


Note that the OVN BGP Agent operates under the next assumptions:

- A dynamic routing solution, in this case FRR, is deployed and
  advertises/withdraws routes added/deleted to/from certain local interface,
  in this case the ones associated to the VRF created to that end. As only VM
  and load balancer IPs needs to be advertised, FRR needs to be configure with
  the proper filtering so that only /32 (or /128 for IPv6) IPs are advertised.
  A sample config for FRR is:

   .. code-block:: ini

        frr version 7.0
        frr defaults traditional
        hostname cmp-1-0
        log file /var/log/frr/frr.log debugging
        log timestamp precision 3
        service integrated-vtysh-config
        line vty

        router bgp 64999
          bgp router-id 172.30.1.1
          bgp log-neighbor-changes
          bgp graceful-shutdown
          no bgp default ipv4-unicast
          no bgp ebgp-requires-policy

          neighbor uplink peer-group
          neighbor uplink remote-as internal
          neighbor uplink password foobar
          neighbor enp2s0 interface peer-group uplink
          neighbor enp3s0 interface peer-group uplink

          address-family ipv4 unicast
            redistribute connected
            neighbor uplink activate
            neighbor uplink allowas-in origin
            neighbor uplink prefix-list only-host-prefixes out
          exit-address-family

          address-family ipv6 unicast
            redistribute connected
            neighbor uplink activate
            neighbor uplink allowas-in origin
            neighbor uplink prefix-list only-host-prefixes out
          exit-address-family

        ip prefix-list only-default permit 0.0.0.0/0
        ip prefix-list only-host-prefixes permit 0.0.0.0/0 ge 32

        route-map rm-only-default permit 10
          match ip address prefix-list only-default
          set src 172.30.1.1

        ip protocol bgp route-map rm-only-default

        ipv6 prefix-list only-default permit ::/0
        ipv6 prefix-list only-host-prefixes permit ::/0 ge 128

        route-map rm-only-default permit 11
          match ipv6 address prefix-list only-default
          set src f00d:f00d:f00d:f00d:f00d:f00d:f00d:0004

        ipv6 protocol bgp route-map rm-only-default

        ip nht resolve-via-default


- The relevant provider OVS bridges are created and configured with a loopback
  IP address (eg. 1.1.1.1/32 for IPv4), and proxy ARP/NDP is enabled on their
  kernel interface. In the case of OpenStack this is done by TripleO directly.


Limitations
-----------

The following limitations apply:

- There is no API to decide what to expose, all VMs/LBs on providers or with
  Floating IPs associated to them will get exposed. For the VMs in the tenant
  networks, the flag ``address_scopes`` should be used for filtering what
  subnets to expose -- which should be also used to ensure no overlapping IPs.

- There is no support for overlapping CIDRs, so this must be avoided, e.g., by
  using address scopes and subnet pools.

- Network traffic is steered by kernel routing (ip routes and rules), therefore
  OVS-DPDK, where the kernel space is skipped, is not supported.

- Network traffic is steered by kernel routing (ip routes and rules), therefore
  SRIOV, where the hypervisor is skipped, is not supported.

- In OpenStack with OVN networking the N/S traffic to the ovn-octavia VIPs on
  the provider or the FIPs associated to the VIPs on tenant networks needs to
  go through the networking nodes (the ones hosting the Neutron Router Gateway
  Ports, i.e., the chassisredirect cr-lrp ports, for the router connecting the
  load balancer members to the provider network). Therefore, the entry point
  into the OVN overlay needs to be one of those networking nodes, and
  consequently the VIPs (or FIPs to VIPs) are exposed through them. From those
  nodes the traffic will follow the normal tunneled path (Geneve tunnel) to
  the OpenStack compute node where the selected member is located.

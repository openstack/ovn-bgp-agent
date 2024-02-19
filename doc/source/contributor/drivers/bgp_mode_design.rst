.. _bgp_driver:

===================================================================
[SB DB] OVN BGP Agent: Design of the BGP Driver with kernel routing
===================================================================

Purpose
-------

The addition of a BGP driver enables the OVN BGP agent to expose virtual
machine (VMs) and load balancer (LBs) IP addresses through the BGP dynamic
protocol when these IP addresses are either associated with a floating IP
(FIP) or are booted or created on a provider network. The same functionality
is available on project networks, when a special flag is set.

This document presents the design decision behind the BGP Driver for the
Networking OVN BGP agent.

Overview
--------

With the growing popularity of virtualized and containerized workloads,
it is common to use pure Layer 3 spine and leaf network deployments in data
centers. The benefits of this practice reduce scaling complexities,
failure domains, and broadcast traffic limits.

The Southbound driver for OVN BGP Agent is a Python-based daemon that runs on
each OpenStack Controller and Compute node.
The agent monitors the Open Virtual Network (OVN) southbound database
for certain VM and floating IP (FIP) events.
When these events occur, the agent notifies the FRR BGP daemon (bgpd)
to advertise the IP address or FIP associated with the VM.
The agent also triggers actions that route the external traffic to the OVN
overlay.
Because the agent uses a multi-driver implementation, you can configure the
agent for the specific infrastructure that runs on top of OVN, such as OSP or
Kubernetes and OpenShift.

 .. note::

     Note it is only intended for the N/S traffic, the E/W traffic will work
     exactly the same as before, i.e., VMs are connected through geneve
     tunnels.


This design simplicity enables the agent to implement different drivers,
depending on what OVN SB DB events are being watched (watchers examples at
``ovn_bgp_agent/drivers/openstack/watchers/``), and what actions are
triggered in reaction to them (drivers examples at
``ovn_bgp_agent/drivers/openstack/XXXX_driver.py``, implementing the
``ovn_bgp_agent/drivers/driver_api.py``).

A driver implements the support for BGP capabilities. It ensures that both VMs
and LBs on provider networks or associated floating IPs are exposed through BGP.
In addition, VMs on tenant networks can be also exposed
if the ``expose_tenant_network`` configuration option is enabled.
To control what tenant networks are exposed another flag can be used:
``address_scopes``. If not set, all the tenant networks will be exposed, while
if it is configured with a (set of) address_scopes, only the tenant networks
whose address_scope matches will be exposed.

A common driver API is defined exposing the these methods:

- ``expose_ip`` and ``withdraw_ip``: exposes or withdraws IPs for local
  OVN ports.

- ``expose_remote_ip`` and ``withdraw_remote_ip``: exposes or withdraws IPs
  through another node when the VM or pods are running on a different node.
  For example, use for VMs on tenant networks where the traffic needs to be
  injected through the OVN router gateway port.

- ``expose_subnet`` and ``withdraw_subnet``: exposes or withdraws subnets
  through the local node.


Proposed Solution
-----------------

To support BGP functionality the OVN BGP Agent includes a driver
that performs the extra steps required for exposing the IPs through BGP on
the correct nodes and steering the traffic to/from the node from/to the OVN
overlay. To configure the OVN BGP agent to use the BGP driver set the
``driver`` configuration option in the ``bgp-agent.conf`` file to
``ovn_bgp_driver``.

The BGP driver requires a watcher to react to the BGP-related events.
In this case, BGP actions are triggered by events related to
``Port_Binding`` and ``Load_Balancer`` OVN SB DB tables.
The information in these tables is modified when VMs and LBs are created and
deleted, and when FIPs for them are associated and disassociated.

Then, the agent performs some actions in order to ensure those VMs are
reachable through BGP:

- Traffic between nodes or BGP Advertisement: These are the actions needed to
  expose the BGP routes and make sure all the nodes know how to reach the
  VM/LB IP on the nodes.

- Traffic within a node or redirecting traffic to/from OVN overlay: These are
  the actions needed to redirect the traffic to/from a VM to the OVN Neutron
  networks, when traffic reaches the node where the VM is or in their way
  out of the node.

The code for the BGP driver is located at
``ovn_bgp_agent/drivers/openstack/ovn_bgp_driver.py``, and its associated
watcher can be found at
``ovn_bgp_agent/drivers/openstack/watchers/bgp_watcher.py``.


OVN SB DB Events
~~~~~~~~~~~~~~~~

The watcher associated with the BGP driver detects the relevant events on the
OVN SB DB to call the driver functions to configure BGP and linux kernel
networking accordingly.
The following events are watched and handled by the BGP watcher:

- VMs or LBs created/deleted on provider networks

- FIPs association/disassociation to VMs or LBs

- VMs or LBs created/deleted on tenant networks (if the
  ``expose_tenant_networks`` configuration option is enabled, or if the
  ``expose_ipv6_gua_tenant_networks`` for only exposing IPv6 GUA ranges)

  .. note::

     If ``expose_tenant_networks`` flag is enabled, it does not matter the
     status of ``expose_ipv6_gua_tenant_networks``, as all the tenant IPs
     are advertised.


It creates new event classes named
``PortBindingChassisEvent`` and ``OVNLBEvent``, that all the events
watched for BGP use as the base (inherit from).

The BGP watcher reacts to the following events:

- ``PortBindingChassisCreatedEvent``: Detects when a port of type
  ``""`` (empty double-quotes), ``virtual``, or ``chassisredirect`` gets
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

- ``FIPSetEvent``: Detects when a Port_Binding entry of type ``patch`` gets
  its ``nat_addresses`` field updated (e.g., action related to FIPs NATing).
  When true, and the associated VM port is on the local chassis, the event
  is processed by the agent and the required IP rule gets created and its
  IP is (BGP) exposed. It calls the ``expose_ip`` driver method, including
  the associated_port information, to perform the required actions.

- ``FIPUnsetEvent``: Same as previous, but when the ``nat_addresses`` field get
  an IP deleted. It calls the ``withdraw_ip`` driver method to perform the
  required actions.

- ``SubnetRouterAttachedEvent``: Detects when a Port_Binding entry of type
  ``patch`` port gets created. This means a subnet is attached to a router.
  In the ``expose_tenant_network``
  case, if the chassis is the one having the cr-lrp port for that router where
  the port is getting created, then the event is processed by the agent and the
  needed actions (ip rules and routes, and ovs rules) for exposing the IPs on
  that network are performed. This event calls the driver API
  ``expose_subnet``. The same happens if ``expose_ipv6_gua_tenant_networks``
  is used, but then, the IPs are only exposed if they are IPv6 global.

- ``SubnetRouterDetachedEvent``: Same as ``SubnetRouterAttachedEvent``,
  but for the deletion of the port. It calls ``withdraw_subnet``.

- ``TenantPortCreateEvent``: Detects when a port of type ``""`` (empty
  double-quotes) or ``virtual`` gets updated. If that port is not on a
  provider network, and the chassis where the event is processed has the
  ``LogicalRouterPort`` for the network and the OVN router gateway port where
  the network is connected to, then the event is processed and the actions to
  expose it through BGP are triggered. It calls the ``expose_remote_ip``
  because in this case the IPs are exposed through the node with the OVN router
  gateway port, instead of the node where the VM is located.

- ``TenantPortDeleteEvent``: Same as ``TenantPortCreateEvent``, but for
  the deletion of the port. It calls ``withdraw_remote_ip``.

- ``OVNLBMemberUpdateEvent``:  This event is required to handle the OVN load
  balancers created on the provider networks. It detects when new datapaths
  are added/removed to/from the ``Load_Balancer`` entries. This happens when
  members are added/removed which triggers the addition/deletion of their
  datapaths into the ``Load_Balancer`` table entry.
  The event is only processed in the nodes with
  the relevant OVN router gateway ports, because it is where it needs to get
  exposed to be injected into OVN overlay.
  ``OVNLBMemberUpdateEvent`` calls ``expose_ovn_lb_on_provider`` only when the
  second datapath is added. The first datapath belongs to the VIP for the
  provider network, while the second one belongs to the load balancer member.
  ``OVNLBMemberUpdateEvent`` calls ``withdraw_ovn_lb_on_provider`` when the
  second datapath is deleted, or the entire load balancer is deleted (event
  type is ``ROW_DELETE``).

  .. note::

    All the load balancer members are expected to be connected through the same
    router to the provider network.


Driver Logic
~~~~~~~~~~~~

The BGP driver is in charge of the networking configuration ensuring that
VMs and LBs on provider networks or with FIPs can be reached through BGP
(N/S traffic). In addition, if the ``expose_tenant_networks`` flag is enabled,
VMs in tenant networks should be reachable too -- although instead of directly
in the node they are created, through one of the network gateway chassis nodes.
The same happens with ``expose_ipv6_gua_tenant_networks`` but only for IPv6
GUA ranges. In addition, if the config option ``address_scopes`` is set, only
the tenant networks with matching corresponding ``address_scope`` will be
exposed.

To accomplish the network configuration and advertisement, the driver ensures:

- VM and LBs IPs can be advertised in a node where the traffic could be
  injected into the OVN overlay, in this case either the node hosting the VM
  or the node where the router gateway port is scheduled (see limitations
  subsection).

- Once the traffic reaches the specific node, the traffic is redirected to the
  OVN overlay by leveraging kernel networking.


.. include:: ../bgp_advertising.rst


.. include:: ../bgp_traffic_redirection.rst


Driver API
++++++++++

The BGP driver needs to implement the ``driver_api.py`` interface with the
following functions:

- ``expose_ip``: creates all the IP rules and routes, and OVS flows needed
  to redirect the traffic to the OVN overlay. It also ensure FRR exposes
  through BGP the required IP.

- ``withdraw_ip``: removes the above configuration to withdraw the exposed IP.

- ``expose_subnet``: add kernel networking configuration (IP rules and route)
  to ensure traffic can go from the node to the OVN overlay, and vice versa,
  for IPs within the tenant subnet CIDR.

- ``withdraw_subnet``: removes the above kernel networking configuration.

- ``expose_remote_ip``: BGP exposes VM tenant network IPs through the chassis
  hosting the OVN gateway port for the router where the VM is connected.
  It ensures traffic destinated to the VM IP arrives to this node by exposing
  the IP through BGP locally. The previous steps in ``expose_subnet`` ensure
  the traffic is redirected to the OVN overlay once on the node.

- ``withdraw_remote_ip``: removes the above steps to stop advertising the IP
  through BGP from the node.

The driver API implements these additional methods for OVN load balancers on
provider networks:

- ``expose_ovn_lb_on_provider``: adds kernel networking configuration to ensure
  traffic is forwarded from the node to the OVN overlay and to expose
  the VIP through BGP.

- ``withdraw_ovn_lb_on_provider``: removes the above steps to stop advertising
  the load balancer VIP.


.. include:: ../agent_deployment.rst


Limitations
-----------

The following limitations apply:

- There is no API to decide what to expose, all VMs/LBs on providers or with
  floating IPs associated with them will get exposed. For the VMs in the tenant
  networks, the flag ``address_scopes`` should be used for filtering what
  subnets to expose -- which should be also used to ensure no overlapping IPs.

- There is no support for overlapping CIDRs, so this must be avoided, e.g., by
  using address scopes and subnet pools.

- Network traffic is steered by kernel routing (IP routes and rules), therefore
  OVS-DPDK, where the kernel space is skipped, is not supported.

- Network traffic is steered by kernel routing (IP routes and rules), therefore
  SR-IOV, where the hypervisor is skipped, is not supported.

- In OpenStack with OVN networking the N/S traffic to the ovn-octavia VIPs on
  the provider or the FIPs associated to the VIPs on tenant networks needs to
  go through the networking nodes (the ones hosting the Distributed Router
  Gateway Ports, i.e., the chassisredirect cr-lrp ports, for the router
  connecting the load balancer members to the provider network). Therefore,
  the entry point into the OVN overlay needs to be one of those networking
  nodes, and consequently the VIPs (or FIPs to VIPs) are exposed through them.
  From those nodes the traffic follows the normal tunneled path (Geneve
  tunnel) to the OpenStack compute node where the selected member is located.

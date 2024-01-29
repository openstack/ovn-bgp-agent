.. _nb_bgp_driver:

======================================================================
[NB DB] NB OVN BGP Agent: Design of the BGP Driver with kernel routing
======================================================================

Purpose
-------

The addition of a BGP driver enables the OVN BGP agent to expose virtual
machine (VMs) and load balancer (LBs) IP addresses through the BGP dynamic
protocol when these IP addresses are either associated with a floating IP
(FIP) or are booted or created on a provider network.
The same functionality is available on project networks, when a special
flag is set.

This document presents the design decision behind the NB BGP Driver for
the Networking OVN BGP agent.

Overview
--------

With the growing popularity of virtualized and containerized workloads,
it is common to use pure Layer 3 spine and leaf network deployments in
data centers. The benefits of this practice reduce scaling complexities,
failure domains, and broadcast traffic limits

The Northbound driver for OVN BGP agent is a Python-based daemon that runs
on each OpenStack Controller and Compute node.
The agent monitors the Open Virtual Network (OVN) northbound database
for certain VM and floating IP (FIP) events.
When these events occur, the agent notifies the FRR BGP daemon (bgpd)
to advertise the IP address or FIP associated with the VM.
The agent also triggers actions that route the external traffic to the OVN
overlay.
Unlike its predecessor, the Southbound driver for OVN BGP agent, the
Northbound driver uses the northbound database API which is more stable than
the southbound database API because the former is isolated from internal
changes to core OVN.

 .. note::

     Note northbound OVN BGP agent driver is only intended for the N/S traffic,
     the E/W traffic will work exactly the same as before, i.e., VMs are
     connected through geneve tunnels.


The agent provides a multi-driver implementation that allows you to configure
it for specific infrastructure running on top of OVN, for instance OpenStack
or Kubernetes/OpenShift.
This design simplicity enables the agent to implement different drivers,
depending on what OVN NB DB events are being watched (watchers examples at
``ovn_bgp_agent/drivers/openstack/watchers/``), and what actions are
triggered in reaction to them (drivers examples at
``ovn_bgp_agent/drivers/openstack/XXXX_driver.py``, implementing the
``ovn_bgp_agent/drivers/driver_api.py``).

A driver implements the support for BGP capabilities. It ensures that both VMs
and LBs on provider networks or associated Floating IPs are exposed through
BGP. In addition, VMs on tenant networks can be also exposed
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

- ``expose_subnet`` and ``withdraw_subnet``: exposes or withdraws subnets through
  the local node.


Proposed Solution
-----------------

To support BGP functionality the NB OVN BGP Agent includes a new driver
that performs the steps required for exposing the IPs through BGP on
the correct nodes and steering the traffic to/from the node from/to the OVN
overlay.
To configure the OVN BGP agent to use the northbound OVN BGP driver, in the
``bgp-agent.conf`` file, set the value of ``driver`` to ``nb_ovn_bgp_driver``.

This driver requires a watcher to react to the BGP-related events.
In this case, BGP actions are triggered by events related to
``Logical_Switch_Port``, ``Logical_Router_Port``and ``Load_Balancer``
on OVN NB DB tables.
The information in these tables is modified when VMs and LBs are created and
deleted, and when FIPs for them are associated and disassociated.

Then, the agent performs these actions to ensure the VMs are reachable through
BGP:

- Traffic between nodes or BGP Advertisement: These are the actions needed to
  expose the BGP routes and make sure all the nodes know how to reach the
  VM/LB IP on the nodes. This is exactly the same as in the initial OVN BGP
  Driver (see :ref:`bgp_driver`)

- Traffic within a node or redirecting traffic to/from OVN overlay (wiring):
  These are the actions needed to redirect the traffic to/from a VM to the OVN
  neutron networks, when traffic reaches the node where the VM is or in their
  way out of the node.

The code for the NB BGP driver is located at
``ovn_bgp_agent/drivers/openstack/nb_ovn_bgp_driver.py``, and its associated
watcher can be found at
``ovn_bgp_agent/drivers/openstack/watchers/nb_bgp_watcher.py``.

Note this new driver also allows different ways of wiring the node to the OVN
overlay. These are configurable through the option ``exposing_method``, where
for now you can select:

- ``underlay``: using kernel routing (what we describe in this document), same
  as supported by the driver at :ref:`bgp_driver`.

- ``ovn``: using an extra OVN cluster per node to perform the routing at
  OVN/OVS level instead of kernel, enabling datapath acceleration
  (Hardware Offloading and OVS-DPDK). More information about this mechanism
  at :ref:`bgp_driver`.


OVN NB DB Events
~~~~~~~~~~~~~~~~

The watcher associated with the BGP driver detects the relevant events on the
OVN NB DB to call the driver functions to configure BGP and linux kernel
networking accordingly.

  .. note::

     Linux Kernel Networking is used when the default ``exposing_method``
     (``underlay``) is used. If ``ovn`` is used instead, OVN routing is
     used instead of Kernel. For more details on this see :ref:`ovn_routing`.

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


The NB BGP watcher reacts to the following events:

- ``Logical_Switch_Port``

- ``Logical_Router_Port``

- ``Load_Balancer``

Besides the previously existing ``OVNLBEvent`` class, the NB BGP watcher has
new event classes named ``LSPChassisEvent`` and ``LRPChassisEvent`` that
all the events watched for NB BGP driver use as the base (inherit from).

The specific defined events to react to are:

- ``LogicalSwitchPortProviderCreateEvent``: Detects when a VM or an amphora LB
  port, logical switch ports of type ``""`` (empty double-qoutes) or
  ``virtual``, comes up or gets attached to the OVN chassis where the agent is
  running. If the ports are on a provider network, then the driver calls the
  ``expose_ip`` driver method to perform the needed actions to expose the port
  (wire and advertise). If the port is on a tenant network, the driver
  dismisses the event.

- ``LogicalSwitchPortProviderDeleteEvent``: Detects when a VM or an amphora LB
  port, logical switch ports of type "" (empty double-qoutes) or ``virtual``,
  goes down or gets detached from the OVN chassis where the agent is running.
  If the ports are on a provider network, then the driver calls the
  ``withdraw_ip`` driver method to perform the needed actions to withdraw the
  port (withdraw and unwire). If the port is on a tenant network, the driver
  dismisses the event.

- ``LogicalSwitchPortFIPCreateEvent``: Similar to
  ``LogicalSwitchPortProviderCreateEvent`` but focusing on the changes on the
  FIP information on the Logical Switch Port external_ids.
  It calls ``expose_fip`` driver method to perform the needed actions to expose
  the floating IP (wire and advertize).

- ``LogicalSwitchPortFIPDeleteEvent``: Same as previous one but for withdrawing
  FIPs. In this case it is similar to ``LogicalSwitchPortProviderDeleteEvent``
  but instaed calls the ``withdraw_fip`` driver method to perform the needed actions
  to withdraw the floating IP (Withdraw and unwire).

- ``LocalnetCreateDeleteEvent``: Detects creation/deletion of OVN localnet
  ports, which indicates the creation/deletion of provider networks. This
  triggers a resync (``sync`` method) action to perform the base configuration
  needed for the provider networks, such as OVS flows or arp/ndp
  configurations.

- ``ChassisRedirectCreateEvent``: Similar to
  ``LogicalSwitchPortProviderCreateEvent`` but with the focus on logical router
  ports, such as the Distributed Router Ports (cr-lrps), instead of logical
  switch ports.
  The driver calls ``expose_ip`` which performs additional steps to also
  expose IPs related to the cr-lrps, such as the ovn-lb or IPs in tenant
  networks. The watcher ``match`` checks the chassis information in the
  ``status`` field, which must be ovn23.09 or later.

- ``ChassisRedirectDeleteEvent``: Similar to
  ``LogicalSwitchPortProviderDeleteEvent`` but with the focus on logical router
  ports, such as the Distributed Router Ports (cr-lrps), instead of logical
  switch ports.
  The driver calls ``withdraw_ip`` which performs additional steps to
  also withdraw IPs related to the cr-lrps, such as the ovn-lb or IPs in tenant
  networks. The watcher ``match`` checks the chassis information in the
  ``status`` field, which must be ovn23.09 or later.

- ``LogicalSwitchPortSubnetAttachEvent``: Detects Logical Switch Ports of type
  ``router`` (connecting Logical Switch to Logical Router) and checks if the
  associated router is associated to the local chassis, i.e., if the cr-lrp of
  the router is located in the local chassis. If that is the case, the
  ``expose_subnet`` driver method is called which is in charge of the wiring
  needed for the IPs on that subnet (set of IP routes and rules).

- ``LogicalSwitchPortSubnetDetachEvent``: Similar to
  ``LogicalSwitchPortSubnetAttachEvent`` but for unwiring the subnet, so it is
  calling  the``withdraw_subnet`` driver method.

- ``LogicalSwitchPortTenantCreateEvent``: Detects when a logical switch port
  of type ``""`` (empty double-qoutes) or ``virtual``, similar to
  ``LogicalSwitchPortProviderCreateEvent``. It checks if the network associated
  to the VM is exposed in the local chassis (meaning its cr-lrp is also local).
  If that is the case, it calls ``expose_remote_ip``, which manages the
  advertising of the IP -- there is no need for wiring, as that is done when
  the subnet is exposed by ``LogicalSwitchPortSubnetAttachEvent`` event.

- ``LogicalSwitchPortTenantDeleteEvent``: Similar to
  ``LogicalSwitchPortTenantCreateEvent`` but for withdrawing IPs.
  Calling ``withdraw_remote_ips``.

- ``OVNLBCreateEvent``: Detects Load_Balancer events and processes them only
  if the Load_Balancer entry has associated VIPs and the router is local to
  the chassis.
  If the VIP or router is added to a provider network, the driver calls
  ``expose_ovn_lb_vip`` to expose and wire the VIP or router.
  If the VIP or router is added to a tenant network, the driver calls
  ``expose_ovn_lb_vip`` to only expose the VIP or router.
  If a floating IP is added, then the driver calls ``expose_ovn_lb_fip`` to
  expose and wire the FIP.

- ``OVNLBDeleteEvent``: If the VIP or router is removed from a provider
  network, the driver calls ``withdraw_ovn_lb_vip`` to withdraw and unwire
  the VIP or router. If the VIP or router is removed to a tenant network,
  the driver calls ``withdraw_ovn_lb_vip`` to only withdraw the VIP or router.
  If a floating IP is removed, then the driver calls ``withdraw_ovn_lb_fip``
  to withdraw and unwire the FIP.


Driver Logic
~~~~~~~~~~~~

The NB BGP driver is in charge of the networking configuration ensuring that
VMs and LBs on provider networks or with FIPs can be reached through BGP
(N/S traffic). In addition, if the ``expose_tenant_networks`` flag is enabled,
VMs in tenant networks should be reachable too -- although instead of directly
in the node they are created, through one of the network gateway chassis nodes.
The same happens with ``expose_ipv6_gua_tenant_networks`` but only for IPv6
GUA ranges. In addition, if the config option ``address_scopes`` is set, only
the tenant networks with matching corresponding ``address_scope`` will be
exposed.

  .. note::

    To be able to expose tenant networks a OVN version OVN 23.09 or newer is
    required.

To accomplish the network configuration and advertisement, the driver ensures:

- VM and LBs IPs can be advertised in a node where the traffic can be injected
  into the OVN overlay: either in the node that hosts the VM or in the node
  where the router gateway port is scheduled. (See the "limitations"
  subsection.).

- After the traffic reaches the specific node, kernel networking redirects the
  traffic to the OVN overlay, if the default ``underlay`` exposing method is
  used.


.. include:: ../bgp_advertising.rst


Traffic flow from tenant networks
+++++++++++++++++++++++++++++++++

By default neutron enables SNAT on routers (because that is typically
what you'd use the routers for). This has some side effects that might not
be all that convenient; for one, all connections initiated from VMs in
tenant networks will be externally identified with the IP of the cr-lrp.

The VMs in the tenant networks are reachable through their own ip and
return traffic will flow as expected as well, but it is just not really
what one would expect.

To prevent tenant networks from being exposed if SNAT is enabled, one can set
the configuration option ``require_snat_disabled_for_tenant_networks`` to ``True``

This will check if the cr-lrp has SNAT disabled for that subnet, and prevent
announcement of those tenant networks.

.. note::
  Neutron will add IPv6 subnets are without NAT, so even though the IPv4 of
  those tenant networks might have NAT enabled, the IPv6 subnet might still
  be exposed, as this has no NAT enabled.

To disable the SNAT on a neutron router, one could simply run this command:

.. code-block:: ini

  $ openstack router set --disable-snat --external-gateway <provider_network> <router>


.. include:: ../bgp_traffic_redirection.rst


Driver API
++++++++++

The NB BGP driver implements the ``driver_api.py`` interface with the
following functions:

- ``expose_ip``: creates all the IP rules and routes, and OVS flows needed
  to redirect the traffic to OVN overlay. It also ensures that FRR exposes
  the required IP by using BGP.

- ``withdraw_ip``: removes the configuration (IP rules/routes, OVS flows)
  from ``expose_ip`` method to withdraw the exposed IP.

- ``expose_subnet``: adds kernel networking configuration (IP rules and route)
  to ensure traffic can go from the node to the OVN overlay (and back)
  for IPs within the tenant subnet CIDR.

- ``withdraw_subnet``: removes kernel networking configuration added by
  ``expose_subnet``.

- ``expose_remote_ip``: BGP expose VM tenant network IPs through the chassis
  hosting the OVN gateway port for the router where the VM is connected.
  It ensures traffic directed to the VM IP arrives at this node by exposing
  the IP through BGP locally. The previous steps in ``expose_subnet`` ensure
  the traffic is redirected to the OVN overlay after it arrives on the node.

- ``withdraw_remote_ip``: removes the configuration added by
  ``expose_remote_ip``.

And in addition, the driver also implements extra methods for the FIPs and the
OVN load balancers:

- ``expose_fip`` and ``withdraw_fip`` which are equivalent to ``expose_ip`` and
  ``withdraw_ip`` but for FIPs.

- ``expose_ovn_lb_vip``: adds kernel networking configuration to ensure
  traffic is forwarded from the node with the associated cr-lrp to the OVN
  overlay, as well as to expose the VIP through BGP in that node.

- ``withdraw_ovn_lb_vip``: removes the above steps to stop advertising
  the load balancer VIP.

- ``expose_ovn_lb_fip`` and ``withdraw_ovn_lb_fip``: for exposing the FIPs
  associated to ovn loadbalancers. This is similar to
  ``expose_fip/withdraw_fip`` but taking into account that it must be exposed
  on the node with the cr-lrp for the router associated to the loadbalancer.


.. include:: ../agent_deployment.rst


Limitations
-----------

The following limitations apply:

- OVN 23.09 or later is needed to support exposing tenant networks IPs and
  OVN loadbalancers.

- There is no API to decide what to expose, all VMs/LBs on providers or with
  floating IPs associated with them are exposed. For the VMs in the tenant
  networks, use the flag ``address_scopes`` to filter which subnets to expose,
  which also prefents having overlapping IPs.

- In the currently implemented exposing methods (``underlay`` and
  ``ovn``) there is no support for overlapping CIDRs, so this must be
  avoided, e.g., by using address scopes and subnet pools.

- For the default exposing method (``underlay``) the network traffic is steered
  by kernel routing (ip routes and rules), therefore OVS-DPDK, where the kernel
  space is skipped, is not supported. With the ``ovn`` exposing method
  the routing is done at ovn level, so this limitation does not exists.
  More details in :ref:`ovn_routing`.

- For the default exposing method (``underlay``) the network traffic is steered
  by kernel routing (ip routes and rules), therefore SRIOV, where the hypervisor
  is skipped, is not supported.  With the ``ovn`` exposing method
  the routing is done at ovn level, so this limitation does not exists.
  More details in :ref:`ovn_routing`.

- In OpenStack with OVN networking the N/S traffic to the ovn-octavia VIPs on
  the provider or the FIPs associated with the VIPs on tenant networks needs to
  go through the networking nodes (the ones hosting the Neutron Router Gateway
  Ports, i.e., the chassisredirect cr-lrp ports, for the router connecting the
  load balancer members to the provider network). Therefore, the entry point
  into the OVN overlay needs to be one of those networking nodes, and
  consequently the VIPs (or FIPs to VIPs) are exposed through them. From those
  nodes the traffic will follow the normal tunneled path (Geneve tunnel) to
  the OpenStack compute node where the selected member is located.

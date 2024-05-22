========================================
EVPN L3VNI using OVN NB database
========================================

One example deployment, is to run the OVN BGP Agent and to expose provider
networks and tenant networks with pure layer 3 functionality.

Traffic flow
~~~~~~~~~~~~

The next figure shows the N/S traffic flow through the VRF to the VM,
including information the routes in the VRF routing table.

.. image:: ../../images/evpn-flow-l3vpn.svg
   :alt: EVPN l3vpn diagram
   :align: center
   :width: 100%


On Host-2, the IPs of both the external router gateway port (GW, ``172.16.2.12``),
as well as the subnet it exposes (``192.168.0.0/24``) gets added to the
routing table of the vrf (``vrf-1001``). Also any instance that is attached
directly on a provider network is added to the routing table.

Then FRR is utilized to expose this vrf through BGP/EVPN. Routes from other nodes
are imported and added as an VXLAN route, pointing to the bridge (``br-1001``).

This allows the external route to reach the internal VM, possibly routed
through the host that is hosting the router gateway port.

Configuration
~~~~~~~~~~~~~

frr-bgpd.conf
--------------------

A typical FRR BGP configuration would look like this (for example for host-1):

.. code-block:: ini

  router bgp 64531
    bgp router-id 10.100.100.1
    bgp default l2vpn-evpn

    neighbor rr-peers peer-group
    neighbor rr-peers remote-as internal
    neighbor rr-peers bfd

    neighbor upstream-peers peer-group
    neighbor upstream-peers remote-as internal
    neighbor upstream-peers bfd

    ! Upstream routers (these will most likely expose the default outbound route)
    neighbor 10.100.250.3 peer-group upstream-peers
    neighbor 10.100.250.4 peer-group upstream-peers

    ! Route reflector peers (used for distributing routes between compute nodes)
    neighbor 10.100.50.66 peer-group rr-peers
    neighbor 10.100.51.66 peer-group rr-peers
    neighbor 10.100.52.66 peer-group rr-peers

    address-family l2vpn evpn
      neighbor rr-peers soft-reconfiguration inbound
      neighbor upstream-peers soft-reconfiguration inbound
      advertise-all-vni
    exit-address-family
  exit

.. note::
  In our best practice we use FRR instances on central nodes to act as route
  reflector. How to scale your BGP network and what practices you might use
  is beyond the perview of this example document.


ovn-bgp-agent.conf
------------------
To run OVN BGP Agent with NB driver and EVPN L3 mode, the following configuration is recommended:

.. code-block:: ini

  [DEFAULT]
  # Time (seconds) between re-sync actions.
  reconcile_interval = 600

  # Time (seconds) between re-sync actions to ensure frr configuration is correct.
  # NOTE: This function does not do anything in our setup, so this high interval is fine.
  frr_reconcile_interval = 86400

  # Expose VM IPs on tenant networks.
  expose_tenant_networks = True

  # The NB driver is capable of advertising the tenant networks either per
  # host or per subnet. So either per /32 or /128 or per subnet like /24.
  # Choose "host" as value for this option to advertise per host or choose
  # "subnet" to announce per subnet prefix.
  advertisement_method_tenant_networks = subnet

  # Require SNAT on the router port to be disabled before exposing the tenant
  # networks. Otherwise the exposed tenant networks will be reachable from the
  # outside, but the connections set up from within the tenant vm will always
  # be SNAT-ed by the router, thus be the router ip. When SNAT is disabled,
  # OVN will do pure routing without SNAT
  require_snat_disabled_for_tenant_networks = True

  # Expose only VM IPv6 IPs on tenant networks if they are GUA.
  # expose_ipv6_gua_tenant_networks = False

  # Driver to be used.
  driver = 'nb_ovn_bgp_driver'

  # The connection string for the native OVSDB backend.
  ovsdb_connection = tcp:127.0.0.1:6640

  # Timeout in seconds for the OVSDB connection transaction.
  # ovsdb_connection_timeout = 180

  # AS number to be used by the Agent when running in BGP mode.
  bgp_AS = < CONFIGURE YOUR AS HERE >

  # Router ID to be used by the Agent when running in BGP mode.
  bgp_router_id = < CONFIGURE YOUR ROUTER ID/IP HERE >

  # IP address of local EVPN VXLAN (tunnel) endpoint.
  evpn_local_ip = < CONFIGURE YOUR HOST'S EVPN VXLAN IP HERE>

  # If enabled, all routes are removed from the VRF table at startup.
  clear_vrf_routes_on_startup = False

  # Allows to filter on the address scope (optional, comma separated list of uuids)
  # address_scopes = 11111111-1111-1111-1111-111111111111,22222222-2222-2222-2222-222222222222

  # The exposing mechanism to be used.
  exposing_method = 'vrf'

  # When using exposing_method vrf and l3 mode on networks, then one can create
  # anycast mac addresses, basically using the same mac address on all nodes for
  # use with routing.
  anycast_evpn_gateway_mode = True

  [ovn]
  # The connection string for the OVN_Northbound OVSDB.
  # Use tcp:IP:PORT for TCP connection.
  # Use unix:FILE for unix domain socket connection.
  ovn_nb_connection = < CONNECTION STRING TO NB OVN DB>

Configure provider networks
---------------------------

This section assumes, that you've already configured OVN, and applied the correct bridge-mappings
on the hosts themselves, see `Neutron documentation regarding provider networks. <https://docs.openstack.org/neutron/latest/admin/ovn/refarch/provider-networks.html>`_

First, create your provider network through neutron

.. code-block:: bash

  openstack network create my_network \
     --provider-network-type vlan \
     --provider-physical-network physnet1 \
     --provider-segment 123 \
     --mtu 1500 \
     --external \
     --default

Then, configure your provider networks through either Neutron BGPVPN API or
with ovn commandline:

.. code-block:: bash

  ovn-nbctl set logical-switch < UUID > external_ids:"neutron_bgpvpn\:type"="l3"
  ovn-nbctl set logical-switch < UUID > external_ids:"neutron_bgpvpn\:vni"="1001"  # or any other number

Now use this network to attach routers on it (so update router:external on
the provider network) or share your network among tenants (shared = True)

And create some routers, or add some instances on the provider network, so a
host will start exposing the networks and/or ips.

Current known limitations
~~~~~~~~~~~~~~~~~~~~~~~~~

- Only one Flat provider network can be exposed per vni. Recommendation is
  to use VLAN provider networks.

- Do not use the same VLAN id twice in the same VNI. A provider network with
  type flat is considered vlan 0.

- It is not possible to have a tenant network (which is routed through a
  gateway) in separate VRF's, make sure to use address scopes and subnet pools
  to prevent ip overlaps, if you are planning to expose tenant networks.

- Provider networks of type ``flat`` is supported, but is limited (because of
  how ``flat`` networks operate) to one provider network per bridge mapping.
  It is recommended to use provider networks of type ``vlan``. That way it is
  also easier to create multiple provider networks, without having to create
  new bridgemappings for every provider network.

  Every provider network can be assigned a separate VNI, so IP overlap is not
  an issue between provider networks, as long as separate VNI's are used for
  those provider networks.

See other known limitations at the NB BGP driver :ref:`NB_BGP_driver_limitations`

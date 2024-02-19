Agent deployment
~~~~~~~~~~~~~~~~

The BGP mode (for both NB and SB drivers) exposes the VMs and LBs in provider
networks or with FIPs, as well as VMs on tenant networks if
``expose_tenant_networks`` or ``expose_ipv6_gua_tenant_networks`` configuration
options are enabled.

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
  Distributed Gateway Port (chassisredirect OVN port (cr-lrp)),
  connecting the provider network to the OVN virtual router.
  Hence, the VM IPs are advertised through BGP in that node, and from there it
  follows the normal path to the OpenStack compute node where the VM is
  located — through the tunnel.

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
      # for SB DB driver
      driver=ovn_bgp_driver
      # for NB DB driver
      #driver=nb_ovn_bgp_driver
      bgp_AS=64999
      bgp_nic=bgp-nic
      bgp_vrf=bgp-vrf
      bgp_vrf_table_id=10
      ovsdb_connection=tcp:127.0.0.1:6640
      address_scopes=2237917c7b12489a84de4ef384a2bcae

      [ovn]
      ovn_nb_connection = tcp:172.17.0.30:6641
      ovn_sb_connection = tcp:172.17.0.30:6642

      [agent]
      root_helper=sudo ovn-bgp-agent-rootwrap /etc/ovn-bgp-agent/rootwrap.conf
      root_helper_daemon=sudo ovn-bgp-agent-rootwrap-daemon /etc/ovn-bgp-agent/rootwrap.conf

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

    If you want to filter the tenant networks to be exposed by some specific
    address scopes, add the list of address scopes to ``address_scope=XXX``
    section. If no filtering should be applied, just remove the line.


Note that the OVN BGP Agent operates under the next assumptions:

- A dynamic routing solution, in this case FRR, is deployed and
  advertises/withdraws routes added/deleted to/from certain local interface,
  in this case the ones associated to the VRF created to that end. As only VM
  and load balancer IPs need to be advertised, FRR needs to be configure with
  the proper filtering so that only /32 (or /128 for IPv6) IPs are advertised.
  A sample config for FRR is:

   .. code-block:: ini

        frr version 7.5
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
  kernel interface.

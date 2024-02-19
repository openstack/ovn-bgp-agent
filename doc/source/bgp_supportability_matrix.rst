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

=========================
BGP Supportability Matrix
=========================

The next sections highlight the options and features supported by each driver


BGP Driver (SB)
---------------

+-----------------+-----------------------------------------------------+------------------------------------------+------------------------------------------+--------------------------+--------------------+-----------------------+-----------+
| Exposing Method | Description                                         | Expose with                              | Wired with                               | Expose Tenants           | Expose only GUA    | OVS-DPDK/HWOL Support | Supported |
+=================+=====================================================+==========================================+==========================================+==========================+====================+=======================+===========+
| Underlay        | Expose IPs on the default underlay network.         | Adding IP to dummy NIC isolated in a VRF | Ingress: ip rules, and ip routes on the  | Yes                      | Yes                | No                    | Yes       |
|                 |                                                     |                                          | routing table associated with OVS        |                          | (expose_ipv6_gua   |                       |           |
|                 |                                                     |                                          | Egress: OVS flow to change MAC           | (expose_tenant_networks) | _tenant_networks)  |                       |           |
+-----------------+-----------------------------------------------------+------------------------------------------+------------------------------------------+--------------------------+--------------------+-----------------------+-----------+


BGP Driver (NB)
---------------

OVN version 23.09 is required to expose tenant networks and ovn Load Balancers,
because Distributed Gateway port (cr-lrp) chassis information in the NB DB is
only available in that version
(https://bugzilla.redhat.com/show_bug.cgi?id=2107515).

The following table lists the various methods you can use to expose the
networks/IPS, how they expose the IPs and the tenant networks, and whether
OVS-DPDK and hardware offload (HWOL) is supported.

+-----------------+-----------------------------------------------------+------------------------------------------+------------------------------------------+--------------------------+-----------------------+---------------+
| Exposing Method | Description                                         | Expose with                              | Wired with                               | Expose Tenants or GUA    | OVS-DPDK/HWOL Support | Supported     |
+=================+=====================================================+==========================================+==========================================+==========================+=======================+===============+
| Underlay        | Expose IPs on the default underlay network.         | Adding IP to dummy NIC isolated in a VRF.| Ingress: ip rules, and ip routes on the  | Yes                      | No                    | Yes           |
|                 |                                                     |                                          | routing table associated to OVS          |                          |                       |               |
|                 |                                                     |                                          | Egress: OVS-flow to change MAC           | (expose_tenant_networks) |                       |               |
+-----------------+-----------------------------------------------------+------------------------------------------+------------------------------------------+--------------------------+-----------------------+---------------+
| L2VNI           | Extends the L2 segment on a given VNI.              | No need to expose it, automatic with the | Ingress: vxlan + bridge device           |  N/A                     | No                    | No            |
|                 |                                                     | FRR configuration and the wiring.        | Egress: nothing                          |                          |                       |               |
+-----------------+-----------------------------------------------------+------------------------------------------+------------------------------------------+--------------------------+-----------------------+---------------+
| VRF             | Expose IPs on a given VRF (vni id).                 | Add IPs to dummy NIC associated to the   | Ingress: vxlan + bridge device           |  Yes                     | No                    | No            |
|                 |                                                     | VRF device (lo_VNI_ID).                  | Egress: flow to redirect to VRF device   |  (Not implemented)       |                       |               |
+-----------------+-----------------------------------------------------+------------------------------------------+------------------------------------------+--------------------------+-----------------------+---------------+
| Dynamic         | Mix of the previous. Depending on annotations it    | Mix of the previous three.               | Ingress: mix of all the above            |  Depends on the method   | No                    | No            |
|                 | exposes IPs differently and on different VNIs.      |                                          | Egress: mix of all the above             |  used                    |                       |               |
+-----------------+-----------------------------------------------------+------------------------------------------+------------------------------------------+--------------------------+-----------------------+---------------+
| OVN             | Make use of an extra OVN cluster (per node) instead | Adding IP to dummy NIC isolated in a VRF | Ingress: OVN routes, OVS flow (MAC tweak)|  Yes                     | Yes                   | Yes. Only for |
|                 | of kernel routing -- exposing the IPs with BGP is   | (as it only supports the underlay        | Egress: OVN routes and policies,         |  (Not implemented)       |                       | ipv4 and flat |
|                 | the same as before.                                 | option).                                 | and OVS flow (MAC tweak)                 |                          |                       | provider      |
|                 |                                                     |                                          |                                          |                          |                       | networks      |
+-----------------+-----------------------------------------------------+------------------------------------------+------------------------------------------+--------------------------+-----------------------+---------------+


BGP Stretched Driver (SB)
-------------------------

+-----------------+-----------------------------------------------------+------------------------------------------+------------------------------------------+----------------+--------------------+-----------------------+-----------+
| Exposing Method | Description                                         | Expose with                              | Wired with                               | Expose Tenants | Expose only GUA    | OVS-DPDK/HWOL Support | Supported |
+=================+=====================================================+==========================================+==========================================+================+====================+=======================+===========+
| Underlay        | Expose IPs on the default underlay network.         | Adding IP routes to default VRF table.   | Ingress: ip rules, and ip routes on the  | Yes            | No                 | No                    | Yes       |
|                 |                                                     |                                          | routing table associated to OVS          |                |                    |                       |           |
|                 |                                                     |                                          | Egress: OVS-flow to change MAC           |                |                    |                       |           |
+-----------------+-----------------------------------------------------+------------------------------------------+------------------------------------------+----------------+--------------------+-----------------------+-----------+


EVPN Driver (SB)
----------------

+-----------------+-----------------------------------------------------+------------------------------------------+------------------------------------------+----------------+--------------------+-----------------------+-----------+
| Exposing Method | Description                                         | Expose with                              | Wired with                               | Expose Tenants | Expose only GUA    | OVS-DPDK/HWOL Support | Supported |
+=================+=====================================================+==========================================+==========================================+================+====================+=======================+===========+
| VRF             | Expose IPs on a given VRF (vni id)  -- requires     | Add IPs to dummy NIC associated to the   | Ingress: vxlan + bridge device           | Yes            | No                 | No                    | No        |
|                 | newtorking-bgpvpn or manual NB DB inputs.           | VRF device (lo_VNI_ID).                  | Egress: flow to redirect to VRF device   |                |                    |                       |           |
+-----------------+-----------------------------------------------------+------------------------------------------+------------------------------------------+----------------+--------------------+-----------------------+-----------+

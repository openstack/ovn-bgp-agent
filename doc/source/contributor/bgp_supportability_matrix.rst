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

+-----------------+-----------------------------------------------------+------------------------------------------+------------------------------------------+--------------------------+--------------------+-----------------------+-------------+
| Exposing Method | Description                                         | Expose with                              | Wired with                               | Expose Tenants           | Expose only GUA    | OVS-DPDK/HWOL Support | Implemented |
+=================+=====================================================+==========================================+==========================================+==========================+====================+=======================+=============+
| Underlay        | Expose IPs on the default underlay network          | Adding IP to dummy nic isolated in a VRF | Ingress: ip rules, and ip routes on the  | Yes                      | Yes                | No                    | Yes         |
|                 |                                                     |                                          | routing table associated with OVS        |                          | (expose_ipv6_gua   |                       |             |
|                 |                                                     |                                          | Egress: OVS flow to change MAC           | (expose_tenant_networks) | _tenant_networks)  |                       |             |
+-----------------+-----------------------------------------------------+------------------------------------------+------------------------------------------+--------------------------+--------------------+-----------------------+-------------+


BGP Driver (NB)
---------------

Note until RFE on OVN (https://bugzilla.redhat.com/show_bug.cgi?id=2107515)
is implemented there is no option to expose tenant networks as we do not know
where the CR-LRP port is associated to.

+-----------------+-----------------------------------------------------+------------------------------------------+------------------------------------------+--------------------------+-----------------------+-------------+
| Exposing Method | Description                                         | Expose with                              | Wired with                               | Expose Tenants or GUA    | OVS-DPDK/HWOL Support | Implemented |
+=================+=====================================================+==========================================+==========================================+==========================+=======================+=============+
| Underlay        | Expose IPs on the default underlay network          | Adding IP to dummy nic isolated in a VRF | Ingress: ip rules, and ip routes on the  | No support until OVN     | No                    | Yes         |
|                 |                                                     |                                          | routing table associated to ovs          | has information about    |                       |             |
|                 |                                                     |                                          | Egress: ovs-flow to change mac           | the CR-LRP chassis on    |                       |             |
+-----------------+-----------------------------------------------------+------------------------------------------+------------------------------------------+ the SB DB                +-----------------------+-------------+
| L2VNI           | Extends the L2 segment on a given VNI               | No need to expose it, automatic with the | Ingress: vxlan + bridge device           |                          | No                    | No          |
|                 |                                                     | FRR configuration and the wiring         | Egress: nothing                          |                          |                       |             |
+-----------------+-----------------------------------------------------+------------------------------------------+------------------------------------------+                          +-----------------------+-------------+
| VRF             | Expose IPs on a given VRF (vni id)                  | Add IPs to dummy nic associated to the   | Ingress: vxlan + bridge device           |                          | No                    | No          |
|                 |                                                     | VRF device (lo_VNI_ID)                   | Egress: flow to redirect to VRF device   |                          |                       |             |
+-----------------+-----------------------------------------------------+------------------------------------------+------------------------------------------+                          +-----------------------+-------------+
| Dynamic         | Mix of the previous, depending on annotations it    | Mix of the previous three                | Ingress: mix of all the above            |                          | No                    | No          |
|                 | exposes it differently and on different VNIs        |                                          | Egress: mix of all the above             |                          |                       |             |
+-----------------+-----------------------------------------------------+------------------------------------------+------------------------------------------+                          +-----------------------+-------------+
| OVN-Cluster     | Make use of an extra OVN cluster (per node) instead | Adding IP to dummy nic isolated in a VRF | Ingress: ovn routes, ovs flow (mac tweak)|                          | Yes                   | No          |
|                 | of kernel routing -- exposing the IPs with BGP is   | (as it only supports the underlay option)| Egress: ovn routes and policies,         |                          |                       |             |
|                 | the same as before                                  |                                          | and ovs flow (mac tweak)                 |                          |                       |             |
+-----------------+-----------------------------------------------------+------------------------------------------+------------------------------------------+--------------------------+-----------------------+-------------+


BGP Stretched Driver (SB)
-------------------------

+-----------------+-----------------------------------------------------+------------------------------------------+------------------------------------------+----------------+--------------------+-----------------------+-------------+
| Exposing Method | Description                                         | Expose with                              | Wired with                               | Expose Tenants | Expose only GUA    | OVS-DPDK/HWOL Support | Implemented |
+=================+=====================================================+==========================================+==========================================+================+====================+=======================+=============+
| Underlay        | Expose IPs on the default underlay network          | Adding IP routes to default VRF table    | Ingress: ip rules, and ip routes on the  | Yes            | No                 | No                    | Yes         |
|                 |                                                     |                                          | routing table associated to ovs          |                |                    |                       |             |
|                 |                                                     |                                          | Egress: ovs-flow to change mac           |                |                    |                       |             |
+-----------------+-----------------------------------------------------+------------------------------------------+------------------------------------------+----------------+--------------------+-----------------------+-------------+


EVPN Driver (SB)
----------------

+-----------------+-----------------------------------------------------+------------------------------------------+------------------------------------------+----------------+--------------------+-----------------------+-------------+
| Exposing Method | Description                                         | Expose with                              | Wired with                               | Expose Tenants | Expose only GUA    | OVS-DPDK/HWOL Support | Implemented |
+=================+=====================================================+==========================================+==========================================+================+====================+=======================+=============+
| VRF             | Expose IPs on a given VRF (vni id)  -- requires     | Add IPs to dummy nic associated to the   | Ingress: vxlan + bridge device           | Yes            | No                 | No                    | No          |
|                 | newtorking-bgpvpn or manual NB DB inputs            | VRF device (lo_VNI_ID)                   | Egress: flow to redirect to VRF device   |                |                    |                       |             |
+-----------------+-----------------------------------------------------+------------------------------------------+------------------------------------------+----------------+--------------------+-----------------------+-------------+

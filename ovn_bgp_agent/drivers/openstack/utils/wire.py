# Copyright 2023 Red Hat, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from oslo_config import cfg
from oslo_log import log as logging

from ovn_bgp_agent import constants
from ovn_bgp_agent.drivers.openstack.utils import ovs
from ovn_bgp_agent import exceptions as agent_exc
from ovn_bgp_agent.utils import helpers
from ovn_bgp_agent.utils import linux_net


CONF = cfg.CONF
LOG = logging.getLogger(__name__)


def ensure_base_wiring_config(idl, ovs_idl, ovn_idl=None, routing_tables={}):
    if CONF.exposing_method == constants.EXPOSE_METHOD_UNDERLAY:
        return _ensure_base_wiring_config_underlay(idl, ovs_idl,
                                                   routing_tables)
    elif CONF.exposing_method == constants.EXPOSE_METHOD_OVN:
        return _ensure_base_wiring_config_ovn(ovs_idl, ovn_idl)


def _ensure_base_wiring_config_underlay(idl, ovs_idl, routing_tables):
    # Get bridge mappings: xxxx:br-ex,yyyy:br-ex2
    bridge_mappings = ovs_idl.get_ovn_bridge_mappings()

    ovn_bridge_mappings = {}
    flows_info = {}
    for bridge_index, bridge_mapping in enumerate(bridge_mappings, 1):
        network, bridge = helpers.parse_bridge_mapping(bridge_mapping)
        if not network:
            continue
        ovn_bridge_mappings[network] = bridge

        linux_net.ensure_routing_table_for_bridge(
            routing_tables, bridge, CONF.bgp_vrf_table_id)
        vlan_tags = idl.get_network_vlan_tag_by_network_name(network)

        for vlan_tag in vlan_tags:
            linux_net.ensure_vlan_device_for_network(bridge,
                                                     vlan_tag)

        linux_net.ensure_arp_ndp_enabled_for_bridge(bridge,
                                                    bridge_index,
                                                    vlan_tags)
        if not flows_info.get(bridge):
            mac = linux_net.get_interface_address(bridge)
            flows_info[bridge] = {'mac': mac, 'in_port': set()}
            flows_info[bridge]['in_port'] = ovs.get_ovs_patch_ports_info(
                bridge)
            ovs.ensure_mac_tweak_flows(bridge, mac,
                                       flows_info[bridge]['in_port'],
                                       constants.OVS_RULE_COOKIE)
    return ovn_bridge_mappings, flows_info


def _ensure_base_wiring_config_ovn(ovs_idl, ovn_idl):
    """Base configuration for extra OVN cluster instead of kernel networking

    This function is in charge of the steps to ensure the in-node OVN cluster
    is properly configured by:
    1. Get the information about the OpenStack provider bridge(s) and the flows
       info, such as the mac and the in_port
    2. Add the egress ovs flows so that the destination mac is the one on the
       extra ovn-cluster, in the LR
    3. Create the LR in the in-node OVN cluster
    4. Create the LR policy in the in-node OVN cluster to redirect the traffic
       (with ECMP support) to the nexthops
    5. Create the LR routes in the in-node OVN cluster to route any traffic the
       peers IPs
    6. Create the LS (+ Localnet port) for the connection between the router
       and the OpenStack OVN networks. then it connects it to the LR
    7. Create the LS (+ Localnet port) for the connection between the router
       and the external network. Then it connects it to the LR
    8. Create the ingress_flow at the external OVN provider bridges to
       redirect the needed traffic to the in-cluster OVN networks

    :param ovs_idl: The idl to communicate with local ovs DB
    :param ovn_idl: The idl to communicate with local (in-node) NB DB
    :return: ovn_bridge_mappings (network and bridges association) and the
             flows_info per bridge
    """
    # OpenStack Egress part
    # Get bridge mappings: xxxx:br-ex,yyyy:br-ex2
    bridge_mappings = ovs_idl.get_ovn_bridge_mappings()
    ovn_bridge_mappings = {}
    flows_info = {}
    for bridge_mapping in bridge_mappings:
        network, bridge = helpers.parse_bridge_mapping(bridge_mapping)
        if not network:
            continue
        ovn_bridge_mappings[network] = bridge

        if not flows_info.get(bridge):
            mac = linux_net.get_interface_address(bridge)
            flows_info[bridge] = {'mac': mac, 'in_port': set()}
            flows_info[bridge]['in_port'] = ovs.get_ovs_patch_ports_info(
                bridge)
        _ensure_egress_flows(bridge, flows_info[bridge]['in_port'])

    # Extra OVN cluster configuration
    provider_cidrs = CONF.local_ovn_cluster.provider_networks_pool_prefixes

    # LR
    cmds = []
    cmds.extend(_ensure_ovn_router(ovn_idl))
    # FIXME(ltomasbo): we need to firsts create the router and then the
    # policies and routes in a different transaction until ovsdbapp
    # allows it to do it in one transaction. Once that happen the next
    # 2 lines can be removed
    _execute_commands(ovn_idl, cmds)
    cmds = []
    cmds.extend(_ensure_ovn_policies(ovn_idl, CONF.local_ovn_cluster.peer_ips))
    cmds.extend(_ensure_ovn_routes(ovn_idl, CONF.local_ovn_cluster.peer_ips))
    # Creation of all router related cmds in a single transaction
    _execute_commands(ovn_idl, cmds)

    # LS
    bgp_bridge_mappings = ovs_idl.get_ovn_bridge_mappings(
        bridge=constants.OVN_CLUSTER_BRIDGE)
    for bridge_mapping in bgp_bridge_mappings:
        network, bridge = helpers.parse_bridge_mapping(bridge_mapping)
        if not network:
            continue
        # Create LS + Localnet port on it
        _ensure_ovn_switch(ovn_idl, network)

        # differentiate between internal LS (connecting to OpenStack)
        # and external LS (connecting to the NICs)
        if bridge in ovn_bridge_mappings.values():
            # Internal Bridge connecting to OpenStack OVN cluster
            _ensure_ovn_network_link(ovn_idl, network, 'internal',
                                     provider_cidrs=provider_cidrs)
        else:
            ip, mac = linux_net.get_nic_info(bridge)
            # External Bridge connecting to the external networks
            _ensure_ovn_network_link(ovn_idl, network, 'external',
                                     ip=ip, mac=mac)
            _ensure_ingress_flows(bridge, mac, network, provider_cidrs)

    return ovn_bridge_mappings, flows_info


def _ensure_ovn_router(ovn_idl):
    return [ovn_idl.lr_add(constants.OVN_CLUSTER_ROUTER, may_exist=True)]


def _ensure_ovn_switch(ovn_idl, switch_name):
    ovn_idl.ls_add(switch_name, may_exist=True).execute(check_error=True)

    # Add localnet port to them
    localnet_port = "{}-localnet".format(switch_name)
    options = {'network_name': switch_name}
    cmds = _ensure_lsp_cmds(ovn_idl, localnet_port, switch_name, 'localnet',
                            'unknown', **options)
    _execute_commands(ovn_idl, cmds)


def _execute_commands(idl, cmds):
    with idl.transaction(check_error=True) as txn:
        for command in cmds:
            txn.add(command)


def _ensure_ovn_network_link(ovn_idl, switch_name, direction,
                             provider_cidrs=None, ip=None, mac=None):
    """Base configuration for connecting LR and LSs

    This function is in charge of connecting the LR to the external or internal
    LS

    For the internal LS it configures:
    1. Creates LRP to connect to the internal switch
    2. If networks (provider_cidrs) are different, adding the new networks
    3. Create LSP related to the LRP with the right options, including the
       arp_proxy
    4. Bind the LRP to the local chassis

    For the external LS it configures:
    1. Creates LRP to connect to the external switch
    2. If networks (ip) is different than the nic network add the nic network
       and remove the extra ones
    3. Create LSP related to the LRP with the right options

    :param ovn_idl: The idl to communicate with local (in-node) NB DB
    :param switch_name: the name of the logical switch to configure
    :param direction: can be 'internal' or 'external'
    :param provider_cidrs (optional): CIDRs to configure the networks of the
                                      LRP, as well as to configure the ARP
                                      proxy on the internal LSP
                                      (only for the internal)
    :param ip (optional): IP to configure in the LRP connected to the external
                          switch (only for the external)
    :param mac (optional): MAC to configure in the LRP connected to the
                           external switch (only for the external)
    """
    # It accepts 2 values for direction: internal or external
    cmds = []
    if direction == 'internal':
        # Connect BGP router to the internal logical switch
        r_port_name = "{}-openstack".format(constants.OVN_CLUSTER_ROUTER)
        try:
            ovn_idl.lrp_add(constants.OVN_CLUSTER_ROUTER, r_port_name,
                            constants.OVN_CLUSTER_ROUTER_INTERNAL_MAC,
                            provider_cidrs, peer=[], may_exist=True).execute(
                check_error=True)
        except RuntimeError as rte:
            # TODO(ltomasbo): Change OVSDBAPP to return a different error for
            # this to avoid having to compare strings as this is error prone
            networks_message = 'with different networks'
            if networks_message not in str(rte):
                raise
            # Trying to sync the networks by adding them
            cmds.append(ovn_idl.lrp_add_networks(r_port_name, provider_cidrs,
                                                 may_exist=True))

        s_port_name = "openstack-{}".format(constants.OVN_CLUSTER_ROUTER)
        # NOTE(ltomasbo): require v23.06.0 so that proxy-arp works as expected.
        # If older version the provider_cidrs should contain all the provider
        # network cidrs, pointing to the gateway IP of the network.
        cidrs = ','.join(provider_cidrs) if provider_cidrs else '0.0.0.0/0'
        options = {'router-port': r_port_name, 'arp_proxy': cidrs}
        cmds.extend(_ensure_lsp_cmds(ovn_idl, s_port_name, switch_name,
                                     'router', 'router', **options))
        # bind to local chassis
        # ovn-nbctl lrp-set-gateway-chassis  bgp-router-public bgp 1
        cmds.append(ovn_idl.lrp_set_gateway_chassis(
            r_port_name, constants.OVN_CLUSTER_BRIDGE, 1))
    else:  # direction == 'external'
        # Connect BGP router to the external logical switch
        r_port_name = "{}-{}".format(constants.OVN_CLUSTER_ROUTER, switch_name)
        # LRP
        try:
            ovn_idl.lrp_add(constants.OVN_CLUSTER_ROUTER, r_port_name,
                            mac, [ip], peer=[], may_exist=True).execute(
                check_error=True)
        except RuntimeError as rte:
            # TODO(ltomasbo): Change OVSDBAPP to return a different error for
            # this to avoid having to compare strings as this is error prone
            networks_message = 'with different networks'
            if networks_message not in str(rte):
                raise
            # Trying to sync the networks by adding them
            cmds.append(ovn_idl.lrp_add_networks(r_port_name,
                                                 [ip],
                                                 may_exist=True))
            lrp = ovn_idl.lrp_get(r_port_name).execute(check_error=True)
            for net in lrp.networks:
                if net != ip:
                    cmds.append(ovn_idl.lrp_del_networks(r_port_name,
                                                         [net],
                                                         if_exists=True))
        # LSP
        s_port_name = "{}-{}".format(switch_name, constants.OVN_CLUSTER_ROUTER)
        options = {'router-port': r_port_name}
        cmds.extend(_ensure_lsp_cmds(ovn_idl, s_port_name, switch_name,
                                     'router', 'router', **options))

    if cmds:
        _execute_commands(ovn_idl, cmds)


def _ensure_lsp_cmds(ovn_idl, port_name, switch, port_type, addresses,
                     **options):
    cmds = []
    cmds.append(ovn_idl.lsp_add(switch, port_name, may_exist=True))
    cmds.append(ovn_idl.lsp_set_type(port_name, port_type))
    cmds.append(ovn_idl.lsp_set_addresses(port_name,
                                          addresses=[addresses]))
    cmds.append(ovn_idl.lsp_set_options(port_name, **options))
    return cmds


def _ensure_ovn_policies(ovn_idl, next_hops):
    priority = 10
    match = 'inport=="{}-openstack"'.format(constants.OVN_CLUSTER_ROUTER)
    action = 'reroute'
    columns = {}
    if len(next_hops) > 1:
        columns = {'nexthops': next_hops}
    elif len(next_hops) == 1:
        columns = {'nexthop': next_hops[0]}

    return [ovn_idl.lr_policy_add(constants.OVN_CLUSTER_ROUTER, priority,
                                  match, action, may_exist=True, **columns)]


def _ensure_ovn_routes(ovn_idl, peer_ips):
    prefix = '0.0.0.0/0'
    cmds = []
    for ip in peer_ips:
        cmds.append(ovn_idl.lr_route_add(constants.OVN_CLUSTER_ROUTER, prefix,
                                         ip, ecmp=True, may_exist=True))
    return cmds


def _ensure_ingress_flows(bridge, mac, switch_name, provider_cidrs):
    # incomming traffic flows
    # patch=`ovs-ofctl show br-ex | grep patch | cut -d "("  -f1 | xargs`
    # ovs-ofctl add-flow br-ex
    #    "cookie=0xbadcaf2,ip,nw_dst=$PROVIDER_NET,in_port=enp2s0,priority=100,
    #     actions=mod_dl_dst:$ENP2S0_MAC,output=$patch"
    if not provider_cidrs:
        return
    patch_port_prefix = 'patch-{}-'.format(switch_name)
    patch_ports = ovs.get_ovs_patch_ports_info(bridge,
                                               prefix=patch_port_prefix)
    if not patch_ports:
        return
    bridge_ports = set(ovs.get_ovs_ports_info(bridge))
    external_nic = list(bridge_ports.intersection(
        set(CONF.local_ovn_cluster.external_nics)))

    if not external_nic:
        LOG.warning("NIC ports (%s) not found for bridge %s. Not possible to "
                    "create the ingress flows. It will be retried if "
                    "reconcile cycle is not disabled",
                    CONF.local_ovn_cluster.external_nics, bridge)
        return
    else:
        # only one external_nic expected per bridge
        external_nic = external_nic[0]

    for provider_cidr in provider_cidrs:
        ip_version = linux_net.get_ip_version(provider_cidr)
        if ip_version == constants.IP_VERSION_6:
            ip = 'ipv6'
        else:
            ip = 'ip'
        flow = (
            "cookie={},priority=1000,{},nw_dst={},in_port={},"
            " actions=mod_dl_dst:{},output={}".format(
                constants.OVS_RULE_COOKIE, ip, provider_cidr, external_nic,
                mac, patch_ports[0]))
        ovs.ensure_flow(bridge, flow)


def _ensure_egress_flows(bridge, patch_ports):
    # outcomming traffic flows
    # patch=`ovs-ofctl show br-provider | grep patch | grep provnet |
    #     cut -d "("  -f1 | xargs`
    # ovs-ofctl add-flow br-provider "cookie=0xbadcaf3,ip,in_port=$patch,
    #     actions=mod_dl_dst:$ROUTER_MAC,NORMAL"
    for patch_port in patch_ports:
        flow = (
            "cookie={},priority=1000,ip,in_port={},"
            " actions=mod_dl_dst:{},NORMAL".format(
                constants.OVS_RULE_COOKIE, patch_port,
                constants.OVN_CLUSTER_ROUTER_INTERNAL_MAC))
        flow_v6 = (
            "cookie={},priority=1000,ipv6,in_port={},"
            " actions=mod_dl_dst:{},NORMAL".format(
                constants.OVS_RULE_COOKIE, patch_port,
                constants.OVN_CLUSTER_ROUTER_INTERNAL_MAC))
        ovs.ensure_flow(bridge, flow)
        ovs.ensure_flow(bridge, flow_v6)


def cleanup_wiring(idl, bridge_mappings, ovs_flows, exposed_ips,
                   routing_tables, routing_tables_routes):
    if CONF.exposing_method == constants.EXPOSE_METHOD_UNDERLAY:
        return _cleanup_wiring_underlay(idl, bridge_mappings, ovs_flows,
                                        exposed_ips, routing_tables,
                                        routing_tables_routes)
    elif CONF.exposing_method == constants.EXPOSE_METHOD_OVN:
        # TODO(ltomasbo): clean up old policies, routes and proxy_arps cidrs
        return True


def _cleanup_wiring_underlay(idl, bridge_mappings, ovs_flows, exposed_ips,
                             routing_tables, routing_tables_routes):
    current_ips = linux_net.get_exposed_ips(CONF.bgp_nic)
    expected_ips = [ip for ip_dict in exposed_ips.values()
                    for ip in ip_dict.keys()]

    ips_to_delete = [ip for ip in current_ips if ip not in expected_ips]
    linux_net.delete_exposed_ips(ips_to_delete, CONF.bgp_nic)

    extra_routes = {}
    for bridge in bridge_mappings.values():
        extra_routes[bridge] = (
            linux_net.get_extra_routing_table_for_bridge(routing_tables,
                                                         bridge))
        # delete extra ovs flows
        ovs.remove_extra_ovs_flows(ovs_flows, bridge,
                                   constants.OVS_RULE_COOKIE)

    # get rules and delete the old ones
    ovn_ip_rules = linux_net.get_ovn_ip_rules(routing_tables.values())
    if ovn_ip_rules:
        for ip in expected_ips:
            if len(ip.split("/")) == 1:
                ip_version = linux_net.get_ip_version(ip)
                if ip_version == constants.IP_VERSION_6:
                    ip_dst = "{}/128".format(ip)
                else:
                    ip_dst = "{}/32".format(ip)
            else:
                ip_dst = ip
            ovn_ip_rules.pop(ip_dst, None)
    linux_net.delete_ip_rules(ovn_ip_rules)

    # remove all the extra routes not needed
    linux_net.delete_bridge_ip_routes(routing_tables, routing_tables_routes,
                                      extra_routes)

    # delete leaked vlan devices from previous vlan provider networks
    delete_vlan_devices_leftovers(idl, bridge_mappings)


def delete_vlan_devices_leftovers(idl, bridge_mappings):
    vlan_tags = idl.get_network_vlan_tags()
    ovs_devices = set(bridge_mappings.values())
    for ovs_device in ovs_devices:
        vlans = linux_net.get_bridge_vlans(ovs_device)
        for vlan in vlans:
            if vlan and vlan not in vlan_tags:
                linux_net.delete_vlan_device_for_network(ovs_device, vlan)


def wire_provider_port(routing_tables_routes, ovs_flows, port_ips,
                       bridge_device, bridge_vlan, localnet, routing_table,
                       proxy_cidrs, lladdr=None, mac=None, ovn_idl=None):
    if CONF.exposing_method == constants.EXPOSE_METHOD_UNDERLAY:
        return _wire_provider_port_underlay(routing_tables_routes, ovs_flows,
                                            port_ips, bridge_device,
                                            bridge_vlan, localnet,
                                            routing_table, proxy_cidrs,
                                            lladdr=lladdr)
    elif CONF.exposing_method == constants.EXPOSE_METHOD_OVN:
        # We need to add a static mac binding due to proxy-arp issue in
        # core ovn that would reply on the incomming traffic from the LR,
        # while it should not
        return _wire_provider_port_ovn(ovn_idl, port_ips, mac)


def unwire_provider_port(routing_tables_routes, port_ips, bridge_device,
                         bridge_vlan, routing_table, proxy_cidrs, lladdr=None,
                         ovn_idl=None):
    if CONF.exposing_method == constants.EXPOSE_METHOD_UNDERLAY:
        return _unwire_provider_port_underlay(routing_tables_routes, port_ips,
                                              bridge_device, bridge_vlan,
                                              routing_table, proxy_cidrs,
                                              lladdr=lladdr)
    elif CONF.exposing_method == constants.EXPOSE_METHOD_OVN:
        # We need to remove thestatic mac binding added due to proxy-arp issue
        # in core ovn that would reply on the incomming traffic from the LR,
        # while it should not
        return _unwire_provider_port_ovn(ovn_idl, port_ips)


def _ensure_updated_mac_tweak_flows(localnet, bridge_device, ovs_flows):
    ofport = ovs.get_ovs_patch_port_ofport(localnet)
    if ofport not in ovs_flows[bridge_device]['in_port']:
        ovs_flows[bridge_device]['in_port'].append(ofport)
        ovs.ensure_mac_tweak_flows(bridge_device,
                                   ovs_flows[bridge_device]['mac'],
                                   [ofport],
                                   constants.OVS_RULE_COOKIE)


def _wire_provider_port_underlay(routing_tables_routes, ovs_flows, port_ips,
                                 bridge_device, bridge_vlan, localnet,
                                 routing_table, proxy_cidrs, lladdr=None):
    if not bridge_device:
        return False
    for ip in port_ips:
        try:
            if lladdr:
                dev = bridge_device
                if bridge_vlan:
                    dev = '{}.{}'.format(dev, bridge_vlan)
                linux_net.add_ip_rule(ip, routing_table[bridge_device],
                                      dev=dev, lladdr=lladdr)
            else:
                linux_net.add_ip_rule(ip, routing_table[bridge_device])
        except agent_exc.InvalidPortIP:
            LOG.exception("Invalid IP to create a rule for port on the "
                          "provider network: %s", ip)
            return False
        linux_net.add_ip_route(routing_tables_routes, ip,
                               routing_table[bridge_device], bridge_device,
                               vlan=bridge_vlan)
    # add proxy ndp config for ipv6
    for n_cidr in proxy_cidrs:
        if linux_net.get_ip_version(n_cidr) == constants.IP_VERSION_6:
            linux_net.add_ndp_proxy(n_cidr, bridge_device, bridge_vlan)
    # NOTE(ltomasbo): This is needed as the patch ports are not created
    # until the first VM/FIP in that provider network is created in a node
    try:
        _ensure_updated_mac_tweak_flows(localnet, bridge_device, ovs_flows)
    except agent_exc.PatchPortNotFound:
        LOG.warning("Patch port %s for bridge %s not found. Not possible to "
                    "create the needed ovs flows for the outgoing traffic. "
                    "It will be retried at the resync.", localnet,
                    bridge_device)
        return False
    return True


def _wire_provider_port_ovn(ovn_idl, port_ips, mac):
    cmds = []
    port = "{}-openstack".format(constants.OVN_CLUSTER_ROUTER)
    for port_ip in port_ips:
        cmds.append(ovn_idl.static_mac_binding_add(
            port, port_ip, mac, override_dynamic_mac=True, may_exist=True))
    if cmds:
        _execute_commands(ovn_idl, cmds)
    # to keep it consisten with the underlay method
    return True


def _unwire_provider_port_underlay(routing_tables_routes, port_ips,
                                   bridge_device, bridge_vlan, routing_table,
                                   proxy_cidrs, lladdr=None):
    if not bridge_device:
        return False
    for ip in port_ips:
        if lladdr:
            if linux_net.get_ip_version(ip) == constants.IP_VERSION_6:
                cr_lrp_ip = '{}/128'.format(ip)
            else:
                cr_lrp_ip = '{}/32'.format(ip)
            try:
                dev = bridge_device
                if bridge_vlan:
                    dev = '{}.{}'.format(dev, bridge_vlan)
                linux_net.del_ip_rule(cr_lrp_ip, routing_table[bridge_device],
                                      dev=dev, lladdr=lladdr)
            except agent_exc.InvalidPortIP:
                LOG.exception("Invalid IP to delete a rule for the "
                              "provider port: %s", cr_lrp_ip)
                return False
        else:
            try:
                linux_net.del_ip_rule(ip, routing_table[bridge_device])
            except agent_exc.InvalidPortIP:
                LOG.exception("Invalid IP to delete a rule for the "
                              "provider port: %s", ip)
                return False
        linux_net.del_ip_route(routing_tables_routes, ip,
                               routing_table[bridge_device], bridge_device,
                               vlan=bridge_vlan)
    for n_cidr in proxy_cidrs:
        if linux_net.get_ip_version(n_cidr) == constants.IP_VERSION_6:
            linux_net.del_ndp_proxy(n_cidr, bridge_device, bridge_vlan)
    return True


def _unwire_provider_port_ovn(ovn_idl, port_ips):
    cmds = []
    port = "{}-openstack".format(constants.OVN_CLUSTER_ROUTER)
    for port_ip in port_ips:
        cmds.append(ovn_idl.static_mac_binding_del(
            port, port_ip, if_exists=True))
    if cmds:
        _execute_commands(ovn_idl, cmds)
    # to keep it consisten with the underlay method
    return True


def wire_lrp_port(routing_tables_routes, ip, bridge_device, bridge_vlan,
                  routing_tables, cr_lrp_ips):
    if CONF.exposing_method == constants.EXPOSE_METHOD_UNDERLAY:
        return _wire_lrp_port_underlay(routing_tables_routes, ip,
                                       bridge_device, bridge_vlan,
                                       routing_tables, cr_lrp_ips)
    elif CONF.exposing_method == constants.EXPOSE_METHOD_OVN:
        # TODO(ltomasbo): Add flow on br-ex(-X)
        # ovs-ofctl add-flow br-ex
        # "cookie=0xbadcaf2,ip,nw_dst=20.0.0.0/24,in_port=enp2s0,priority=100,
        # actions=mod_dl_dst:$ENP2S0_MAC,output=$patch"
        # Add router route to go through cr-lrp ip:
        # ovn-nbctl lr-route-add bgp-router 20.0.0.0/24 172.16.100.143
        #     bgp-router-public
        return


def _wire_lrp_port_underlay(routing_tables_routes, ip, bridge_device,
                            bridge_vlan, routing_tables, cr_lrp_ips):
    if not bridge_device:
        return False
    LOG.debug("Adding IP Rules for network %s", ip)
    try:
        linux_net.add_ip_rule(ip, routing_tables[bridge_device])
    except agent_exc.InvalidPortIP:
        LOG.exception("Invalid IP to create a rule for the lrp (network "
                      "router interface) port: %s", ip)
        return False
    LOG.debug("Added IP Rules for network %s", ip)

    LOG.debug("Adding IP Routes for network %s", ip)
    # NOTE(ltomasbo): This assumes the provider network can only have
    # (at most) 2 subnets, one for IPv4, one for IPv6
    ip_version = linux_net.get_ip_version(ip)
    for cr_lrp_ip in cr_lrp_ips:
        if linux_net.get_ip_version(cr_lrp_ip) == ip_version:
            linux_net.add_ip_route(
                routing_tables_routes,
                ip.split("/")[0],
                routing_tables[bridge_device],
                bridge_device,
                vlan=bridge_vlan,
                mask=ip.split("/")[1],
                via=cr_lrp_ip)
            break
    LOG.debug("Added IP Routes for network %s", ip)
    return True


def unwire_lrp_port(routing_tables_routes, ip, bridge_device, bridge_vlan,
                    routing_tables, cr_lrp_ips):
    if CONF.exposing_method == constants.EXPOSE_METHOD_UNDERLAY:
        return _unwire_lrp_port_underlay(routing_tables_routes, ip,
                                         bridge_device, bridge_vlan,
                                         routing_tables, cr_lrp_ips)
    elif CONF.exposing_method == constants.EXPOSE_METHOD_OVN:
        # TODO(ltomasbo): Remove flow(s) and router route
        return


def _unwire_lrp_port_underlay(routing_tables_routes, ip, bridge_device,
                              bridge_vlan, routing_tables, cr_lrp_ips):
    if not bridge_device:
        return False
    LOG.debug("Deleting IP Rules for network %s", ip)
    try:
        linux_net.del_ip_rule(ip, routing_tables[bridge_device])
    except agent_exc.InvalidPortIP:
        LOG.exception("Invalid IP to delete a rule for the "
                      "lrp (network router interface) port: %s", ip)
        return False
    LOG.debug("Deleted IP Rules for network %s", ip)

    LOG.debug("Deleting IP Routes for network %s", ip)
    ip_version = linux_net.get_ip_version(ip)
    for cr_lrp_ip in cr_lrp_ips:
        if linux_net.get_ip_version(cr_lrp_ip) == ip_version:
            linux_net.del_ip_route(
                routing_tables_routes,
                ip.split("/")[0],
                routing_tables[bridge_device],
                bridge_device,
                vlan=bridge_vlan,
                mask=ip.split("/")[1],
                via=cr_lrp_ip)
    LOG.debug("Deleted IP Routes for network %s", ip)
    return True

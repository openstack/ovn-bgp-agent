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


def ensure_base_wiring_config(idl, bridge_mappings, routing_tables):
    if CONF.exposing_method == constants.EXPOSE_METHOD_UNDERLAY:
        return _ensure_base_wiring_config_underlay(idl, bridge_mappings,
                                                   routing_tables)
    elif CONF.exposing_method == constants.EXPOSE_METHOD_OVN:
        raise NotImplementedError()


def _ensure_base_wiring_config_underlay(idl, bridge_mappings, routing_tables):
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
            flows_info[bridge] = {'mac': mac, 'in_port': set([])}
            flows_info[bridge]['in_port'] = ovs.get_ovs_patch_ports_info(
                bridge)
            ovs.ensure_mac_tweak_flows(bridge, mac,
                                       flows_info[bridge]['in_port'],
                                       constants.OVS_RULE_COOKIE)
    return ovn_bridge_mappings, flows_info


def cleanup_wiring(idl, bridge_mappings, ovs_flows, exposed_ips,
                   routing_tables, routing_tables_routes):
    if CONF.exposing_method == constants.EXPOSE_METHOD_UNDERLAY:
        return _cleanup_wiring_underlay(idl, bridge_mappings, ovs_flows,
                                        exposed_ips, routing_tables,
                                        routing_tables_routes)
    elif CONF.exposing_method == constants.EXPOSE_METHOD_OVN:
        raise NotImplementedError()


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
            ip_version = linux_net.get_ip_version(ip)
            if ip_version == constants.IP_VERSION_6:
                ip_dst = "{}/128".format(ip)
            else:
                ip_dst = "{}/32".format(ip)
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
                       proxy_cidrs, lladdr=None):
    if CONF.exposing_method == constants.EXPOSE_METHOD_UNDERLAY:
        return _wire_provider_port_underlay(routing_tables_routes, ovs_flows,
                                            port_ips, bridge_device,
                                            bridge_vlan, localnet,
                                            routing_table, proxy_cidrs,
                                            lladdr=lladdr)
    elif CONF.exposing_method == constants.EXPOSE_METHOD_OVN:
        # No need to wire anything
        return True


def unwire_provider_port(routing_tables_routes, port_ips, bridge_device,
                         bridge_vlan, routing_table, proxy_cidrs, lladdr=None):
    if CONF.exposing_method == constants.EXPOSE_METHOD_UNDERLAY:
        return _unwire_provider_port_underlay(routing_tables_routes, port_ips,
                                              bridge_device, bridge_vlan,
                                              routing_table, proxy_cidrs,
                                              lladdr=lladdr)
    elif CONF.exposing_method == constants.EXPOSE_METHOD_OVN:
        # No need to wire anything
        return True


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
    if proxy_cidrs:
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
    if proxy_cidrs:
        for n_cidr in proxy_cidrs:
            if linux_net.get_ip_version(n_cidr) == constants.IP_VERSION_6:
                linux_net.del_ndp_proxy(n_cidr, bridge_device, bridge_vlan)
    return True


def wire_lrp_port(routing_tables_routes, ip, bridge_device, bridge_vlan,
                  routing_table, cr_lrp_ips):
    if not bridge_device:
        return False
    LOG.debug("Adding IP Rules for network %s", ip)
    try:
        linux_net.add_ip_rule(ip, routing_table[bridge_device])
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
                routing_table[bridge_device],
                bridge_device,
                vlan=bridge_vlan,
                mask=ip.split("/")[1],
                via=cr_lrp_ip)
            break
    LOG.debug("Added IP Routes for network %s", ip)
    return True


def unwire_lrp_port(routing_tables_routes, ip, bridge_device, bridge_vlan,
                    routing_table, cr_lrp_ips):
    if not bridge_device:
        return False
    LOG.debug("Deleting IP Rules for network %s", ip)
    try:
        linux_net.del_ip_rule(ip, routing_table[bridge_device])
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
                routing_table[bridge_device],
                bridge_device,
                vlan=bridge_vlan,
                mask=ip.split("/")[1],
                via=cr_lrp_ip)
    LOG.debug("Deleted IP Routes for network %s", ip)
    return True

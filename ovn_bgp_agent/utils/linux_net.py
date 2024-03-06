# Copyright 2021 Red Hat, Inc.
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

import ipaddress
import random
import re
import sys

import netaddr
from oslo_log import log as logging
import pyroute2
from pyroute2.netlink import exceptions as netlink_exceptions
import tenacity

from ovn_bgp_agent import constants
from ovn_bgp_agent import exceptions as agent_exc
import ovn_bgp_agent.privileged.linux_net
from ovn_bgp_agent.utils import common as common_utils

LOG = logging.getLogger(__name__)

RE_TABLE_ROW = re.compile(r"^(?P<table>[0-9]+)\s+(?P<bridge>\S+)")


def get_ip_version(ip):
    # IP network can consume both an IP address and a network with cidr
    # notation
    return netaddr.IPNetwork(ip).version


@tenacity.retry(
    retry=tenacity.retry_if_exception_type(
        netlink_exceptions.NetlinkDumpInterrupted),
    wait=tenacity.wait_exponential(multiplier=0.02, max=1),
    stop=tenacity.stop_after_delay(8),
    reraise=True)
def get_interfaces(filter_out=[]):
    with pyroute2.IPRoute() as ipr:
        return [iface.get_attr('IFLA_IFNAME') for iface in ipr.get_links()
                if iface.get_attr('IFLA_IFNAME') not in filter_out]


@tenacity.retry(
    retry=tenacity.retry_if_exception_type(
        netlink_exceptions.NetlinkDumpInterrupted),
    wait=tenacity.wait_exponential(multiplier=0.02, max=1),
    stop=tenacity.stop_after_delay(8),
    reraise=True)
def get_interface_index(nic):
    try:
        with pyroute2.IPRoute() as ipr:
            return ipr.link_lookup(ifname=nic)[0]
    except IndexError:
        raise agent_exc.NetworkInterfaceNotFound(device=nic)


@tenacity.retry(
    retry=tenacity.retry_if_exception_type(
        netlink_exceptions.NetlinkDumpInterrupted),
    wait=tenacity.wait_exponential(multiplier=0.02, max=1),
    stop=tenacity.stop_after_delay(8),
    reraise=True)
def get_interface_address(nic):
    try:
        with pyroute2.IPRoute() as ipr:
            idx = ipr.link_lookup(ifname=nic)[0]
            return ipr.get_links(idx)[0].get_attr('IFLA_ADDRESS')
    except IndexError:
        raise agent_exc.NetworkInterfaceNotFound(device=nic)


@tenacity.retry(
    retry=tenacity.retry_if_exception_type(
        netlink_exceptions.NetlinkDumpInterrupted),
    wait=tenacity.wait_exponential(multiplier=0.02, max=1),
    stop=tenacity.stop_after_delay(8),
    reraise=True)
def get_nic_info(nic):
    try:
        with pyroute2.IPRoute() as ipr:
            idx = ipr.link_lookup(ifname=nic)[0]
            nic_addr = ipr.get_addr(index=idx)[0]
            ip = '{}/{}'.format(
                nic_addr.get_attr('IFA_ADDRESS'),
                nic_addr.get('prefixlen'))
            mac = ipr.get_links(idx)[0].get_attr('IFLA_ADDRESS')
            return ip, mac
    except IndexError:
        raise agent_exc.NetworkInterfaceNotFound(device=nic)


def ensure_vrf(vrf_name, vrf_table):
    ovn_bgp_agent.privileged.linux_net.ensure_vrf(vrf_name, vrf_table)


def ensure_bridge(bridge_name):
    ovn_bgp_agent.privileged.linux_net.ensure_bridge(bridge_name)


def ensure_vxlan(vxlan_name, vni, local_ip, dstport):
    ovn_bgp_agent.privileged.linux_net.ensure_vxlan(vxlan_name, vni, local_ip,
                                                    dstport)


def ensure_veth(veth_name, veth_peer):
    ovn_bgp_agent.privileged.linux_net.ensure_veth(veth_name, veth_peer)


def set_master_for_device(device, master):
    ovn_bgp_agent.privileged.linux_net.set_master_for_device(device, master)


def ensure_dummy_device(device):
    ovn_bgp_agent.privileged.linux_net.ensure_dummy_device(device)


def ensure_ovn_device(ovn_ifname, vrf_name):
    ensure_dummy_device(ovn_ifname)
    set_master_for_device(ovn_ifname, vrf_name)


def delete_device(device):
    ovn_bgp_agent.privileged.linux_net.delete_device(device)


def ensure_arp_ndp_enabled_for_bridge(bridge, offset, vlan_tag=None):
    ipv4 = "%s%d.%s" % (
        constants.ARP_IPV4_PREFIX, offset / constants.IPV4_OCTET_RANGE,
        offset % constants.IPV4_OCTET_RANGE)
    ipv6 = "%s%x" % (constants.NDP_IPV6_PREFIX, offset)

    for ip in (ipv4, ipv6):
        try:
            ovn_bgp_agent.privileged.linux_net.add_ip_to_dev(ip, bridge)
        except agent_exc.IpAddressAlreadyExists:
            LOG.debug("IP %s already added on bridge %s", ip, bridge)
        except KeyError as e:
            if "object exists" not in str(e):
                LOG.error("Unable to add IP on bridge %s to enable arp/ndp. "
                          "Exception: %s", bridge, e)
                raise

    # also enable the arp/ndp on the bridge in case there are flat networks
    enable_proxy_arp(bridge)
    enable_proxy_ndp(bridge)


def ensure_routing_table_for_bridge(ovn_routing_tables, bridge, vrf_table):
    # check a routing table with the bridge name exists on
    # /etc/iproute2/rt_tables
    found_tables = {vrf_table}

    with open(constants.ROUTING_TABLES_FILE, 'r') as rt_file:
        for line in rt_file.readlines():
            match = RE_TABLE_ROW.match(line)
            if match:
                if match.group('bridge') == bridge:
                    # We don't need to catch exception for TypeError because
                    # the regular expression matches only integers
                    ovn_routing_tables[match.group('bridge')] = int(
                        match.group('table'))
                    LOG.debug("Found routing table for %s with: %s",
                              bridge, match.group('table'))
                    break
                else:
                    found_tables.add(int(match.group('table')))
        else:
            LOG.debug("Routing table for bridge %s not configured at ", bridge)
            try:
                routing_table_range = set(
                    range(constants.ROUTING_TABLE_MIN,
                          constants.ROUTING_TABLE_MAX + 1))
                table_number = random.choice(
                    list(routing_table_range - found_tables))
            except IndexError:
                LOG.error("No more routing tables available for bridge %s "
                          "at %s", constants.ROUTING_TABLES_FILE, bridge)
                sys.exit(1)
            ovn_bgp_agent.privileged.linux_net.create_routing_table_for_bridge(
                table_number, bridge)
            ovn_routing_tables[bridge] = int(table_number)
            LOG.debug("Added routing table for %s with number: %s",
                      bridge, table_number)

    return _ensure_routing_table_routes(ovn_routing_tables, bridge)


@tenacity.retry(
    retry=tenacity.retry_if_exception_type(
        netlink_exceptions.NetlinkDumpInterrupted),
    wait=tenacity.wait_exponential(multiplier=0.02, max=1),
    stop=tenacity.stop_after_delay(8),
    reraise=True)
def _ensure_routing_table_routes(ovn_routing_tables, bridge):
    # add default route on that table if it does not exist
    extra_routes = []
    bridge_idx = get_interface_index(bridge)

    with pyroute2.IPRoute() as ip:
        table_route_dsts = {
            (r.get_attr('RTA_DST'), r['dst_len'])
            for r in ip.get_routes(table=ovn_routing_tables[bridge])
        }

        if not table_route_dsts:
            r1 = {'dst': 'default', 'oif': bridge_idx,
                  'table': ovn_routing_tables[bridge], 'scope': 253,
                  'proto': 3}
            ovn_bgp_agent.privileged.linux_net.route_create(r1)

            r2 = {'dst': 'default', 'oif': bridge_idx,
                  'table': ovn_routing_tables[bridge],
                  'family': constants.AF_INET6,
                  'proto': 3}
            ovn_bgp_agent.privileged.linux_net.route_create(r2)
        else:
            route_missing = True
            route6_missing = True
            for (dst, dst_len) in table_route_dsts:
                if not dst:  # default route
                    try:
                        route = [
                            r for r in ip.get_routes(
                                table=ovn_routing_tables[bridge],
                                family=constants.AF_INET)
                            if not r.get_attr('RTA_DST')][0]
                        if bridge_idx == route.get_attr('RTA_OIF'):
                            route_missing = False
                        else:
                            extra_routes.append(route)
                    except IndexError:
                        pass  # no ipv4 default rule
                    try:
                        route_6 = [
                            r for r in ip.get_routes(
                                table=ovn_routing_tables[bridge],
                                family=constants.AF_INET6)
                            if not r.get_attr('RTA_DST')][0]
                        if bridge_idx == route_6.get_attr('RTA_OIF'):
                            route6_missing = False
                        else:
                            extra_routes.append(route_6)
                    except IndexError:
                        pass  # no ipv6 default rule
                else:
                    if get_ip_version(dst) == constants.IP_VERSION_6:
                        extra_routes.append(
                            ip.get_routes(
                                table=ovn_routing_tables[bridge],
                                dst=dst,
                                dst_len=dst_len,
                                family=constants.AF_INET6)[0])
                    else:
                        extra_routes.append(
                            ip.get_routes(
                                table=ovn_routing_tables[bridge],
                                dst=dst,
                                dst_len=dst_len,
                                family=constants.AF_INET)[0])

            if route_missing:
                r = {'dst': 'default', 'oif': bridge_idx,
                     'table': ovn_routing_tables[bridge], 'scope': 253,
                     'proto': 3}
                ovn_bgp_agent.privileged.linux_net.route_create(r)
            if route6_missing:
                r = {'dst': 'default', 'oif': bridge_idx,
                     'table': ovn_routing_tables[bridge],
                     'family': constants.AF_INET6,
                     'proto': 3}
                ovn_bgp_agent.privileged.linux_net.route_create(r)
    return extra_routes


@tenacity.retry(
    retry=tenacity.retry_if_exception_type(
        netlink_exceptions.NetlinkDumpInterrupted),
    wait=tenacity.wait_exponential(multiplier=0.02, max=1),
    stop=tenacity.stop_after_delay(8),
    reraise=True)
def get_extra_routing_table_for_bridge(ovn_routing_tables, bridge):
    extra_routes = []
    bridge_idx = get_interface_index(bridge)
    with pyroute2.IPRoute() as ip:
        table_route_dsts = {
            (r.get_attr('RTA_DST'), r['dst_len'])
            for r in ip.get_routes(table=ovn_routing_tables[bridge])
        }

        if not table_route_dsts:
            return extra_routes

        for (dst, dst_len) in table_route_dsts:
            if not dst:  # default route
                try:
                    route = [
                        r for r in ip.get_routes(
                            table=ovn_routing_tables[bridge],
                            family=constants.AF_INET)
                        if not r.get_attr('RTA_DST')][0]
                    if bridge_idx != route.get_attr('RTA_OIF'):
                        extra_routes.append(route)
                except IndexError:
                    pass  # no IPv4 default rule
                try:
                    route_6 = [
                        r for r in ip.get_routes(
                            table=ovn_routing_tables[bridge],
                            family=constants.AF_INET6)
                        if not r.get_attr('RTA_DST')][0]
                    if bridge_idx != route_6.get_attr('RTA_OIF'):
                        extra_routes.append(route_6)
                except IndexError:
                    pass  # no IPv6 default rule
            else:
                if get_ip_version(dst) == constants.IP_VERSION_6:
                    extra_routes.append(
                        ip.get_routes(
                            table=ovn_routing_tables[bridge],
                            dst=dst,
                            dst_len=dst_len,
                            family=constants.AF_INET6)[0])
                else:
                    extra_routes.append(
                        ip.get_routes(
                            table=ovn_routing_tables[bridge],
                            dst=dst,
                            dst_len=dst_len,
                            family=constants.AF_INET)[0])
    return extra_routes


def ensure_vlan_device_for_network(bridge, vlan_tag):
    ovn_bgp_agent.privileged.linux_net.ensure_vlan_device_for_network(bridge,
                                                                      vlan_tag)
    device = "{}/{}".format(bridge, vlan_tag)
    enable_proxy_arp(device)
    enable_proxy_ndp(device)


def delete_vlan_device_for_network(bridge, vlan_tag):
    vlan_device_name = '{}.{}'.format(bridge, vlan_tag)
    delete_device(vlan_device_name)


def get_bridge_vlans(bridge):
    return ovn_bgp_agent.privileged.linux_net.get_bridge_vlans(bridge)


def enable_proxy_ndp(device):
    flag = "net.ipv6.conf.{}.proxy_ndp".format(device)
    ovn_bgp_agent.privileged.linux_net.set_kernel_flag(flag, 1)


def enable_proxy_arp(device):
    flag = "net.ipv4.conf.{}.proxy_arp".format(device)
    ovn_bgp_agent.privileged.linux_net.set_kernel_flag(flag, 1)


@tenacity.retry(
    retry=tenacity.retry_if_exception_type(
        netlink_exceptions.NetlinkDumpInterrupted),
    wait=tenacity.wait_exponential(multiplier=0.02, max=1),
    stop=tenacity.stop_after_delay(8),
    reraise=True)
def get_exposed_ips(nic):
    nic_idx = get_interface_index(nic)
    try:
        with pyroute2.IPRoute() as ipr:
            return [ip.get_attr('IFA_ADDRESS')
                    for ip in ipr.get_addr(index=nic_idx)
                    if ip['prefixlen'] in (32, 128)]
    except pyroute2.netlink.exceptions.NetlinkError:
        # Nic does not exist
        LOG.debug("NIC %s does not yet exist, so it does not have exposed IPs",
                  nic)
        return []


@tenacity.retry(
    retry=tenacity.retry_if_exception_type(
        netlink_exceptions.NetlinkDumpInterrupted),
    wait=tenacity.wait_exponential(multiplier=0.02, max=1),
    stop=tenacity.stop_after_delay(8),
    reraise=True)
def get_nic_ip(nic, prefixlen_filter=None):
    nic_idx = get_interface_index(nic)
    with pyroute2.IPRoute() as ipr:
        if prefixlen_filter:
            return [
                ip.get_attr('IFA_ADDRESS')
                for ip in ipr.get_addr(index=nic_idx,
                                       prefixlen=prefixlen_filter)
            ]
        else:
            return [
                ip.get_attr('IFA_ADDRESS')
                for ip in ipr.get_addr(index=nic_idx)
            ]


def get_exposed_ips_on_network(nic, network):
    exposed_ips = get_exposed_ips(nic)
    return [ip for ip in exposed_ips if ipaddress.ip_address(ip) in network]


@tenacity.retry(
    retry=tenacity.retry_if_exception_type(
        netlink_exceptions.NetlinkDumpInterrupted),
    wait=tenacity.wait_exponential(multiplier=0.02, max=1),
    stop=tenacity.stop_after_delay(8),
    reraise=True)
def get_exposed_routes_on_network(table_ids, network):
    with pyroute2.NDB() as ndb:
        # NOTE: skip bgp routes (proto 186)
        return [
            r
            for r in ndb.routes.dump()
            if r.table in table_ids and
            r.dst != "" and
            r.gateway is not None and
            r.proto != 186 and
            ipaddress.ip_address(r.gateway) in network
        ]


@tenacity.retry(
    retry=tenacity.retry_if_exception_type(
        netlink_exceptions.NetlinkDumpInterrupted),
    wait=tenacity.wait_exponential(multiplier=0.02, max=1),
    stop=tenacity.stop_after_delay(8),
    reraise=True)
def get_ovn_ip_rules(routing_tables):
    ovn_ip_rules = {}
    with pyroute2.IPRoute() as ipr:
        rules_info = [
            (rule.get_attr('FRA_TABLE'),
             "{}/{}".format(rule.get_attr('FRA_DST'), rule['dst_len']),
             rule['family'])
            for rule in (
                ipr.get_rules(family=constants.AF_INET) +
                ipr.get_rules(family=constants.AF_INET6))
            if rule.get_attr('FRA_TABLE') in routing_tables
        ]
        for table, dst, family in rules_info:
            ovn_ip_rules[dst] = {'table': table, 'family': family}
    return ovn_ip_rules


def delete_exposed_ips(ips, nic):
    ovn_bgp_agent.privileged.linux_net.delete_exposed_ips(ips, nic)


def delete_ip_rules(ip_rules):
    ovn_bgp_agent.privileged.linux_net.delete_ip_rules(ip_rules)


def delete_bridge_ip_routes(routing_tables, routing_tables_routes,
                            extra_routes):
    for device, routes_info in routing_tables_routes.items():
        if not extra_routes.get(device):
            continue
        for route_info in routes_info:
            oif = get_interface_index(device)
            if route_info['vlan']:
                vlan_device_name = '{}.{}'.format(device,
                                                  route_info['vlan'])
                oif = get_interface_index(vlan_device_name)
            if 'gateway' in route_info['route'].keys():  # subnet route
                possible_matchings = [
                    r for r in extra_routes[device]
                    if (r.get_attr('RTA_DST') == route_info['route']['dst'] and
                        r['dst_len'] == route_info['route']['dst_len'] and
                        r.get_attr('RTA_GATEWAY') == route_info['route'][
                            'gateway'])]
            else:  # cr-lrp
                possible_matchings = [
                    r for r in extra_routes[device]
                    if (r.get_attr('RTA_DST') == route_info['route']['dst'] and
                        r['dst_len'] == route_info['route']['dst_len'] and
                        r.get_attr('RTA_OIF') == oif)]
            for r in possible_matchings:
                extra_routes[device].remove(r)

    for bridge, routes in extra_routes.items():
        for route in routes:
            r_info = {'dst': route.get_attr('RTA_DST'),
                      'dst_len': route['dst_len'],
                      'family': route['family'],
                      'oif': route.get_attr('RTA_OIF'),
                      'table': routing_tables[bridge]}
            if route.get_attr('RTA_GATEWAY'):
                r_info['gateway'] = route.get_attr('RTA_GATEWAY')
            ovn_bgp_agent.privileged.linux_net.route_delete(r_info)


def delete_routes_from_table(table):
    table_routes = _get_table_routes(table)
    delete_ip_routes(table_routes)


@tenacity.retry(
    retry=tenacity.retry_if_exception_type(
        netlink_exceptions.NetlinkDumpInterrupted),
    wait=tenacity.wait_exponential(multiplier=0.02, max=1),
    stop=tenacity.stop_after_delay(8),
    reraise=True)
def _get_table_routes(table):
    with pyroute2.IPRoute() as ipr:
        return [
            r for r in ipr.get_routes(table=table)
            if r['scope'] != 254 and r['proto'] != 186
        ]


@tenacity.retry(
    retry=tenacity.retry_if_exception_type(
        netlink_exceptions.NetlinkDumpInterrupted),
    wait=tenacity.wait_exponential(multiplier=0.02, max=1),
    stop=tenacity.stop_after_delay(8),
    reraise=True)
def get_routes_on_tables(table_ids):
    routes = []
    with pyroute2.IPRoute() as ipr:
        for table_id in table_ids:
            table_routes = [
                r for r in ipr.get_routes(table=table_id)
                if r.get_attr('RTA_DST') and r['proto'] != 186
            ]
            routes.extend(table_routes)
    return routes


def delete_ip_routes(routes):
    for route in routes:
        r_info = {'dst': route.get('dst'),
                  'dst_len': route['dst_len'],
                  'family': route['family'],
                  'oif': route.get('oif'),
                  'gateway': route.get('gateway'),
                  'table': route['table']}
        ovn_bgp_agent.privileged.linux_net.route_delete(r_info)


def add_ndp_proxy(ip, dev, vlan=None):
    ovn_bgp_agent.privileged.linux_net.add_ndp_proxy(ip, dev, vlan)


def del_ndp_proxy(ip, dev, vlan=None):
    ovn_bgp_agent.privileged.linux_net.del_ndp_proxy(ip, dev, vlan)


def add_ips_to_dev(nic, ips, clear_local_route_at_table=False):
    already_added_ips = []
    for ip in ips:
        try:
            ovn_bgp_agent.privileged.linux_net.add_ip_to_dev(ip, nic)
        except agent_exc.IpAddressAlreadyExists:
            already_added_ips.append(ip)

    if clear_local_route_at_table:
        for ip in ips:
            if ip in already_added_ips:
                continue
            oif = get_interface_index(nic)
            route = {'table': clear_local_route_at_table,
                     'proto': 2,
                     'scope': 254,
                     'dst': ip,
                     'oif': oif}
            ovn_bgp_agent.privileged.linux_net.route_delete(route)


def del_ips_from_dev(nic, ips):
    for ip in ips:
        ovn_bgp_agent.privileged.linux_net.del_ip_from_dev(ip, nic)


def create_rule_from_ip(ip, table):
    try:
        ip_network = netaddr.IPNetwork(ip)
    except (netaddr.AddrFormatError, ValueError):
        raise agent_exc.InvalidPortIP(ip=ip)

    return {
        'dst': str(ip_network.ip),
        'table': table,
        'dst_len': ip_network.prefixlen,
        'family': common_utils.IP_VERSION_FAMILY_MAP[ip_network.version],
    }


def add_ip_rule(ip, table, dev=None, lladdr=None):
    rule = create_rule_from_ip(ip, table)

    ovn_bgp_agent.privileged.linux_net.rule_create(rule)

    if lladdr:
        add_ip_nei(ip, lladdr, dev)


def add_ip_nei(ip, lladdr, dev):
    """Add ip neighbor permament entry

    param ip: IP of the neighbor to add an entry for
    param lladdr: link layer address of the neighbor to associate to that IP
    param dev: the interface to which the neighbor is attached
    """
    ovn_bgp_agent.privileged.linux_net.add_ip_nei(ip, lladdr, dev)


def del_ip_rule(ip, table, dev=None, lladdr=None):
    rule = create_rule_from_ip(ip, table)

    ovn_bgp_agent.privileged.linux_net.rule_delete(rule)

    if lladdr:
        del_ip_nei(ip, lladdr, dev)


def del_ip_nei(ip, lladdr, dev):
    """Del ip neighbor permament entry

    param ip: IP of the neighbor to delete the entry
    param lladdr: link layer address of the neighbor to disassociate
    param dev: the interface to which the neighbor is attached
    """
    ovn_bgp_agent.privileged.linux_net.del_ip_nei(ip, lladdr, dev)


def add_unreachable_route(vrf_name):
    ovn_bgp_agent.privileged.linux_net.add_unreachable_route(vrf_name)


@tenacity.retry(
    retry=tenacity.retry_if_exception_type(
        netlink_exceptions.NetlinkDumpInterrupted),
    wait=tenacity.wait_exponential(multiplier=0.02, max=1),
    stop=tenacity.stop_after_delay(8),
    reraise=True)
def add_ip_route(ovn_routing_tables_routes, ip_address, route_table, dev,
                 vlan=None, mask=None, via=None):
    net_ip = ip_address
    if not mask:  # default /32 or /128
        if get_ip_version(ip_address) == constants.IP_VERSION_6:
            mask = 128
        else:
            mask = 32
    else:
        ip = '{}/{}'.format(ip_address, mask)
        if get_ip_version(ip_address) == constants.IP_VERSION_6:
            net_ip = '{}'.format(ipaddress.IPv6Network(
                ip, strict=False).network_address)
        else:
            net_ip = '{}'.format(ipaddress.IPv4Network(
                ip, strict=False).network_address)

    if vlan:
        oif_name = '{}.{}'.format(dev, vlan)
        try:
            oif = get_interface_index(oif_name)
        except agent_exc.NetworkInterfaceNotFound:
            # Most provider network was recently created an
            # there has not been a sync since then, therefore
            # the vlan device has not yet been created
            # Trying to create the device and retrying
            ensure_vlan_device_for_network(dev, vlan)
            oif = get_interface_index(oif_name)
    else:
        oif = get_interface_index(dev)

    route = {'dst': net_ip, 'dst_len': int(mask), 'oif': oif,
             'table': int(route_table), 'proto': 3}
    if via:
        route['gateway'] = via
        route['scope'] = 0
    else:
        route['scope'] = 253
    if get_ip_version(net_ip) == constants.IP_VERSION_6:
        route['family'] = constants.AF_INET6
        del route['scope']

    with pyroute2.IPRoute() as ipr:
        if not ipr.route('show', **route):
            LOG.debug("Creating route at table %s: %s", route_table, route)
            ovn_bgp_agent.privileged.linux_net.route_create(route)
            LOG.debug("Route created at table %s: %s", route_table, route)
        else:
            LOG.debug("Route already existing: %s", route)
    route_info = {'vlan': vlan, 'route': route}
    ovn_routing_tables_routes.setdefault(dev, []).append(route_info)


def del_ip_route(ovn_routing_tables_routes, ip_address, route_table, dev,
                 vlan=None, mask=None, via=None):
    net_ip = ip_address
    if not mask:  # default /32 or /128
        if get_ip_version(ip_address) == constants.IP_VERSION_6:
            mask = 128
        else:
            mask = 32
    else:
        ip = '{}/{}'.format(ip_address, mask)
        if get_ip_version(ip_address) == constants.IP_VERSION_6:
            net_ip = '{}'.format(ipaddress.IPv6Network(
                ip, strict=False).network_address)
        else:
            net_ip = '{}'.format(ipaddress.IPv4Network(
                ip, strict=False).network_address)

    try:
        if vlan:
            oif_name = '{}.{}'.format(dev, vlan)
            oif = get_interface_index(oif_name)
        else:
            oif = get_interface_index(dev)
    except agent_exc.NetworkInterfaceNotFound:
        LOG.debug("Device %s does not exists, so the associated "
                  "routes should have been automatically deleted.", dev)
        ovn_routing_tables_routes.pop(dev, None)
        return

    route = {'dst': net_ip, 'dst_len': int(mask), 'oif': oif,
             'table': int(route_table), 'proto': 3}
    if via:
        route['gateway'] = via
        route['scope'] = 0
    else:
        route['scope'] = 253
    if get_ip_version(net_ip) == constants.IP_VERSION_6:
        route['family'] = constants.AF_INET6
        del route['scope']

    LOG.debug("Deleting route at table %s: %s", route_table, route)
    ovn_bgp_agent.privileged.linux_net.route_delete(route)
    LOG.debug("Route deleted at table %s: %s", route_table, route)
    route_info = {'vlan': vlan, 'route': route}
    if route_info in ovn_routing_tables_routes.get(dev, []):
        ovn_routing_tables_routes[dev].remove(route_info)


def set_device_status(device, status, ndb=None):
    ovn_bgp_agent.privileged.linux_net.set_device_state(
        device, status, ndb=ndb)

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
import pyroute2
import random
import re
import sys

from pyroute2.netlink.rtnl import ndmsg
from socket import AF_INET
from socket import AF_INET6

from oslo_log import log as logging

from ovn_bgp_agent import constants
from ovn_bgp_agent import exceptions as agent_exc
import ovn_bgp_agent.privileged.linux_net

LOG = logging.getLogger(__name__)


def get_ip_version(ip):
    return ipaddress.ip_address(ip.split('/')[0]).version


def get_interfaces(filter_out=[]):
    with pyroute2.NDB() as ndb:
        return [iface.ifname for iface in ndb.interfaces
                if iface.ifname not in filter_out]


def get_interface_index(nic):
    with pyroute2.NDB() as ndb:
        return ndb.interfaces[nic]['index']


def ensure_vrf(vrf_name, vrf_table):
    with pyroute2.NDB() as ndb:
        try:
            with ndb.interfaces[vrf_name] as vrf:
                if vrf['state'] != constants.LINK_UP:
                    vrf['state'] = constants.LINK_UP
        except KeyError:
            ndb.interfaces.create(
                kind="vrf", ifname=vrf_name, vrf_table=int(vrf_table)).set(
                    'state', constants.LINK_UP).commit()


def ensure_bridge(bridge_name):
    with pyroute2.NDB() as ndb:
        try:
            with ndb.interfaces[bridge_name] as bridge:
                if bridge['state'] != constants.LINK_UP:
                    bridge['state'] = constants.LINK_UP
        except KeyError:
            ndb.interfaces.create(
                kind="bridge", ifname=bridge_name, br_stp_state=0).set(
                    'state', constants.LINK_UP).commit()


def ensure_vxlan(vxlan_name, vni, local_ip, dstport):
    with pyroute2.NDB() as ndb:
        try:
            with ndb.interfaces[vxlan_name] as vxlan:
                if vxlan['state'] != constants.LINK_UP:
                    vxlan['state'] = constants.LINK_UP
        except KeyError:
            # FIXME: Perhaps we need to set neigh_suppress on
            ndb.interfaces.create(
                kind="vxlan", ifname=vxlan_name, vxlan_id=int(vni),
                vxlan_port=dstport, vxlan_local=local_ip,
                vxlan_learning=False).set('state', constants.LINK_UP).commit()


def ensure_veth(veth_name, veth_peer):
    try:
        set_device_status(veth_name, constants.LINK_UP)
    except KeyError:
        with pyroute2.NDB() as ndb:
            ndb.interfaces.create(
                kind="veth", ifname=veth_name, peer=veth_peer).set(
                    'state', constants.LINK_UP).commit()
    set_device_status(veth_peer, constants.LINK_UP)


def set_master_for_device(device, master):
    with pyroute2.NDB() as ndb:
        # Check if already associated to the master, and associate it if not
        if (ndb.interfaces[device].get('master') !=
                ndb.interfaces[master]['index']):
            with ndb.interfaces[device] as iface:
                iface.set('master', ndb.interfaces[master]['index'])


def set_device_status(device, status):
    with pyroute2.NDB() as ndb:
        with ndb.interfaces[device] as dev:
            if dev['state'] != status:
                dev['state'] = status


def ensure_dummy_device(device):
    with pyroute2.NDB() as ndb:
        try:
            with ndb.interfaces[device] as iface:
                if iface['state'] != constants.LINK_UP:
                    iface['state'] = constants.LINK_UP
        except KeyError:
            ndb.interfaces.create(kind="dummy", ifname=device).set(
                'state', constants.LINK_UP).commit()


def ensure_ovn_device(ovn_ifname, vrf_name):
    ensure_dummy_device(ovn_ifname)
    set_master_for_device(ovn_ifname, vrf_name)


def delete_device(device):
    try:
        with pyroute2.NDB() as ndb:
            ndb.interfaces[device].remove().commit()
    except KeyError:
        LOG.debug("Interfaces %s already deleted.", device)


def ensure_routing_table_for_bridge(ovn_routing_tables, bridge):
    # check a routing table with the bridge name exists on
    # /etc/iproute2/rt_tables
    regex = r'^[0-9]*[\s]*{}$'.format(bridge)
    matching_table = [line.replace('\t', ' ')
                      for line in open('/etc/iproute2/rt_tables')
                      if re.findall(regex, line)]
    if matching_table:
        table_info = matching_table[0].strip().split()
        ovn_routing_tables[table_info[1]] = int(table_info[0])
        LOG.debug("Found routing table for %s with: %s", bridge,
                  table_info)
    # if not configured, add random number for the table
    else:
        LOG.debug("Routing table for bridge %s not configured "
                  "at /etc/iproute2/rt_tables", bridge)
        regex = r'^[0-9]+[\s]*'
        existing_routes = [int(line.replace('\t', ' ').split(' ')[0])
                           for line in open('/etc/iproute2/rt_tables')
                           if re.findall(regex, line)]
        # pick a number between 1 and 252
        try:
            table_number = random.choice(list(
                set([x for x in range(1, 253)]).difference(
                    set(existing_routes))))
        except IndexError:
            LOG.error("No more routing tables available for bridge %s "
                      "at /etc/iproute2/rt_tables", bridge)
            sys.exit()

        with open('/etc/iproute2/rt_tables', 'a') as rt_tables:
            rt_tables.write('{} {}\n'.format(table_number, bridge))

        ovn_routing_tables[bridge] = int(table_number)
        LOG.debug("Added routing table for %s with number: %s", bridge,
                  table_number)

    # add default route on that table if it does not exist
    extra_routes = []

    with pyroute2.NDB() as ndb:
        table_route_dsts = set([r.dst for r in ndb.routes.summary().filter(
                                table=ovn_routing_tables[bridge])])
        if not table_route_dsts:
            ndb.routes.create(dst='default',
                              oif=ndb.interfaces[bridge]['index'],
                              table=ovn_routing_tables[bridge],
                              scope=253,
                              proto=3).commit()
            ndb.routes.create(dst='default',
                              oif=ndb.interfaces[bridge]['index'],
                              table=ovn_routing_tables[bridge],
                              family=AF_INET6,
                              proto=3).commit()
        else:
            route_missing = True
            route6_missing = True
            for dst in table_route_dsts:
                if not dst:  # default route
                    try:
                        route = ndb.routes[
                            {'table': ovn_routing_tables[bridge],
                             'dst': '',
                             'family': AF_INET}]
                        if (bridge ==
                                ndb.interfaces[{'index': route['oif']}][
                                    'ifname']):
                            route_missing = False
                        else:
                            extra_routes.append(route)
                    except KeyError:
                        pass  # no ipv4 default rule
                    try:
                        route_6 = ndb.routes[
                            {'table': ovn_routing_tables[bridge],
                             'dst': '',
                             'family': AF_INET6}]
                        if (bridge ==
                                ndb.interfaces[{'index': route_6['oif']}][
                                    'ifname']):
                            route6_missing = False
                        else:
                            extra_routes.append(route_6)
                    except KeyError:
                        pass  # no ipv6 default rule
                else:
                    extra_routes.append(
                        ndb.routes[{'table': ovn_routing_tables[bridge],
                                    'dst': dst}]
                    )

            if route_missing:
                ndb.routes.create(dst='default',
                                  oif=ndb.interfaces[bridge]['index'],
                                  table=ovn_routing_tables[bridge],
                                  scope=253,
                                  proto=3).commit()
            if route6_missing:
                ndb.routes.create(dst='default',
                                  oif=ndb.interfaces[bridge]['index'],
                                  table=ovn_routing_tables[bridge],
                                  family=AF_INET6,
                                  proto=3).commit()
    return extra_routes


def ensure_vlan_device_for_network(bridge, vlan_tag):
    vlan_device_name = '{}.{}'.format(bridge, vlan_tag)

    with pyroute2.NDB() as ndb:
        try:
            with ndb.interfaces[vlan_device_name] as iface:
                if iface['state'] != constants.LINK_UP:
                    iface['state'] = constants.LINK_UP
        except KeyError:
            ndb.interfaces.create(
                kind="vlan", ifname=vlan_device_name, vlan_id=vlan_tag,
                link=ndb.interfaces[bridge]['index']).set(
                'state', constants.LINK_UP).commit()

    device = "{}/{}".format(bridge, vlan_tag)
    enable_proxy_arp(device)
    enable_proxy_ndp(device)


def delete_vlan_device_for_network(bridge, vlan_tag):
    vlan_device_name = '{}.{}'.format(bridge, vlan_tag)
    delete_device(vlan_device_name)


def enable_proxy_ndp(device):
    flag = "net.ipv6.conf.{}.proxy_ndp".format(device)
    ovn_bgp_agent.privileged.linux_net.set_kernel_flag(flag, 1)


def enable_proxy_arp(device):
    flag = "net.ipv4.conf.{}.proxy_arp".format(device)
    ovn_bgp_agent.privileged.linux_net.set_kernel_flag(flag, 1)


def get_exposed_ips(nic):
    exposed_ips = []
    with pyroute2.NDB() as ndb:
        exposed_ips = [ip.address
                       for ip in ndb.interfaces[nic].ipaddr.summary()
                       if ip.prefixlen == 32 or ip.prefixlen == 128]
    return exposed_ips


def get_nic_ip(nic, prefixlen_filter=None):
    exposed_ips = []
    with pyroute2.NDB() as ndb:
        if prefixlen_filter:
            exposed_ips = [ip.address
                           for ip in ndb.interfaces[nic].ipaddr.summary(
                               ).filter(prefixlen=prefixlen_filter)]
        else:
            exposed_ips = [ip.address
                           for ip in ndb.interfaces[nic].ipaddr.summary()]

    return exposed_ips


def get_exposed_ips_on_network(nic, network):
    exposed_ips = []
    with pyroute2.NDB() as ndb:
        try:
            exposed_ips = [ip.address
                           for ip in ndb.interfaces[nic].ipaddr.summary()
                           if ((ip.prefixlen == 32 or ip.prefixlen == 128) and
                               ipaddress.ip_address(ip.address) in network)]
        except KeyError:
            # Nic does not exists
            LOG.debug("Nic %s does not yet exists, so it does not have "
                      "exposed IPs", nic)
    return exposed_ips


def get_ovn_ip_rules(routing_table):
    # get the rules pointing to ovn bridges
    ovn_ip_rules = {}
    with pyroute2.NDB() as ndb:
        rules_info = [(rule.table,
                       "{}/{}".format(rule.dst, rule.dst_len),
                       rule.family) for rule in ndb.rules.dump()
                      if rule.table in routing_table]
        for table, dst, family in rules_info:
            ovn_ip_rules[dst] = {'table': table, 'family': family}
    return ovn_ip_rules


def delete_exposed_ips(ips, nic):
    with pyroute2.NDB() as ndb:
        for ip in ips:
            address = '{}/32'.format(ip)
            if get_ip_version(ip) == constants.IP_VERSION_6:
                address = '{}/128'.format(ip)
            try:
                ndb.interfaces[nic].ipaddr[address].remove().commit()
            except KeyError:
                LOG.debug("IP address {} already removed from nic {}.".format(
                    ip, nic))


def delete_ip_rules(ip_rules):
    with pyroute2.NDB() as ndb:
        for rule_ip, rule_info in ip_rules.items():
            rule = {'dst': rule_ip.split("/")[0],
                    'dst_len': rule_ip.split("/")[1],
                    'table': rule_info['table'],
                    'family': rule_info['family']}
            try:
                with ndb.rules[rule] as r:
                    r.remove()
            except KeyError:
                LOG.debug("Rule {} already deleted".format(rule))
            except pyroute2.netlink.exceptions.NetlinkError:
                # FIXME: There is a issue with NDB and ip rules deletion:
                # https://github.com/svinota/pyroute2/issues/771
                LOG.debug("This should not happen, skipping: NetlinkError "
                          "deleting rule %s", rule)


def delete_bridge_ip_routes(routing_tables, routing_tables_routes,
                            extra_routes):
    with pyroute2.NDB() as ndb:
        for bridge, routes_info in routing_tables_routes.items():
            if not extra_routes[bridge]:
                continue
            for route_info in routes_info:
                oif = ndb.interfaces[bridge]['index']
                if route_info['vlan']:
                    vlan_device_name = '{}.{}'.format(bridge,
                                                      route_info['vlan'])
                    oif = ndb.interfaces[vlan_device_name]['index']
                if 'gateway' in route_info['route'].keys():  # subnet route
                    possible_matchings = [
                        r for r in extra_routes[bridge]
                        if (r['dst'] == route_info['route']['dst'] and
                            r['dst_len'] == route_info['route']['dst_len'] and
                            r['gateway'] == route_info['route']['gateway'])]
                else:  # cr-lrp
                    possible_matchings = [
                        r for r in extra_routes[bridge]
                        if (r['dst'] == route_info['route']['dst'] and
                            r['dst_len'] == route_info['route']['dst_len'] and
                            r['oif'] == oif)]
                for r in possible_matchings:
                    extra_routes[bridge].remove(r)

        for bridge, routes in extra_routes.items():
            for route in routes:
                r_info = {'dst': route['dst'],
                          'dst_len': route['dst_len'],
                          'family': route['family'],
                          'oif': route['oif'],
                          'gateway': route['gateway'],
                          'table': routing_tables[bridge]}
                try:
                    with ndb.routes[r_info] as r:
                        r.remove()
                except KeyError:
                    LOG.debug("Route already deleted: {}".format(route))


def delete_routes_from_table(table):
    with pyroute2.NDB() as ndb:
        # FIXME: problem in pyroute2 removing routes with local (254) scope
        table_routes = [r for r in ndb.routes.dump().filter(table=table)
                        if r.scope != 254 and r.proto != 186]
        for route in table_routes:
            try:
                with ndb.routes[route] as r:
                    r.remove()
            except KeyError:
                LOG.debug("Route already deleted: %s", route)


def get_routes_on_tables(table_ids):
    with pyroute2.NDB() as ndb:
        # NOTE: skip bgp routes (proto 186)
        return [r for r in ndb.routes.dump()
                if r.table in table_ids and r.dst != '' and r.proto != 186]


def delete_ip_routes(routes):
    with pyroute2.NDB() as ndb:
        for route in routes:
            r_info = {'dst': route['dst'],
                      'dst_len': route['dst_len'],
                      'family': route['family'],
                      'oif': route['oif'],
                      'gateway': route['gateway'],
                      'table': route['table']}
            try:
                with ndb.routes[r_info] as r:
                    r.remove()
            except KeyError:
                LOG.debug("Route already deleted: %s", route)


def add_ndp_proxy(ip, dev, vlan=None):
    ovn_bgp_agent.privileged.linux_net.add_ndp_proxy(ip, dev, vlan)


def del_ndp_proxy(ip, dev, vlan=None):
    ovn_bgp_agent.privileged.linux_net.del_ndp_proxy(ip, dev, vlan)


def add_ips_to_dev(nic, ips, clear_local_route_at_table=False):
    already_added_ips = []
    for ip in ips:
        try:
            with pyroute2.NDB() as ndb:
                with ndb.interfaces[nic] as iface:
                    address = '{}/32'.format(ip)
                    if get_ip_version(ip) == constants.IP_VERSION_6:
                        address = '{}/128'.format(ip)
                    iface.add_ip(address)
        except KeyError:
            # NDB raises KeyError: 'object exists'
            # if the ip is already added
            already_added_ips.append(ip)

    if clear_local_route_at_table:
        for ip in ips:
            with pyroute2.NDB() as ndb:
                oif = ndb.interfaces[nic]['index']
                if ip in already_added_ips:
                    continue
                route = {'table': clear_local_route_at_table,
                         'proto': 2,
                         'scope': 254,
                         'dst': ip,
                         'oif': oif}
                try:
                    LOG.debug("Deleting local route: %s", route)
                    with ndb.routes[route] as r:
                        r.remove()
                except (KeyError, ValueError):
                    LOG.debug("Local route already deleted: %s", route)


def del_ips_from_dev(nic, ips):
    with pyroute2.NDB() as ndb:
        with ndb.interfaces[nic] as iface:
            for ip in ips:
                address = '{}/32'.format(ip)
                if get_ip_version(ip) == constants.IP_VERSION_6:
                    address = '{}/128'.format(ip)
                iface.del_ip(address)


def add_ip_rule(ip, table, dev=None, lladdr=None):
    ip_version = get_ip_version(ip)
    ip_info = ip.split("/")

    if len(ip_info) == 1:
        rule = {'dst': ip_info[0], 'table': table, 'dst_len': 32}
        if ip_version == constants.IP_VERSION_6:
            rule['dst_len'] = 128
            rule['family'] = AF_INET6
    elif len(ip_info) == 2:
        rule = {'dst': ip_info[0], 'table': table, 'dst_len': int(ip_info[1])}
        if ip_version == constants.IP_VERSION_6:
            rule['family'] = AF_INET6
    else:
        raise agent_exc.InvalidPortIP(ip)

    with pyroute2.NDB() as ndb:
        try:
            ndb.rules[rule]
        except KeyError:
            LOG.debug("Creating ip rule with: %s", rule)
            ndb.rules.create(rule).commit()

    if lladdr:
        add_ip_nei(ip, lladdr, dev)


def add_ip_nei(ip, lladdr, dev):
    """Add ip neighbor permament entry

    param ip: IP of the neighbor to add an entry for
    param lladdr: link layer address of the neighbor to associate to that IP
    param dev: the interface to which the neighbor is attached
    """
    # FIXME: There is no support for creating neighbours in NDB
    # So we are using iproute here
    ip_version = get_ip_version(ip)
    with pyroute2.IPRoute() as iproute:
        # This is doing something like:
        # sudo ip nei replace 172.24.4.69
        # lladdr fa:16:3e:d3:5d:7b dev br-ex nud permanent
        network_bridge_if = iproute.link_lookup(ifname=dev)[0]
        if ip_version == constants.IP_VERSION_6:
            iproute.neigh('set',
                          dst=ip,
                          lladdr=lladdr,
                          family=AF_INET6,
                          ifindex=network_bridge_if,
                          state=ndmsg.states['permanent'])
        else:
            iproute.neigh('set',
                          dst=ip,
                          lladdr=lladdr,
                          ifindex=network_bridge_if,
                          state=ndmsg.states['permanent'])


def del_ip_rule(ip, table, dev=None, lladdr=None):
    ip_version = get_ip_version(ip)
    ip_info = ip.split("/")

    if len(ip_info) == 1:
        rule = {'dst': ip_info[0], 'table': table, 'dst_len': 32}
        if ip_version == constants.IP_VERSION_6:
            rule['dst_len'] = 128
            rule['family'] = AF_INET6
    elif len(ip_info) == 2:
        rule = {'dst': ip_info[0], 'table': table, 'dst_len': int(ip_info[1])}
        if ip_version == constants.IP_VERSION_6:
            rule['family'] = AF_INET6
    else:
        LOG.error("Invalid ip: {}".format(ip))
        return
    with pyroute2.NDB() as ndb:
        try:
            ndb.rules[rule].remove().commit()
            LOG.debug("Deleting ip rule with: %s", rule)
        except KeyError:
            LOG.debug("Rule already deleted: %s", rule)

    if lladdr:
        del_ip_nei(ip, lladdr, dev)


def del_ip_nei(ip, lladdr, dev):
    """Del ip neighbor permament entry

    param ip: IP of the neighbor to delete the entry
    param lladdr: link layer address of the neighbor to disassociate
    param dev: the interface to which the neighbor is attached
    """
    # FIXME: There is no support for deleting neighbours in NDB
    # So we are using iproute here
    ip_version = get_ip_version(ip)
    with pyroute2.IPRoute() as iproute:
        # This is doing something like:
        # sudo ip nei del 172.24.4.69
        # lladdr fa:16:3e:d3:5d:7b dev br-ex nud permanent
        try:
            network_bridge_if = iproute.link_lookup(
                ifname=dev)[0]
        except IndexError:
            # Neigbhbor device does not exists, continuing
            LOG.debug("No need to remove nei for dev %s as it does not "
                      "exists", dev)
            return
        if ip_version == constants.IP_VERSION_6:
            iproute.neigh('del',
                          dst=ip.split("/")[0],
                          lladdr=lladdr,
                          family=AF_INET6,
                          ifindex=network_bridge_if,
                          state=ndmsg.states['permanent'])
        else:
            iproute.neigh('del',
                          dst=ip.split("/")[0],
                          lladdr=lladdr,
                          ifindex=network_bridge_if,
                          state=ndmsg.states['permanent'])


def add_unreachable_route(vrf_name):
    ovn_bgp_agent.privileged.linux_net.add_unreachable_route(vrf_name)


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

    with pyroute2.NDB() as ndb:
        if vlan:
            oif_name = '{}.{}'.format(dev, vlan)
            oif = ndb.interfaces[oif_name]['index']
        else:
            oif = ndb.interfaces[dev]['index']

    route = {'dst': net_ip, 'dst_len': int(mask), 'oif': oif,
             'table': int(route_table), 'proto': 3}
    if via:
        route['gateway'] = via
        route['scope'] = 0
    else:
        route['scope'] = 253
    if get_ip_version(net_ip) == constants.IP_VERSION_6:
        route['family'] = AF_INET6
        del route['scope']

    with pyroute2.NDB() as ndb:
        try:
            with ndb.routes[route] as r:
                LOG.debug("Route already existing: %s", r)
        except KeyError:
            LOG.debug("Creating route at table %s: %s", route_table, route)
            ndb.routes.create(route).commit()
            LOG.debug("Route created at table %s: %s", route_table, route)
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

    with pyroute2.NDB() as ndb:
        try:
            if vlan:
                oif_name = '{}.{}'.format(dev, vlan)
                oif = ndb.interfaces[oif_name]['index']
            else:
                oif = ndb.interfaces[dev]['index']
        except KeyError:
            LOG.debug("Device %s does not exists, so the associated "
                      "routes should have been automatically deleted.", dev)
            if ovn_routing_tables_routes.get(dev):
                del ovn_routing_tables_routes[dev]
            return

    route = {'dst': net_ip, 'dst_len': int(mask), 'oif': oif,
             'table': int(route_table), 'proto': 3}
    if via:
        route['gateway'] = via
        route['scope'] = 0
    else:
        route['scope'] = 253
    if get_ip_version(net_ip) == constants.IP_VERSION_6:
        route['family'] = AF_INET6

    with pyroute2.NDB() as ndb:
        try:
            LOG.debug("Deleting route at table %s: %s", route_table, route)
            with ndb.routes[route] as r:
                r.remove()
            LOG.debug("Route deleted at table %s: %s", route_table, route)
            route_info = {'vlan': vlan, 'route': route}
            ovn_routing_tables_routes[dev].remove(route_info)
        except (KeyError, ValueError):
            LOG.debug("Route already deleted: %s", route)

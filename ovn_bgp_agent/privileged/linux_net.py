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
import os
import pyroute2

from pyroute2 import netlink as pyroute_netlink
from pyroute2.netlink.rtnl import ndmsg
from socket import AF_INET6

from oslo_concurrency import processutils
from oslo_log import log as logging

from ovn_bgp_agent import constants
from ovn_bgp_agent.utils import linux_net as l_net

import ovn_bgp_agent.privileged.linux_net

LOG = logging.getLogger(__name__)


@ovn_bgp_agent.privileged.default.entrypoint
def set_device_status(device, status, ndb=None):
    _ndb = ndb
    if ndb is None:
        _ndb = pyroute2.NDB()
    try:
        with _ndb.interfaces[device] as dev:
            if dev['state'] != status:
                dev['state'] = status
    finally:
        if ndb is None:
            _ndb.close()


@ovn_bgp_agent.privileged.default.entrypoint
def ensure_vrf(vrf_name, vrf_table):
    with pyroute2.NDB() as ndb:
        try:
            set_device_status(vrf_name, constants.LINK_UP, ndb=ndb)
        except KeyError:
            ndb.interfaces.create(
                kind="vrf", ifname=vrf_name, vrf_table=int(vrf_table)).set(
                    'state', constants.LINK_UP).commit()


@ovn_bgp_agent.privileged.default.entrypoint
def ensure_bridge(bridge_name):
    with pyroute2.NDB() as ndb:
        try:
            set_device_status(bridge_name, constants.LINK_UP, ndb=ndb)
        except KeyError:
            ndb.interfaces.create(
                kind="bridge", ifname=bridge_name, br_stp_state=0).set(
                    'state', constants.LINK_UP).commit()


@ovn_bgp_agent.privileged.default.entrypoint
def ensure_vxlan(vxlan_name, vni, local_ip, dstport):
    with pyroute2.NDB() as ndb:
        try:
            set_device_status(vxlan_name, constants.LINK_UP, ndb=ndb)
        except KeyError:
            # FIXME: Perhaps we need to set neigh_suppress on
            ndb.interfaces.create(
                kind="vxlan", ifname=vxlan_name, vxlan_id=int(vni),
                vxlan_port=dstport, vxlan_local=local_ip,
                vxlan_learning=False).set('state', constants.LINK_UP).commit()


@ovn_bgp_agent.privileged.default.entrypoint
def ensure_veth(veth_name, veth_peer):
    try:
        set_device_status(veth_name, constants.LINK_UP)
    except KeyError:
        with pyroute2.NDB() as ndb:
            ndb.interfaces.create(
                kind="veth", ifname=veth_name, peer=veth_peer).set(
                    'state', constants.LINK_UP).commit()
    set_device_status(veth_peer, constants.LINK_UP)


@ovn_bgp_agent.privileged.default.entrypoint
def set_master_for_device(device, master):
    with pyroute2.NDB() as ndb:
        # Check if already associated to the master, and associate it if not
        if (ndb.interfaces[device].get('master') !=
                ndb.interfaces[master]['index']):
            with ndb.interfaces[device] as iface:
                iface.set('master', ndb.interfaces[master]['index'])


@ovn_bgp_agent.privileged.default.entrypoint
def ensure_dummy_device(device):
    with pyroute2.NDB() as ndb:
        try:
            set_device_status(device, constants.LINK_UP, ndb=ndb)
        except KeyError:
            ndb.interfaces.create(kind="dummy", ifname=device).set(
                'state', constants.LINK_UP).commit()


@ovn_bgp_agent.privileged.default.entrypoint
def delete_device(device):
    try:
        with pyroute2.NDB() as ndb:
            ndb.interfaces[device].remove().commit()
    except KeyError:
        LOG.debug("Interfaces %s already deleted.", device)


@ovn_bgp_agent.privileged.default.entrypoint
def route_create(route):
    with pyroute2.NDB() as ndb:
        ndb.routes.create(route).commit()


@ovn_bgp_agent.privileged.default.entrypoint
def route_delete(route):
    with pyroute2.NDB() as ndb:
        try:
            with ndb.routes[route] as r:
                r.remove()
        except (KeyError, ValueError):
            LOG.debug("Route already deleted: {}".format(route))


@ovn_bgp_agent.privileged.default.entrypoint
def ensure_vlan_device_for_network(bridge, vlan_tag):
    vlan_device_name = '{}.{}'.format(bridge, vlan_tag)

    with pyroute2.NDB() as ndb:
        try:
            set_device_status(vlan_device_name, constants.LINK_UP, ndb=ndb)
        except KeyError:
            ndb.interfaces.create(
                kind="vlan", ifname=vlan_device_name, vlan_id=vlan_tag,
                link=ndb.interfaces[bridge]['index']).set(
                'state', constants.LINK_UP).commit()


@ovn_bgp_agent.privileged.default.entrypoint
def set_kernel_flag(flag, value):
    command = ["sysctl", "-w", "{}={}".format(flag, value)]
    try:
        return processutils.execute(*command)
    except Exception as e:
        LOG.error("Unable to execute %s. Exception: %s", command, e)
        raise


@ovn_bgp_agent.privileged.default.entrypoint
def delete_exposed_ips(ips, nic):
    with pyroute2.NDB() as ndb:
        for ip in ips:
            address = '{}/32'.format(ip)
            if l_net.get_ip_version(ip) == constants.IP_VERSION_6:
                address = '{}/128'.format(ip)
            try:
                ndb.interfaces[nic].ipaddr[address].remove().commit()
            except KeyError:
                LOG.debug("IP address {} already removed from nic {}.".format(
                    ip, nic))


@ovn_bgp_agent.privileged.default.entrypoint
def rule_create(rule):
    with pyroute2.NDB() as ndb:
        try:
            ndb.rules[rule]
        except KeyError:
            LOG.debug("Creating ip rule with: %s", rule)
            try:
                ndb.rules.create(rule).commit()
            except ValueError:
                # FIXME: There is an issue with NDB and ip rules
                # Remove try/except once the next is fixed:
                # https://github.com/svinota/pyroute2/issues/967
                pass


@ovn_bgp_agent.privileged.default.entrypoint
def rule_delete(rule):
    with pyroute2.NDB() as ndb:
        try:
            ndb.rules[rule].remove().commit()
            LOG.debug("Deleting ip rule with: %s", rule)
        except KeyError:
            LOG.debug("Rule already deleted: %s", rule)
        except ValueError:
            # FIXME: There is an issue with NDB and ip rules
            # Remove except once the next is fixed:
            # https://github.com/svinota/pyroute2/issues/967
            pass


@ovn_bgp_agent.privileged.default.entrypoint
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
            except pyroute_netlink.exceptions.NetlinkError:
                # FIXME: There is a issue with NDB and ip rules deletion:
                # https://github.com/svinota/pyroute2/issues/771
                LOG.debug("This should not happen, skipping: NetlinkError "
                          "deleting rule %s", rule)


@ovn_bgp_agent.privileged.default.entrypoint
def add_ndp_proxy(ip, dev, vlan=None):
    # FIXME(ltomasbo): This should use pyroute instead but I didn't find
    # out how
    net_ip = str(ipaddress.IPv6Network(ip, strict=False).network_address)
    dev_name = dev
    if vlan:
        dev_name = "{}.{}".format(dev, vlan)
    command = ["ip", "-6", "nei", "add", "proxy", net_ip, "dev", dev_name]
    try:
        return processutils.execute(*command)
    except Exception as e:
        LOG.error("Unable to execute %s. Exception: %s", command, e)
        raise


@ovn_bgp_agent.privileged.default.entrypoint
def del_ndp_proxy(ip, dev, vlan=None):
    # FIXME(ltomasbo): This should use pyroute instead but I didn't find
    # out how
    net_ip = str(ipaddress.IPv6Network(ip, strict=False).network_address)
    dev_name = dev
    if vlan:
        dev_name = "{}.{}".format(dev, vlan)
    command = ["ip", "-6", "nei", "del", "proxy", net_ip, "dev", dev_name]
    env = dict(os.environ)
    env['LC_ALL'] = 'C'
    try:
        return processutils.execute(*command, env_variables=env)
    except Exception as e:
        if "No such file or directory" in e.stderr:
            # Already deleted
            return
        LOG.error("Unable to execute %s. Exception: %s", command, e)
        raise


@ovn_bgp_agent.privileged.default.entrypoint
def add_ip_to_dev(ip, nic):
    with pyroute2.NDB() as ndb:
        with ndb.interfaces[nic] as iface:
            address = '{}/32'.format(ip)
            if l_net.get_ip_version(ip) == constants.IP_VERSION_6:
                address = '{}/128'.format(ip)
            iface.add_ip(address)


@ovn_bgp_agent.privileged.default.entrypoint
def del_ip_from_dev(ip, nic):
    with pyroute2.NDB() as ndb:
        with ndb.interfaces[nic] as iface:
            address = '{}/32'.format(ip)
            if l_net.get_ip_version(ip) == constants.IP_VERSION_6:
                address = '{}/128'.format(ip)
            iface.del_ip(address)


@ovn_bgp_agent.privileged.default.entrypoint
def add_ip_nei(ip, lladdr, dev):
    ip_version = l_net.get_ip_version(ip)
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


@ovn_bgp_agent.privileged.default.entrypoint
def del_ip_nei(ip, lladdr, dev):
    ip_version = l_net.get_ip_version(ip)
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


@ovn_bgp_agent.privileged.default.entrypoint
def add_unreachable_route(vrf_name):
    # FIXME: This should use pyroute instead but I didn't find
    # out how
    env = dict(os.environ)
    env['LC_ALL'] = 'C'
    for ip_version in [-4, -6]:
        command = ["ip", ip_version, "route", "add", "vrf", vrf_name,
                   "unreachable", "default", "metric", "4278198272"]
        try:
            processutils.execute(*command, env_variables=env)
        except Exception as e:
            if "RTNETLINK answers: File exists" in e.stderr:
                continue
            LOG.error("Unable to execute %s. Exception: %s", command, e)
            raise


@ovn_bgp_agent.privileged.default.entrypoint
def create_routing_table_for_bridge(table_number, bridge):
    with open('/etc/iproute2/rt_tables', 'a') as rt_tables:
        rt_tables.write('{} {}\n'.format(table_number, bridge))

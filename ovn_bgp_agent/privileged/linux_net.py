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

import errno
import ipaddress
import os
import socket

import netaddr
from socket import AF_INET6

from oslo_concurrency import processutils
from oslo_log import log as logging
import pyroute2
from pyroute2 import iproute
from pyroute2 import netlink as pyroute_netlink
from pyroute2.netlink import exceptions as netlink_exceptions
from pyroute2.netlink.rtnl import ndmsg
import tenacity

from ovn_bgp_agent import constants
from ovn_bgp_agent import exceptions as agent_exc
from ovn_bgp_agent.utils import linux_net as l_net

import ovn_bgp_agent.privileged.linux_net

LOG = logging.getLogger(__name__)

_IP_VERSION_FAMILY_MAP = {4: socket.AF_INET, 6: socket.AF_INET6}


class NetworkInterfaceNotFound(RuntimeError):
    message = 'Network interface %(device)s not found'

    def __init__(self, message=None, device=None):
        message = message or self.message % {'device': device}
        super(NetworkInterfaceNotFound, self).__init__(message)


class InterfaceAlreadyExists(RuntimeError):
    message = "Interface %(device)s already exists."

    def __init__(self, message=None, device=None):
        message = message or self.message % {'device': device}
        super(InterfaceAlreadyExists, self).__init__(message)


class InterfaceOperationNotSupported(RuntimeError):
    message = "Operation not supported on interface %(device)s."

    def __init__(self, message=None, device=None):
        message = message or self.message % {'device': device}
        super(InterfaceOperationNotSupported, self).__init__(message)


class InvalidArgument(RuntimeError):
    message = "Invalid parameter/value used on interface %(device)s."

    def __init__(self, message=None, device=None):
        message = message or self.message % {'device': device}
        super(InvalidArgument, self).__init__(message)


def set_device_state(device, state):
    set_link_attribute(device, state=state)


@ovn_bgp_agent.privileged.default.entrypoint
def ensure_vrf(vrf_name, vrf_table):
    try:
        set_device_state(vrf_name, constants.LINK_UP)
    except NetworkInterfaceNotFound:
        create_interface(vrf_name, 'vrf', vrf_table=vrf_table,
                         state=constants.LINK_UP)


@ovn_bgp_agent.privileged.default.entrypoint
def ensure_bridge(bridge_name):
    try:
        set_device_state(bridge_name, constants.LINK_UP)
    except NetworkInterfaceNotFound:
        create_interface(bridge_name, 'bridge', br_stp_state=0,
                         state=constants.LINK_UP)


@ovn_bgp_agent.privileged.default.entrypoint
def ensure_vxlan(vxlan_name, vni, local_ip, dstport):
    try:
        set_device_state(vxlan_name, constants.LINK_UP)
    except NetworkInterfaceNotFound:
        # FIXME: Perhaps we need to set neigh_suppress on
        create_interface(vxlan_name, 'vxlan',
                         vxlan_id=vni,
                         vxlan_port=dstport,
                         vxlan_local=local_ip,
                         vxlan_learning=False,
                         state=constants.LINK_UP)


@ovn_bgp_agent.privileged.default.entrypoint
def ensure_veth(veth_name, veth_peer):
    try:
        set_device_state(veth_name, constants.LINK_UP)
    except NetworkInterfaceNotFound:
        create_interface(veth_name, 'veth', peer=veth_peer,
                         state=constants.LINK_UP)
    set_device_state(veth_peer, constants.LINK_UP)


@ovn_bgp_agent.privileged.default.entrypoint
def ensure_dummy_device(device):
    try:
        set_device_state(device, constants.LINK_UP)
    except NetworkInterfaceNotFound:
        create_interface(device, 'dummy', state=constants.LINK_UP)


@ovn_bgp_agent.privileged.default.entrypoint
def ensure_vlan_device_for_network(bridge, vlan_tag):
    vlan_device_name = '{}.{}'.format(bridge, vlan_tag)
    try:
        set_device_state(vlan_device_name, constants.LINK_UP)
    except NetworkInterfaceNotFound:
        create_interface(vlan_device_name, 'vlan',
                         physical_interface=bridge,
                         vlan_id=vlan_tag,
                         state=constants.LINK_UP)


@tenacity.retry(
    retry=tenacity.retry_if_exception_type(
        netlink_exceptions.NetlinkDumpInterrupted),
    wait=tenacity.wait_exponential(multiplier=0.02, max=1),
    stop=tenacity.stop_after_delay(8),
    reraise=True)
@ovn_bgp_agent.privileged.default.entrypoint
def set_master_for_device(device, master):
    try:
        with pyroute2.IPRoute() as ipr:
            dev_index = ipr.link_lookup(ifname=device)[0]
            master_index = ipr.link_lookup(ifname=master)[0]
            # Check if already associated to the master,
            # and associate it if not
            iface = ipr.link('get', index=dev_index)[0]
            if iface.get_attr('IFLA_MASTER') != master_index:
                ipr.link('set', index=dev_index, master=master_index)
    except IndexError:
        LOG.debug("No need to set %s on VRF %s, as one of them is deleted",
                  device, master)


@ovn_bgp_agent.privileged.default.entrypoint
def delete_device(device):
    try:
        delete_interface(device)
    except NetworkInterfaceNotFound:
        LOG.debug("Interfaces %s already deleted.", device)


@ovn_bgp_agent.privileged.default.entrypoint
def route_create(route):
    try:
        with pyroute2.NDB() as ndb:
            ndb.routes.create(route).commit()
    except KeyError:  # Already exists
        LOG.debug("Route %s already exists.", route)


@ovn_bgp_agent.privileged.default.entrypoint
def route_delete(route):
    with pyroute2.NDB() as ndb:
        try:
            with ndb.routes[route] as r:
                r.remove()
        except (KeyError, ValueError):
            LOG.debug("Route already deleted: {}".format(route))


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
    for ip_address in ips:
        delete_ip_address(ip_address, nic)


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
            # fixed on pyroute2 0.7.2 version, remove it when that version
            # is the minimal one supported
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
                # fixed on pyroute2 0.7.2 version, remove it when that version
                # is the minimal one supported
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
    add_ip_address(ip, nic)


@ovn_bgp_agent.privileged.default.entrypoint
def del_ip_from_dev(ip, nic):
    delete_ip_address(ip, nic)


@ovn_bgp_agent.privileged.default.entrypoint
def add_ip_nei(ip, lladdr, dev):
    ip_version = l_net.get_ip_version(ip)
    with pyroute2.IPRoute() as iproute:
        # This is doing something like:
        # sudo ip nei replace 172.24.4.69
        # lladdr fa:16:3e:d3:5d:7b dev br-ex nud permanent
        try:
            network_bridge_if = iproute.link_lookup(ifname=dev)[0]
        except IndexError:
            LOG.debug("No need to add nei for dev %s as it does not exists",
                      dev)
            return
        if ip_version == constants.IP_VERSION_6:
            iproute.neigh('replace',
                          dst=ip,
                          lladdr=lladdr,
                          family=AF_INET6,
                          ifindex=network_bridge_if,
                          state=ndmsg.states['permanent'])
        else:
            iproute.neigh('replace',
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
            LOG.debug("No need to remove nei for dev %s as it does not exists",
                      dev)
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


def _translate_ip_device_exception(e, device):
    if e.code == errno.ENODEV:
        raise NetworkInterfaceNotFound(device=device)
    if e.code == errno.EOPNOTSUPP:
        raise InterfaceOperationNotSupported(device=device)
    if e.code == errno.EINVAL:
        raise InvalidArgument(device=device)
    if e.code == errno.EEXIST:
        raise InterfaceAlreadyExists(device=device)
    raise e


def _translate_ip_addr_exception(e, ip, device):
    if e.code == errno.EEXIST:
        raise agent_exc.IpAddressAlreadyExists(ip=ip, device=device)
    if e.code == errno.EADDRNOTAVAIL:
        LOG.debug('No need to delete IP address %s on dev %s as it does '
                  'not exist', ip, device)
        return
    raise e


def get_attr(pyroute2_obj, attr_name):
    """Get an attribute in a pyroute object

    pyroute2 object attributes are stored under a key called 'attrs'. This key
    contains a tuple of tuples. E.g.:
      pyroute2_obj = {'attrs': (('TCA_KIND': 'htb'),
                                ('TCA_OPTIONS': {...}))}

    :param pyroute2_obj: (dict) pyroute2 object
    :param attr_name: (string) first value of the tuple we are looking for
    :return: (object) second value of the tuple, None if the tuple doesn't
             exist
    """
    rule_attrs = pyroute2_obj.get('attrs', [])
    for attr in (attr for attr in rule_attrs if attr[0] == attr_name):
        return attr[1]


def make_serializable(value):
    """Make a pyroute2 object serializable

    This function converts 'netlink.nla_slot' object (key, value) in a list
    of two elements.
    """
    def _ensure_string(value):
        return value.decode() if isinstance(value, bytes) else value

    if isinstance(value, list):
        return [make_serializable(item) for item in value]
    elif isinstance(value, pyroute_netlink.nla_slot):
        return [_ensure_string(value[0]), make_serializable(value[1])]
    elif isinstance(value, pyroute_netlink.nla_base):
        return make_serializable(value.dump())
    elif isinstance(value, dict):
        return {_ensure_string(key): make_serializable(data)
                for key, data in value.items()}
    elif isinstance(value, tuple):
        return tuple(make_serializable(item) for item in value)
    return _ensure_string(value)


def _get_link_id(ifname, raise_exception=True):
    with iproute.IPRoute() as ip:
        link_id = ip.link_lookup(ifname=ifname)
    if not link_id or len(link_id) < 1:
        if raise_exception:
            raise NetworkInterfaceNotFound(device=ifname)
        LOG.debug('Interface %(dev)s not found', {'dev': ifname})
        return None
    return link_id[0]


@ovn_bgp_agent.privileged.default.entrypoint
def get_link_id(device):
    return _get_link_id(device, raise_exception=False)


def get_link_state(device_name):
    device = get_link_device(device_name)
    return device['state'] if device else None


def get_link_device(device_name):
    for device in get_link_devices():
        if get_attr(device, 'IFLA_IFNAME') == device_name:
            return device


@tenacity.retry(
    retry=tenacity.retry_if_exception_type(
        netlink_exceptions.NetlinkDumpInterrupted),
    wait=tenacity.wait_exponential(multiplier=0.02, max=1),
    stop=tenacity.stop_after_delay(8),
    reraise=True)
@ovn_bgp_agent.privileged.default.entrypoint
def get_link_devices(**kwargs):
    """List interfaces in a namespace

    :return: (list) interfaces in a namespace
    """
    index = kwargs.pop('index') if 'index' in kwargs else 'all'
    try:
        with iproute.IPRoute() as ip:
            return make_serializable(ip.get_links(index, **kwargs))
    except OSError:
        raise


def _run_iproute_link(command, ifname, **kwargs):
    try:
        with iproute.IPRoute() as ip:
            idx = _get_link_id(ifname)
            return ip.link(command, index=idx, **kwargs)
    except netlink_exceptions.NetlinkError as e:
        _translate_ip_device_exception(e, ifname)


def _run_iproute_addr(command, device, **kwargs):
    try:
        with iproute.IPRoute() as ip:
            idx = _get_link_id(device)
            return ip.addr(command, index=idx, **kwargs)
    except netlink_exceptions.NetlinkError as e:
        _translate_ip_addr_exception(e, ip=kwargs['address'], device=device)


@ovn_bgp_agent.privileged.default.entrypoint
def create_interface(ifname, kind, **kwargs):
    ifname = ifname[:15]
    try:
        with iproute.IPRoute() as ip:
            physical_interface = kwargs.pop('physical_interface', None)
            if physical_interface:
                link_key = 'vxlan_link' if kind == 'vxlan' else 'link'
                kwargs[link_key] = _get_link_id(physical_interface)
            ip.link("add", ifname=ifname, kind=kind, **kwargs)
    except netlink_exceptions.NetlinkError as e:
        _translate_ip_device_exception(e, ifname)


def delete_interface(ifname, **kwargs):
    _run_iproute_link('del', ifname, **kwargs)


@ovn_bgp_agent.privileged.default.entrypoint
def set_link_attribute(ifname, **kwargs):
    _run_iproute_link("set", ifname, **kwargs)


@ovn_bgp_agent.privileged.default.entrypoint
def add_ip_address(ip_address, ifname):
    net = netaddr.IPNetwork(ip_address)
    ip_version = l_net.get_ip_version(ip_address)
    address = str(net.ip)
    prefixlen = 32 if ip_version == 4 else 128
    family = _IP_VERSION_FAMILY_MAP[ip_version]
    _run_iproute_addr('add',
                      ifname,
                      address=address,
                      mask=prefixlen,
                      family=family)


@ovn_bgp_agent.privileged.default.entrypoint
def delete_ip_address(ip_address, ifname):
    net = netaddr.IPNetwork(ip_address)
    ip_version = l_net.get_ip_version(ip_address)
    address = str(net.ip)
    prefixlen = 32 if ip_version == 4 else 128
    family = _IP_VERSION_FAMILY_MAP[ip_version]
    _run_iproute_addr("delete",
                      ifname,
                      address=address,
                      mask=prefixlen,
                      family=family)


@ovn_bgp_agent.privileged.default.entrypoint
def get_ip_addresses(**kwargs):
    """List of IP addresses in a namespace

    :return: (tuple) IP addresses in a namespace
    """
    with iproute.IPRoute() as ip:
        return make_serializable(ip.get_addr(**kwargs))

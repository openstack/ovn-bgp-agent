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

import netaddr

from oslo_concurrency import processutils
from oslo_log import log as logging
import pyroute2
from pyroute2 import iproute
from pyroute2 import netlink as pyroute_netlink
from pyroute2.netlink import exceptions as netlink_exceptions
from pyroute2.netlink import rtnl
from pyroute2.netlink.rtnl import ndmsg
import tenacity

import ovn_bgp_agent
from ovn_bgp_agent import constants
from ovn_bgp_agent import exceptions as agent_exc
from ovn_bgp_agent.utils import common as common_utils
from ovn_bgp_agent.utils import linux_net as l_net

LOG = logging.getLogger(__name__)

NUD_STATES = {state[1]: state[0] for state in ndmsg.states.items()}


def get_scope_name(scope):
    """Return the name of the scope or the scope number if the name is unknown.

    For backward compatibility (with "ip" tool) "global" scope is converted to
    "universe" before converting to number
    """
    scope = 'universe' if scope == 'global' else scope
    return rtnl.rt_scope.get(scope, scope)


def set_device_state(device, state):
    set_link_attribute(device, state=state)


@ovn_bgp_agent.privileged.default.entrypoint
def ensure_vrf(vrf_name, vrf_table):
    try:
        set_device_state(vrf_name, constants.LINK_UP)
    except agent_exc.NetworkInterfaceNotFound:
        create_interface(vrf_name, 'vrf', vrf_table=vrf_table,
                         state=constants.LINK_UP)


@ovn_bgp_agent.privileged.default.entrypoint
def ensure_bridge(bridge_name):
    try:
        set_device_state(bridge_name, constants.LINK_UP)
    except agent_exc.NetworkInterfaceNotFound:
        create_interface(bridge_name, 'bridge', br_stp_state=0,
                         state=constants.LINK_UP)


@ovn_bgp_agent.privileged.default.entrypoint
def ensure_vxlan(vxlan_name, vni, local_ip, dstport):
    try:
        set_device_state(vxlan_name, constants.LINK_UP)
    except agent_exc.NetworkInterfaceNotFound:
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
    except agent_exc.NetworkInterfaceNotFound:
        create_interface(veth_name, 'veth', peer=veth_peer,
                         state=constants.LINK_UP)
    set_device_state(veth_peer, constants.LINK_UP)


@ovn_bgp_agent.privileged.default.entrypoint
def ensure_dummy_device(device):
    try:
        set_device_state(device, constants.LINK_UP)
    except agent_exc.NetworkInterfaceNotFound:
        create_interface(device, 'dummy', state=constants.LINK_UP)


@ovn_bgp_agent.privileged.default.entrypoint
def ensure_vlan_device_for_network(bridge, vlan_tag):
    vlan_device_name = '{}.{}'.format(bridge, vlan_tag)
    try:
        set_device_state(vlan_device_name, constants.LINK_UP)
    except agent_exc.NetworkInterfaceNotFound:
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
    except agent_exc.NetworkInterfaceNotFound:
        LOG.debug("Interfaces %s already deleted.", device)


@ovn_bgp_agent.privileged.default.entrypoint
def route_create(route):
    scope = route.pop('scope', 'link')
    route['scope'] = get_scope_name(scope)
    if 'family' not in route:
        route['family'] = constants.AF_INET
    _run_iproute_route('replace', **route)


@ovn_bgp_agent.privileged.default.entrypoint
def route_delete(route):
    scope = route.pop('scope', 'link')
    route['scope'] = get_scope_name(scope)
    if 'family' not in route:
        route['family'] = constants.AF_INET
    _run_iproute_route('del', **route)


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
    _run_iproute_rule('add', **rule)


@ovn_bgp_agent.privileged.default.entrypoint
def rule_delete(rule):
    _run_iproute_rule('del', **rule)


@ovn_bgp_agent.privileged.default.entrypoint
def delete_ip_rules(ip_rules):
    for rule_ip, rule_info in ip_rules.items():
        rule = l_net.create_rule_from_ip(rule_ip, int(rule_info['table']))
        _run_iproute_rule('del', **rule)


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
    family = common_utils.IP_VERSION_FAMILY_MAP[ip_version]
    _run_iproute_neigh('replace',
                       dev,
                       dst=ip,
                       lladdr=lladdr,
                       family=family,
                       state=ndmsg.states['permanent'])


@ovn_bgp_agent.privileged.default.entrypoint
def del_ip_nei(ip, lladdr, dev):
    ip_network = netaddr.IPNetwork(ip)
    family = common_utils.IP_VERSION_FAMILY_MAP[ip_network.version]

    _run_iproute_neigh('del',
                       dev,
                       dst=str(ip_network.ip),
                       lladdr=lladdr,
                       family=family,
                       state=ndmsg.states['permanent'])


@tenacity.retry(
    retry=tenacity.retry_if_exception_type(
        netlink_exceptions.NetlinkDumpInterrupted),
    wait=tenacity.wait_exponential(multiplier=0.02, max=1),
    stop=tenacity.stop_after_delay(8),
    reraise=True)
def get_neigh_entries(device, ip_version, **kwargs):
    """Dump all neighbour entries.

    :param ip_version: IP version of entries to show (4 or 6)
    :param device: Device name to use in dumping entries
    :param kwargs: Callers add any filters they use as kwargs
    :return: a list of dictionaries, each representing a neighbour.
    The dictionary format is: {'dst': ip_address,
                               'lladdr': mac_address,
                               'device': device_name}
    """
    family = common_utils.IP_VERSION_FAMILY_MAP[ip_version]
    dump = _run_iproute_neigh('dump',
                              device,
                              family=family,
                              **kwargs)
    entries = []
    for entry in dump:
        attrs = dict(entry['attrs'])
        entries.append({'dst': attrs['NDA_DST'],
                        'lladdr': attrs.get('NDA_LLADDR'),
                        'device': device,
                        'state': NUD_STATES[entry['state']]})
    return entries


def add_unreachable_route(vrf_name):
    # NOTE(ltomasbo): This method is to set the default route for the table
    # (and hence default route for the VRF)
    # ip route add table 10 unreachable default metric 4278198272
    # Find vrf table.
    device = get_link_device(vrf_name)
    ifla_linkinfo = get_attr(device, 'IFLA_LINKINFO')
    ifla_data = get_attr(ifla_linkinfo, 'IFLA_INFO_DATA')
    vrf_table = get_attr(ifla_data, 'IFLA_VRF_TABLE')
    for ip_version in common_utils.IP_VERSION_FAMILY_MAP.values():
        kwargs = {'dst': 'default',
                  'family': ip_version,
                  'table': vrf_table,
                  'type': 'unreachable',
                  'scope': None,
                  'proto': 'boot',
                  'priority': 4278198272}
        route_create(kwargs)


@ovn_bgp_agent.privileged.default.entrypoint
def create_routing_table_for_bridge(table_number, bridge):
    with open('/etc/iproute2/rt_tables', 'a') as rt_tables:
        rt_tables.write('{} {}\n'.format(table_number, bridge))


def _translate_ip_device_exception(e, device):
    if e.code == errno.ENODEV:
        raise agent_exc.NetworkInterfaceNotFound(device=device)
    if e.code == errno.EOPNOTSUPP:
        raise agent_exc.InterfaceOperationNotSupported(device=device)
    if e.code == errno.EINVAL:
        raise agent_exc.InvalidArgument(device=device)
    if e.code == errno.EEXIST:
        raise agent_exc.InterfaceAlreadyExists(device=device)
    raise e


def _translate_ip_addr_exception(e, ip, device):
    if e.code == errno.EEXIST:
        raise agent_exc.IpAddressAlreadyExists(ip=ip, device=device)
    if e.code == errno.EADDRNOTAVAIL:
        LOG.debug('No need to delete IP address %s on dev %s as it does '
                  'not exist', ip, device)
        return
    raise e


def _translate_ip_route_exception(e, kwargs):
    if e.code == errno.EEXIST:  # Already exists
        LOG.debug("Route %s already exists.", kwargs)
        return
    if e.code == errno.ENOENT or e.code == errno.ESRCH:  # Not found
        LOG.debug("Route already deleted: %s", kwargs)
        return
    raise e


def _translate_ip_rule_exception(e, kwargs):
    if e.code == errno.EEXIST:  # Already exists
        LOG.debug("Rule %s already exists.", kwargs)
        return
    if e.code == errno.ENOENT:  # Not found
        LOG.debug("Rule already deleted: %s", kwargs)
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
            raise agent_exc.NetworkInterfaceNotFound(device=ifname)
        LOG.debug('Interface %(dev)s not found', {'dev': ifname})
        return
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


@ovn_bgp_agent.privileged.default.entrypoint
def get_bridge_vlans(device_name):
    index = _get_link_id(device_name, raise_exception=False)
    if not index:
        LOG.debug("OVS Bridge %s deleted, no need to get information about "
                  "associated vlan devices", device_name)

    vlan_devices = get_link_devices(link=index)
    vlans = []
    for vlan_device in vlan_devices:
        ifla_linkinfo = get_attr(vlan_device, 'IFLA_LINKINFO')
        if ifla_linkinfo:
            ifla_data = get_attr(ifla_linkinfo, 'IFLA_INFO_DATA')
            if ifla_data:
                vlans.append(get_attr(ifla_data, 'IFLA_VLAN_ID'))
    return vlans


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


def _run_iproute_route(command, **kwargs):
    try:
        with iproute.IPRoute() as ip:
            ip.route(command, **kwargs)
    except netlink_exceptions.NetlinkError as e:
        _translate_ip_route_exception(e, kwargs)


def _run_iproute_rule(command, **kwargs):
    try:
        with iproute.IPRoute() as ip:
            ip.rule(command, **kwargs)
    except netlink_exceptions.NetlinkError as e:
        _translate_ip_rule_exception(e, kwargs)


def _run_iproute_neigh(command, device, **kwargs):
    try:
        with iproute.IPRoute() as ip:
            idx = _get_link_id(device)
            return ip.neigh(command, ifindex=idx, **kwargs)
    except agent_exc.NetworkInterfaceNotFound:
        LOG.debug("No need to %s nei for dev %s as it does not exists",
                  command, device)


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


@ovn_bgp_agent.privileged.default.entrypoint
def delete_interface(ifname, **kwargs):
    ifname = ifname[:15]
    _run_iproute_link('del', ifname, **kwargs)


@ovn_bgp_agent.privileged.default.entrypoint
def set_link_attribute(ifname, **kwargs):
    ifname = ifname[:15]
    _run_iproute_link("set", ifname, **kwargs)


@ovn_bgp_agent.privileged.default.entrypoint
def add_ip_address(ip_address, ifname):
    ifname = ifname[:15]
    net = netaddr.IPNetwork(ip_address)
    ip_version = l_net.get_ip_version(ip_address)
    address = str(net.ip)
    prefixlen = 32 if ip_version == 4 else 128
    family = common_utils.IP_VERSION_FAMILY_MAP[ip_version]
    _run_iproute_addr('add',
                      ifname,
                      address=address,
                      mask=prefixlen,
                      family=family)


@ovn_bgp_agent.privileged.default.entrypoint
def delete_ip_address(ip_address, ifname):
    ifname = ifname[:15]
    net = netaddr.IPNetwork(ip_address)
    ip_version = l_net.get_ip_version(ip_address)
    address = str(net.ip)
    prefixlen = 32 if ip_version == 4 else 128
    family = common_utils.IP_VERSION_FAMILY_MAP[ip_version]
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


@tenacity.retry(
    retry=tenacity.retry_if_exception_type(
        netlink_exceptions.NetlinkDumpInterrupted),
    wait=tenacity.wait_exponential(multiplier=0.02, max=1),
    stop=tenacity.stop_after_delay(8),
    reraise=True)
@ovn_bgp_agent.privileged.default.entrypoint
def list_ip_routes(ip_version, device=None, table=None, **kwargs):
    """List IP routes"""
    kwargs['family'] = common_utils.IP_VERSION_FAMILY_MAP[ip_version]
    if device:
        kwargs['oif'] = _get_link_id(device)
    if table:
        kwargs['table'] = int(table)
    with iproute.IPRoute() as ip:
        return make_serializable(ip.route('show', **kwargs))


@ovn_bgp_agent.privileged.default.entrypoint
def list_ip_rules(ip_version, **kwargs):
    """List all IP rules"""
    with iproute.IPRoute() as ip:
        return make_serializable(ip.get_rules(
            family=common_utils.IP_VERSION_FAMILY_MAP[ip_version], **kwargs))

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

import functools
import random

import netaddr
from neutron_lib import constants as n_const
from oslo_utils import uuidutils
from pyroute2.iproute import linux as iproute_linux
from pyroute2.netlink import rtnl
from pyroute2.netlink.rtnl import ifaddrmsg

from ovn_bgp_agent import constants
from ovn_bgp_agent import exceptions as agent_exc
from ovn_bgp_agent.privileged import linux_net
from ovn_bgp_agent.tests.functional import base as base_functional
from ovn_bgp_agent.tests import utils as test_utils
from ovn_bgp_agent.utils import common as common_utils
from ovn_bgp_agent.utils import linux_net as l_net


IP_ADDRESS_EVENTS = {'RTM_NEWADDR': 'added',
                     'RTM_DELADDR': 'removed'}
IP_ADDRESS_SCOPE = {rtnl.rtscopes['RT_SCOPE_UNIVERSE']: 'global',
                    rtnl.rtscopes['RT_SCOPE_SITE']: 'site',
                    rtnl.rtscopes['RT_SCOPE_LINK']: 'link',
                    rtnl.rtscopes['RT_SCOPE_HOST']: 'host'}


def set_up(ifname):
    linux_net.set_link_attribute(ifname, state='up')


def ip_to_cidr(ip, prefix=None):
    """Convert an ip with no prefix to cidr notation

    :param ip: An ipv4 or ipv6 address.  Convertible to netaddr.IPNetwork.
    :param prefix: Optional prefix.  If None, the default 32 will be used for
        ipv4 and 128 for ipv6.
    """
    net = netaddr.IPNetwork(ip)
    if prefix is not None:
        # Can't pass ip and prefix separately.  Must concatenate strings.
        net = netaddr.IPNetwork(str(net.ip) + '/' + str(prefix))
    return str(net)


def _parse_ip_address(pyroute2_address, device_name):
    ip = linux_net.get_attr(pyroute2_address, 'IFA_ADDRESS')
    ip_length = pyroute2_address['prefixlen']
    event = IP_ADDRESS_EVENTS.get(pyroute2_address.get('event'))
    cidr = ip_to_cidr(ip, prefix=ip_length)
    flags = linux_net.get_attr(pyroute2_address, 'IFA_FLAGS')
    dynamic = not bool(flags & ifaddrmsg.IFA_F_PERMANENT)
    tentative = bool(flags & ifaddrmsg.IFA_F_TENTATIVE)
    dadfailed = bool(flags & ifaddrmsg.IFA_F_DADFAILED)
    scope = IP_ADDRESS_SCOPE[pyroute2_address['scope']]
    return {'name': device_name,
            'cidr': cidr,
            'scope': scope,
            'broadcast': linux_net.get_attr(pyroute2_address, 'IFA_BROADCAST'),
            'dynamic': dynamic,
            'tentative': tentative,
            'dadfailed': dadfailed,
            'event': event}


def get_ip_addresses(ifname):
    device = get_devices_info(ifname=ifname)
    if not device:
        return
    ip_addresses = linux_net.get_ip_addresses(
        index=list(device.values())[0]['index'])
    return [_parse_ip_address(_ip, ifname) for _ip in ip_addresses]


def get_devices_info(**kwargs):
    devices = linux_net.get_link_devices(**kwargs)
    retval = {}
    for device in devices:
        ret = {'index': device['index'],
               'name': linux_net.get_attr(device, 'IFLA_IFNAME'),
               'operstate': linux_net.get_attr(device, 'IFLA_OPERSTATE'),
               'state': device['state'],
               'linkmode': linux_net.get_attr(device, 'IFLA_LINKMODE'),
               'mtu': linux_net.get_attr(device, 'IFLA_MTU'),
               'promiscuity': linux_net.get_attr(device, 'IFLA_PROMISCUITY'),
               'mac': linux_net.get_attr(device, 'IFLA_ADDRESS'),
               'broadcast': linux_net.get_attr(device, 'IFLA_BROADCAST'),
               'master': linux_net.get_attr(device, 'IFLA_MASTER'),
               }
        ifla_link = linux_net.get_attr(device, 'IFLA_LINK')
        if ifla_link:
            ret['parent_index'] = ifla_link
        ifla_linkinfo = linux_net.get_attr(device, 'IFLA_LINKINFO')
        if ifla_linkinfo:
            ret['kind'] = linux_net.get_attr(ifla_linkinfo, 'IFLA_INFO_KIND')
            ret['slave_kind'] = linux_net.get_attr(ifla_linkinfo,
                                                   'IFLA_INFO_SLAVE_KIND')
            ifla_data = linux_net.get_attr(ifla_linkinfo, 'IFLA_INFO_DATA')
            if ret['kind'] == 'vxlan':
                ret['vxlan_id'] = linux_net.get_attr(ifla_data,
                                                     'IFLA_VXLAN_ID')
                ret['vxlan_group'] = linux_net.get_attr(ifla_data,
                                                        'IFLA_VXLAN_GROUP')
                ret['vxlan_link_index'] = linux_net.get_attr(ifla_data,
                                                             'IFLA_VXLAN_LINK')
                ret['vxlan_port'] = linux_net.get_attr(ifla_data,
                                                       'IFLA_VXLAN_PORT')
                ret['vxlan_local'] = linux_net.get_attr(ifla_data,
                                                        'IFLA_VXLAN_LOCAL')
                ret['vxlan_learning'] = bool(
                    linux_net.get_attr(ifla_data, 'IFLA_VXLAN_LEARNING'))
            elif ret['kind'] == 'vlan':
                ret['vlan_id'] = linux_net.get_attr(ifla_data, 'IFLA_VLAN_ID')
            elif ret['kind'] == 'bridge':
                ret['stp'] = linux_net.get_attr(ifla_data, 'IFLA_BR_STP_STATE')
                ret['forward_delay'] = linux_net.get_attr(
                    ifla_data, 'IFLA_BR_FORWARD_DELAY')
            elif ret['kind'] == 'vrf':
                ret['vrf_table'] = linux_net.get_attr(ifla_data,
                                                      'IFLA_VRF_TABLE')

        retval[device['index']] = ret

    for device in retval.values():
        if device.get('parent_index'):
            parent_device = retval.get(device['parent_index'])
            if parent_device:
                device['parent_name'] = parent_device['name']
        elif device.get('vxlan_link_index'):
            device['vxlan_link_name'] = (
                retval[device['vxlan_link_index']]['name'])

    return retval


class _LinuxNetTestCase(base_functional.BaseFunctionalTestCase):

    def setUp(self):
        super().setUp()
        self.dev_name = uuidutils.generate_uuid()[:15]
        self.dev_name2 = uuidutils.generate_uuid()[:15]
        self.addCleanup(self._delete_interface)

    def _delete_interface(self):
        def delete_device(device_name):
            try:
                linux_net.delete_interface(device_name)
            except Exception:
                pass

        if self._get_device(self.dev_name):
            delete_device(self.dev_name)
        if self._get_device(self.dev_name2):
            delete_device(self.dev_name2)

    def _get_device(self, device_name):
        devices = get_devices_info()
        for device in devices.values():
            if device['name'] == device_name:
                return device

    def _assert_state(self, device_name, state):
        device = self._get_device(device_name)
        return state == device['state']

    def _check_status(self, device_name):
        fn = functools.partial(self._assert_state, device_name,
                               constants.LINK_DOWN)
        test_utils.wait_until_true(fn, timeout=5)
        set_up(device_name)
        fn = functools.partial(self._assert_state, device_name,
                               constants.LINK_UP)
        test_utils.wait_until_true(fn, timeout=5)


class IpLinkTestCase(_LinuxNetTestCase):

    def test_create_interface_dummy(self):
        linux_net.create_interface(self.dev_name, 'dummy')
        device = self._get_device(self.dev_name)
        self.assertEqual('dummy', device['kind'])
        self._check_status(self.dev_name)

    def test_create_interface_vlan(self):
        vlan_id = random.randint(2, 4094)
        linux_net.create_interface(self.dev_name, 'dummy')
        linux_net.create_interface(self.dev_name2, 'vlan',
                                   physical_interface=self.dev_name,
                                   vlan_id=vlan_id)
        device = self._get_device(self.dev_name2)
        self.assertEqual('vlan', device['kind'])
        self.assertEqual(vlan_id, device['vlan_id'])
        self._check_status(self.dev_name)

    def test_create_interface_vxlan(self):
        vxlan_id = random.randint(2, 4094)
        vxlan_port = random.randint(10000, 65534)
        vxlan_local = '1.2.3.4'
        linux_net.create_interface(self.dev_name, 'vxlan',
                                   vxlan_id=vxlan_id,
                                   vxlan_port=vxlan_port,
                                   vxlan_local=vxlan_local,
                                   vxlan_learning=False,
                                   state=constants.LINK_UP)
        device = self._get_device(self.dev_name)
        self.assertEqual('vxlan', device['kind'])
        self.assertEqual(vxlan_id, device['vxlan_id'])
        self.assertEqual(vxlan_port, device['vxlan_port'])
        self.assertEqual(vxlan_local, device['vxlan_local'])
        self.assertEqual(constants.LINK_UP, device['state'])
        self.assertFalse(device['vxlan_learning'])

    def test_create_interface_veth(self):
        linux_net.create_interface(self.dev_name, 'veth', peer=self.dev_name2)
        device = self._get_device(self.dev_name)
        self.assertEqual('veth', device['kind'])
        self.assertEqual(self.dev_name2, device['parent_name'])
        device = self._get_device(self.dev_name2)
        self.assertEqual('veth', device['kind'])
        self.assertEqual(self.dev_name, device['parent_name'])
        self._check_status(self.dev_name)
        self._check_status(self.dev_name2)

    def test_create_interface_bridge(self):
        linux_net.create_interface(self.dev_name, 'bridge', br_stp_state=0)
        device = self._get_device(self.dev_name)
        self.assertEqual('bridge', device['kind'])
        self.assertEqual(0, device['stp'])
        self._check_status(self.dev_name)

    def test_create_interface_vrf(self):
        vrf_table = random.randint(10, 2000)
        linux_net.create_interface(self.dev_name, 'vrf', vrf_table=vrf_table)
        device = self._get_device(self.dev_name)
        self.assertEqual('vrf', device['kind'])
        self.assertEqual(vrf_table, device['vrf_table'])
        self._check_status(self.dev_name)

    def _check_device_master_vrf(self, device, master=None):
        device_info = self._get_device(device)
        if not master:
            self.assertIsNone(device_info['master'])
            self.assertIsNone(device_info['slave_kind'])
        else:
            master_info = self._get_device(master)
            self.assertEqual(master_info['index'], device_info['master'])
            self.assertEqual('vrf', device_info['slave_kind'])

    def test_set_master_for_device_bridge(self):
        vrf_table = random.randint(10, 2000)
        linux_net.create_interface(self.dev_name, 'vrf', vrf_table=vrf_table)
        linux_net.create_interface(self.dev_name2, 'bridge', br_stp_state=0)
        self._check_device_master_vrf(self.dev_name2)
        linux_net.set_master_for_device(self.dev_name2, self.dev_name)
        self._check_device_master_vrf(self.dev_name2, master=self.dev_name)

    def test_set_master_for_device_dummy(self):
        vrf_table = random.randint(10, 2000)
        linux_net.create_interface(self.dev_name, 'vrf', vrf_table=vrf_table)
        linux_net.create_interface(self.dev_name2, 'dummy')
        self._check_device_master_vrf(self.dev_name2)
        linux_net.set_master_for_device(self.dev_name2, self.dev_name)
        self._check_device_master_vrf(self.dev_name2, master=self.dev_name)

    def test_set_master_for_device_vlan(self):
        vrf_table = random.randint(10, 2000)
        linux_net.create_interface(self.dev_name, 'vrf', vrf_table=vrf_table)
        vlan_id = random.randint(2, 4094)
        dev_name3 = uuidutils.generate_uuid()[:15]
        linux_net.create_interface(self.dev_name2, 'dummy')
        linux_net.create_interface(dev_name3, 'vlan',
                                   physical_interface=self.dev_name2,
                                   vlan_id=vlan_id)
        self._check_device_master_vrf(dev_name3)
        linux_net.set_master_for_device(dev_name3, self.dev_name)
        self._check_device_master_vrf(dev_name3, master=self.dev_name)

    def test_set_master_for_device_veth(self):
        vrf_table = random.randint(10, 2000)
        linux_net.create_interface(self.dev_name, 'vrf', vrf_table=vrf_table)
        dev_name3 = uuidutils.generate_uuid()[:15]
        linux_net.create_interface(self.dev_name2, 'veth', peer=dev_name3)
        self._check_device_master_vrf(self.dev_name2)
        linux_net.set_master_for_device(self.dev_name2, self.dev_name)
        self._check_device_master_vrf(self.dev_name2, master=self.dev_name)

    def test_ensure_vlan_device_for_network(self):
        self.dev_name = uuidutils.generate_uuid()[:8]
        linux_net.create_interface(self.dev_name, 'dummy')
        linux_net.set_device_state(self.dev_name, constants.LINK_UP)
        vlan_id = random.randint(2, 4094)

        # Ensure the method call is idempotent.
        for _ in range(2):
            linux_net.ensure_vlan_device_for_network(self.dev_name, vlan_id)
            fn = functools.partial(self._assert_state, self.dev_name,
                                   constants.LINK_UP)
            test_utils.wait_until_true(fn, timeout=5)

    def test_ensure_vrf(self):
        vrf_table = random.randint(10, 2000)
        # Ensure the method call is idempotent.
        for _ in range(2):
            linux_net.ensure_vrf(self.dev_name, vrf_table)
            fn = functools.partial(self._assert_state, self.dev_name,
                                   constants.LINK_UP)
            test_utils.wait_until_true(fn, timeout=5)

    def test_ensure_bridge(self):
        # Ensure the method call is idempotent.
        for _ in range(2):
            linux_net.ensure_bridge(self.dev_name)
            fn = functools.partial(self._assert_state, self.dev_name,
                                   constants.LINK_UP)
            test_utils.wait_until_true(fn, timeout=5)

    def test_ensure_vxlan(self):
        vxlan_id = random.randint(2, 4094)
        vxlan_port = random.randint(10000, 65534)
        vxlan_local = '1.2.3.4'
        # Ensure the method call is idempotent.
        for _ in range(2):
            linux_net.ensure_vxlan(self.dev_name, vxlan_id, vxlan_local,
                                   vxlan_port)
            fn = functools.partial(self._assert_state, self.dev_name,
                                   constants.LINK_UP)
            test_utils.wait_until_true(fn, timeout=5)

    def test_ensure_veth(self):
        # Ensure the method call is idempotent.
        for _ in range(2):
            linux_net.ensure_veth(self.dev_name, self.dev_name2)
            fn = functools.partial(self._assert_state, self.dev_name,
                                   constants.LINK_UP)
            test_utils.wait_until_true(fn, timeout=5)

    def test_ensure_dummy(self):
        for _ in range(2):
            linux_net.ensure_dummy_device(self.dev_name)
            fn = functools.partial(self._assert_state, self.dev_name,
                                   constants.LINK_UP)
            test_utils.wait_until_true(fn, timeout=5)

    def test_get_bridge_vlan_devices(self):
        vlan_id = random.randint(2, 4094)
        linux_net.create_interface(self.dev_name, 'dummy')
        linux_net.create_interface(self.dev_name2, 'vlan',
                                   physical_interface=self.dev_name,
                                   vlan_id=vlan_id)

        vlan_devices = linux_net.get_bridge_vlans(self.dev_name)
        self.assertEqual(vlan_devices[0], vlan_id)


class IpAddressTestCase(_LinuxNetTestCase):

    def test_add_and_delete_ip_address(self):
        def check_ip_address(ip_address, device_name, present=True):
            ip_addresses = get_ip_addresses(self.dev_name)
            if l_net.get_ip_version(ip_address) == constants.IP_VERSION_6:
                address = '{}/128'.format(ip_address)
            else:
                address = '{}/32'.format(ip_address)
            for _ip in ip_addresses:
                if _ip['cidr'] == address:
                    if present:
                        return
                    else:
                        self.fail('IP address %s present in device %s' %
                                  (ip_address, device_name))

            if present:
                self.fail('IP address %s not found in device %s' %
                          (ip_address, device_name))

        ip_addresses = ('240.0.0.1', 'fd00::1')
        linux_net.create_interface(self.dev_name, 'dummy')
        for ip_address in ip_addresses:
            linux_net.add_ip_address(ip_address, self.dev_name)
            check_ip_address(ip_address, self.dev_name)
            # ensure nothing breaks if same IP gets added,
            # it should raise exception that is handled in the utils
            self.assertRaises(agent_exc.IpAddressAlreadyExists,
                              linux_net.add_ip_address, ip_address,
                              self.dev_name)

        for ip_address in ip_addresses:
            linux_net.delete_ip_address(ip_address, self.dev_name)
            check_ip_address(ip_address, self.dev_name, present=False)
            # ensure removing a missing IP is ok
            linux_net.delete_ip_address(ip_address, self.dev_name)

    def test_add_ip_address_no_device(self):
        self.assertRaises(agent_exc.NetworkInterfaceNotFound,
                          linux_net.add_ip_address, '240.0.0.1', self.dev_name)

    def test_delete_ip_address_no_device(self):
        self.assertRaises(agent_exc.NetworkInterfaceNotFound,
                          linux_net.delete_ip_address, '240.0.0.1',
                          self.dev_name)

    def test_delete_ip_address_no_ip_on_device(self):
        linux_net.create_interface(self.dev_name, 'dummy')
        # No exception is raised.
        linux_net.delete_ip_address('192.168.0.1', self.dev_name)


class IpRouteTestCase(_LinuxNetTestCase):

    def setUp(self):
        super().setUp()
        linux_net.create_interface(self.dev_name, 'dummy',
                                   state=constants.LINK_UP)
        self.device = self._get_device(self.dev_name)

    def _check_routes(self, cidrs, device_name, table=None, scope='link',
                      proto='static', route_present=True):
        table = table or iproute_linux.DEFAULT_TABLE
        cidr = None
        for cidr in cidrs:
            ip_version = l_net.get_ip_version(cidr)
            if ip_version == n_const.IP_VERSION_6:
                scope = 0
            if isinstance(scope, int):
                scope = linux_net.get_scope_name(scope)
            routes = linux_net.list_ip_routes(ip_version, device=device_name)
            for route in routes:
                ip = linux_net.get_attr(route, 'RTA_DST')
                mask = route['dst_len']
                if not (ip == str(netaddr.IPNetwork(cidr).ip) and
                        mask == netaddr.IPNetwork(cidr).cidr.prefixlen):
                    continue
                self.assertEqual(table, route['table'])
                self.assertEqual(
                    common_utils.IP_VERSION_FAMILY_MAP[ip_version],
                    route['family'])
                ret_scope = linux_net.get_scope_name(route['scope'])
                self.assertEqual(scope, ret_scope)
                self.assertEqual(rtnl.rt_proto[proto], route['proto'])
                break
            else:
                if route_present:
                    self.fail('CIDR %s not found in the list of routes' % cidr)
                else:
                    return
        if not route_present:
            self.fail('CIDR %s found in the list of routes' % cidr)

    def _add_route_device_and_check(self, cidrs, table=None, scope='link',
                                    proto='static'):
        for cidr in cidrs:
            ip_version = l_net.get_ip_version(cidr)
            family = common_utils.IP_VERSION_FAMILY_MAP[ip_version]
            route = {'dst': cidr,
                     'oif': self.device['index'],
                     'table': table,
                     'family': family,
                     'scope': scope,
                     'proto': proto}
            linux_net.route_create(route)
            # recreate route to ensure it does not break anything
            linux_net.route_create(route)
        self._check_routes(cidrs, self.dev_name, table=table, scope=scope,
                           proto=proto)
        for cidr in cidrs:
            ip_version = l_net.get_ip_version(cidr)
            family = common_utils.IP_VERSION_FAMILY_MAP[ip_version]
            route = {'dst': cidr,
                     'oif': self.device['index'],
                     'table': table,
                     'family': family,
                     'scope': scope,
                     'proto': proto}
            linux_net.route_delete(route)
            # redelete route to ensure it does not break anything
            linux_net.route_delete(route)
        self._check_routes(cidrs, self.dev_name, table=table, scope=scope,
                           proto=proto, route_present=False)

    def test_add_route_device(self):
        cidrs = ['192.168.1.0/24', '2001:db1::/64']
        self._add_route_device_and_check(cidrs=cidrs, table=None)

    def test_add_route_device_table(self):
        cidrs = ['192.168.2.0/24', '2001:db2::/64']
        self._add_route_device_and_check(cidrs=cidrs, table=100)

    def test_add_route_device_scope_site(self):
        cidrs = ['192.168.3.0/24', '2003:db3::/64']
        self._add_route_device_and_check(cidrs=cidrs, scope='site')

    def test_add_route_device_scope_host(self):
        cidrs = ['192.168.4.0/24', '2003:db4::/64']
        self._add_route_device_and_check(cidrs=cidrs, scope='host')

    def test_add_route_device_proto_static(self):
        cidrs = ['192.168.5.0/24', '2003:db5::/64']
        self._add_route_device_and_check(cidrs=cidrs, proto='static')

    def test_add_route_device_proto_redirect(self):
        cidrs = ['192.168.6.0/24', '2003:db6::/64']
        self._add_route_device_and_check(cidrs=cidrs, proto='redirect')

    def test_add_route_device_proto_kernel(self):
        cidrs = ['192.168.7.0/24', '2003:db7::/64']
        self._add_route_device_and_check(cidrs=cidrs, proto='kernel')

    def test_add_route_device_proto_boot(self):
        cidrs = ['192.168.8.0/24', '2003:db8::/64']
        self._add_route_device_and_check(cidrs=cidrs, proto='boot')

    def test_add_unreachable_route(self):
        vrf_table = random.randint(10, 2000)
        linux_net.create_interface(self.dev_name2, 'vrf', vrf_table=vrf_table)
        linux_net.add_unreachable_route(self.dev_name2)
        for ip_version in (n_const.IP_VERSION_4, n_const.IP_VERSION_6):
            routes = linux_net.list_ip_routes(ip_version, table=vrf_table)
            self.assertEqual(1, len(routes))
            self.assertEqual(rtnl.rt_proto['boot'], routes[0]['proto'])
            self.assertEqual(rtnl.rtypes['RTN_UNREACHABLE'], routes[0]['type'])
            self.assertEqual(4278198272,
                             linux_net.get_attr(routes[0], 'RTA_PRIORITY'))


class IpRuleTestCase(_LinuxNetTestCase):

    def _test_add_and_delete_ip_rule(self, ip_version, cidrs):
        table = random.randint(10, 250)
        rules_added = []
        for cidr in cidrs:
            _ip = netaddr.IPNetwork(cidr)
            rule = {'dst': str(_ip.ip),
                    'dst_len': _ip.netmask.netmask_bits(),
                    'table': table,
                    'family': common_utils.IP_VERSION_FAMILY_MAP[ip_version]}
            rules_added.append(rule)
            linux_net.rule_create(rule)
            # recreate the last rule, to ensure recreation does not fail
            linux_net.rule_create(rule)
        rules = linux_net.list_ip_rules(ip_version, table=table)
        self.assertEqual(len(cidrs), len(rules))
        for idx, rule in enumerate(rules):
            _ip = netaddr.IPNetwork(cidrs[idx])
            self.assertEqual(str(_ip.ip), linux_net.get_attr(rule, 'FRA_DST'))
            self.assertEqual(_ip.netmask.netmask_bits(), rule['dst_len'])

        for rule in rules_added:
            linux_net.rule_delete(rule)
            # remove again the last rule to ensure it does not fail
            linux_net.rule_delete(rule)
        rules = linux_net.list_ip_rules(ip_version, table=table)
        self.assertEqual(0, len(rules))

    def test_add_and_delete_ip_rule_v4(self):
        cidrs = ['192.168.0.0/24', '172.90.0.0/16', '10.0.0.0/8']
        self._test_add_and_delete_ip_rule(n_const.IP_VERSION_4, cidrs)

    def test_add_and_delete_ip_rule_v6(self):
        cidrs = ['2001:db8::/64', 'fe80::/10']
        self._test_add_and_delete_ip_rule(n_const.IP_VERSION_6, cidrs)


class IpNeighTestCase(_LinuxNetTestCase):

    def setUp(self):
        super().setUp()
        linux_net.create_interface(self.dev_name, 'dummy',
                                   state=constants.LINK_UP)
        self.device = self._get_device(self.dev_name)

    def test_add_and_delete_neigh(self):
        # Initial check, nothing in the ARP table.
        neigh4 = linux_net.get_neigh_entries(self.dev_name,
                                             constants.IP_VERSION_4)
        neigh6 = linux_net.get_neigh_entries(self.dev_name,
                                             constants.IP_VERSION_6)
        self.assertEqual([], neigh4)
        self.assertEqual([], neigh6)

        # Add a set of IP/MAC addresses.
        ip_and_mac = [('10.0.0.1', 'ca:fe:ca:fe:00:01'),
                      ('10.0.0.2', 'ca:fe:ca:fe:00:02'),
                      ('2001:db8::3', 'ca:fe:ca:fe:00:03'),
                      ('2001:db8::4', 'ca:fe:ca:fe:00:04')]
        for ip, mac in ip_and_mac:
            linux_net.add_ip_nei(ip, mac, self.dev_name)
        neigh4 = linux_net.get_neigh_entries(self.dev_name,
                                             constants.IP_VERSION_4)
        neigh6 = linux_net.get_neigh_entries(self.dev_name,
                                             constants.IP_VERSION_6)
        self.assertEqual(2, len(neigh4))
        self.assertEqual(2, len(neigh6))
        for neigh in neigh4 + neigh6:
            for ip, mac in ip_and_mac:
                if ip == neigh['dst'] and mac == neigh['lladdr']:
                    break
            else:
                self.fail('IP/MAC %s/%s is not present in the ip-neigh table' %
                          (neigh['dst'], neigh['lladdr']))

        # Delete the entries.
        for ip, mac in ip_and_mac:
            linux_net.del_ip_nei(ip, mac, self.dev_name)
        neigh4 = linux_net.get_neigh_entries(self.dev_name,
                                             constants.IP_VERSION_4)
        neigh6 = linux_net.get_neigh_entries(self.dev_name,
                                             constants.IP_VERSION_6)
        self.assertEqual(0, len(neigh4))
        self.assertEqual(0, len(neigh6))

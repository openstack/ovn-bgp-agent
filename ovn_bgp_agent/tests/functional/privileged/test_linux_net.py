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
from oslo_utils import uuidutils
from pyroute2.netlink import rtnl
from pyroute2.netlink.rtnl import ifaddrmsg

from ovn_bgp_agent import constants
from ovn_bgp_agent import exceptions as agent_exc
from ovn_bgp_agent.privileged import linux_net
from ovn_bgp_agent.tests.functional import base as base_functional
from ovn_bgp_agent.tests import utils as test_utils
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


class LinuxNetTestCase(base_functional.BaseFunctionalTestCase):

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
            # ensure nothing breaks if same IP gets added
            # It should raise exception that is handled in the utils
            self.assertRaises(agent_exc.IpAddressAlreadyExists,
                              linux_net.add_ip_address, ip_address,
                              self.dev_name)

        for ip_address in ip_addresses:
            linux_net.delete_ip_address(ip_address, self.dev_name)
            check_ip_address(ip_address, self.dev_name, present=False)
            # ensure removing a missing IP is ok
            linux_net.delete_ip_address(ip_address, self.dev_name)

    def test_add_ip_address_no_device(self):
        self.assertRaises(linux_net.NetworkInterfaceNotFound,
                          linux_net.add_ip_address, '240.0.0.1', self.dev_name)

    def test_delete_ip_address_no_device(self):
        self.assertRaises(linux_net.NetworkInterfaceNotFound,
                          linux_net.delete_ip_address, '240.0.0.1',
                          self.dev_name)

    def test_delete_ip_address_no_ip_on_device(self):
        linux_net.create_interface(self.dev_name, 'dummy')
        # No exception is raised.
        linux_net.delete_ip_address('192.168.0.1', self.dev_name)

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

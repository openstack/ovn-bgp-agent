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

import netaddr
from neutron_lib.utils import net as net_utils
from oslo_utils import uuidutils

from ovn_bgp_agent import exceptions as agent_exc
from ovn_bgp_agent.privileged import linux_net as priv_linux_net
from ovn_bgp_agent.tests.functional import base as base_functional
from ovn_bgp_agent.tests.functional.privileged import test_linux_net as \
    test_priv_linux_net
from ovn_bgp_agent.utils import common as common_utils
from ovn_bgp_agent.utils import linux_net


class GetInterfaceTestCase(base_functional.BaseFunctionalTestCase):

    def _delete_interfaces(self, dev_names):
        for dev_name in dev_names:
            try:
                priv_linux_net.delete_interface(dev_name)
            except Exception:
                pass

    def _get_device(self, device_name):
        device_index = linux_net.get_interface_index(device_name)
        devices = test_priv_linux_net.get_devices_info(index=device_index)
        for device in devices.values():
            if device['name'] == device_name:
                return device

    def test_get_interfaces(self):
        dev_names = list(map(lambda x: uuidutils.generate_uuid()[:15],
                             range(3)))
        self.addCleanup(self._delete_interfaces, dev_names)
        for dev_name in dev_names:
            priv_linux_net.create_interface(dev_name, 'dummy')
        ret = linux_net.get_interfaces()
        for dev in dev_names:
            self.assertIn(dev, ret)

    def test_get_interface_index(self):
        dev_name = uuidutils.generate_uuid()[:15]
        self.addCleanup(self._delete_interfaces, [dev_name])
        priv_linux_net.create_interface(dev_name, 'dummy')
        device = self._get_device(dev_name)

        ret = linux_net.get_interface_index(dev_name)
        self.assertEqual(device['index'], ret)

    def test_get_interface_address(self):
        dev_names = list(map(lambda x: uuidutils.generate_uuid()[:15],
                             range(5)))
        self.addCleanup(self._delete_interfaces, dev_names)
        for dev_name in dev_names:
            mac_address = net_utils.get_random_mac(
                'fa:16:3e:00:00:00'.split(':'))
            priv_linux_net.create_interface(dev_name, 'dummy',
                                            address=mac_address)
            mac = linux_net.get_interface_address(dev_name)
            self.assertEqual(mac_address, mac)

    def test_get_interface_address_no_interface(self):
        self.assertRaises(agent_exc.NetworkInterfaceNotFound,
                          linux_net.get_interface_address, 'no_interface_name')

    def test_get_nic_info(self):
        dev_name = uuidutils.generate_uuid()[:15]
        ip = '172.24.10.100/32'
        self.addCleanup(self._delete_interfaces, [dev_name])
        mac_address = net_utils.get_random_mac(
            'fa:16:3e:00:00:00'.split(':'))
        priv_linux_net.create_interface(dev_name, 'dummy',
                                        address=mac_address)
        priv_linux_net.add_ip_address(ip, dev_name)
        ret = linux_net.get_nic_info(dev_name)
        self.assertEqual((ip, mac_address), ret)

    def test_get_nic_info_no_interface(self):
        self.assertRaises(agent_exc.NetworkInterfaceNotFound,
                          linux_net.get_nic_info, 'no_interface_name')

    def test_get_exposed_ips(self):
        ips = ['240.0.0.1', 'fd00::1']
        dev_name = uuidutils.generate_uuid()[:15]
        self.addCleanup(self._delete_interfaces, [dev_name])
        priv_linux_net.create_interface(dev_name, 'dummy')
        for ip in ips:
            priv_linux_net.add_ip_address(ip, dev_name)

        ret = linux_net.get_exposed_ips(dev_name)
        self.assertEqual(ips, ret)

    def test_get_nic_ip(self):
        ips = ['240.0.0.1', 'fd00::1']
        dev_name = uuidutils.generate_uuid()[:15]
        self.addCleanup(self._delete_interfaces, [dev_name])
        priv_linux_net.create_interface(dev_name, 'dummy')
        for ip in ips:
            priv_linux_net.add_ip_address(ip, dev_name)

        ret = linux_net.get_nic_ip(dev_name)
        self.assertEqual(ips, ret)


class GetRulesTestCase(base_functional.BaseFunctionalTestCase):

    def _delete_rules(self, rules):
        for rule in rules:
            try:
                priv_linux_net.rule_delete(rule)
            except Exception:
                pass

    def test_get_ovn_ip_rules(self):
        cidrs = ['192.168.0.0/24', '172.90.0.0/16', 'fd00::1/128']
        table = 100
        expected_rules = {}
        rules_added = []
        for cidr in cidrs:
            _ip = netaddr.IPNetwork(cidr)
            ip_version = linux_net.get_ip_version(cidr)
            rule = {'dst': str(_ip.ip),
                    'dst_len': _ip.netmask.netmask_bits(),
                    'table': table,
                    'family': common_utils.IP_VERSION_FAMILY_MAP[ip_version]}
            dst = "{}/{}".format(str(_ip.ip), _ip.netmask.netmask_bits())
            rules_added.append(rule)
            expected_rules[dst] = {
                'table': table,
                'family': common_utils.IP_VERSION_FAMILY_MAP[ip_version]}
        self.addCleanup(self._delete_rules, rules_added)
        for rule in rules_added:
            priv_linux_net.rule_create(rule)

        ret = linux_net.get_ovn_ip_rules([table])
        self.assertEqual(expected_rules, ret)

# Copyright 2024 team.blue/nl
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from ovn_bgp_agent import constants
from ovn_bgp_agent.drivers.openstack.utils import driver_utils
from ovn_bgp_agent.tests import base as test_base
from ovn_bgp_agent.tests import utils


class TestDriverUtils(test_base.TestCase):

    def setUp(self):
        super(TestDriverUtils, self).setUp()

    def test_is_ipv6_gua(self):
        self.assertFalse(driver_utils.is_ipv6_gua('1.1.1.1'))
        self.assertFalse(driver_utils.is_ipv6_gua('fe80::1337'))
        self.assertTrue(driver_utils.is_ipv6_gua('2a01:db8::1337'))

    def test_get_addr_scopes(self):
        subnet_pool_addr_scope4 = '88e8aec3-da29-402d-becf-9fa2c38e69b8'
        subnet_pool_addr_scope6 = 'b7834aeb-2aa2-40ac-a8b5-2cded713cb58'

        # Both address pools set
        port = utils.create_row(external_ids={
            constants.SUBNET_POOL_ADDR_SCOPE4: subnet_pool_addr_scope4,
            constants.SUBNET_POOL_ADDR_SCOPE6: subnet_pool_addr_scope6,
        })
        self.assertDictEqual(driver_utils.get_addr_scopes(port), {
            constants.IP_VERSION_4: subnet_pool_addr_scope4,
            constants.IP_VERSION_6: subnet_pool_addr_scope6,
        })

        # Only IPv4
        port = utils.create_row(external_ids={
            constants.SUBNET_POOL_ADDR_SCOPE4: subnet_pool_addr_scope4,
        })
        self.assertDictEqual(driver_utils.get_addr_scopes(port), {
            constants.IP_VERSION_4: subnet_pool_addr_scope4,
            constants.IP_VERSION_6: None,
        })

        # Only IPv6
        port = utils.create_row(external_ids={
            constants.SUBNET_POOL_ADDR_SCOPE6: subnet_pool_addr_scope6,
        })
        self.assertDictEqual(driver_utils.get_addr_scopes(port), {
            constants.IP_VERSION_4: None,
            constants.IP_VERSION_6: subnet_pool_addr_scope6,
        })

        # No Address pools
        port = utils.create_row(external_ids={})
        self.assertDictEqual(driver_utils.get_addr_scopes(port), {
            constants.IP_VERSION_4: None,
            constants.IP_VERSION_6: None,
        })

    def test_get_port_chassis_from_options(self):
        my_host = 'foo-host'

        # it is a VM port type, should use options field.
        row = utils.create_row(
            external_ids={constants.OVN_HOST_ID_EXT_ID_KEY: 'bar-host'},
            options={constants.OVN_REQUESTED_CHASSIS: my_host})

        self.assertEqual(driver_utils.get_port_chassis(row, chassis=my_host),
                         (my_host, constants.OVN_CHASSIS_AT_OPTIONS))

    def test_get_port_chassis_from_external_ids(self):
        my_host = 'foo-host'

        # it is a VM port type, should use options field.
        row = utils.create_row(
            external_ids={constants.OVN_HOST_ID_EXT_ID_KEY: my_host})

        self.assertEqual(driver_utils.get_port_chassis(row, chassis=my_host),
                         (my_host, constants.OVN_CHASSIS_AT_EXT_IDS))

    def test_get_port_chassis_from_external_ids_virtual_port(self):
        my_host = 'foo-host'

        # it is a VM port type, should use options field.
        row = utils.create_row(
            external_ids={constants.OVN_HOST_ID_EXT_ID_KEY: my_host},
            options={constants.OVN_REQUESTED_CHASSIS: 'bar-host'},
            type=constants.OVN_VIRTUAL_VIF_PORT_TYPE)

        self.assertEqual(driver_utils.get_port_chassis(row, chassis=my_host),
                         (my_host, constants.OVN_CHASSIS_AT_EXT_IDS))

    def test_get_port_chassis_no_information(self):
        row = utils.create_row()
        self.assertEqual(driver_utils.get_port_chassis(row, chassis='foo'),
                         (None, None))

    def test_check_name_prefix(self):
        lb = utils.create_row(name='some-name')
        self.assertTrue(driver_utils.check_name_prefix(lb, 'some'))
        self.assertFalse(driver_utils.check_name_prefix(lb, 'other'))

        lb = utils.create_row(no_name='aa')
        self.assertFalse(driver_utils.check_name_prefix(lb, ''))

    def is_pf_lb(self):
        lb = utils.create_row(name='pf-floating-ip-someuuid')
        self.assertTrue(driver_utils.is_pf_lb(lb))

        lb = utils.create_row(name='lb-someuuid')
        self.assertFalse(driver_utils.is_pf_lb(lb))

    def test_get_prefixes_from_ips(self):
        # IPv4
        ips = ['192.168.0.1/24', '192.168.0.244/28', '172.13.37.59/27']
        self.assertListEqual(driver_utils.get_prefixes_from_ips(ips),
                             ['192.168.0.0/24', '192.168.0.240/28',
                              '172.13.37.32/27'])

        # IPv6
        ips = ['fe80::5097/64', 'ff00::13:37/112', 'fc00::1/46']
        self.assertListEqual(driver_utils.get_prefixes_from_ips(ips),
                             ['fe80::/64', 'ff00::13:0/112', 'fc00::/46'])

        # combined.
        ips = ['172.13.37.59/27', 'ff00::13:37/112']
        self.assertListEqual(driver_utils.get_prefixes_from_ips(ips),
                             ['172.13.37.32/27', 'ff00::13:0/112'])

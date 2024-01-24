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

# Copyright 2024 Red Hat, Inc.
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

from ovn_bgp_agent.drivers.openstack.utils import port
from ovn_bgp_agent.tests import base as test_base


class TestHasIpAddressDefined(test_base.TestCase):
    def test_no_ip_address(self):
        self.assertFalse(
            port.has_ip_address_defined('aa:bb:cc:dd:ee:ff'))

    def test_one_ip_address(self):
        self.assertTrue(
            port.has_ip_address_defined('aa:bb:cc:dd:ee:ff 10.10.1.16'))

    def test_two_ip_addresses(self):
        self.assertTrue(
            port.has_ip_address_defined(
                'aa:bb:cc:dd:ee:ff 10.10.1.16 10.10.1.17'))

    def test_three_ip_addresses(self):
        self.assertTrue(
            port.has_ip_address_defined(
                'aa:bb:cc:dd:ee:ff 10.10.1.16 10.10.1.17 10.10.1.18'))

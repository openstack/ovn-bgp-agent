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

from ovn_bgp_agent import constants
from ovn_bgp_agent.drivers.openstack.utils import loadbalancer as lb_utils
from ovn_bgp_agent.tests import base as test_base
from ovn_bgp_agent.tests import utils as test_utils


class TestGetVipsFromLb(test_base.TestCase):
    def test_get_vips(self):
        vips = {'192.168.1.50:80': '192.168.1.100:80',
                '172.24.4.5:80': '192.168.1.100:80'}
        expected_vip_set = {"192.168.1.50", "172.24.4.5"}
        row = test_utils.create_row(vips=vips)
        observed = lb_utils.get_vips(row)

        self.assertSetEqual(expected_vip_set, observed)

    def test_get_vips_not_present(self):
        row = test_utils.create_row()
        observed = lb_utils.get_vips(row)

        self.assertSetEqual(set(), observed)


class TestIsVip(test_base.TestCase):
    def test_is_vip(self):
        ip = 'ip'
        row = test_utils.create_row(
            external_ids={constants.OVN_LB_VIP_IP_EXT_ID_KEY: ip})

        self.assertTrue(lb_utils.is_vip(row, ip))


class TestIsFip(test_base.TestCase):
    def test_is_fip(self):
        ip = 'ip'
        row = test_utils.create_row(
            external_ids={constants.OVN_LB_VIP_FIP_EXT_ID_KEY: ip})

        self.assertTrue(lb_utils.is_fip(row, ip))

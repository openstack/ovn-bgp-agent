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

from ovn_bgp_agent.tests import base as test_base
from ovn_bgp_agent.tests import utils
from ovn_bgp_agent.utils import helpers


class TestHelpers(test_base.TestCase):

    def setUp(self):
        super(TestHelpers, self).setUp()

    def test_parse_bridge_mappings(self):
        bridge_mappings = "provider-1:br-ex"
        ret_net, ret_bridge = helpers.parse_bridge_mapping(bridge_mappings)

        self.assertEqual(ret_net, 'provider-1')
        self.assertEqual(ret_bridge, 'br-ex')

    def test_parse_bridge_mappings_missing_mapping(self):
        bridge_mappings = ""
        ret_net, ret_bridge = helpers.parse_bridge_mapping(bridge_mappings)

        self.assertEqual(ret_net, None)
        self.assertEqual(ret_bridge, None)

    def test_parse_bridge_mappings_wrong_format(self):
        bridge_mappings = "provider-1:br-ex:extra_field"
        ret_net, ret_bridge = helpers.parse_bridge_mapping(bridge_mappings)

        self.assertEqual(ret_net, None)
        self.assertEqual(ret_bridge, None)


class TestHelperGetLBDatapathGroup(test_base.TestCase):

    def setUp(self):
        super(TestHelperGetLBDatapathGroup, self).setUp()
        self.dp_group = utils.create_row(_uuid='fake_dp_group',
                                         datapaths=['dp'])
        self.dp_group1 = utils.create_row(_uuid='fake_dp_group1',
                                          datapaths=['dp1'])

    def test_get_lb_datapath_group(self):
        lb = utils.create_row(name='ovn-lb',
                              datapath_group=[self.dp_group])
        self.assertEqual((['dp'], []), helpers.get_lb_datapath_groups(lb))

    def test_get_lb_datapath_group_ls_datapath(self):
        lb = utils.create_row(name='ovn-lb',
                              ls_datapath_group=[self.dp_group])
        self.assertEqual((['dp'], []), helpers.get_lb_datapath_groups(lb))

    def test_get_lb_datapath_group_lr_datapath(self):
        lb = utils.create_row(name='ovn-lb',
                              lr_datapath_group=[self.dp_group])
        self.assertEqual(([], ['dp']), helpers.get_lb_datapath_groups(lb))

    def test_get_lb_datapath_group_ls_and_lr_datapath(self):
        lb = utils.create_row(name='ovn-lb',
                              ls_datapath_group=[self.dp_group],
                              lr_datapath_group=[self.dp_group1])
        self.assertEqual((['dp'], ['dp1']), helpers.get_lb_datapath_groups(lb))

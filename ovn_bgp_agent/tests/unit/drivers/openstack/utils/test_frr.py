# Copyright 2021 Red Hat, Inc.
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

import tempfile
from unittest import mock

from ovn_bgp_agent import constants
from ovn_bgp_agent.drivers.openstack.utils import frr as frr_utils
from ovn_bgp_agent.tests import base as test_base


class TestFrr(test_base.TestCase):

    def setUp(self):
        super(TestFrr, self).setUp()
        self.mock_vtysh = mock.patch('ovn_bgp_agent.privileged.vtysh').start()

    def test__get_router_id(self):
        router_id = 'fake-router'
        self.mock_vtysh.run_vtysh_command.return_value = (
            '{"ipv4Unicast": {"routerId": "%s"}}' % router_id)
        ret = frr_utils._get_router_id()
        self.assertEqual(router_id, ret)

    def test__get_router_id_no_ipv4_settings(self):
        self.mock_vtysh.run_vtysh_command.return_value = '{}'
        ret = frr_utils._get_router_id()
        self.assertIsNone(ret)

    @mock.patch.object(frr_utils, '_get_router_id')
    @mock.patch.object(tempfile, 'NamedTemporaryFile')
    def test_vrf_leak(self, mock_tf, mock_gri):
        vrf = 'fake-vrf'
        bgp_as = 'fake-bgp-as'
        router_id = 'fake-router-id'
        mock_gri.return_value = router_id

        frr_utils.vrf_leak(vrf, bgp_as)

        write_arg = mock_tf.return_value.write.call_args_list[0][0][0]
        self.assertIn(vrf, write_arg)
        self.assertIn(bgp_as, write_arg)
        # Assert the file was closed
        mock_tf.return_value.close.assert_called_once_with()

    @mock.patch.object(frr_utils, '_get_router_id')
    @mock.patch.object(tempfile, 'NamedTemporaryFile')
    def test_vrf_leak_no_router_id(self, mock_tf, mock_gri):
        mock_gri.return_value = None
        frr_utils.vrf_leak('fake-vrf', 'fake-bgp-as')
        # Assert no file was created
        self.assertFalse(mock_tf.called)

    @mock.patch.object(tempfile, 'NamedTemporaryFile')
    def _test_vrf_reconfigure(self, mock_tf, add_vrf=True):
        action = 'add-vrf' if add_vrf else 'del-vrf'
        evpn_info = {'vni': '1001', 'bgp_as': 'fake-bgp-as'}

        frr_utils.vrf_reconfigure(evpn_info, action)

        vrf_name = "{}{}".format(constants.OVN_EVPN_VRF_PREFIX,
                                 evpn_info['vni'])
        write_arg = mock_tf.return_value.write.call_args_list[0][0][0]

        if add_vrf:
            self.assertIn('\nvrf %s' % vrf_name, write_arg)
            self.assertIn('\nrouter bgp %s' % evpn_info['bgp_as'], write_arg)
        else:
            self.assertIn("no vrf %s" % vrf_name, write_arg)
            self.assertIn("no router bgp %s" % evpn_info['bgp_as'], write_arg)

        self.mock_vtysh.run_vtysh_config.assert_called_once_with(
            mock_tf.return_value.name)
        # Assert the file was closed
        mock_tf.return_value.close.assert_called_once_with()

    def test_vrf_reconfigure_add_vrf(self):
        self._test_vrf_reconfigure()

    def test_vrf_reconfigure_del_vrf(self):
        self._test_vrf_reconfigure(add_vrf=False)

    def test_vrf_reconfigure_unknown_action(self):
        frr_utils.vrf_reconfigure('fake-evpn-info', 'non-existing-action')
        # Assert run_vtysh_command() wasn't called
        self.assertFalse(self.mock_vtysh.run_vtysh_config.called)

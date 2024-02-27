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

from oslo_config import cfg
from unittest import mock

from ovn_bgp_agent import constants
from ovn_bgp_agent.drivers.openstack.utils import bgp as bgp_utils
from ovn_bgp_agent.tests import base as test_base


CONF = cfg.CONF


class TestEVPN(test_base.TestCase):

    def setUp(self):
        super(TestEVPN, self).setUp()

        self.mock_frr = mock.patch.object(bgp_utils, 'frr').start()
        self.mock_linux_net = mock.patch.object(bgp_utils, 'linux_net').start()

    def _set_exposing_method(self, exposing_method):
        CONF.set_override('exposing_method', exposing_method)
        self.addCleanup(CONF.clear_override, 'exposing_method')

    def _test_announce_ips(self, exposing_method):
        ips = ['10.10.10.1', '10.20.10.1']
        self._set_exposing_method(exposing_method)

        bgp_utils.announce_ips(list(ips))

        if exposing_method in [constants.EXPOSE_METHOD_VRF]:
            self.mock_linux_net.add_ips_to_dev.assert_not_called()
        else:
            self.mock_linux_net.add_ips_to_dev.assert_called_once_with(
                CONF.bgp_nic, ips)

    def test_announce_ips_underlay(self):
        self._test_announce_ips('underlay')

    def test_announce_ips_dynamic(self):
        self._test_announce_ips('dynamic')

    def test_announce_ips_ovn(self):
        self._test_announce_ips('ovn')

    def test_announce_ips_vrf(self):
        self._test_announce_ips('vrf')

    def test_announce_ips_l2vni(self):
        self._test_announce_ips('l2vni')

    def _test_withdraw_ips(self, exposing_method):
        ips = ['10.10.10.1', '10.20.10.1']
        self._set_exposing_method(exposing_method)

        bgp_utils.withdraw_ips(list(ips))

        if exposing_method in [constants.EXPOSE_METHOD_VRF]:
            self.mock_linux_net.del_ips_from_dev.assert_not_called()
        else:
            self.mock_linux_net.del_ips_from_dev.assert_called_once_with(
                CONF.bgp_nic, ips)

    def test_withdraw_ips_underlay(self):
        self._test_withdraw_ips('underlay')

    def test_withdraw_ips_dynamic(self):
        self._test_withdraw_ips('dynamic')

    def test_withdraw_ips_ovn(self):
        self._test_withdraw_ips('ovn')

    def test_withdraw_ips_vrf(self):
        self._test_withdraw_ips('vrf')

    def test_withdraw_ips_l2vni(self):
        self._test_withdraw_ips('l2vni')

    def _test_ensure_base_bgp_configuration(self, exposing_method):
        self._set_exposing_method(exposing_method)

        bgp_utils.ensure_base_bgp_configuration()

        if exposing_method not in [constants.EXPOSE_METHOD_UNDERLAY,
                                   constants.EXPOSE_METHOD_DYNAMIC,
                                   constants.EXPOSE_METHOD_OVN]:
            self.mock_frr.vrf_leak.assert_not_called()
            self.mock_linux_net.ensure_vrf.assert_not_called()
            self.mock_linux_net.ensure_ovn_device.assert_not_called()
        else:
            self.mock_frr.vrf_leak.assert_called_once()
            self.mock_linux_net.ensure_vrf.assert_called_once()
            self.mock_linux_net.ensure_ovn_device.assert_called_once()

    def test_ensure_base_bgp_configuration_underlay(self):
        self._test_ensure_base_bgp_configuration('underlay')

    def test_ensure_base_bgp_configuration_dynamic(self):
        self._test_ensure_base_bgp_configuration('dynamic')

    def test_ensure_base_bgp_configuration_ovn(self):
        self._test_ensure_base_bgp_configuration('ovn')

    def test_ensure_base_bgp_configuration_vrf(self):
        self._test_ensure_base_bgp_configuration('vrf')

    def test_ensure_base_bgp_configuration_l2vni(self):
        self._test_ensure_base_bgp_configuration('l2vni')

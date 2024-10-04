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
from ovn_bgp_agent.drivers.openstack import nb_exceptions
from ovn_bgp_agent.drivers.openstack.utils import nat as nat_utils
from ovn_bgp_agent.tests import base as test_base
from ovn_bgp_agent.tests import utils as test_utils


class TestGetGatewayLrp(test_base.TestCase):
    def test_get(self):
        port = 'foo'
        nat = test_utils.create_row(gateway_port=[port])
        observed = nat_utils.get_gateway_lrp(nat)
        self.assertEqual(port, observed)

    def test_no_gw_port(self):
        nat = test_utils.create_row(gateway_port=[])
        self.assertRaises(
            nb_exceptions.NATNotFound, nat_utils.get_gateway_lrp, nat)


class TestGetChassisHostingCrlrp(test_base.TestCase):
    def test_get_chassis(self):
        chassis = 'foo'
        port = test_utils.create_row(
            status={constants.OVN_STATUS_CHASSIS: chassis})
        nat = test_utils.create_row(gateway_port=[port])
        observed = nat_utils.get_chassis_hosting_crlrp(nat)
        self.assertEqual(chassis, observed)

    def test_no_chasssis(self):
        port = test_utils.create_row(
            status={})
        nat = test_utils.create_row(gateway_port=[port])
        self.assertRaises(
            nb_exceptions.ChassisNotFound,
            nat_utils.get_chassis_hosting_crlrp, nat)

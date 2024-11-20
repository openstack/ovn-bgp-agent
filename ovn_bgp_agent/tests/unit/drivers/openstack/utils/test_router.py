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
from ovn_bgp_agent.drivers.openstack.utils import router as r_utils
from ovn_bgp_agent.tests import base as test_base
from ovn_bgp_agent.tests import utils as test_utils


class TestGetNameFromExternalIds(test_base.TestCase):
    def test_router_present(self):
        expected_router = 'foo'
        r_ext_id = 'neutron-{:s}'.format(expected_router)
        row = test_utils.create_row(
            external_ids={
                constants.OVN_LB_LR_REF_EXT_ID_KEY: r_ext_id})
        router = r_utils.get_name_from_external_ids(row)

        self.assertEqual(expected_router, router)

    def test_router_present_custom_field(self):
        expected_router = 'foo'
        custom_field = 'bar'
        r_ext_id = 'neutron-{:s}'.format(expected_router)
        row = test_utils.create_row(
            external_ids={custom_field: r_ext_id})
        router = r_utils.get_name_from_external_ids(row, key=custom_field)

        self.assertEqual(expected_router, router)

    def test_router_missing(self):
        row = test_utils.create_row(external_ids={})
        router = r_utils.get_name_from_external_ids(row)

        self.assertIsNone(router)

    def test_router_missing_custom_field(self):
        row = test_utils.create_row(external_ids={})
        router = r_utils.get_name_from_external_ids(row, key='foo')

        self.assertIsNone(router)

    def test_router_bad_name(self):
        expected_router = 'foo'
        row = test_utils.create_row(
            external_ids={
                constants.OVN_LB_LR_REF_EXT_ID_KEY: expected_router})
        router = r_utils.get_name_from_external_ids(row)

        self.assertEqual(expected_router, router)

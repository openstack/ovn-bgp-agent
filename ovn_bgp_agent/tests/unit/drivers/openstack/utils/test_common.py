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

from ovn_bgp_agent.drivers.openstack.utils import common
from ovn_bgp_agent.tests import base as test_base
from ovn_bgp_agent.tests import utils as test_utils


class TestGetFromExternalIds(test_base.TestCase):
    def test_all_present(self):
        key = 'foo'
        value = 'bar'
        row = test_utils.create_row(external_ids={key: value})

        observed_value = common.get_from_external_ids(row, key)
        self.assertEqual(value, observed_value)

    def test_external_ids_missing(self):
        row = test_utils.create_row()

        self.assertIsNone(common.get_from_external_ids(row, 'key'))

    def test_key_missing(self):
        row = test_utils.create_row(external_ids={})

        self.assertIsNone(common.get_from_external_ids(row, 'key'))


class TestIpMatchesInRow(test_base.TestCase):
    def test_ip_is_in_row(self):
        ip = 'ip'
        key = 'key'
        row = test_utils.create_row(external_ids={key: ip})

        self.assertTrue(common.ip_matches_in_row(row, ip, key))

    def test_external_ids_missing_returns_none(self):
        ip = 'ip'
        key = 'key'
        row = test_utils.create_row()

        self.assertIsNone(common.ip_matches_in_row(row, ip, key))

    def test_key_missing(self):
        ip = 'ip'
        key = 'key'
        row = test_utils.create_row(external_ids={})

        self.assertFalse(common.ip_matches_in_row(row, ip, key))

    def test_key_missing_but_ip_is_none(self):
        ip = None
        key = 'key'
        row = test_utils.create_row(external_ids={})

        self.assertTrue(common.ip_matches_in_row(row, ip, key))

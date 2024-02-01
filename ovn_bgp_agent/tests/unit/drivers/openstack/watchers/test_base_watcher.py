# Copyright 2022 Red Hat, Inc.
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

from unittest import mock

from ovn_bgp_agent import constants
from ovn_bgp_agent.drivers.openstack.watchers import base_watcher
from ovn_bgp_agent.tests import base as test_base
from ovn_bgp_agent.tests import utils


class FakePortBindingChassisEvent(base_watcher.PortBindingChassisEvent):
    def run(self):
        pass


class TestPortBindingChassisEvent(test_base.TestCase):

    def setUp(self):
        super(TestPortBindingChassisEvent, self).setUp()
        self.pb_event = FakePortBindingChassisEvent(
            mock.Mock(), [mock.Mock()])

    def test__check_ip_associated(self):
        self.assertTrue(self.pb_event._check_ip_associated(
            'aa:bb:cc:dd:ee:ff 10.10.1.16'))
        self.assertTrue(self.pb_event._check_ip_associated(
            'aa:bb:cc:dd:ee:ff 10.10.1.16 10.10.1.17'))
        self.assertFalse(self.pb_event._check_ip_associated(
            'aa:bb:cc:dd:ee:ff'))
        self.assertTrue(self.pb_event._check_ip_associated(
            'aa:bb:cc:dd:ee:ff 10.10.1.16 10.10.1.17 10.10.1.18'))


class FakeOVNLBEvent(base_watcher.OVNLBEvent):
    def run(self):
        pass


class TestOVNLBEvent(test_base.TestCase):

    def setUp(self):
        super(TestOVNLBEvent, self).setUp()
        self.ovnlb_event = FakeOVNLBEvent(
            mock.Mock(), [mock.Mock()])

    def test__get_router(self):
        row = utils.create_row(
            external_ids={constants.OVN_LB_LR_REF_EXT_ID_KEY: 'neutron-net'})
        self.assertEqual('net', self.ovnlb_event._get_router(
            row, constants.OVN_LB_LR_REF_EXT_ID_KEY))
        self.assertEqual('net', self.ovnlb_event._get_router(row))
        row = utils.create_row(
            external_ids={constants.OVN_LR_NAME_EXT_ID_KEY: 'neutron-router1'})
        self.assertEqual('router1', self.ovnlb_event._get_router(
            row, constants.OVN_LR_NAME_EXT_ID_KEY))
        row = utils.create_row(external_ids={})
        self.assertEqual(None, self.ovnlb_event._get_router(row))

    def test__get_vip_fip(self):
        row = utils.create_row(
            external_ids={constants.OVN_LB_VIP_FIP_EXT_ID_KEY: 'fip'})
        self.assertEqual('fip', self.ovnlb_event._get_vip_fip(row))
        row = utils.create_row(external_ids={})
        self.assertEqual(None, self.ovnlb_event._get_vip_fip(row))


class FakeLSPChassisEvent(base_watcher.LSPChassisEvent):
    def run(self):
        pass


class TestLSPChassisEvent(test_base.TestCase):

    def setUp(self):
        super(TestLSPChassisEvent, self).setUp()
        self.lsp_event = FakeLSPChassisEvent(
            mock.Mock(), [mock.Mock()])

    def test__check_ip_associated(self):
        self.assertTrue(self.lsp_event._check_ip_associated(
            'aa:bb:cc:dd:ee:ff 10.10.1.16'))
        self.assertTrue(self.lsp_event._check_ip_associated(
            'aa:bb:cc:dd:ee:ff 10.10.1.16 10.10.1.17'))
        self.assertFalse(self.lsp_event._check_ip_associated(
            'aa:bb:cc:dd:ee:ff'))
        self.assertTrue(self.lsp_event._check_ip_associated(
            'aa:bb:cc:dd:ee:ff 10.10.1.16 10.10.1.17 10.10.1.18'))

    def test__get_network(self):
        row = utils.create_row(
            external_ids={constants.OVN_LS_NAME_EXT_ID_KEY: 'test-net'})
        self.assertEqual('test-net', self.lsp_event._get_network(row))
        row = utils.create_row(external_ids={})
        self.assertEqual(None, self.lsp_event._get_network(row))


class FakeLRPChassisEvent(base_watcher.LRPChassisEvent):
    def run(self):
        pass


class TestLRPChassisEvent(test_base.TestCase):

    def setUp(self):
        super(TestLRPChassisEvent, self).setUp()
        self.lrp_event = FakeLRPChassisEvent(
            mock.Mock(), [mock.Mock()])

    def test__get_network(self):
        row = utils.create_row(
            external_ids={constants.OVN_LS_NAME_EXT_ID_KEY: 'test-net'})
        self.assertEqual('test-net', self.lrp_event._get_network(row))
        row = utils.create_row(external_ids={})
        self.assertEqual(None, self.lrp_event._get_network(row))

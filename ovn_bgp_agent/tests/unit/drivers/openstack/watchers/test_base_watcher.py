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

from ovn_bgp_agent.drivers.openstack.watchers import base_watcher
from ovn_bgp_agent.tests import base as test_base


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

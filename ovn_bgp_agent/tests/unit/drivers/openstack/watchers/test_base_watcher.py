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


class TestChassisCreateEvent(test_base.TestCase):
    _event = base_watcher.ChassisCreateEvent

    def setUp(self):
        super(TestChassisCreateEvent, self).setUp()
        self.chassis = '935f91fa-b8f8-47b9-8b1b-3a7a90ef7c26'
        self.agent = mock.Mock(chassis=self.chassis)
        self.event = self._event(self.agent)

    def test_run(self):
        self.assertTrue(self.event.first_time)
        self.event.run(mock.Mock(), mock.Mock(), mock.Mock())

        self.assertFalse(self.event.first_time)
        self.agent.sync.assert_not_called()

    def test_run_not_first_time(self):
        self.event.first_time = False
        self.event.run(mock.Mock(), mock.Mock(), mock.Mock())
        self.agent.sync.assert_called_once_with()


class TestChassisPrivateCreateEvent(TestChassisCreateEvent):
    _event = base_watcher.ChassisPrivateCreateEvent

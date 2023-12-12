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

import importlib
from unittest import mock

from oslo_concurrency import processutils

from ovn_bgp_agent.privileged import ovs_vsctl
from ovn_bgp_agent.tests import base as test_base

# Mock the privsep decorator and reload the module
mock.patch('ovn_bgp_agent.privileged.ovs_vsctl_cmd.entrypoint',
           lambda x: x).start()
importlib.reload(ovs_vsctl)


class FakeException(Exception):
    stderr = ''


class TestPrivilegedOvsVsctl(test_base.TestCase):

    def setUp(self):
        super(TestPrivilegedOvsVsctl, self).setUp()
        # Mock processutils.execute()
        self.mock_exc = mock.patch.object(processutils, 'execute').start()

    def test_ovs_cmd(self):
        ovs_vsctl.ovs_cmd(
            'ovs-vsctl', ['--if-exists', 'del-port', 'fake-port'])
        self.mock_exc.assert_called_once_with(
            'ovs-vsctl', '--if-exists', 'del-port', 'fake-port')

    def test_ovs_cmd_timeout(self):
        ovs_vsctl.ovs_cmd(
            'ovs-vsctl', ['--if-exists', 'del-port', 'fake-port'], timeout=10)
        self.mock_exc.assert_called_once_with(
            'ovs-vsctl', '--timeout=10', '--if-exists', 'del-port',
            'fake-port')

    def test_ovs_cmd_fallback_OF_version(self):
        self.mock_exc.side_effect = (
            processutils.ProcessExecutionError(), None)
        ovs_vsctl.ovs_cmd(
            'ovs-vsctl', ['--if-exists', 'del-port', 'fake-port'])

        calls = [mock.call('ovs-vsctl', '--if-exists', 'del-port',
                           'fake-port'),
                 mock.call('ovs-vsctl', '--if-exists', 'del-port',
                           'fake-port', '-O', 'OpenFlow13')]
        self.mock_exc.assert_has_calls(calls)

    def test_ovs_cmd_exception(self):
        self.mock_exc.side_effect = FakeException()
        self.assertRaises(
            FakeException, ovs_vsctl.ovs_cmd, 'ovs-vsctl',
            ['--if-exists', 'del-port', 'fake-port'])
        self.mock_exc.assert_called_once_with(
            'ovs-vsctl', '--if-exists', 'del-port', 'fake-port')

    def test_ovs_cmd_fallback_exception(self):
        self.mock_exc.side_effect = (
            processutils.ProcessExecutionError(), FakeException())
        self.assertRaises(
            FakeException, ovs_vsctl.ovs_cmd, 'ovs-vsctl',
            ['--if-exists', 'del-port', 'fake-port'])
        calls = [mock.call('ovs-vsctl', '--if-exists', 'del-port',
                           'fake-port'),
                 mock.call('ovs-vsctl', '--if-exists', 'del-port',
                           'fake-port', '-O', 'OpenFlow13')]
        self.mock_exc.assert_has_calls(calls)

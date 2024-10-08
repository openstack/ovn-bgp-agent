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

    def test_ovs_vsctl(self):
        ovs_vsctl.ovs_vsctl(
            ['--if-exists', 'del-port', 'fake-port'])
        self.mock_exc.assert_called_once_with(
            'ovs-vsctl', '--if-exists', 'del-port', 'fake-port')

    def test_ovs_ofctl(self):
        ovs_vsctl.ovs_ofctl(
            ['dump-flows', 'dummy-br'])
        self.mock_exc.assert_called_once_with(
            'ovs-ofctl', 'dump-flows', 'dummy-br')

    def test_ovs_vsctl_timeout(self):
        ovs_vsctl.ovs_vsctl(
            ['--if-exists', 'del-port', 'fake-port'], timeout=10)
        self.mock_exc.assert_called_once_with(
            'ovs-vsctl', '--timeout=10', '--if-exists', 'del-port',
            'fake-port')

    def test_ovs_ofctl_timeout(self):
        ovs_vsctl.ovs_ofctl(
            ['dump-flows', 'dummy-br'], timeout=10)
        self.mock_exc.assert_called_once_with(
            'ovs-ofctl', '--timeout=10', 'dump-flows', 'dummy-br')

    def test_ovs_ofctl_fallback_OF_version(self):
        # fallback only applies to ovs-ofctl command
        self.mock_exc.side_effect = (
            processutils.ProcessExecutionError(), None)
        ovs_vsctl.ovs_ofctl(
            ['--strict', 'del-flows', 'br-ex', 'dummy-flow'])

        calls = [mock.call('ovs-ofctl', '--strict', 'del-flows',
                           'br-ex', 'dummy-flow'),
                 mock.call('ovs-ofctl', '--strict', 'del-flows',
                           'br-ex', 'dummy-flow', '-O', 'OpenFlow13')]
        self.mock_exc.assert_has_calls(calls)

    def test_ovs_vsctl_process_execution_error_no_fallback(self):
        # fallback does not apply to ovs-vsctl command
        self.mock_exc.side_effect = processutils.ProcessExecutionError()
        self.assertRaises(
            processutils.ProcessExecutionError, ovs_vsctl.ovs_vsctl,
            ['--if-exists', 'del-port', 'fake-port'])
        self.mock_exc.assert_called_once_with(
            'ovs-vsctl', '--if-exists', 'del-port', 'fake-port')

    def test_ovs_ofctl_exception(self):
        self.mock_exc.side_effect = FakeException()
        self.assertRaises(
            FakeException, ovs_vsctl.ovs_ofctl,
            ['add-flow', 'br-ex', 'dummy-flow'])
        self.mock_exc.assert_called_once_with(
            'ovs-ofctl', 'add-flow', 'br-ex', 'dummy-flow')

    def test_ovs_cmd_fallback_exception(self):
        self.mock_exc.side_effect = (
            processutils.ProcessExecutionError(), FakeException())
        self.assertRaises(
            FakeException, ovs_vsctl.ovs_ofctl,
            ['add-flow', 'br-ex', 'dummy-flow'])
        calls = [mock.call('ovs-ofctl', 'add-flow', 'br-ex', 'dummy-flow'),
                 mock.call('ovs-ofctl', 'add-flow', 'br-ex', 'dummy-flow',
                           '-O', 'OpenFlow13')]
        self.mock_exc.assert_has_calls(calls)

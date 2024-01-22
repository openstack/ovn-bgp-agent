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

from ovn_bgp_agent import constants
from ovn_bgp_agent.privileged import vtysh
from ovn_bgp_agent.tests import base as test_base

# Mock the privsep decorator and reload the module
mock.patch('ovn_bgp_agent.privileged.vtysh_cmd.entrypoint',
           lambda x: x).start()
importlib.reload(vtysh)


class FakeException(Exception):
    stderr = ''


class TestPrivilegedVtysh(test_base.TestCase):

    def setUp(self):
        super(TestPrivilegedVtysh, self).setUp()
        # Mock processutils.execute()
        self.mock_exc = mock.patch.object(processutils, 'execute').start()

    def test_run_vtysh_config(self):
        vtysh.run_vtysh_config('/fake/frr.config')
        self.mock_exc.assert_called_once_with(
            '/usr/bin/vtysh', '--vty_socket', constants.FRR_SOCKET_PATH,
            '-f', '/fake/frr.config')

    def test_run_vtysh_config_exception(self):
        self.mock_exc.side_effect = FakeException()
        self.assertRaises(
            FakeException,
            vtysh.run_vtysh_config, '/fake/frr.config')

    def test_run_vtysh_command(self):
        cmd = 'show ip bgp summary json'
        vtysh.run_vtysh_command(cmd)
        self.mock_exc.assert_called_once_with(
            '/usr/bin/vtysh', '--vty_socket', constants.FRR_SOCKET_PATH,
            '-c', cmd)

    def test_run_vtysh_command_exception(self):
        self.mock_exc.side_effect = FakeException()
        self.assertRaises(
            FakeException,
            vtysh.run_vtysh_command, 'show ip bgp summary json')

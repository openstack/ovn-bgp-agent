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

import imp
from unittest import mock

from oslo_concurrency import processutils

from ovn_bgp_agent.privileged import linux_net as priv_linux_net
from ovn_bgp_agent.tests import base as test_base

# Mock the privsep decorator and reload the module
mock.patch('ovn_bgp_agent.privileged.default.entrypoint', lambda x: x).start()
imp.reload(priv_linux_net)


class FakeException(Exception):
    stderr = ''


class TestPrivilegedLinuxNet(test_base.TestCase):

    def setUp(self):
        super(TestPrivilegedLinuxNet, self).setUp()
        # Mock pyroute2.NDB context manager object
        self.mock_exc = mock.patch.object(processutils, 'execute').start()

        # Helper variables used accross many tests
        self.ipv6 = '2002::1234:abcd:ffff:c0a8:101'
        self.dev = 'ethfake'

    def test_set_kernel_flag(self):
        priv_linux_net.set_kernel_flag('net.ipv6.conf.fake', 1)
        self.mock_exc.assert_called_once_with(
            'sysctl', '-w', 'net.ipv6.conf.fake=1')

    def test_set_kernel_flag_exception(self):
        self.mock_exc.side_effect = FakeException()
        self.assertRaises(
            FakeException,
            priv_linux_net.set_kernel_flag, 'net.ipv6.conf.fake', 1)

    def test_add_ndp_proxy(self):
        priv_linux_net.add_ndp_proxy(self.ipv6, self.dev)
        self.mock_exc.assert_called_once_with(
            'ip', '-6', 'nei', 'add', 'proxy', self.ipv6, 'dev', self.dev)

    def test_add_ndp_proxy_vlan(self):
        priv_linux_net.add_ndp_proxy(self.ipv6, self.dev, vlan=10)
        self.mock_exc.assert_called_once_with(
            'ip', '-6', 'nei', 'add', 'proxy', self.ipv6,
            'dev', '%s.10' % self.dev)

    def test_add_ndp_proxy_exception(self):
        self.mock_exc.side_effect = FakeException()
        self.assertRaises(
            FakeException,
            priv_linux_net.add_ndp_proxy, self.ipv6, self.dev)

    def test_del_ndp_proxy(self):
        priv_linux_net.del_ndp_proxy(self.ipv6, self.dev)
        self.mock_exc.assert_called_once_with(
            'ip', '-6', 'nei', 'del', 'proxy', self.ipv6, 'dev',
            self.dev, env_variables=mock.ANY)

    def test_del_ndp_proxy_vlan(self):
        priv_linux_net.del_ndp_proxy(self.ipv6, self.dev, vlan=10)
        self.mock_exc.assert_called_once_with(
            'ip', '-6', 'nei', 'del', 'proxy', self.ipv6, 'dev',
            '%s.10' % self.dev, env_variables=mock.ANY)

    def test_del_ndp_proxy_exception(self):
        self.mock_exc.side_effect = FakeException()
        self.assertRaises(
            FakeException,
            priv_linux_net.del_ndp_proxy, self.ipv6, self.dev)

    def test_del_ndp_proxy_exception_no_such_file(self):
        exp = FakeException()
        exp.stderr = 'No such file or directory'
        self.mock_exc.side_effect = exp
        self.assertIsNone(priv_linux_net.del_ndp_proxy(self.ipv6, self.dev))

    def test_add_unreachable_route(self):
        priv_linux_net.add_unreachable_route('fake-vrf')
        calls = [mock.call('ip', -4, 'route', 'add', 'vrf', 'fake-vrf',
                           'unreachable', 'default', 'metric', '4278198272',
                           env_variables=mock.ANY),
                 mock.call('ip', -6, 'route', 'add', 'vrf', 'fake-vrf',
                           'unreachable', 'default', 'metric', '4278198272',
                           env_variables=mock.ANY)]
        self.mock_exc.assert_has_calls(calls)

    def test_add_unreachable_route_exception(self):
        self.mock_exc.side_effect = FakeException()
        self.assertRaises(
            FakeException,
            priv_linux_net.add_unreachable_route, 'fake-vrf')

    def test_add_unreachable_route_exception_file_exists(self):
        exp = FakeException()
        exp.stderr = 'RTNETLINK answers: File exists'
        self.mock_exc.side_effect = exp
        self.assertIsNone(priv_linux_net.add_unreachable_route('fake-vrf'))

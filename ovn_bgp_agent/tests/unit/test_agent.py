# Copyright 2021 Red Hat, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from unittest import mock

from ovn_bgp_agent import agent
from ovn_bgp_agent.tests import base as test_base


class TestAgent(test_base.TestCase):

    @mock.patch('oslo_service.service.launch')
    @mock.patch('ovn_bgp_agent.config.register_opts')
    @mock.patch('ovn_bgp_agent.config.init')
    @mock.patch('ovn_bgp_agent.config.setup_logging')
    @mock.patch('ovn_bgp_agent.agent.BGPAgent')
    def test_start(self, m_agent, m_setup_logging, m_config_init,
                   m_register_opts, m_oslo_launch):
        m_launcher = mock.Mock()
        m_oslo_launch.return_value = m_launcher

        agent.start()

        m_register_opts.assert_called()
        m_config_init.assert_called()
        m_setup_logging.assert_called()
        m_agent.assert_called()
        m_oslo_launch.assert_called()
        m_launcher.wait.assert_called()

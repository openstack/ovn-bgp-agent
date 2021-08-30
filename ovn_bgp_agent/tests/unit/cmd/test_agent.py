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

from ovn_bgp_agent.tests import base as test_base


class TestAgentCmd(test_base.TestCase):
    @mock.patch('ovn_bgp_agent.agent.start')
    def test_start(self, m_start):
        from ovn_bgp_agent.cmd import agent  # To make it import a mock.
        agent.start()

        m_start.assert_called()

# Copyright 2024 Red Hat, Inc.
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

from ovn_bgp_agent import constants
from ovn_bgp_agent.tests.functional import base


class OvsdbNbOvnIdl(base.BaseFunctionalNorthboundTestCase):
    def _lsp_add(self, ls_name, lsp_name, type_, tag):
        self.api.lsp_add(ls_name, lsp_name, type=type_).execute(
            check_error=True)
        # lsp_add requires parent to be specified with the tag, work it
        # around with the db_set
        self.api.db_set(
            'Logical_Switch_Port', lsp_name, ('tag', tag)).execute(
                check_error=True)

    def test_get_network_vlan_tags(self):
        # 0 is not a valid tag, let's start with 1
        expected_tags = list(range(1, 4))
        len_tags = len(expected_tags)

        for i, tag in enumerate(expected_tags):
            self.api.ls_add('ls%d' % i).execute(check_error=True)
            ls_name = 'ls%d' % (i % 2)
            lsp_name = 'localnetport%d' % i
            self._lsp_add(
                ls_name, lsp_name,
                constants.OVN_LOCALNET_VIF_PORT_TYPE, tag=tag)
        for i, tag in enumerate(expected_tags):
            ls_name = 'ls%d' % i
            lsp_name = 'port%d' % i
            self._lsp_add(
                ls_name, lsp_name,
                type_=None, tag=i + len_tags)

        tags = self.api.get_network_vlan_tags()
        self.assertCountEqual(expected_tags, tags)

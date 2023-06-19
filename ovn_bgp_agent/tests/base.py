# -*- coding: utf-8 -*-

# Copyright 2010-2011 OpenStack Foundation
# Copyright (c) 2013 Hewlett-Packard Development Company, L.P.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from unittest import mock

from oslotest import base

from ovn_bgp_agent import config
from ovn_bgp_agent import privileged


class TestCase(base.BaseTestCase):

    """Test case base class for all unit tests."""

    def setUp(self):
        super(TestCase, self).setUp()
        privileged.default.client_mode = False
        privileged.ovs_vsctl_cmd.client_mode = False
        privileged.vtysh_cmd.client_mode = False
        config.register_opts()
        self.addCleanup(self._clean_up)
        self.addCleanup(mock.patch.stopall)

    def _clean_up(self):
        privileged.default.client_mode = True
        privileged.ovs_vsctl_cmd.client_mode = True
        privileged.vtysh_cmd.client_mode = True

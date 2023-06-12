# Copyright 2023 Red Hat, Inc.
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

from oslo_utils import uuidutils

from ovn_bgp_agent import exceptions as agent_exc
from ovn_bgp_agent.privileged import linux_net as priv_linux_net
from ovn_bgp_agent.tests.functional import base as base_functional
from ovn_bgp_agent.tests.functional.privileged import test_linux_net as \
    test_priv_linux_net
from ovn_bgp_agent.utils import linux_net


class GetInterfaceAddressTestCase(base_functional.BaseFunctionalTestCase):

    def _delete_interfaces(self, dev_names):
        for dev_name in dev_names:
            try:
                priv_linux_net.delete_interface(dev_name)
            except Exception:
                pass

    def _get_device(self, device_name):
        devices = test_priv_linux_net.get_devices_info()
        for device in devices.values():
            if device['name'] == device_name:
                return device

    def test_get_interface_address(self):
        dev_names = list(map(lambda x: uuidutils.generate_uuid()[:15],
                             range(5)))
        self.addCleanup(self._delete_interfaces, dev_names)
        for dev_name in dev_names:
            priv_linux_net.create_interface(dev_name, 'dummy')
            device = self._get_device(dev_name)
            mac = linux_net.get_interface_address(dev_name)
            self.assertEqual(device['mac'], mac)

    def test_get_interface_address_no_interface(self):
        self.assertRaises(agent_exc.NetworkInterfaceNotFound,
                          linux_net.get_interface_address, 'no_interface_name')

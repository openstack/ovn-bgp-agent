# Copyright 2022 Red Hat, Inc.
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

import ipaddress
from oslo_log import log as logging

from ovn_bgp_agent import constants
from ovn_bgp_agent.utils import linux_net

LOG = logging.getLogger(__name__)


def is_ipv6_gua(ip):
    if linux_net.get_ip_version(ip) != constants.IP_VERSION_6:
        return False

    ipv6 = ipaddress.IPv6Address(ip.split('/')[0])
    if ipv6.is_global:
        return True
    return False


def get_addr_scopes(port):
    return {
        constants.IP_VERSION_4: port.external_ids.get(
            constants.SUBNET_POOL_ADDR_SCOPE4),
        constants.IP_VERSION_6: port.external_ids.get(
            constants.SUBNET_POOL_ADDR_SCOPE6),
        }

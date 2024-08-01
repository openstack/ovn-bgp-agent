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
from ovn_bgp_agent.drivers.openstack.utils import common as common_utils
from ovn_bgp_agent.drivers.openstack.utils import driver_utils


def get_vips(lb):
    """Return a set of vips from a Load_Balancer row

    Note: As LB VIP contains a port (e.g., '192.168.1.1:80'), the port part
          is removed.
    """
    return {driver_utils.remove_port_from_ip(ipport)
            for ipport in getattr(lb, 'vips', {})}


def get_diff_ip_from_vips(new, old):
    """Return a set of IPs that are present in 'new' but not in 'old'"""
    return get_vips(new) - get_vips(old)


def is_vip(row, ip):
    return common_utils.ip_matches_in_row(
        row, ip, constants.OVN_LB_VIP_IP_EXT_ID_KEY)


def is_fip(row, ip):
    return common_utils.ip_matches_in_row(
        row, ip, constants.OVN_LB_VIP_FIP_EXT_ID_KEY)

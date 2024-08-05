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
from ovn_bgp_agent.drivers.openstack.utils import common


def has_ip_address_defined(address):
    return ' ' in address.strip()


def get_fip(lsp):
    return common.get_from_external_ids(lsp, key=constants.OVN_FIP_EXT_ID_KEY)


def has_additional_binding(row):
    # requested-chassis can be a comma separated list, so if there
    # is a comma in the string, there is an additional binding.
    return ',' in getattr(row, 'options', {}).get(
        constants.OVN_REQUESTED_CHASSIS, '')


def make_lsp_dict(row):
    # TODO(jlibosva): Stop passing around dynamic maps
    return {
        'mac': row.addresses[0].strip().split(' ')[0],
        'cidrs': row.external_ids.get(constants.OVN_CIDRS_EXT_ID_KEY,
                                      "").split(),
        'type': row.type,
        'logical_switch': common.get_from_external_ids(
            row, constants.OVN_LS_NAME_EXT_ID_KEY),
    }

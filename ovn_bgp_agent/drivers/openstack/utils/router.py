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


def get_name_from_external_ids(row, key=constants.OVN_LB_LR_REF_EXT_ID_KEY):
    router_name = common_utils.get_from_external_ids(row, key)

    try:
        return router_name.replace('neutron-', "", 1)
    except AttributeError:
        pass

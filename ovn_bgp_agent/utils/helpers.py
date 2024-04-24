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

from oslo_log import log as logging

LOG = logging.getLogger(__name__)


def parse_bridge_mapping(bridge_mapping):
    try:
        network, bridge = bridge_mapping.split(":")
    except ValueError:
        LOG.warning("Incorrect bridge mapping settings: %s",
                    bridge_mapping)
        return None, None
    return network, bridge


def _get_lb_datapaths_from_group(lb, attr):
    try:
        dps = getattr(lb, attr)[0].datapaths
        if dps:
            return dps
    except (AttributeError, IndexError):
        pass
    return []


def get_lb_datapaths(lb):
    for attr in ('ls_datapath_group', 'datapath_group'):
        ls_dps = _get_lb_datapaths_from_group(lb, attr)
        if ls_dps:
            break

    lr_dps = _get_lb_datapaths_from_group(lb, 'lr_datapath_group')
    return (ls_dps, lr_dps)

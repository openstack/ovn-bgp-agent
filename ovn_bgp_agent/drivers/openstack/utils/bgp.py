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

from oslo_config import cfg
from oslo_log import log as logging

from ovn_bgp_agent import constants
from ovn_bgp_agent.drivers.openstack.utils import frr
from ovn_bgp_agent.utils import linux_net


CONF = cfg.CONF
LOG = logging.getLogger(__name__)


def announce_ips(port_ips):
    linux_net.add_ips_to_dev(CONF.bgp_nic, port_ips)


def withdraw_ips(port_ips):
    linux_net.del_ips_from_dev(CONF.bgp_nic, port_ips)


def ensure_base_bgp_configuration(template=frr.LEAK_VRF_TEMPLATE):
    if CONF.exposing_method not in [constants.EXPOSE_METHOD_UNDERLAY,
                                    constants.EXPOSE_METHOD_DYNAMIC,
                                    constants.EXPOSE_METHOD_OVN]:
        return

    # Create VRF
    linux_net.ensure_vrf(CONF.bgp_vrf, CONF.bgp_vrf_table_id)

    # If we expose subnet routes, we should add kernel routes too.
    if CONF.advertisement_method_tenant_networks == 'subnet':
        frr.set_default_redistribute(['connected', 'kernel'])

    # Ensure FRR is configure to leak the routes
    frr.vrf_leak(CONF.bgp_vrf, CONF.bgp_AS, CONF.bgp_router_id,
                 template=template)

    # Create OVN dummy device
    linux_net.ensure_ovn_device(CONF.bgp_nic, CONF.bgp_vrf)

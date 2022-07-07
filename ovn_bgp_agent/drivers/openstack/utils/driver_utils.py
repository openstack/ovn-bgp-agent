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

from oslo_log import log as logging

LOG = logging.getLogger(__name__)


def parse_vip_from_lb_table(vip):
    # The VIP format comes from the Load_Balancer table as is like:
    # (ipv4): 172.24.100.66:80
    # (ipv6): [2001:db8::f816:3eff:fe55:ef1e]:80
    vip_split = vip.split("]:")
    if len(vip_split) == 1:  # ipv4
        return vip.split(":")[0]
    if len(vip_split) == 2:  # ipv6
        return vip_split[0].split("[")[1]

    LOG.error("Malformated VIP at Load Balancer SB table: %s", vip)

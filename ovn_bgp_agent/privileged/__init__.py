# Copyright 2021 Red Hat, Inc.
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

from oslo_privsep import capabilities
from oslo_privsep import priv_context

default = priv_context.PrivContext(
    __name__,
    cfg_section='privsep',
    pypath=__name__ + '.default',
    capabilities=[capabilities.CAP_DAC_OVERRIDE,
                  capabilities.CAP_DAC_READ_SEARCH,
                  capabilities.CAP_NET_ADMIN,
                  capabilities.CAP_SYS_ADMIN],
)

ovs_vsctl_cmd = priv_context.PrivContext(
    __name__,
    cfg_section='privsep_ovs_vsctl',
    pypath=__name__ + '.ovs_vsctl_cmd',
    capabilities=[capabilities.CAP_SYS_ADMIN,
                  capabilities.CAP_NET_ADMIN]
)

vtysh_cmd = priv_context.PrivContext(
    __name__,
    cfg_section='privsep_vtysh',
    pypath=__name__ + '.vtysh_cmd',
    capabilities=[capabilities.CAP_SYS_ADMIN,
                  capabilities.CAP_NET_ADMIN]
)

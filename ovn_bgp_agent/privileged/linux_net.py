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

import ipaddress
import os

from oslo_concurrency import processutils
from oslo_log import log as logging

import ovn_bgp_agent.privileged.linux_net

LOG = logging.getLogger(__name__)


@ovn_bgp_agent.privileged.default.entrypoint
def set_kernel_flag(flag, value):
    command = ["sysctl", "-w", "{}={}".format(flag, value)]
    try:
        return processutils.execute(*command)
    except Exception as e:
        LOG.error("Unable to execute %s. Exception: %s", command, e)
        raise


@ovn_bgp_agent.privileged.default.entrypoint
def add_ndp_proxy(ip, dev, vlan=None):
    # FIXME(ltomasbo): This should use pyroute instead but I didn't find
    # out how
    net_ip = str(ipaddress.IPv6Network(ip, strict=False).network_address)
    dev_name = dev
    if vlan:
        dev_name = "{}.{}".format(dev, vlan)
    command = ["ip", "-6", "nei", "add", "proxy", net_ip, "dev", dev_name]
    try:
        return processutils.execute(*command)
    except Exception as e:
        LOG.error("Unable to execute %s. Exception: %s", command, e)
        raise


@ovn_bgp_agent.privileged.default.entrypoint
def del_ndp_proxy(ip, dev, vlan=None):
    # FIXME(ltomasbo): This should use pyroute instead but I didn't find
    # out how
    net_ip = str(ipaddress.IPv6Network(ip, strict=False).network_address)
    dev_name = dev
    if vlan:
        dev_name = "{}.{}".format(dev, vlan)
    command = ["ip", "-6", "nei", "del", "proxy", net_ip, "dev", dev_name]
    env = dict(os.environ)
    env['LC_ALL'] = 'C'
    try:
        return processutils.execute(*command, env_variables=env)
    except Exception as e:
        if "No such file or directory" in e.stderr:
            # Already deleted
            return
        LOG.error("Unable to execute %s. Exception: %s", command, e)
        raise


@ovn_bgp_agent.privileged.default.entrypoint
def add_unreachable_route(vrf_name):
    # FIXME: This should use pyroute instead but I didn't find
    # out how
    env = dict(os.environ)
    env['LC_ALL'] = 'C'
    for ip_version in [-4, -6]:
        command = ["ip", ip_version, "route", "add", "vrf", vrf_name,
                   "unreachable", "default", "metric", "4278198272"]
        try:
            return processutils.execute(*command, env_variables=env)
        except Exception as e:
            if "RTNETLINK answers: File exists" in e.stderr:
                continue
            LOG.error("Unable to execute %s. Exception: %s", command, e)
            raise

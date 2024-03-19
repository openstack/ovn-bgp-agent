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


def get_port_chassis(port, chassis,
                     default_port_type=constants.OVN_VM_VIF_PORT_TYPE):
    # row.options['requested-chassis'] superseeds the id in external_ids.
    # Since it is not used for virtual ports by ovn, this option will be
    # ignored for virtual ports.

    # since 'old' rows could be used, it will not hold the type information
    # if that is the case, please supply a default in the arguments.

    port_type = getattr(port, 'type', default_port_type)
    if (port_type not in [constants.OVN_VIRTUAL_VIF_PORT_TYPE] and
            hasattr(port, 'options') and
            port.options.get(constants.OVN_REQUESTED_CHASSIS)):

        # requested-chassis can be a comma separated list,
        # so lets only return our chassis if it is a list, to be able
        # to do a == equal comparison
        req_chassis = port.options[constants.OVN_REQUESTED_CHASSIS]
        if chassis in req_chassis.split(','):
            req_chassis = chassis

        return req_chassis.split(',')[0], constants.OVN_CHASSIS_AT_OPTIONS

    elif (hasattr(port, 'external_ids') and
            port.external_ids.get(constants.OVN_HOST_ID_EXT_ID_KEY)):

        return (
            port.external_ids[constants.OVN_HOST_ID_EXT_ID_KEY],
            constants.OVN_CHASSIS_AT_EXT_IDS
        )

    return None, None


def check_name_prefix(entity, prefix):
    try:
        return entity.name.startswith(prefix)
    except AttributeError:
        return False


def is_pf_lb(lb):
    return check_name_prefix(lb, constants.OVN_LB_PF_NAME_PREFIX)


def get_prefixes_from_ips(ips: 'list[str]') -> 'list[str]':
    '''Return the network address for any given ip (with mask)

    For a list like ['192.168.0.1/24'] it will return ['192.168.0.0/24']
    '''
    return ['/'.join([ipaddress.ip_network(ip, strict=False)[0].compressed,
                      ip.split('/')[-1]])
            for ip in ips]


def remove_port_from_ip(ip_address):
    last_colon_index = ip_address.rfind(':')
    # no port
    if last_colon_index == -1:
        return ip_address
    # check if right side from index is a digit, in positive case remove it.
    # For IPv6 it will come on format [ipv6]:port, so will also remove
    # correctly just only the port
    if ip_address[last_colon_index + 1:].isdigit():
        return ip_address[:last_colon_index]
    return ip_address

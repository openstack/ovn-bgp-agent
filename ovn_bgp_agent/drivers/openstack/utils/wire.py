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
from ovn_bgp_agent import exceptions as agent_exc
from ovn_bgp_agent.utils import linux_net


CONF = cfg.CONF
LOG = logging.getLogger(__name__)


def wire_provider_port(routing_tables_routes, port_ips, bridge_device,
                       bridge_vlan, routing_table, proxy_cidrs, lladdr=None):
    for ip in port_ips:
        try:
            if lladdr:
                dev = bridge_device
                if bridge_vlan:
                    dev = '{}.{}'.format(dev, bridge_vlan)
                linux_net.add_ip_rule(ip, routing_table, dev=dev,
                                      lladdr=lladdr)
            else:
                linux_net.add_ip_rule(ip, routing_table)
        except agent_exc.InvalidPortIP:
            LOG.exception("Invalid IP to create a rule for port on the "
                          "provider network: %s", ip)
            return False
        linux_net.add_ip_route(routing_tables_routes, ip, routing_table,
                               bridge_device, vlan=bridge_vlan)
    if proxy_cidrs:
        # add proxy ndp config for ipv6
        for n_cidr in proxy_cidrs:
            if linux_net.get_ip_version(n_cidr) == constants.IP_VERSION_6:
                linux_net.add_ndp_proxy(n_cidr, bridge_device, bridge_vlan)
    return True


def unwire_provider_port(routing_tables_routes, port_ips, bridge_device,
                         bridge_vlan, routing_table, proxy_cidrs, lladdr=None):
    for ip in port_ips:
        if lladdr:
            if linux_net.get_ip_version(ip) == constants.IP_VERSION_6:
                cr_lrp_ip = '{}/128'.format(ip)
            else:
                cr_lrp_ip = '{}/32'.format(ip)
            try:
                linux_net.del_ip_rule(cr_lrp_ip, routing_table, bridge_device,
                                      lladdr=lladdr)
            except agent_exc.InvalidPortIP:
                LOG.exception("Invalid IP to delete a rule for the "
                              "provider port: %s", cr_lrp_ip)
                return False
        else:
            try:
                linux_net.del_ip_rule(ip, routing_table, bridge_device)
            except agent_exc.InvalidPortIP:
                LOG.exception("Invalid IP to delete a rule for the "
                              "provider port: %s", ip)
                return False
        linux_net.del_ip_route(routing_tables_routes, ip, routing_table,
                               bridge_device, vlan=bridge_vlan)
    if proxy_cidrs:
        for n_cidr in proxy_cidrs:
            if linux_net.get_ip_version(n_cidr) == constants.IP_VERSION_6:
                linux_net.del_ndp_proxy(n_cidr, bridge_device, bridge_vlan)
    return True


def wire_lrp_port(routing_tables_routes, ip, bridge_device, bridge_vlan,
                  routing_table, cr_lrp_ips):
    LOG.debug("Adding IP Rules for network %s", ip)
    try:
        linux_net.add_ip_rule(ip, routing_table)
    except agent_exc.InvalidPortIP:
        LOG.exception("Invalid IP to create a rule for the lrp (network "
                      "router interface) port: %s", ip)
        return False
    LOG.debug("Added IP Rules for network %s", ip)

    LOG.debug("Adding IP Routes for network %s", ip)
    # NOTE(ltomasbo): This assumes the provider network can only have
    # (at most) 2 subnets, one for IPv4, one for IPv6
    ip_version = linux_net.get_ip_version(ip)
    for cr_lrp_ip in cr_lrp_ips:
        if linux_net.get_ip_version(cr_lrp_ip) == ip_version:
            linux_net.add_ip_route(
                routing_tables_routes,
                ip.split("/")[0],
                routing_table,
                bridge_device,
                vlan=bridge_vlan,
                mask=ip.split("/")[1],
                via=cr_lrp_ip)
            break
    LOG.debug("Added IP Routes for network %s", ip)
    return True


def unwire_lrp_port(routing_tables_routes, ip, bridge_device, bridge_vlan,
                    routing_table, cr_lrp_ips):
    LOG.debug("Deleting IP Rules for network %s", ip)
    try:
        linux_net.del_ip_rule(ip, routing_table, bridge_device)
    except agent_exc.InvalidPortIP:
        LOG.exception("Invalid IP to delete a rule for the "
                      "lrp (network router interface) port: %s", ip)
        return False
    LOG.debug("Deleted IP Rules for network %s", ip)

    LOG.debug("Deleting IP Routes for network %s", ip)
    ip_version = linux_net.get_ip_version(ip)
    for cr_lrp_ip in cr_lrp_ips:
        if linux_net.get_ip_version(cr_lrp_ip) == ip_version:
            linux_net.del_ip_route(
                routing_tables_routes,
                ip.split("/")[0],
                routing_table,
                bridge_device,
                vlan=bridge_vlan,
                mask=ip.split("/")[1],
                via=cr_lrp_ip)
    LOG.debug("Deleted IP Routes for network %s", ip)
    return True

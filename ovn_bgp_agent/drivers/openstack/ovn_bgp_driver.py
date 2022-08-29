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

import collections
import ipaddress
import pyroute2
import threading

from oslo_concurrency import lockutils
from oslo_config import cfg
from oslo_log import log as logging

from ovn_bgp_agent import constants
from ovn_bgp_agent.drivers import driver_api
from ovn_bgp_agent.drivers.openstack.utils import driver_utils
from ovn_bgp_agent.drivers.openstack.utils import frr
from ovn_bgp_agent.drivers.openstack.utils import ovn
from ovn_bgp_agent.drivers.openstack.utils import ovs
from ovn_bgp_agent.drivers.openstack.watchers import bgp_watcher as watcher
from ovn_bgp_agent import exceptions as agent_exc
from ovn_bgp_agent.utils import linux_net


CONF = cfg.CONF
LOG = logging.getLogger(__name__)
# LOG.setLevel(logging.DEBUG)
# logging.basicConfig(level=logging.DEBUG)

OVN_TABLES = ["Port_Binding", "Chassis", "Datapath_Binding", "Load_Balancer"]


class OVNBGPDriver(driver_api.AgentDriverBase):

    def __init__(self):
        self._expose_tenant_networks = CONF.expose_tenant_networks
        self.ovn_routing_tables = {}  # {'br-ex': 200}
        self.ovn_bridge_mappings = {}  # {'public': 'br-ex'}
        self.ovn_local_cr_lrps = {}
        self.ovn_local_lrps = set([])
        # {'br-ex': [route1, route2]}
        self.ovn_routing_tables_routes = collections.defaultdict()
        # {ovn_lb: VIP1, VIP2}
        self.ovn_lb_vips = collections.defaultdict()

        self._sb_idl = None
        self._post_fork_event = threading.Event()

    @property
    def sb_idl(self):
        if not self._sb_idl:
            self._post_fork_event.wait()
        return self._sb_idl

    @sb_idl.setter
    def sb_idl(self, val):
        self._sb_idl = val

    def start(self):
        # Ensure FRR is configure to leak the routes
        # NOTE: If we want to recheck this every X time, we should move it
        # inside the sync function instead
        frr.vrf_leak(constants.OVN_BGP_VRF, CONF.bgp_AS, CONF.bgp_router_id)

        self.ovs_idl = ovs.OvsIdl()
        self.ovs_idl.start(CONF.ovsdb_connection)
        self.chassis = self.ovs_idl.get_own_chassis_name()
        self.ovn_remote = self.ovs_idl.get_ovn_remote()
        LOG.debug("Loaded chassis %s.", self.chassis)

        events = ()
        for event in self._get_events():
            event_class = getattr(watcher, event)
            events += (event_class(self),)

        self._post_fork_event.clear()
        # TODO(lucasagomes): The OVN package in the ubuntu LTS is old
        # and does not support Chassis_Private. Once the package is updated
        # we can remove this fallback mode.
        try:
            self.sb_idl = ovn.OvnSbIdl(
                self.ovn_remote,
                chassis=self.chassis,
                tables=OVN_TABLES + ["Chassis_Private"],
                events=events).start()
        except AssertionError:
            self.sb_idl = ovn.OvnSbIdl(
                self.ovn_remote,
                chassis=self.chassis,
                tables=OVN_TABLES,
                events=events).start()

        # Now IDL connections can be safely used
        self._post_fork_event.set()

    def _get_events(self):
        events = set(["PortBindingChassisCreatedEvent",
                      "PortBindingChassisDeletedEvent",
                      "FIPSetEvent",
                      "FIPUnsetEvent",
                      "OVNLBMemberUpdateEvent",
                      "ChassisCreateEvent"])
        if self._expose_tenant_networks:
            events.update(["SubnetRouterAttachedEvent",
                           "SubnetRouterDetachedEvent",
                           "TenantPortCreatedEvent",
                           "TenantPortDeletedEvent"])
        return events

    @lockutils.synchronized('bgp')
    def sync(self):
        self.ovn_local_cr_lrps = {}
        self.ovn_local_lrps = set([])
        self.ovn_routing_tables_routes = collections.defaultdict()
        self.ovn_lb_vips = collections.defaultdict()

        LOG.debug("Ensuring VRF configuration for advertising routes")
        # Create VRF
        linux_net.ensure_vrf(constants.OVN_BGP_VRF,
                             constants.OVN_BGP_VRF_TABLE)
        # Create OVN dummy device
        linux_net.ensure_ovn_device(constants.OVN_BGP_NIC,
                                    constants.OVN_BGP_VRF)

        LOG.debug("Configuring br-ex default rule and routing tables for "
                  "each provider network")
        flows_info = {}
        # 1) Get bridge mappings: xxxx:br-ex,yyyy:br-ex2
        bridge_mappings = self.ovs_idl.get_ovn_bridge_mappings()
        # 2) Get macs for bridge mappings
        extra_routes = {}
        with pyroute2.NDB() as ndb:
            for bridge_index, bridge_mapping in enumerate(bridge_mappings, 1):
                network = bridge_mapping.split(":")[0]
                bridge = bridge_mapping.split(":")[1]
                self.ovn_bridge_mappings[network] = bridge

                if not extra_routes.get(bridge):
                    extra_routes[bridge] = (
                        linux_net.ensure_routing_table_for_bridge(
                            self.ovn_routing_tables, bridge))
                vlan_tag = self.sb_idl.get_network_vlan_tag_by_network_name(
                    network)

                if vlan_tag:
                    vlan_tag = vlan_tag[0]
                    linux_net.ensure_vlan_device_for_network(bridge,
                                                             vlan_tag)

                linux_net.ensure_arp_ndp_enabed_for_bridge(bridge,
                                                           bridge_index,
                                                           vlan_tag)

                if flows_info.get(bridge):
                    continue
                flows_info[bridge] = {
                    'mac': ndb.interfaces[bridge]['address'],
                    'in_port': set([])}
                # 3) Get in_port for bridge mappings (br-ex, br-ex2)
                ovs.get_ovs_flows_info(bridge, flows_info,
                                       constants.OVS_RULE_COOKIE)
        # 4) Add/Remove flows for each bridge mappings
        ovs.remove_extra_ovs_flows(flows_info, constants.OVS_RULE_COOKIE)

        LOG.debug("Syncing current routes.")
        exposed_ips = linux_net.get_exposed_ips(constants.OVN_BGP_NIC)
        # get the rules pointing to ovn bridges
        ovn_ip_rules = linux_net.get_ovn_ip_rules(
            self.ovn_routing_tables.values())

        # add missing routes/ips for fips/provider VMs
        ports = self.sb_idl.get_ports_on_chassis(self.chassis)
        for port in ports:
            self._ensure_port_exposed(port, exposed_ips, ovn_ip_rules)

        cr_lrp_ports = self.sb_idl.get_cr_lrp_ports_on_chassis(self.chassis)
        for cr_lrp_port in cr_lrp_ports:
            self._ensure_cr_lrp_associated_ports_exposed(
                cr_lrp_port, exposed_ips, ovn_ip_rules)

        for cr_lrp_port, cr_lrp_info in self.ovn_local_cr_lrps.items():
            lrp_ports = self.sb_idl.get_lrp_ports_for_router(
                cr_lrp_info['router_datapath'])
            for lrp in lrp_ports:
                if (lrp.chassis or
                        not lrp.logical_port.startswith('lrp-') or
                        "chassis-redirect-port" in lrp.options.keys()):
                    continue
                subnet_datapath = self.sb_idl.get_port_datapath(
                    lrp.logical_port.split('lrp-')[1])
                self.ovn_local_cr_lrps[cr_lrp_port]['subnets_datapath'].update(
                    {lrp.logical_port: subnet_datapath})
                # add missing route/ips for tenant network VMs
                if self._expose_tenant_networks:
                    self._ensure_network_exposed(
                        lrp, cr_lrp_info, exposed_ips, ovn_ip_rules)

            # add missing routes/ips related to ovn-octavia loadbalancers
            # on the provider networks
            ovn_lbs = self.sb_idl.get_ovn_lb_on_provider_datapath(
                cr_lrp_info['provider_datapath'])
            for ovn_lb in ovn_lbs:
                match_subnets_datapaths = [
                    subnet_dp for subnet_dp in cr_lrp_info[
                        'subnets_datapath'].values()
                    if subnet_dp in ovn_lb.datapaths]
                if not match_subnets_datapaths:
                    continue

                for vip in ovn_lb.vips.keys():
                    ip = driver_utils.parse_vip_from_lb_table(vip)
                    self._expose_ovn_lb_on_provider(
                        ovn_lb.name, ip, cr_lrp_info['provider_datapath'],
                        cr_lrp_port)
                    if ip in exposed_ips:
                        exposed_ips.remove(ip)
                    ip_version = linux_net.get_ip_version(ip)
                    if ip_version == constants.IP_VERSION_6:
                        ip_dst = "{}/128".format(ip)
                    else:
                        ip_dst = "{}/32".format(ip)
                    ovn_ip_rules.pop(ip_dst, None)
                self.ovn_local_cr_lrps[cr_lrp_port]['ovn_lbs'].append(
                    ovn_lb.name)

        # remove extra routes/ips
        # remove all the leftovers on the list of current ips on dev OVN
        linux_net.delete_exposed_ips(exposed_ips, constants.OVN_BGP_NIC)
        # remove all the leftovers on the list of current ip rules for ovn
        # bridges
        linux_net.delete_ip_rules(ovn_ip_rules)

        # remove all the extra rules not needed
        linux_net.delete_bridge_ip_routes(self.ovn_routing_tables,
                                          self.ovn_routing_tables_routes,
                                          extra_routes)

    def _ensure_cr_lrp_associated_ports_exposed(self, cr_lrp_port,
                                                exposed_ips, ovn_ip_rules):
        ips, patch_port_row = self.sb_idl.get_cr_lrp_nat_addresses_info(
            cr_lrp_port, self.chassis, self.sb_idl)
        if not ips:
            return
        self._expose_ip(ips, patch_port_row, associated_port=cr_lrp_port)
        for ip in ips:
            ip_version = linux_net.get_ip_version(ip)
            if ip_version == constants.IP_VERSION_6:
                ip_dst = "{}/128".format(ip)
            else:
                ip_dst = "{}/32".format(ip)
            if ip in exposed_ips:
                exposed_ips.remove(ip)
            ovn_ip_rules.pop(ip_dst, None)

    def _ensure_port_exposed(self, port, exposed_ips, ovn_ip_rules):
        if port.type not in constants.OVN_VIF_PORT_TYPES or not port.mac:
            return
        if (len(port.mac[0].split(' ')) != 2 and
                len(port.mac[0].split(' ')) != 3):
            return
        port_ips = [port.mac[0].split(' ')[1]]
        if len(port.mac[0].split(' ')) == 3:
            port_ips.append(port.mac[0].split(' ')[2])

        fip = self._expose_ip(port_ips, port)
        if fip:
            if fip in exposed_ips:
                exposed_ips.remove(fip)
            fip_dst = "{}/32".format(fip)
            ovn_ip_rules.pop(fip_dst, None)

        for port_ip in port_ips:
            ip_address = port_ip.split("/")[0]
            ip_version = linux_net.get_ip_version(port_ip)
            if ip_version == constants.IP_VERSION_6:
                ip_dst = "{}/128".format(ip_address)
            else:
                ip_dst = "{}/32".format(ip_address)
            if ip_address in exposed_ips:
                # remove each ip to add from the list of current ips on dev OVN
                exposed_ips.remove(ip_address)
            ovn_ip_rules.pop(ip_dst, None)

    def _ensure_network_exposed(self, router_port, gateway, exposed_ips=[],
                                ovn_ip_rules={}):
        gateway_ips = [ip.split('/')[0] for ip in gateway['ips']]
        try:
            router_port_ip = router_port.mac[0].split(' ')[1]
        except IndexError:
            return
        router_ip = router_port_ip.split('/')[0]
        if router_ip in gateway_ips:
            return
        self.ovn_local_lrps.add(router_port.logical_port)
        rule_bridge, vlan_tag = self._get_bridge_for_datapath(
            gateway['provider_datapath'])

        try:
            linux_net.add_ip_rule(router_port_ip,
                                  self.ovn_routing_tables[rule_bridge],
                                  rule_bridge)
        except agent_exc.InvalidPortIP:
            LOG.exception("Invalid IP to create a rule for the network router"
                          " interface port: %s", router_port_ip)
            return

        ovn_ip_rules.pop(router_port_ip, None)

        router_port_ip_version = linux_net.get_ip_version(router_port_ip)
        for gateway_ip in gateway_ips:
            if linux_net.get_ip_version(gateway_ip) == router_port_ip_version:
                linux_net.add_ip_route(
                    self.ovn_routing_tables_routes,
                    router_ip,
                    self.ovn_routing_tables[rule_bridge],
                    rule_bridge,
                    vlan=vlan_tag,
                    mask=router_port_ip.split("/")[1],
                    via=gateway_ip)
                break

        network_port_datapath = self.sb_idl.get_port_datapath(
            router_port.options['peer'])
        if network_port_datapath:
            ports = self.sb_idl.get_ports_on_datapath(
                network_port_datapath)
            for port in ports:
                if (not port.mac or
                        port.type not in (
                            constants.OVN_VM_VIF_PORT_TYPE,
                            constants.OVN_VIRTUAL_VIF_PORT_TYPE) or
                        (port.type == constants.OVN_VM_VIF_PORT_TYPE and
                         not port.chassis)):
                    continue
                try:
                    port_ips = [port.mac[0].split(' ')[1]]
                except IndexError:
                    continue
                if len(port.mac[0].split(' ')) == 3:
                    port_ips.append(port.mac[0].split(' ')[2])

                for port_ip in port_ips:
                    # Only adding the port ips that match the lrp
                    # IP version
                    port_ip_version = linux_net.get_ip_version(port_ip)
                    if port_ip_version == router_port_ip_version:
                        linux_net.add_ips_to_dev(
                            constants.OVN_BGP_NIC, [port_ip])
                        if port_ip in exposed_ips:
                            exposed_ips.remove(port_ip)
                        if router_port_ip_version == constants.IP_VERSION_6:
                            ip_dst = "{}/128".format(port_ip)
                        else:
                            ip_dst = "{}/32".format(port_ip)

                        ovn_ip_rules.pop(ip_dst, None)

    def _remove_network_exposed(self, router_port, gateway):
        gateway_ips = [ip.split('/')[0] for ip in gateway['ips']]
        try:
            router_port_ip = router_port.mac[0].split(' ')[1]
        except IndexError:
            return
        router_ip = router_port_ip.split('/')[0]
        if router_ip in gateway_ips:
            return

        if router_port.logical_port in self.ovn_local_lrps:
            self.ovn_local_lrps.remove(router_port.logical_port)
        rule_bridge, vlan_tag = self._get_bridge_for_datapath(
            gateway['provider_datapath'])

        linux_net.del_ip_rule(router_port_ip,
                              self.ovn_routing_tables[rule_bridge],
                              rule_bridge)

        router_port_ip_version = linux_net.get_ip_version(router_port_ip)
        for gateway_ip in gateway_ips:
            if linux_net.get_ip_version(gateway_ip) == router_port_ip_version:
                linux_net.del_ip_route(
                    self.ovn_routing_tables_routes,
                    router_ip,
                    self.ovn_routing_tables[rule_bridge],
                    rule_bridge,
                    vlan=vlan_tag,
                    mask=router_port_ip.split("/")[1],
                    via=gateway_ip)
                if (linux_net.get_ip_version(gateway_ip) ==
                        constants.IP_VERSION_6):
                    net = ipaddress.IPv6Network(router_port_ip, strict=False)
                else:
                    net = ipaddress.IPv4Network(router_port_ip, strict=False)
                break
        # Check if there are VMs on the network
        # and if so withdraw the routes
        vms_on_net = linux_net.get_exposed_ips_on_network(
            constants.OVN_BGP_NIC, net)
        if vms_on_net:
            linux_net.delete_exposed_ips(vms_on_net, constants.OVN_BGP_NIC)

    def _get_bridge_for_datapath(self, datapath):
        network_name, network_tag = self.sb_idl.get_network_name_and_tag(
            datapath, self.ovn_bridge_mappings.keys())
        if network_name:
            if network_tag:
                return self.ovn_bridge_mappings[network_name], network_tag[0]
            return self.ovn_bridge_mappings[network_name], None
        return None, None

    @lockutils.synchronized('bgp')
    def expose_ovn_lb_on_provider(self, ovn_lb, ip, provider_dp, cr_lrp):
        self._expose_ovn_lb_on_provider(ovn_lb, ip, provider_dp, cr_lrp)

    def _expose_ovn_lb_on_provider(self, ovn_lb, ip, provider_dp, cr_lrp):
        self.ovn_local_cr_lrps[cr_lrp]['ovn_lbs'].append(ovn_lb)
        self.ovn_lb_vips.setdefault(ovn_lb, []).append(ip)

        LOG.info("Add BGP route for loadbalancer VIP %s", ip)
        linux_net.add_ips_to_dev(constants.OVN_BGP_NIC, [ip])

        rule_bridge, vlan_tag = self._get_bridge_for_datapath(provider_dp)
        try:
            linux_net.add_ip_rule(
                ip, self.ovn_routing_tables[rule_bridge], rule_bridge)
        except agent_exc.InvalidPortIP:
            LOG.exception("Invalid IP to create a rule for the VM ip"
                          " on the provider network: %s", ip)
            return
        linux_net.add_ip_route(
            self.ovn_routing_tables_routes, ip,
            self.ovn_routing_tables[rule_bridge], rule_bridge,
            vlan=vlan_tag)

    @lockutils.synchronized('bgp')
    def withdraw_ovn_lb_on_provider(self, ovn_lb, provider_dp, cr_lrp):
        for ip in self.ovn_lb_vips[ovn_lb].copy():
            LOG.info("Delete BGP route for loadbalancer VIP %s", ip)
            linux_net.del_ips_from_dev(constants.OVN_BGP_NIC, [ip])

            rule_bridge, vlan_tag = self._get_bridge_for_datapath(provider_dp)

            linux_net.del_ip_rule(ip, self.ovn_routing_tables[rule_bridge],
                                  rule_bridge)
            linux_net.del_ip_route(self.ovn_routing_tables_routes, ip,
                                   self.ovn_routing_tables[rule_bridge],
                                   rule_bridge, vlan=vlan_tag)
            if ip in self.ovn_lb_vips[ovn_lb]:
                self.ovn_lb_vips[ovn_lb].remove(ip)
        if ovn_lb in self.ovn_local_cr_lrps[cr_lrp]['ovn_lbs']:
            self.ovn_local_cr_lrps[cr_lrp]['ovn_lbs'].remove(ovn_lb)

    @lockutils.synchronized('bgp')
    def expose_ip(self, ips, row, associated_port=None):
        '''Advertice BGP route by adding IP to device.

        This methods ensures BGP advertises the IP of the VM in the provider
        network, or the FIP associated to a VM in a tenant networks.

        It relies on Zebra, which creates and advertises a route when an IP
        is added to a local interface.

        This method assumes a device named self.ovn_decice exists (inside a
        VRF), and adds the IP of either:
        - VM IP on the provider network,
        - VM FIP, or
        - CR-LRP OVN port
        '''
        self._expose_ip(ips, row, associated_port)

    def _expose_ip(self, ips, row, associated_port=None):
        # VM on provider Network
        if ((row.type == constants.OVN_VM_VIF_PORT_TYPE or
                row.type == constants.OVN_VIRTUAL_VIF_PORT_TYPE) and
                self.sb_idl.is_provider_network(row.datapath)):
            LOG.info("Add BGP route for logical port with ip %s", ips)
            linux_net.add_ips_to_dev(constants.OVN_BGP_NIC, ips)

            rule_bridge, vlan_tag = self._get_bridge_for_datapath(row.datapath)
            for ip in ips:
                try:
                    linux_net.add_ip_rule(
                        ip, self.ovn_routing_tables[rule_bridge], rule_bridge)
                except agent_exc.InvalidPortIP:
                    LOG.exception("Invalid IP to create a rule for the VM ip"
                                  " on the provider network: %s", ip)
                    return
                linux_net.add_ip_route(
                    self.ovn_routing_tables_routes, ip,
                    self.ovn_routing_tables[rule_bridge], rule_bridge,
                    vlan=vlan_tag)

        # VM with FIP
        elif (row.type == constants.OVN_VM_VIF_PORT_TYPE or
                row.type == constants.OVN_VIRTUAL_VIF_PORT_TYPE):
            # FIPs are only supported with IPv4
            fip_address, fip_datapath = self.sb_idl.get_fip_associated(
                row.logical_port)
            if fip_address:
                LOG.info("Add BGP route for FIP with ip %s", fip_address)
                linux_net.add_ips_to_dev(constants.OVN_BGP_NIC,
                                         [fip_address])

                rule_bridge, vlan_tag = self._get_bridge_for_datapath(
                    fip_datapath)
                try:
                    linux_net.add_ip_rule(
                        fip_address, self.ovn_routing_tables[rule_bridge],
                        rule_bridge)
                except agent_exc.InvalidPortIP:
                    LOG.exception("Invalid IP to create a rule for the VM "
                                  "floating IP: %s", fip_address)
                    return

                linux_net.add_ip_route(
                    self.ovn_routing_tables_routes, fip_address,
                    self.ovn_routing_tables[rule_bridge], rule_bridge,
                    vlan=vlan_tag)
                return fip_address
            else:
                ovs.ensure_default_ovs_flows(self.ovn_bridge_mappings.values(),
                                             constants.OVS_RULE_COOKIE)

        # FIP association to VM
        elif row.type == constants.OVN_PATCH_VIF_PORT_TYPE:
            if (associated_port and self.sb_idl.is_port_on_chassis(
                    associated_port, self.chassis)):
                LOG.info("Add BGP route for FIP with ip %s", ips)
                linux_net.add_ips_to_dev(constants.OVN_BGP_NIC, ips)

                rule_bridge, vlan_tag = self._get_bridge_for_datapath(
                    row.datapath)
                for ip in ips:
                    try:
                        linux_net.add_ip_rule(
                            ip, self.ovn_routing_tables[rule_bridge],
                            rule_bridge)
                    except agent_exc.InvalidPortIP:
                        LOG.exception("Invalid IP to create a rule for the "
                                      "floating IP associated to the VM: %s",
                                      ip)
                        return
                    linux_net.add_ip_route(
                        self.ovn_routing_tables_routes, ip,
                        self.ovn_routing_tables[rule_bridge], rule_bridge,
                        vlan=vlan_tag)

        # CR-LRP Port
        elif (row.type == constants.OVN_CHASSISREDIRECT_VIF_PORT_TYPE and
              row.logical_port.startswith('cr-')):
            cr_lrp_datapath = self.sb_idl.get_provider_datapath_from_cr_lrp(
                row.logical_port)
            if not cr_lrp_datapath:
                return

            LOG.info("Add BGP route for CR-LRP Port %s", ips)
            # Keeping information about the associated network for
            # tenant network advertisement
            self.ovn_local_cr_lrps[row.logical_port] = {
                'router_datapath': row.datapath,
                'provider_datapath': cr_lrp_datapath,
                'ips': ips,
                'subnets_datapath': {},
                'ovn_lbs': []
            }
            ips_without_mask = [ip.split("/")[0] for ip in ips]
            linux_net.add_ips_to_dev(constants.OVN_BGP_NIC, ips_without_mask)

            rule_bridge, vlan_tag = self._get_bridge_for_datapath(
                cr_lrp_datapath)

            for ip in ips:
                ip_without_mask = ip.split("/")[0]
                try:
                    linux_net.add_ip_rule(
                        ip_without_mask,
                        self.ovn_routing_tables[rule_bridge], rule_bridge,
                        lladdr=row.mac[0].split(' ')[0])
                except agent_exc.InvalidPortIP:
                    LOG.exception("Invalid IP to create a rule for the "
                                  "router gateway port: %s", ip_without_mask)
                    return
                linux_net.add_ip_route(
                    self.ovn_routing_tables_routes, ip_without_mask,
                    self.ovn_routing_tables[rule_bridge], rule_bridge,
                    vlan=vlan_tag)
                # add proxy ndp config for ipv6
                if (linux_net.get_ip_version(ip_without_mask) ==
                        constants.IP_VERSION_6):
                    linux_net.add_ndp_proxy(ip, rule_bridge, vlan_tag)

            # Check if there are networks attached to the router,
            # and if so, add the needed routes/rules
            lrp_ports = self.sb_idl.get_lrp_ports_for_router(row.datapath)
            for lrp in lrp_ports:
                if (lrp.chassis or
                        not lrp.logical_port.startswith('lrp-') or
                        "chassis-redirect-port" in lrp.options.keys()):
                    continue
                subnet_datapath = self.sb_idl.get_port_datapath(
                    lrp.logical_port.split('lrp-')[1])
                self.ovn_local_cr_lrps[row.logical_port][
                    'subnets_datapath'].update(
                        {lrp.logical_port: subnet_datapath})
                if self._expose_tenant_networks:
                    self._ensure_network_exposed(
                        lrp, self.ovn_local_cr_lrps[row.logical_port])

            ovn_lbs = self.sb_idl.get_ovn_lb_on_provider_datapath(
                cr_lrp_datapath)
            for ovn_lb in ovn_lbs:
                if any([True for ovn_dp in ovn_lb.datapaths
                        if ovn_dp in self.ovn_local_cr_lrps[
                            row.logical_port]['subnets_datapath'].values()]):
                    for vip in ovn_lb.vips.keys():
                        ip = driver_utils.parse_vip_from_lb_table(vip)
                        self._expose_ovn_lb_on_provider(
                            ovn_lb.name, ip, cr_lrp_datapath,
                            row.logical_port)
                    self.ovn_local_cr_lrps[row.logical_port][
                        'ovn_lbs'].append(ovn_lb.name)

    @lockutils.synchronized('bgp')
    def withdraw_ip(self, ips, row, associated_port=None):
        '''Withdraw BGP route by removing IP from device.

        This methods ensures BGP withdraw an advertised IP of a VM, either
        in the provider network, or the FIP associated to a VM in a tenant
        networks.

        It relies on Zebra, which withdraws the advertisement as soon as the
        IP is deleted from the local interface.

        This method assumes a device named self.ovn_decice exists (inside a
        VRF), and removes the IP of either:
        - VM IP on the provider network,
        - VM FIP, or
        - CR-LRP OVN port
        '''
        # VM on provider Network
        if ((row.type == constants.OVN_VM_VIF_PORT_TYPE or
                row.type == constants.OVN_VIRTUAL_VIF_PORT_TYPE) and
                self.sb_idl.is_provider_network(row.datapath)):
            LOG.info("Delete BGP route for logical port with ip %s", ips)
            linux_net.del_ips_from_dev(constants.OVN_BGP_NIC, ips)

            rule_bridge, vlan_tag = self._get_bridge_for_datapath(row.datapath)
            for ip in ips:
                linux_net.del_ip_rule(ip,
                                      self.ovn_routing_tables[rule_bridge],
                                      rule_bridge)
                linux_net.del_ip_route(
                    self.ovn_routing_tables_routes, ip,
                    self.ovn_routing_tables[rule_bridge], rule_bridge,
                    vlan=vlan_tag)

        # VM with FIP
        elif (row.type == constants.OVN_VM_VIF_PORT_TYPE or
                row.type == constants.OVN_VIRTUAL_VIF_PORT_TYPE):
            # FIPs are only supported with IPv4
            fip_address, fip_datapath = self.sb_idl.get_fip_associated(
                row.logical_port)
            if not fip_address:
                return

            LOG.info("Delete BGP route for FIP with ip %s", fip_address)
            linux_net.del_ips_from_dev(constants.OVN_BGP_NIC,
                                       [fip_address])

            rule_bridge, vlan_tag = self._get_bridge_for_datapath(
                fip_datapath)
            linux_net.del_ip_rule(fip_address,
                                  self.ovn_routing_tables[rule_bridge],
                                  rule_bridge)
            linux_net.del_ip_route(
                self.ovn_routing_tables_routes, fip_address,
                self.ovn_routing_tables[rule_bridge], rule_bridge,
                vlan=vlan_tag)

        # FIP association to VM
        elif row.type == constants.OVN_PATCH_VIF_PORT_TYPE:
            if (associated_port and (
                    self.sb_idl.is_port_on_chassis(
                        associated_port, self.chassis) or
                    self.sb_idl.is_port_deleted(associated_port))):
                LOG.info("Delete BGP route for FIP with ip %s", ips)
                linux_net.del_ips_from_dev(constants.OVN_BGP_NIC, ips)

                rule_bridge, vlan_tag = self._get_bridge_for_datapath(
                    row.datapath)
                for ip in ips:
                    linux_net.del_ip_rule(ip,
                                          self.ovn_routing_tables[rule_bridge],
                                          rule_bridge)
                    linux_net.del_ip_route(
                        self.ovn_routing_tables_routes, ip,
                        self.ovn_routing_tables[rule_bridge], rule_bridge,
                        vlan=vlan_tag)

        # CR-LRP Port
        elif (row.type == constants.OVN_CHASSISREDIRECT_VIF_PORT_TYPE and
              row.logical_port.startswith('cr-')):
            cr_lrp_datapath = self.ovn_local_cr_lrps.get(
                row.logical_port, {}).get('provider_datapath')
            if not cr_lrp_datapath:
                return

            LOG.info("Delete BGP route for CR-LRP Port %s", ips)
            # Removing information about the associated network for
            # tenant network advertisement
            ips_without_mask = [ip.split("/")[0] for ip in ips]
            linux_net.del_ips_from_dev(constants.OVN_BGP_NIC,
                                       ips_without_mask)

            rule_bridge, vlan_tag = self._get_bridge_for_datapath(
                cr_lrp_datapath)

            for ip in ips_without_mask:
                if linux_net.get_ip_version(ip) == constants.IP_VERSION_6:
                    cr_lrp_ip = '{}/128'.format(ip)
                else:
                    cr_lrp_ip = '{}/32'.format(ip)
                linux_net.del_ip_rule(
                    cr_lrp_ip, self.ovn_routing_tables[rule_bridge],
                    rule_bridge, lladdr=row.mac[0].split(' ')[0])
                linux_net.del_ip_route(
                    self.ovn_routing_tables_routes, ip,
                    self.ovn_routing_tables[rule_bridge], rule_bridge,
                    vlan=vlan_tag)
                # del proxy ndp config for ipv6
                if linux_net.get_ip_version(ip) == constants.IP_VERSION_6:
                    cr_lrps_on_same_provider = [
                        p for p in self.ovn_local_cr_lrps.values()
                        if p['provider_datapath'] == cr_lrp_datapath]
                    if (len(cr_lrps_on_same_provider) > 1):
                        linux_net.del_ndp_proxy(ip, rule_bridge, vlan_tag)

            # Check if there are networks attached to the router,
            # and if so, delete the needed routes/rules
            lrp_ports = self.sb_idl.get_lrp_ports_for_router(row.datapath)
            for lrp in lrp_ports:
                if (lrp.chassis or
                        not lrp.logical_port.startswith('lrp-') or
                        "chassis-redirect-port" in lrp.options.keys()):
                    continue
                local_cr_lrp_info = self.ovn_local_cr_lrps.get(
                    row.logical_port)
                if local_cr_lrp_info:
                    self._remove_network_exposed(lrp, local_cr_lrp_info)
            ovn_lbs = self.ovn_local_cr_lrps[row.logical_port][
                'ovn_lbs'].copy()
            for ovn_lb in ovn_lbs:
                self.withdraw_ovn_lb_on_provider(
                    ovn_lb, cr_lrp_datapath, row.logical_port)
                self.ovn_local_cr_lrps[row.logical_port][
                    'ovn_lbs'].remove(ovn_lb)
            try:
                del self.ovn_local_cr_lrps[row.logical_port]
            except KeyError:
                LOG.debug("Gateway port %s already cleanup from the "
                          "agent", row.logical_port)

    @lockutils.synchronized('bgp')
    def expose_remote_ip(self, ips, row):
        if (self.sb_idl.is_provider_network(row.datapath) or
                not self._expose_tenant_networks):
            return
        port_lrp = self.sb_idl.get_lrp_port_for_datapath(row.datapath)
        if port_lrp in self.ovn_local_lrps:
            LOG.info("Add BGP route for tenant IP %s on chassis %s",
                     ips, self.chassis)
            linux_net.add_ips_to_dev(constants.OVN_BGP_NIC, ips)

    @lockutils.synchronized('bgp')
    def withdraw_remote_ip(self, ips, row):
        if (self.sb_idl.is_provider_network(row.datapath) or
                not self._expose_tenant_networks):
            return
        port_lrp = self.sb_idl.get_lrp_port_for_datapath(row.datapath)
        if port_lrp in self.ovn_local_lrps:
            LOG.info("Delete BGP route for tenant IP %s on chassis %s",
                     ips, self.chassis)
            linux_net.del_ips_from_dev(constants.OVN_BGP_NIC, ips)

    @lockutils.synchronized('bgp')
    def expose_subnet(self, ip, row):
        cr_lrp = self.sb_idl.is_router_gateway_on_chassis(row.datapath,
                                                          self.chassis)
        if not cr_lrp:
            return

        cr_lrp_info = self.ovn_local_cr_lrps.get(cr_lrp, {})
        cr_lrp_datapath = cr_lrp_info.get('provider_datapath')
        if not cr_lrp_datapath:
            return

        network_port_datapath = self.sb_idl.get_port_datapath(
            row.options['peer'])
        # update information needed for the loadbalancers
        self.ovn_local_cr_lrps[cr_lrp]['subnets_datapath'].update(
            {row.logical_port: network_port_datapath})

        if not self._expose_tenant_networks:
            return

        LOG.info("Add IP Rules for network %s on chassis %s", ip,
                 self.chassis)
        self.ovn_local_lrps.add(row.logical_port)
        cr_lrp_ips = [ip_address.split('/')[0]
                      for ip_address in cr_lrp_info.get('ips', [])]
        rule_bridge, vlan_tag = self._get_bridge_for_datapath(
            cr_lrp_datapath)
        try:
            linux_net.add_ip_rule(
                ip, self.ovn_routing_tables[rule_bridge], rule_bridge)
        except agent_exc.InvalidPortIP:
            LOG.exception("Invalid IP to create a rule for the "
                          "network router interface port: %s", ip)

        ip_version = linux_net.get_ip_version(ip)
        for cr_lrp_ip in cr_lrp_ips:
            if linux_net.get_ip_version(cr_lrp_ip) == ip_version:
                linux_net.add_ip_route(
                    self.ovn_routing_tables_routes,
                    ip.split("/")[0],
                    self.ovn_routing_tables[rule_bridge],
                    rule_bridge,
                    vlan=vlan_tag,
                    mask=ip.split("/")[1],
                    via=cr_lrp_ip)
                break

        # Check if there are VMs on the network
        # and if so expose the route
        ports = self.sb_idl.get_ports_on_datapath(network_port_datapath)
        for port in ports:
            if (not port.mac or
                    port.type not in (
                        constants.OVN_VM_VIF_PORT_TYPE,
                        constants.OVN_VIRTUAL_VIF_PORT_TYPE)):
                continue
            try:
                port_ips = [port.mac[0].split(' ')[1]]
            except IndexError:
                continue
            if len(port.mac[0].split(' ')) == 3:
                port_ips.append(port.mac[0].split(' ')[2])

            for port_ip in port_ips:
                # Only adding the port ips that match the lrp
                # IP version
                port_ip_version = linux_net.get_ip_version(port_ip)
                if port_ip_version == ip_version:
                    linux_net.add_ips_to_dev(constants.OVN_BGP_NIC, [port_ip])

    @lockutils.synchronized('bgp')
    def withdraw_subnet(self, ip, row):
        cr_lrp = self.sb_idl.is_router_gateway_on_chassis(row.datapath,
                                                          self.chassis)
        if not cr_lrp:
            return

        cr_lrp_info = self.ovn_local_cr_lrps.get(cr_lrp, {})
        cr_lrp_datapath = cr_lrp_info.get('provider_datapath')
        if not cr_lrp_datapath:
            return

        self.ovn_local_cr_lrps[cr_lrp]['subnets_datapath'].pop(
            row.logical_port, None)

        if not self._expose_tenant_networks:
            return

        LOG.info("Delete IP Rules for network %s on chassis %s", ip,
                 self.chassis)
        if row.logical_port in self.ovn_local_lrps:
            self.ovn_local_lrps.remove(row.logical_port)

        cr_lrp_ips = [ip_address.split('/')[0]
                      for ip_address in cr_lrp_info.get('ips', [])]
        rule_bridge, vlan_tag = self._get_bridge_for_datapath(
            cr_lrp_datapath)
        linux_net.del_ip_rule(ip, self.ovn_routing_tables[rule_bridge],
                              rule_bridge)

        ip_version = linux_net.get_ip_version(ip)
        for cr_lrp_ip in cr_lrp_ips:
            if linux_net.get_ip_version(cr_lrp_ip) == ip_version:
                linux_net.del_ip_route(
                    self.ovn_routing_tables_routes,
                    ip.split("/")[0],
                    self.ovn_routing_tables[rule_bridge],
                    rule_bridge,
                    vlan=vlan_tag,
                    mask=ip.split("/")[1],
                    via=cr_lrp_ip)
                if (linux_net.get_ip_version(cr_lrp_ip) ==
                        constants.IP_VERSION_6):
                    net = ipaddress.IPv6Network(ip, strict=False)
                else:
                    net = ipaddress.IPv4Network(ip, strict=False)
                break

        # Check if there are VMs on the network
        # and if so withdraw the routes
        vms_on_net = linux_net.get_exposed_ips_on_network(
            constants.OVN_BGP_NIC, net)
        linux_net.delete_exposed_ips(vms_on_net, constants.OVN_BGP_NIC)

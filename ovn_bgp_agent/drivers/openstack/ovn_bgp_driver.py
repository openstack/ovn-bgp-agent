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

OVN_TABLES = ["Port_Binding", "Chassis", "Datapath_Binding"]


class OVNBGPDriver(driver_api.AgentDriverBase):

    def __init__(self):
        self._expose_tenant_networks = (CONF.expose_tenant_networks or
                                        CONF.expose_ipv6_gua_tenant_networks)
        self.allowed_address_scopes = set(CONF.address_scopes or [])
        self.ovn_routing_tables = {}  # {'br-ex': 200}
        self.ovn_bridge_mappings = {}  # {'public': 'br-ex'}
        self.ovn_local_cr_lrps = {}
        self.ovn_local_lrps = {}
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
        self.ovs_idl = ovs.OvsIdl()
        self.ovs_idl.start(CONF.ovsdb_connection)
        self.chassis = self.ovs_idl.get_own_chassis_name()
        self.ovn_remote = self.ovs_idl.get_ovn_remote()
        LOG.info("Loaded chassis %s.", self.chassis)

        LOG.info("Starting VRF configuration for advertising routes")
        # Create VRF
        linux_net.ensure_vrf(CONF.bgp_vrf, CONF.bgp_vrf_table_id)

        # Ensure FRR is configure to leak the routes
        # NOTE: If we want to recheck this every X time, we should move it
        # inside the sync function instead
        frr.vrf_leak(CONF.bgp_vrf, CONF.bgp_AS, CONF.bgp_router_id)

        # Create OVN dummy device
        linux_net.ensure_ovn_device(CONF.bgp_nic, CONF.bgp_vrf)

        # Clear vrf routing table
        if CONF.clear_vrf_routes_on_startup:
            linux_net.delete_routes_from_table(CONF.bgp_vrf_table_id)

        LOG.info("VRF configuration for advertising routes completed")
        if self._expose_tenant_networks and self.allowed_address_scopes:
            LOG.info("Configured allowed address scopes: %s",
                     ", ".join(self.allowed_address_scopes))

        events = ()
        for event in self._get_events():
            event_class = getattr(watcher, event)
            events += (event_class(self),)

        self._post_fork_event.clear()
        # TODO(lucasagomes): The OVN package in the ubuntu LTS is old
        # and does not support Chassis_Private. Once the package is updated
        # we can remove this fallback mode.
        try:
            try:
                self.sb_idl = ovn.OvnSbIdl(
                    self.ovn_remote,
                    chassis=self.chassis,
                    tables=OVN_TABLES + ["Chassis_Private",
                                         "Logical_DP_Group"],
                    events=events).start()
            except AssertionError:
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
                      "OVNLBVIPPortEvent",
                      "ChassisCreateEvent"])
        if self._expose_tenant_networks:
            events.update(["SubnetRouterAttachedEvent",
                           "SubnetRouterDetachedEvent",
                           "TenantPortCreatedEvent",
                           "TenantPortDeletedEvent"])
        return events

    @lockutils.synchronized('bgp')
    def sync(self):
        self._expose_tenant_networks = (CONF.expose_tenant_networks or
                                        CONF.expose_ipv6_gua_tenant_networks)
        self.ovn_local_cr_lrps = {}
        self.ovn_local_lrps = {}
        self.ovn_routing_tables_routes = collections.defaultdict()
        self.ovn_lb_vips = collections.defaultdict()

        LOG.debug("Ensuring VRF configuration for advertising routes")
        # Create VRF
        linux_net.ensure_vrf(CONF.bgp_vrf,
                             CONF.bgp_vrf_table_id)
        # Create OVN dummy device
        linux_net.ensure_ovn_device(CONF.bgp_nic,
                                    CONF.bgp_vrf)

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

                linux_net.ensure_arp_ndp_enabled_for_bridge(bridge,
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
        exposed_ips = linux_net.get_exposed_ips(CONF.bgp_nic)
        # get the rules pointing to ovn bridges
        ovn_ip_rules = linux_net.get_ovn_ip_rules(
            self.ovn_routing_tables.values())

        # add missing routes/ips for IPs on provider network
        ports = self.sb_idl.get_ports_on_chassis(self.chassis)
        for port in ports:
            self._ensure_port_exposed(port, exposed_ips, ovn_ip_rules)

        # this information is only available when there are cr-lrps add
        # missing routes/ips for FIPs associated to VMs/LBs on the chassis
        cr_lrp_ports = self.sb_idl.get_cr_lrp_ports_on_chassis(
            self.chassis)
        for cr_lrp_port in cr_lrp_ports:
            self._ensure_cr_lrp_associated_ports_exposed(
                cr_lrp_port, exposed_ips, ovn_ip_rules)

        for cr_lrp_port, cr_lrp_info in self.ovn_local_cr_lrps.items():
            lrp_ports = self.sb_idl.get_lrp_ports_for_router(
                cr_lrp_info['router_datapath'])
            for lrp in lrp_ports:
                self._process_lrp_port(lrp, cr_lrp_port, exposed_ips,
                                       ovn_ip_rules)

            # add missing routes/ips related to ovn-octavia loadbalancers
            # on the provider networks
            ovn_lb_vips = self.sb_idl.get_ovn_lb_vips_on_provider_datapath(
                cr_lrp_info['provider_datapath'])
            for ovn_lb_port, ovn_lb_ip in ovn_lb_vips.items():
                self._expose_ovn_lb_on_provider(ovn_lb_ip,
                                                ovn_lb_port,
                                                cr_lrp_port)

        # remove extra routes/ips
        # remove all the leftovers on the list of current ips on dev OVN
        linux_net.delete_exposed_ips(exposed_ips, CONF.bgp_nic)
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

        port_ips = []
        if port.mac == ['unknown']:
            # For FIPs associated to VM ports we don't need the port IP, so
            # we can check if it is a VM on the provider and trigger the
            # expose_ip without passing any port_ips
            if ((port.type != constants.OVN_VM_VIF_PORT_TYPE and
                    port.type != constants.OVN_VIRTUAL_VIF_PORT_TYPE) or
                    self.sb_idl.is_provider_network(port.datapath)):
                return
        else:
            if len(port.mac[0].split(' ')) < 2:
                return
            port_ips = port.mac[0].split(' ')[1:]

        ips_adv = self._expose_ip(port_ips, port)

        for port_ip in ips_adv:
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

    def _expose_provider_port(self, port_ips, provider_datapath,
                              bridge_device=None, bridge_vlan=None,
                              lladdr=None):
        linux_net.add_ips_to_dev(CONF.bgp_nic, port_ips)

        if not bridge_device and not bridge_vlan:
            bridge_device, bridge_vlan = self._get_bridge_for_datapath(
                provider_datapath)
        for ip in port_ips:
            try:
                if lladdr:
                    linux_net.add_ip_rule(
                        ip, self.ovn_routing_tables[bridge_device],
                        bridge_device, lladdr=lladdr)
                else:
                    linux_net.add_ip_rule(
                        ip, self.ovn_routing_tables[bridge_device],
                        bridge_device)
            except agent_exc.InvalidPortIP:
                LOG.exception("Invalid IP to create a rule for port"
                              " on the provider network: %s", ip)
                return []
            linux_net.add_ip_route(
                self.ovn_routing_tables_routes, ip,
                self.ovn_routing_tables[bridge_device], bridge_device,
                vlan=bridge_vlan)

    def _expose_tenant_port(self, port, ip_version, exposed_ips=[],
                            ovn_ip_rules={}):
        # specific case for ovn-lb vips on tenant networks
        if not port.mac and not port.chassis and not port.up[0]:
            ext_n_cidr = port.external_ids.get(
                constants.OVN_CIDRS_EXT_ID_KEY)
            if ext_n_cidr:
                ovn_lb_ip = ext_n_cidr.split(" ")[0].split("/")[0]
                linux_net.add_ips_to_dev(
                    CONF.bgp_nic, [ovn_lb_ip])
                if ovn_lb_ip in exposed_ips:
                    exposed_ips.remove(ovn_lb_ip)
                ovn_ip_rules.pop(ext_n_cidr.split(" ")[0], None)
            return
        elif (not port.mac or
                port.type not in (
                    constants.OVN_VM_VIF_PORT_TYPE,
                    constants.OVN_VIRTUAL_VIF_PORT_TYPE) or
                (port.type == constants.OVN_VM_VIF_PORT_TYPE and
                    not port.chassis)):
            return

        try:
            if port.mac == ['unknown']:
                # Handling the case for unknown MACs when configdrive is used
                # instead of dhcp
                n_cidrs = port.external_ids.get(constants.OVN_CIDRS_EXT_ID_KEY)
                port_ips = [ip.split("/")[0] for ip in n_cidrs.split(" ")]
            else:
                port_ips = port.mac[0].split(' ')[1:]
        except IndexError:
            return

        for port_ip in port_ips:
            # Only adding the port ips that match the lrp
            # IP version
            port_ip_version = linux_net.get_ip_version(port_ip)
            if port_ip_version == ip_version:
                linux_net.add_ips_to_dev(
                    CONF.bgp_nic, [port_ip])
                if port_ip in exposed_ips:
                    exposed_ips.remove(port_ip)
                if port_ip_version == constants.IP_VERSION_6:
                    ip_dst = "{}/128".format(port_ip)
                else:
                    ip_dst = "{}/32".format(port_ip)
                ovn_ip_rules.pop(ip_dst, None)

    def _withdraw_provider_port(self, port_ips, provider_datapath,
                                bridge_device=None, bridge_vlan=None,
                                lladdr=None):
        linux_net.del_ips_from_dev(CONF.bgp_nic, port_ips)

        # assuming either you pass both or none
        if not bridge_device and not bridge_vlan:
            bridge_device, bridge_vlan = self._get_bridge_for_datapath(
                provider_datapath)
        for ip in port_ips:
            if lladdr:
                if linux_net.get_ip_version(ip) == constants.IP_VERSION_6:
                    cr_lrp_ip = '{}/128'.format(ip)
                else:
                    cr_lrp_ip = '{}/32'.format(ip)
                linux_net.del_ip_rule(
                    cr_lrp_ip, self.ovn_routing_tables[bridge_device],
                    bridge_device, lladdr=lladdr)
            else:
                linux_net.del_ip_rule(
                    ip, self.ovn_routing_tables[bridge_device], bridge_device)
            linux_net.del_ip_route(
                self.ovn_routing_tables_routes, ip,
                self.ovn_routing_tables[bridge_device], bridge_device,
                vlan=bridge_vlan)

    def _get_bridge_for_datapath(self, datapath):
        network_name, network_tag = self.sb_idl.get_network_name_and_tag(
            datapath, self.ovn_bridge_mappings.keys())
        if network_name:
            if network_tag:
                return self.ovn_bridge_mappings[network_name], network_tag[0]
            return self.ovn_bridge_mappings[network_name], None
        return None, None

    @lockutils.synchronized('bgp')
    def expose_ovn_lb(self, ip, row):
        self._process_ovn_lb(ip, row, constants.EXPOSE)

    @lockutils.synchronized('bgp')
    def withdraw_ovn_lb(self, ip, row):
        self._process_ovn_lb(ip, row, constants.WITHDRAW)

    def _process_ovn_lb(self, ip, row, action):
        if not self.sb_idl.is_provider_network(row.datapath):
            if not self._expose_tenant_networks:
                return
            if action == constants.EXPOSE:
                return self._expose_remote_ip([ip], row)
            if action == constants.WITHDRAW:
                return self._withdraw_remote_ip([ip], row)
            # if unknown action return
            return
        local_lb_cr_lrp = None
        for cr_lrp_port, cr_lrp_info in self.ovn_local_cr_lrps.items():
            if cr_lrp_info['provider_datapath'] == row.datapath:
                local_lb_cr_lrp = cr_lrp_port
                break
        if not local_lb_cr_lrp:
            return
        vip_port = row.logical_port
        if action == constants.EXPOSE:
            self._expose_ovn_lb_on_provider(ip, vip_port, local_lb_cr_lrp)
        if action == constants.WITHDRAW:
            self._withdraw_ovn_lb_on_provider(vip_port, local_lb_cr_lrp)

    def _expose_ovn_lb_on_provider(self, ip, ovn_lb_vip_port, cr_lrp):
        self.ovn_local_cr_lrps[cr_lrp]['ovn_lb_vips'].append(ovn_lb_vip_port)
        self.ovn_lb_vips.setdefault(ovn_lb_vip_port, []).append(ip)
        bridge_device = self.ovn_local_cr_lrps[cr_lrp]['bridge_device']
        bridge_vlan = self.ovn_local_cr_lrps[cr_lrp]['bridge_vlan']

        LOG.debug("Adding BGP route for loadbalancer VIP %s", ip)
        self._expose_provider_port([ip], None, bridge_device=bridge_device,
                                   bridge_vlan=bridge_vlan)
        LOG.debug("Added BGP route for loadbalancer VIP %s", ip)

    def _withdraw_ovn_lb_on_provider(self, ovn_lb_vip_port, cr_lrp):
        bridge_device = self.ovn_local_cr_lrps[cr_lrp]['bridge_device']
        bridge_vlan = self.ovn_local_cr_lrps[cr_lrp]['bridge_vlan']

        for ip in self.ovn_lb_vips[ovn_lb_vip_port].copy():
            LOG.debug("Deleting BGP route for loadbalancer VIP %s", ip)
            self._withdraw_provider_port([ip], None,
                                         bridge_device=bridge_device,
                                         bridge_vlan=bridge_vlan)
            if ip in self.ovn_lb_vips[ovn_lb_vip_port]:
                self.ovn_lb_vips[ovn_lb_vip_port].remove(ip)
            LOG.debug("Deleted BGP route for loadbalancer VIP %s", ip)
        if ovn_lb_vip_port in self.ovn_local_cr_lrps[cr_lrp]['ovn_lb_vips']:
            self.ovn_local_cr_lrps[cr_lrp]['ovn_lb_vips'].remove(
                ovn_lb_vip_port)

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
            LOG.debug("Adding BGP route for logical port with ip %s", ips)
            self._expose_provider_port(ips, row.datapath)
            # NOTE: For Amphora Load Balancer with IPv6 VIP on the provider
            # network, we need a NDP Proxy so that the traffic from the
            # amphora can properly be redirected back
            if row.type == constants.OVN_VIRTUAL_VIF_PORT_TYPE:
                bridge_device, bridge_vlan = self._get_bridge_for_datapath(
                    row.datapath)
                # NOTE: This is neutron specific as we need the provider
                # prefix to add the ndp proxy
                n_cidr = row.external_ids.get(constants.OVN_CIDRS_EXT_ID_KEY)
                if n_cidr and (linux_net.get_ip_version(n_cidr) ==
                               constants.IP_VERSION_6):
                    linux_net.add_ndp_proxy(n_cidr, bridge_device, bridge_vlan)
            LOG.debug("Added BGP route for logical port with ip %s", ips)
            return ips

        # VM with FIP
        elif (row.type == constants.OVN_VM_VIF_PORT_TYPE or
                row.type == constants.OVN_VIRTUAL_VIF_PORT_TYPE):
            # FIPs are only supported with IPv4
            fip_address, fip_datapath = self.sb_idl.get_fip_associated(
                row.logical_port)
            if fip_address:
                LOG.debug("Adding BGP route for FIP with ip %s", fip_address)
                self._expose_provider_port([fip_address], fip_datapath)
                LOG.debug("Added BGP route for FIP with ip %s", fip_address)
                return [fip_address]

        # FIP association to VM
        elif row.type == constants.OVN_PATCH_VIF_PORT_TYPE:
            if (associated_port and self.sb_idl.is_port_on_chassis(
                    associated_port, self.chassis)):
                LOG.debug("Adding BGP route for FIP with ip %s", ips)
                self._expose_provider_port(ips, row.datapath)
                LOG.debug("Added BGP route for FIP with ip %s", ips)
                return ips

        # CR-LRP Port
        elif (row.type == constants.OVN_CHASSISREDIRECT_VIF_PORT_TYPE and
              row.logical_port.startswith('cr-')):
            cr_lrp_datapath = self.sb_idl.get_provider_datapath_from_cr_lrp(
                row.logical_port)
            if not cr_lrp_datapath:
                return []

            bridge_device, bridge_vlan = self._get_bridge_for_datapath(
                cr_lrp_datapath)
            mac = row.mac[0].split(' ')[0]
            # Keeping information about the associated network for
            # tenant network advertisement
            self.ovn_local_cr_lrps[row.logical_port] = {
                'router_datapath': row.datapath,
                'provider_datapath': cr_lrp_datapath,
                'ips': ips,
                'mac': mac,
                'subnets_datapath': {},
                'subnets_cidr': [],
                'ovn_lb_vips': [],
                'bridge_vlan': bridge_vlan,
                'bridge_device': bridge_device
            }

            self._expose_cr_lrp_port(ips, mac, bridge_device, bridge_vlan,
                                     router_datapath=row.datapath,
                                     provider_datapath=cr_lrp_datapath,
                                     cr_lrp_port=row.logical_port)

            return ips
        return []

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
            LOG.debug("Deleting BGP route for logical port with ip %s", ips)
            self._withdraw_provider_port(ips, row.datapath)
            if row.type == constants.OVN_VIRTUAL_VIF_PORT_TYPE:
                virtual_provider_ports = (
                    self.sb_idl.get_virtual_ports_on_datapath_by_chassis(
                        row.datapath, self.chassis))
                if not virtual_provider_ports:
                    cr_lrps_on_same_provider = [
                        p for p in self.ovn_local_cr_lrps.values()
                        if p['provider_datapath'] == row.datapath]
                    if not cr_lrps_on_same_provider:
                        bridge_device, bridge_vlan = (
                            self._get_bridge_for_datapath(row.datapath))
                        # NOTE: This is neutron specific as we need the
                        # provider prefix to add the ndp proxy
                        n_cidr = row.external_ids.get(
                            constants.OVN_CIDRS_EXT_ID_KEY)
                        if n_cidr and (linux_net.get_ip_version(n_cidr) ==
                                       constants.IP_VERSION_6):
                            linux_net.del_ndp_proxy(n_cidr, bridge_device,
                                                    bridge_vlan)
            LOG.debug("Deleted BGP route for logical port with ip %s", ips)

        # VM with FIP
        elif (row.type == constants.OVN_VM_VIF_PORT_TYPE or
                row.type == constants.OVN_VIRTUAL_VIF_PORT_TYPE):
            # FIPs are only supported with IPv4
            fip_address, fip_datapath = self.sb_idl.get_fip_associated(
                row.logical_port)
            if not fip_address:
                return

            LOG.debug("Deleting BGP route for FIP with ip %s", fip_address)
            self._withdraw_provider_port([fip_address], fip_datapath)
            LOG.debug("Deleted BGP route for FIP with ip %s", fip_address)

        # FIP association to VM
        elif row.type == constants.OVN_PATCH_VIF_PORT_TYPE:
            if (associated_port and (
                    self.sb_idl.is_port_on_chassis(
                        associated_port, self.chassis) or
                    self.sb_idl.is_port_deleted(associated_port))):
                LOG.debug("Deleting BGP route for FIP with ip %s", ips)
                self._withdraw_provider_port(ips, row.datapath)
                LOG.debug("Deleted BGP route for FIP with ip %s", ips)

        # CR-LRP Port
        elif (row.type == constants.OVN_CHASSISREDIRECT_VIF_PORT_TYPE and
              row.logical_port.startswith('cr-')):
            cr_lrp_datapath = self.ovn_local_cr_lrps.get(
                row.logical_port, {}).get('provider_datapath')
            if not cr_lrp_datapath:
                return

            bridge_vlan = self.ovn_local_cr_lrps[row.logical_port].get(
                'bridge_vlan')
            bridge_device = self.ovn_local_cr_lrps[row.logical_port].get(
                'bridge_device')
            mac = row.mac[0].split(' ')[0]
            self._withdraw_cr_lrp_port(ips, mac, bridge_device, bridge_vlan,
                                       provider_datapath=cr_lrp_datapath,
                                       cr_lrp_port=row.logical_port)

    @lockutils.synchronized('bgp')
    def expose_remote_ip(self, ips, row):
        self._expose_remote_ip(ips, row)

    def _expose_remote_ip(self, ips, row):
        if (self.sb_idl.is_provider_network(row.datapath) or
                not self._expose_tenant_networks):
            return
        if not CONF.expose_tenant_networks:
            # This means CONF.expose_ipv6_gua_tenant_networks is enabled
            gua_ips = []
            for ip in ips:
                if driver_utils.is_ipv6_gua(ip):
                    gua_ips.append(ip)
            if not gua_ips:
                return
            ips = gua_ips

        ips_to_expose = []
        for ip in ips:
            if self._address_scope_allowed(ip, None, row):
                ips_to_expose.append(ip)
        if not ips_to_expose:
            return

        port_lrp = self.sb_idl.get_lrp_port_for_datapath(row.datapath)
        if port_lrp in self.ovn_local_lrps.keys():
            LOG.debug("Adding BGP route for tenant IP %s on chassis %s",
                      ips_to_expose, self.chassis)
            linux_net.add_ips_to_dev(CONF.bgp_nic, ips_to_expose)
            LOG.debug("Added BGP route for tenant IP %s on chassis %s",
                      ips_to_expose, self.chassis)

    @lockutils.synchronized('bgp')
    def withdraw_remote_ip(self, ips, row, chassis=None):
        self._withdraw_remote_ip(ips, row, chassis)

    def _withdraw_remote_ip(self, ips, row, chassis=None):
        if (self.sb_idl.is_provider_network(row.datapath) or
                not self._expose_tenant_networks):
            return
        if not CONF.expose_tenant_networks:
            # This means CONF.expose_ipv6_gua_tenant_networks is enabled
            gua_ips = []
            for ip in ips:
                if driver_utils.is_ipv6_gua(ip):
                    gua_ips.append(ip)
            if not gua_ips:
                return
            ips = gua_ips

        ips_to_withdraw = []
        for ip in ips:
            if self._address_scope_allowed(ip, None, row):
                ips_to_withdraw.append(ip)
        if not ips_to_withdraw:
            return
        port_lrp = self.sb_idl.get_lrp_port_for_datapath(row.datapath)
        if port_lrp in self.ovn_local_lrps.keys():
            LOG.debug("Deleting BGP route for tenant IP %s on chassis %s",
                      ips_to_withdraw, self.chassis)
            linux_net.del_ips_from_dev(CONF.bgp_nic, ips_to_withdraw)
            LOG.debug("Deleted BGP route for tenant IP %s on chassis %s",
                      ips_to_withdraw, self.chassis)

    def _process_cr_lrp_port(self, cr_lrp_port_name, provider_datapath,
                             router_port):
        ips = router_port.mac[0].split(' ')[1:]
        bridge_device, bridge_vlan = self._get_bridge_for_datapath(
            provider_datapath)
        mac = router_port.mac[0].split(' ')[0]
        self.ovn_local_cr_lrps[cr_lrp_port_name] = {
            'router_datapath': router_port.datapath,
            'provider_datapath': provider_datapath,
            'ips': ips,
            'mac': mac,
            'subnets_datapath': {},
            'subnets_cidr': [],
            'ovn_lb_vips': [],
            'bridge_vlan': bridge_vlan,
            'bridge_device': bridge_device
        }
        # NOTE: This is like if it was the cr-lrp action on expose_ip
        return self._expose_cr_lrp_port(
            ips, mac, bridge_device, bridge_vlan,
            router_datapath=router_port.datapath,
            provider_datapath=provider_datapath,
            cr_lrp_port=cr_lrp_port_name)

    def _process_lrp_port(self, lrp, associated_cr_lrp, exposed_ips=[],
                          ovn_ip_rules={}):
        if (lrp.chassis or
                not lrp.logical_port.startswith('lrp-') or
                "chassis-redirect-port" in lrp.options.keys() or
                associated_cr_lrp.strip('cr-') == lrp.logical_port):
            return
        # add missing route/ips for tenant network VMs
        if self._expose_tenant_networks:
            try:
                lrp_ip = lrp.mac[0].split(' ')[1]
            except IndexError:
                # This should not happen: subnet without CIDR
                return

            if not lrp.options.get('peer'):
                # if there is no peer associated to the port we need to
                # 1) creation: wait for another re-sync to expose it
                # 2) deletion: no need to add it as it being removed
                return
            if not self._address_scope_allowed(lrp_ip, lrp.options['peer']):
                return
            subnet_datapath = self.sb_idl.get_port_datapath(
                lrp.options['peer'])
            self._expose_lrp_port(lrp_ip, lrp.logical_port,
                                  associated_cr_lrp, subnet_datapath,
                                  exposed_ips=exposed_ips,
                                  ovn_ip_rules=ovn_ip_rules)

    def _expose_cr_lrp_port(self, ips, mac, bridge_device, bridge_vlan,
                            router_datapath, provider_datapath, cr_lrp_port):
        LOG.debug("Adding BGP route for CR-LRP Port %s", ips)
        ips_without_mask = [ip.split("/")[0] for ip in ips]
        self._expose_provider_port(ips_without_mask, provider_datapath,
                                   bridge_device, bridge_vlan,
                                   lladdr=mac)
        # add proxy ndp config for ipv6
        for ip in ips:
            if linux_net.get_ip_version(ip) == constants.IP_VERSION_6:
                linux_net.add_ndp_proxy(ip, bridge_device, bridge_vlan)
        LOG.debug("Added BGP route for CR-LRP Port %s", ips)

        # Check if there are networks attached to the router,
        # and if so, add the needed routes/rules
        lrp_ports = self.sb_idl.get_lrp_ports_for_router(router_datapath)
        for lrp in lrp_ports:
            self._process_lrp_port(lrp, cr_lrp_port)

        ovn_lb_vips = self.sb_idl.get_ovn_lb_vips_on_provider_datapath(
            provider_datapath)
        for ovn_lb_port, ovn_lb_ip in ovn_lb_vips.items():
            self._expose_ovn_lb_on_provider(ovn_lb_ip,
                                            ovn_lb_port,
                                            cr_lrp_port)

    def _withdraw_cr_lrp_port(self, ips, mac, bridge_device, bridge_vlan,
                              provider_datapath, cr_lrp_port):
        LOG.debug("Deleting BGP route for CR-LRP Port %s", ips)
        # Removing information about the associated network for
        # tenant network advertisement
        ips_without_mask = [ip.split("/")[0] for ip in ips]
        self._withdraw_provider_port(ips_without_mask, provider_datapath,
                                     bridge_device=bridge_device,
                                     bridge_vlan=bridge_vlan,
                                     lladdr=mac)
        # del proxy ndp config for ipv6
        for ip in ips_without_mask:
            if linux_net.get_ip_version(ip) == constants.IP_VERSION_6:
                cr_lrps_on_same_provider = [
                    p for p in self.ovn_local_cr_lrps.values()
                    if p['provider_datapath'] == provider_datapath]
                # if no other cr-lrp port on the same provider
                # delete the ndp proxy
                if (len(cr_lrps_on_same_provider) <= 1):
                    linux_net.del_ndp_proxy(ip, bridge_device, bridge_vlan)
        LOG.debug("Deleted BGP route for CR-LRP Port %s", ips)

        # Check if there are networks attached to the router,
        # and if so delete the needed routes/rules
        local_cr_lrp_info = self.ovn_local_cr_lrps.get(cr_lrp_port)
        for subnet_cidr in local_cr_lrp_info['subnets_cidr']:
            self._withdraw_lrp_port(subnet_cidr, None, cr_lrp_port)

        # check if there are loadbalancers associated to the router,
        # and if so delete the needed routes/rules
        ovn_lb_vips = self.ovn_local_cr_lrps[cr_lrp_port][
            'ovn_lb_vips'].copy()
        for ovn_lb_vip in ovn_lb_vips:
            self._withdraw_ovn_lb_on_provider(ovn_lb_vip, cr_lrp_port)
            self.ovn_local_cr_lrps[cr_lrp_port]['ovn_lb_vips'].remove(
                ovn_lb_vip)
        try:
            del self.ovn_local_cr_lrps[cr_lrp_port]
        except KeyError:
            LOG.debug("Gateway port %s already cleanup from the agent.",
                      cr_lrp_port)

    def _expose_lrp_port(self, ip, lrp, associated_cr_lrp, subnet_datapath,
                         exposed_ips=[], ovn_ip_rules={}):
        if not self._expose_tenant_networks:
            return
        if not CONF.expose_tenant_networks:
            # This means CONF.expose_ipv6_gua_tenant_networks is enabled
            if not driver_utils.is_ipv6_gua(ip):
                return
        cr_lrp_info = self.ovn_local_cr_lrps.get(associated_cr_lrp, {})
        cr_lrp_ips = [ip_address.split('/')[0]
                      for ip_address in cr_lrp_info.get('ips', [])]

        # this is the router gateway port
        if ip.split('/')[0] in cr_lrp_ips:
            return

        cr_lrp_datapath = cr_lrp_info.get('provider_datapath')
        if not cr_lrp_datapath:
            return

        bridge_device = cr_lrp_info.get('bridge_device')
        bridge_vlan = cr_lrp_info.get('bridge_vlan')

        # update information needed for the loadbalancers
        self.ovn_local_cr_lrps[associated_cr_lrp]['subnets_datapath'].update(
            {lrp: subnet_datapath})
        self.ovn_local_cr_lrps[associated_cr_lrp]['subnets_cidr'].append(ip)
        self.ovn_local_lrps.update({lrp: associated_cr_lrp})

        LOG.debug("Adding IP Rules for network %s on chassis %s", ip,
                  self.chassis)
        try:
            linux_net.add_ip_rule(
                ip, self.ovn_routing_tables[bridge_device], bridge_device)
        except agent_exc.InvalidPortIP:
            LOG.exception("Invalid IP to create a rule for the "
                          "lrp (network router interface) port: %s", ip)
            return
        LOG.debug("Added IP Rules for network %s on chassis %s", ip,
                  self.chassis)
        if ovn_ip_rules:
            ovn_ip_rules.pop(ip, None)

        LOG.debug("Adding IP Routes for network %s on chassis %s", ip,
                  self.chassis)
        # NOTE(ltomasbo): This assumes the provider network can only have
        # (at most) 2 subnets, one for IPv4, one for IPv6
        ip_version = linux_net.get_ip_version(ip)
        for cr_lrp_ip in cr_lrp_ips:
            if linux_net.get_ip_version(cr_lrp_ip) == ip_version:
                linux_net.add_ip_route(
                    self.ovn_routing_tables_routes,
                    ip.split("/")[0],
                    self.ovn_routing_tables[bridge_device],
                    bridge_device,
                    vlan=bridge_vlan,
                    mask=ip.split("/")[1],
                    via=cr_lrp_ip)
                break
        LOG.debug("Added IP Routes for network %s on chassis %s", ip,
                  self.chassis)

        # Check if there are VMs on the network
        # and if so expose the route
        ports = self.sb_idl.get_ports_on_datapath(subnet_datapath)
        for port in ports:
            self._expose_tenant_port(port, ip_version=ip_version,
                                     exposed_ips=exposed_ips,
                                     ovn_ip_rules=ovn_ip_rules)

    def _withdraw_lrp_port(self, ip, lrp, associated_cr_lrp):
        if not self._expose_tenant_networks:
            return
        if not CONF.expose_tenant_networks:
            # This means CONF.expose_ipv6_gua_tenant_networks is enabled
            if not driver_utils.is_ipv6_gua(ip):
                return
        cr_lrp_info = self.ovn_local_cr_lrps.get(associated_cr_lrp, {})

        LOG.debug("Deleting IP Rules for network %s on chassis %s", ip,
                  self.chassis)
        exposed_lrp = False
        if lrp:
            if lrp in self.ovn_local_lrps.keys():
                exposed_lrp = True
                self.ovn_local_lrps.pop(lrp)
        else:
            for subnet_lp in cr_lrp_info['subnets_datapath'].keys():
                if subnet_lp in self.ovn_local_lrps.keys():
                    exposed_lrp = True
                    self.ovn_local_lrps.pop(subnet_lp)
                    break
        self.ovn_local_cr_lrps[associated_cr_lrp]['subnets_datapath'].pop(
            lrp, None)
        if not exposed_lrp:
            return

        cr_lrp_ips = [ip_address.split('/')[0]
                      for ip_address in cr_lrp_info.get('ips', [])]
        bridge_device = self.ovn_local_cr_lrps[associated_cr_lrp].get(
            'bridge_device')
        bridge_vlan = self.ovn_local_cr_lrps[associated_cr_lrp].get(
            'bridge_vlan')

        linux_net.del_ip_rule(ip, self.ovn_routing_tables[bridge_device],
                              bridge_device)
        LOG.debug("Deleted IP Rules for network %s on chassis %s", ip,
                  self.chassis)

        LOG.debug("Deleting IP Routes for network %s on chassis %s", ip,
                  self.chassis)
        ip_version = linux_net.get_ip_version(ip)
        for cr_lrp_ip in cr_lrp_ips:
            if linux_net.get_ip_version(cr_lrp_ip) == ip_version:
                linux_net.del_ip_route(
                    self.ovn_routing_tables_routes,
                    ip.split("/")[0],
                    self.ovn_routing_tables[bridge_device],
                    bridge_device,
                    vlan=bridge_vlan,
                    mask=ip.split("/")[1],
                    via=cr_lrp_ip)
                if (linux_net.get_ip_version(cr_lrp_ip) ==
                        constants.IP_VERSION_6):
                    net = ipaddress.IPv6Network(ip, strict=False)
                else:
                    net = ipaddress.IPv4Network(ip, strict=False)
                break
        LOG.debug("Deleted IP Routes for network %s on chassis %s", ip,
                  self.chassis)

        # Check if there are VMs on the network
        # and if so withdraw the routes
        if net:
            vms_on_net = linux_net.get_exposed_ips_on_network(
                CONF.bgp_nic, net)
            linux_net.delete_exposed_ips(vms_on_net, CONF.bgp_nic)

    @lockutils.synchronized('bgp')
    def expose_subnet(self, ip, row):
        cr_lrp = self.sb_idl.is_router_gateway_on_chassis(
            row.datapath, self.chassis)
        subnet_datapath = self.sb_idl.get_port_datapath(
            row.options['peer'])

        if not cr_lrp:
            return

        if not self._address_scope_allowed(ip, row.options['peer']):
            return

        self._expose_lrp_port(ip, row.logical_port, cr_lrp, subnet_datapath)

    @lockutils.synchronized('bgp')
    def withdraw_subnet(self, ip, row):
        try:
            cr_lrp = self.sb_idl.is_router_gateway_on_chassis(
                row.datapath, self.chassis)
        except ValueError:
            # NOTE(ltomasbo): This happens when the router (datapath) gets
            # deleted at the same time as subnets are detached from it.
            # Usually this will be hit when router is deleted without
            # removing its gateway. In that case we don't need to withdraw
            # the subnet as it is not exposed, just the cr-lrp which is
            # handle in a different event/method (withdraw_ip)
            LOG.debug("Router is being deleted, so it's datapath does "
                      "not exists any more. Checking if port %s belongs "
                      "to chassis redirect and skip in that case.",
                      row.logical_port)
            cr_lrp = [cr_lrp_name
                      for cr_lrp_name in self.ovn_local_cr_lrps.keys()
                      if row.logical_port in cr_lrp_name]
            # if cr_lrp exists, this means the lrp port is for the router
            # gateway, so there is no need to proceed
            if cr_lrp:
                LOG.debug("Port %s is related to chassis redirect, so "
                          "there is no need to do further actions for "
                          "subnet withdrawal, as this port was not "
                          "triggering a subnet exposure.",
                          row.logical_port)
                return
        if not cr_lrp:
            return

        self._withdraw_lrp_port(ip, row.logical_port, cr_lrp)

    def _address_scope_allowed(self, ip, port_name, sb_port=None):
        if not self.allowed_address_scopes:
            # No address scopes to filter on => announce everything
            return True

        if not sb_port:
            sb_port = self.sb_idl.get_port_by_name(port_name)
        if not sb_port:
            LOG.error("Port %s missing, skipping.", port_name)
            return False
        address_scopes = driver_utils.get_addr_scopes(sb_port)

        # if we should filter on address scopes and this port has no
        # address scopes set we do not need to expose it
        if not any(address_scopes.values()):
            return False
        # if address scope does not match, no need to expose it
        ip_version = linux_net.get_ip_version(ip)

        return address_scopes[ip_version] in self.allowed_address_scopes

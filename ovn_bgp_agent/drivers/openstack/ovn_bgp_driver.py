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
import threading

from oslo_concurrency import lockutils
from oslo_config import cfg
from oslo_log import log as logging

from ovn_bgp_agent import constants
from ovn_bgp_agent.drivers import driver_api
from ovn_bgp_agent.drivers.openstack.utils import bgp as bgp_utils
from ovn_bgp_agent.drivers.openstack.utils import driver_utils
from ovn_bgp_agent.drivers.openstack.utils import ovn
from ovn_bgp_agent.drivers.openstack.utils import ovs
from ovn_bgp_agent.drivers.openstack.utils import wire as wire_utils
from ovn_bgp_agent.drivers.openstack.watchers import bgp_watcher as watcher
from ovn_bgp_agent import exceptions as agent_exc
from ovn_bgp_agent.utils import helpers
from ovn_bgp_agent.utils import linux_net


CONF = cfg.CONF
LOG = logging.getLogger(__name__)
# LOG.setLevel(logging.DEBUG)
# logging.basicConfig(level=logging.DEBUG)

OVN_TABLES = ["Port_Binding", "Chassis", "Datapath_Binding", "Load_Balancer",
              "Chassis_Private", "Logical_DP_Group"]


class OVNBGPDriver(driver_api.AgentDriverBase):

    def __init__(self):
        self._expose_tenant_networks = (CONF.expose_tenant_networks or
                                        CONF.expose_ipv6_gua_tenant_networks)
        self.allowed_address_scopes = set(CONF.address_scopes or [])
        self.ovn_routing_tables = {}  # {'br-ex': 200}
        self.ovn_bridge_mappings = {}  # {'public': 'br-ex'}
        self.ovs_flows = {}
        self.ovn_local_cr_lrps = {}
        self.ovn_local_lrps = {}
        # {'br-ex': [route1, route2]}
        self.ovn_routing_tables_routes = collections.defaultdict()
        # {ovn_lb: {'ips': [VIP1, VIP2], 'gateway_port': cr-lrpX}
        self.provider_ovn_lbs = collections.defaultdict()
        # {datapath: localnet_port_name}
        self.ovn_provider_datapath = {}

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
        self.chassis = self.ovs_idl.get_own_chassis_id()
        self.ovn_remote = self.ovs_idl.get_ovn_remote()
        LOG.info("Loaded chassis %s.", self.chassis)

        LOG.info("Starting VRF configuration for advertising routes")
        # Base BGP configuration
        bgp_utils.ensure_base_bgp_configuration()

        # Clear vrf routing table
        if CONF.clear_vrf_routes_on_startup:
            linux_net.delete_routes_from_table(CONF.bgp_vrf_table_id)

        LOG.info("VRF configuration for advertising routes completed")
        if self._expose_tenant_networks and self.allowed_address_scopes:
            LOG.info("Configured allowed address scopes: %s",
                     ", ".join(self.allowed_address_scopes))

        self._post_fork_event.clear()

        events = self._get_events()
        self.sb_idl = ovn.OvnSbIdl(
            self.ovn_remote,
            chassis=self.chassis,
            tables=OVN_TABLES,
            events=events).start()

        # Now IDL connections can be safely used
        self._post_fork_event.set()

    def _get_events(self):
        events = {watcher.PortBindingChassisCreatedEvent(self),
                  watcher.PortBindingChassisDeletedEvent(self),
                  watcher.FIPSetEvent(self),
                  watcher.FIPUnsetEvent(self),
                  watcher.OVNLBMemberCreateEvent(self),
                  watcher.OVNLBMemberDeleteEvent(self),
                  watcher.ChassisCreateEvent(self),
                  watcher.ChassisPrivateCreateEvent(self),
                  watcher.LocalnetCreateDeleteEvent(self)}
        if self._expose_tenant_networks:
            events.update({watcher.SubnetRouterAttachedEvent(self),
                           watcher.SubnetRouterDetachedEvent(self),
                           watcher.TenantPortCreatedEvent(self),
                           watcher.TenantPortDeletedEvent(self),
                           watcher.OVNLBVIPPortEvent(self)})
        return events

    @lockutils.synchronized('bgp')
    def frr_sync(self):
        LOG.debug("Ensuring VRF configuration for advertising routes")
        # Base BGP configuration
        bgp_utils.ensure_base_bgp_configuration()

    @lockutils.synchronized('bgp')
    def sync(self):
        self._expose_tenant_networks = (CONF.expose_tenant_networks or
                                        CONF.expose_ipv6_gua_tenant_networks)
        self.ovn_routing_tables = {}
        self.ovn_bridge_mappings = {}
        self.ovn_local_cr_lrps = {}
        self.ovn_local_lrps = {}
        self.ovn_routing_tables_routes = collections.defaultdict()
        self.provider_ovn_lbs = collections.defaultdict()
        self.ovs_flows = {}

        LOG.debug("Configuring br-ex default rule and routing tables for "
                  "each provider network")
        # 1) Get bridge mappings: xxxx:br-ex,yyyy:br-ex2
        bridge_mappings = self.ovs_idl.get_ovn_bridge_mappings()
        # 2) Get macs for bridge mappings
        extra_routes = {}

        for bridge_index, bridge_mapping in enumerate(bridge_mappings, 1):
            network, bridge = helpers.parse_bridge_mapping(bridge_mapping)
            if not network:
                continue
            self.ovn_bridge_mappings[network] = bridge

            if not extra_routes.get(bridge):
                extra_routes[bridge] = (
                    linux_net.ensure_routing_table_for_bridge(
                        self.ovn_routing_tables, bridge,
                        CONF.bgp_vrf_table_id))
            vlan_tags = self.sb_idl.get_network_vlan_tag_by_network_name(
                network)

            for vlan_tag in vlan_tags:
                linux_net.ensure_vlan_device_for_network(bridge,
                                                         vlan_tag)

            linux_net.ensure_arp_ndp_enabled_for_bridge(bridge,
                                                        bridge_index,
                                                        vlan_tags)

            if self.ovs_flows.get(bridge):
                continue

            mac = linux_net.get_interface_address(bridge)
            self.ovs_flows[bridge] = {
                'mac': mac,
                'in_port': set([])}
            # 3) Get in_port for bridge mappings (br-ex, br-ex2)
            self.ovs_flows[bridge]['in_port'] = (
                ovs.get_ovs_patch_ports_info(bridge))

            # 4) Add/Remove flows for each bridge mappings
            ovs.ensure_mac_tweak_flows(bridge,
                                       self.ovs_flows[bridge]['mac'],
                                       self.ovs_flows[bridge]['in_port'],
                                       constants.OVS_RULE_COOKIE)
            ovs.remove_extra_ovs_flows(self.ovs_flows, bridge,
                                       constants.OVS_RULE_COOKIE)

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
            provider_ovn_lbs = self.sb_idl.get_provider_ovn_lbs_on_cr_lrp(
                cr_lrp_info['provider_datapath'],
                cr_lrp_info['router_datapath'])
            for ovn_lb, ovn_lb_ip in provider_ovn_lbs.items():
                self._expose_ovn_lb_on_provider(ovn_lb_ip,
                                                ovn_lb,
                                                cr_lrp_port,
                                                exposed_ips,
                                                ovn_ip_rules)

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

        wire_utils.delete_vlan_devices_leftovers(self.sb_idl,
                                                 self.ovn_bridge_mappings)

    def _ensure_cr_lrp_associated_ports_exposed(self, cr_lrp_port,
                                                exposed_ips, ovn_ip_rules):
        ips, patch_port_row = self.sb_idl.get_cr_lrp_nat_addresses_info(
            cr_lrp_port, self.chassis, self.sb_idl)
        if not ips:
            return
        ips_adv = self._expose_ip(ips, patch_port_row,
                                  associated_port=cr_lrp_port)
        for ip in ips_adv:
            if exposed_ips and ip in exposed_ips:
                exposed_ips.remove(ip)
            if ovn_ip_rules:
                ip_version = linux_net.get_ip_version(ip)
                if ip_version == constants.IP_VERSION_6:
                    ip_dst = "{}/128".format(ip)
                else:
                    ip_dst = "{}/32".format(ip)
                ovn_ip_rules.pop(ip_dst, None)

    def _ensure_port_exposed(self, port, exposed_ips, ovn_ip_rules):
        if port.type not in constants.OVN_VIF_PORT_TYPES or not port.mac:
            return

        port_ips = []
        if port.mac == ['unknown']:
            # For FIPs associated to VM ports we don't need the port IP, so
            # we can check if it is a VM on the provider and trigger the
            # expose_ip without passing any port_ips
            try:
                if ((port.type != constants.OVN_VM_VIF_PORT_TYPE and
                        port.type != constants.OVN_VIRTUAL_VIF_PORT_TYPE) or
                        self.sb_idl.is_provider_network(port.datapath)):
                    return
            except agent_exc.DatapathNotFound:
                # There is no need to expose anything related to a removed
                # datapath
                LOG.debug("Port %s not being exposed as its datapath %s was "
                          "removed", port.logical_port, port.datapath)
                return
        else:
            if len(port.mac[0].strip().split(' ')) < 2:
                return
            port_ips = port.mac[0].strip().split(' ')[1:]

        ips_adv = self._expose_ip(port_ips, port)

        for port_ip in ips_adv:
            ip_address = port_ip.split("/")[0]
            if exposed_ips and ip_address in exposed_ips:
                # remove each ip to add from the list of current ips on dev OVN
                exposed_ips.remove(ip_address)
            if ovn_ip_rules:
                ip_version = linux_net.get_ip_version(port_ip)
                if ip_version == constants.IP_VERSION_6:
                    ip_dst = "{}/128".format(ip_address)
                else:
                    ip_dst = "{}/32".format(ip_address)
                ovn_ip_rules.pop(ip_dst, None)

    def _expose_provider_port(self, port_ips, provider_datapath,
                              bridge_device=None, bridge_vlan=None,
                              lladdr=None, proxy_cidrs=None):
        if proxy_cidrs is None:
            proxy_cidrs = []
        if not bridge_device and not bridge_vlan:
            bridge_device, bridge_vlan = self._get_bridge_for_datapath(
                provider_datapath)
        if (not bridge_device or
                bridge_device not in self.ovn_bridge_mappings.values()):
            return False

        localnet = self.ovn_provider_datapath.get(provider_datapath)
        if not localnet:
            try:
                localnet = self.sb_idl.get_localnet_for_datapath(
                    provider_datapath)
                if localnet:
                    self.ovn_provider_datapath[provider_datapath] = localnet
                else:
                    LOG.warning("%s is not a provider network as it does not"
                                "have a localnet port, no need to expose the"
                                "ips %s", provider_datapath, port_ips)
                    return False
            except agent_exc.DatapathNotFound:
                LOG.exception("Provider network not found, no need to expose "
                              "ips %s", port_ips)
                return False

        # Connect to OVN
        try:
            if wire_utils.wire_provider_port(
                    self.ovn_routing_tables_routes, self.ovs_flows, port_ips,
                    bridge_device, bridge_vlan, localnet,
                    self.ovn_routing_tables, proxy_cidrs, lladdr=lladdr):
                # Expose the IP now that it is connected
                bgp_utils.announce_ips(port_ips)
                return True
            return False
        except Exception as e:
            LOG.exception("Unexpected exception while wiring provider port: "
                          "%s", e)
            return False

    def _expose_tenant_port(self, port, ip_version, exposed_ips=None,
                            ovn_ip_rules=None):
        # specific case for ovn-lb vips on tenant networks
        if not port.mac and not port.chassis and not port.up[0]:
            ext_n_cidr = port.external_ids.get(
                constants.OVN_CIDRS_EXT_ID_KEY, "")
            if ext_n_cidr:
                ovn_lb_ip = ext_n_cidr.split(" ")[0].split("/")[0]
                bgp_utils.announce_ips([ovn_lb_ip])
                if exposed_ips and ovn_lb_ip in exposed_ips:
                    exposed_ips.remove(ovn_lb_ip)
                if ovn_ip_rules:
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
                n_cidrs = port.external_ids.get(constants.OVN_CIDRS_EXT_ID_KEY,
                                                "")
                port_ips = [ip.split("/")[0] for ip in n_cidrs.split(" ")]
            else:
                port_ips = port.mac[0].strip().split(' ')[1:]
        except IndexError:
            return

        for port_ip in port_ips:
            # Only adding the port ips that match the lrp
            # IP version
            port_ip_version = linux_net.get_ip_version(port_ip)
            if port_ip_version == ip_version:
                bgp_utils.announce_ips([port_ip])
                if exposed_ips and port_ip in exposed_ips:
                    exposed_ips.remove(port_ip)
                if ovn_ip_rules:
                    if port_ip_version == constants.IP_VERSION_6:
                        ip_dst = "{}/128".format(port_ip)
                    else:
                        ip_dst = "{}/32".format(port_ip)
                    ovn_ip_rules.pop(ip_dst, None)

    def _withdraw_provider_port(self, port_ips, provider_datapath,
                                bridge_device=None, bridge_vlan=None,
                                lladdr=None, proxy_cidrs=None):
        if proxy_cidrs is None:
            proxy_cidrs = []
        # Withdraw IP before disconnecting it
        bgp_utils.withdraw_ips(port_ips)

        # Disconnect IP from OVN
        # assuming either you pass both or none
        if not bridge_device and not bridge_vlan:
            bridge_device, bridge_vlan = self._get_bridge_for_datapath(
                provider_datapath)
            if not bridge_device:
                return False
        try:
            return wire_utils.unwire_provider_port(
                self.ovn_routing_tables_routes, port_ips, bridge_device,
                bridge_vlan, self.ovn_routing_tables, proxy_cidrs,
                lladdr=lladdr)
        except Exception as e:
            LOG.exception("Unexpected exception while unwiring provider port: "
                          "%s", e)
            return False

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
        try:
            if (not self._expose_tenant_networks or
                    self.sb_idl.is_provider_network(row.datapath)):
                return
        except agent_exc.DatapathNotFound:
            # There is no need to expose anything related to a removed
            # datapath
            LOG.debug("LoadBalancer with VIP %s not being exposed/withdraw as"
                      " its associated datapath %s was removed", ip,
                      row.datapath)
            return
        if action == constants.EXPOSE:
            return self._expose_remote_ip([ip], row)
        if action == constants.WITHDRAW:
            return self._withdraw_remote_ip([ip], row)
        # if unknown action return
        return

    @lockutils.synchronized('bgp')
    def expose_ovn_lb_on_provider(self, ip, lb_name, cr_lrp_port):
        self._expose_ovn_lb_on_provider(ip, lb_name, cr_lrp_port)

    @lockutils.synchronized('bgp')
    def withdraw_ovn_lb_on_provider(self, lb_name, cr_lrp_port):
        self._withdraw_ovn_lb_on_provider(lb_name, cr_lrp_port)

    def _expose_ovn_lb_on_provider(self, ip, lb_name, cr_lrp,
                                   exposed_ips=None, ovn_ip_rules=None):
        LOG.debug("Adding BGP route for loadbalancer VIP %s", ip)
        try:
            bridge_device = self.ovn_local_cr_lrps[cr_lrp]['bridge_device']
            bridge_vlan = self.ovn_local_cr_lrps[cr_lrp]['bridge_vlan']
        except KeyError:
            LOG.debug("Failure adding BGP route for loadbalancer VIP %s", ip)
            return False

        self.ovn_local_cr_lrps[cr_lrp]['provider_ovn_lbs'].append(lb_name)
        if self.provider_ovn_lbs.get(lb_name):
            self.provider_ovn_lbs[lb_name]['ips'].append(ip)
        else:
            self.provider_ovn_lbs[lb_name] = {'ips': [ip],
                                              'gateway_port': cr_lrp}
        if not self._expose_provider_port(
                [ip], self.ovn_local_cr_lrps[cr_lrp]['provider_datapath'],
                bridge_device=bridge_device, bridge_vlan=bridge_vlan):
            LOG.debug("Failure adding BGP route for loadbalancer VIP %s", ip)
            return False
        LOG.debug("Added BGP route for loadbalancer VIP %s", ip)
        if exposed_ips and ip in exposed_ips:
            exposed_ips.remove(ip)
        if ovn_ip_rules:
            ip_version = linux_net.get_ip_version(ip)
            if ip_version == constants.IP_VERSION_6:
                ip_dst = "{}/128".format(ip)
            else:
                ip_dst = "{}/32".format(ip)
            ovn_ip_rules.pop(ip_dst, None)
        return True

    def _withdraw_ovn_lb_on_provider(self, lb_name, cr_lrp):
        try:
            bridge_device = self.ovn_local_cr_lrps[cr_lrp]['bridge_device']
            bridge_vlan = self.ovn_local_cr_lrps[cr_lrp]['bridge_vlan']
        except KeyError:
            LOG.debug("Failure deleting BGP routes for loadbalancer VIPs "
                      "%s", self.provider_ovn_lbs[lb_name].get('ips'))
            return False

        for ip in self.provider_ovn_lbs[lb_name].get('ips').copy():
            LOG.debug("Deleting BGP route for loadbalancer VIP %s", ip)
            if not self._withdraw_provider_port(
                    [ip], None, bridge_device=bridge_device,
                    bridge_vlan=bridge_vlan):
                LOG.debug("Failure deleting BGP route for loadbalancer VIP "
                          "%s", ip)
                return False
            if ip in self.provider_ovn_lbs[lb_name].get('ips', []):
                self.provider_ovn_lbs[lb_name]['ips'].remove(ip)
            LOG.debug("Deleted BGP route for loadbalancer VIP %s", ip)
        if lb_name in self.ovn_local_cr_lrps[cr_lrp]['provider_ovn_lbs']:
            self.ovn_local_cr_lrps[cr_lrp]['provider_ovn_lbs'].remove(
                lb_name)
        return True

    @lockutils.synchronized('bgp')
    def expose_ip(self, ips, row, associated_port=None):
        '''Advertice BGP route by adding IP to device.

        This methods ensures BGP advertises the IP of the VM in the provider
        network, or the FIP associated to a VM in a tenant networks.

        It relies on Zebra, which creates and advertises a route when an IP
        is added to a local interface.

        This method assumes a device named self.ovn_device exists (inside a
        VRF), and adds the IP of either:
        - VM IP on the provider network,
        - VM FIP, or
        - CR-LRP OVN port
        '''
        self._expose_ip(ips, row, associated_port)

    def _expose_ip(self, ips, row, associated_port=None):
        if (row.type == constants.OVN_VM_VIF_PORT_TYPE or
                row.type == constants.OVN_VIRTUAL_VIF_PORT_TYPE):
            try:
                provider_network = self.sb_idl.is_provider_network(
                    row.datapath)
            except agent_exc.DatapathNotFound:
                # There is no need to expose anything related to a removed
                # datapath
                LOG.debug("Port %s not being exposed as its associated "
                          "datapath %s was removed", row.logical_port,
                          row.datapath)
                return []
            # VM on provider Network
            if provider_network:
                exposed_port = False
                LOG.debug("Adding BGP route for logical port with ip %s", ips)
                if row.type == constants.OVN_VIRTUAL_VIF_PORT_TYPE:
                    # NOTE: For Amphora Load Balancer with IPv6 VIP on the
                    # provider network, we need a NDP Proxy so that the
                    # traffic from the amphora can properly be redirected back
                    bridge_device, bridge_vlan = self._get_bridge_for_datapath(
                        row.datapath)
                    # NOTE: This is neutron specific as we need the provider
                    # prefix to add the ndp proxy
                    n_cidr = row.external_ids.get(
                        constants.OVN_CIDRS_EXT_ID_KEY, "").split()
                    exposed_port = self._expose_provider_port(
                        ips, row.datapath, bridge_device, bridge_vlan, None,
                        n_cidr)
                else:
                    exposed_port = self._expose_provider_port(ips,
                                                              row.datapath)
                if not exposed_port:
                    LOG.debug("Failure adding BGP route for logical port with "
                              "ip %s", ips)
                    return []
                LOG.debug("Added BGP route for logical port with ip %s", ips)
                return ips
            # VM with FIP
            else:
                # FIPs are only supported with IPv4
                fip_address, fip_datapath = self.sb_idl.get_fip_associated(
                    row.logical_port)

                if not fip_address:
                    return []
                if not self.sb_idl.is_provider_network(fip_datapath):
                    # Only exposing IPs if the associated network is a
                    # provider network
                    return []
                LOG.debug("Adding BGP route for FIP with ip %s", fip_address)
                if self._expose_provider_port([fip_address], fip_datapath):
                    LOG.debug("Added BGP route for FIP with ip %s",
                              fip_address)
                    return [fip_address]
                LOG.debug("Failure adding BGP route for FIP with ip %s",
                          fip_address)
                return []

        # FIP association to VM
        elif row.type == constants.OVN_PATCH_VIF_PORT_TYPE:
            if (associated_port and self.sb_idl.is_port_on_chassis(
                    associated_port, self.chassis)):
                if not self.sb_idl.is_provider_network(row.datapath):
                    # Only exposing IPs if the associated network is a
                    # provider network
                    return []
                LOG.debug("Adding BGP route for FIP with ip %s", ips)
                if self._expose_provider_port(ips, row.datapath):
                    LOG.debug("Added BGP route for FIP with ip %s", ips)
                    return ips
                LOG.debug("Failure adding BGP route for FIP with ip %s", ips)
                return []

        # CR-LRP Port
        elif (row.type == constants.OVN_CHASSISREDIRECT_VIF_PORT_TYPE and
              row.logical_port.startswith('cr-')):
            cr_lrp_datapath = self.sb_idl.get_provider_datapath_from_cr_lrp(
                row.logical_port)
            if not cr_lrp_datapath:
                return []
            if not self.sb_idl.is_provider_network(cr_lrp_datapath):
                # Only exposing IPs if the associated network is a
                # provider network
                return []

            bridge_device, bridge_vlan = self._get_bridge_for_datapath(
                cr_lrp_datapath)
            mac = row.mac[0].strip().split(' ')[0]
            # Keeping information about the associated network for
            # tenant network advertisement
            self.ovn_local_cr_lrps[row.logical_port] = {
                'router_datapath': row.datapath,
                'provider_datapath': cr_lrp_datapath,
                'ips': ips,
                'mac': mac,
                'subnets_datapath': {},
                'subnets_cidr': [],
                'provider_ovn_lbs': [],
                'bridge_vlan': bridge_vlan,
                'bridge_device': bridge_device
            }

            if self._expose_cr_lrp_port(ips, mac, bridge_device, bridge_vlan,
                                        router_datapath=row.datapath,
                                        provider_datapath=cr_lrp_datapath,
                                        cr_lrp_port=row.logical_port):
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

        This method assumes a device named self.ovn_device exists (inside a
        VRF), and removes the IP of either:
        - VM IP on the provider network,
        - VM FIP, or
        - CR-LRP OVN port
        '''
        if (row.type == constants.OVN_VM_VIF_PORT_TYPE or
                row.type == constants.OVN_VIRTUAL_VIF_PORT_TYPE):
            try:
                provider_network = self.sb_idl.is_provider_network(
                    row.datapath)
            except agent_exc.DatapathNotFound:
                # NOTE(ltomasbo): Datapath has been deleted. This means that:
                # - If it was a provider network we need to withdraw it
                # - It it was a VM with a FIP, the removal would be handled
                #   by the FIP dissassociation even (FIP removal) that must
                #   happen before removing the subnet from the router, and
                #   before being able to remove the subnet
                # This means we only need to process the "provider_network"
                # case
                provider_network = True
                LOG.debug("Port %s belongs to a removed datapath %s. "
                          "Assuming it was a provider network to avoid "
                          "leaks.", row.logical_port, row.datapath)
            # VM on provider Network
            if provider_network:
                LOG.debug("Deleting BGP route for logical port with ip %s",
                          ips)
                n_cidr = None
                withdrawn_port = False
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
                                constants.OVN_CIDRS_EXT_ID_KEY, "").split()
                if n_cidr:
                    withdrawn_port = self._withdraw_provider_port(
                        ips, row.datapath, bridge_device, bridge_vlan, None,
                        n_cidr)
                else:
                    withdrawn_port = self._withdraw_provider_port(ips,
                                                                  row.datapath)
                if not withdrawn_port:
                    LOG.debug("Failure deleting BGP route for logical port "
                              "with ip %s", ips)
                    return
                LOG.debug("Deleted BGP route for logical port with ip %s", ips)
                return
            # VM with FIP
            else:
                # FIPs are only supported with IPv4
                fip_address, fip_datapath = self.sb_idl.get_fip_associated(
                    row.logical_port)
                if not fip_address:
                    return
                if not self.sb_idl.is_provider_network(fip_datapath):
                    # Only exposing IPs if the associated network is a
                    # provider network
                    return
                LOG.debug("Deleting BGP route for FIP with ip %s", fip_address)
                if not self._withdraw_provider_port([fip_address],
                                                    fip_datapath):
                    LOG.debug("Failure deleting BGP route for FIP with ip %s",
                              fip_address)
                    return
                LOG.debug("Deleted BGP route for FIP with ip %s", fip_address)
                return

        # FIP disassociation to VM
        elif row.type == constants.OVN_PATCH_VIF_PORT_TYPE:
            if (associated_port and (
                    self.sb_idl.is_port_on_chassis(
                        associated_port, self.chassis) or
                    self.sb_idl.is_port_without_chassis(associated_port) or
                    self.sb_idl.is_port_deleted(associated_port))):
                if not self.sb_idl.is_provider_network(row.datapath):
                    # Only exposing IPs if the associated network is a
                    # provider network
                    return
                LOG.debug("Deleting BGP route for FIP with ip %s", ips)
                if not self._withdraw_provider_port(ips, row.datapath):
                    LOG.debug("Failure deleting BGP route for FIP with ip %s",
                              ips)
                    return
                LOG.debug("Deleted BGP route for FIP with ip %s", ips)
                return

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
            mac = row.mac[0].strip().split(' ')[0]
            self._withdraw_cr_lrp_port(ips, mac, bridge_device, bridge_vlan,
                                       provider_datapath=cr_lrp_datapath,
                                       cr_lrp_port=row.logical_port)

    @lockutils.synchronized('bgp')
    def expose_remote_ip(self, ips, row):
        self._expose_remote_ip(ips, row)

    def _expose_remote_ip(self, ips, row):
        try:
            if (self.sb_idl.is_provider_network(row.datapath) or
                    not self._expose_tenant_networks):
                return
        except agent_exc.DatapathNotFound:
            # There is no need to expose anything related to a removed
            # datapath
            LOG.debug("Port %s not being exposed as its datapath %s was "
                      "removed", row.logical_port, row.datapath)
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

        port_lrps = self.sb_idl.get_lrps_for_datapath(row.datapath)
        for port_lrp in port_lrps:
            if port_lrp in self.ovn_local_lrps.keys():
                LOG.debug("Adding BGP route for tenant IP %s on chassis %s",
                          ips_to_expose, self.chassis)
                bgp_utils.announce_ips(ips_to_expose)
                LOG.debug("Added BGP route for tenant IP %s on chassis %s",
                          ips_to_expose, self.chassis)
                break

    @lockutils.synchronized('bgp')
    def withdraw_remote_ip(self, ips, row, chassis=None):
        self._withdraw_remote_ip(ips, row, chassis)

    def _withdraw_remote_ip(self, ips, row, chassis=None):
        try:
            if (self.sb_idl.is_provider_network(row.datapath) or
                    not self._expose_tenant_networks):
                return
        except agent_exc.DatapathNotFound:
            # There is no need to continue as the subnet removal (patch port
            # removal) will trigger a withdraw_subnet event that will remove
            # the associated IPs
            LOG.debug("Port %s not being withdrawn as its datapath %s was "
                      "removed. The subnet withdraw action will take care of "
                      "the withdrawal.", row.logical_port, row.datapath)
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
        port_lrps = self.sb_idl.get_lrps_for_datapath(row.datapath)
        for port_lrp in port_lrps:
            if port_lrp in self.ovn_local_lrps.keys():
                LOG.debug("Deleting BGP route for tenant IP %s on chassis %s",
                          ips_to_withdraw, self.chassis)
                bgp_utils.withdraw_ips(ips_to_withdraw)
                LOG.debug("Deleted BGP route for tenant IP %s on chassis %s",
                          ips_to_withdraw, self.chassis)
                break

    def _process_lrp_port(self, lrp, associated_cr_lrp, exposed_ips=None,
                          ovn_ip_rules=None):
        if (lrp.chassis or
                not lrp.logical_port.startswith('lrp-') or
                "chassis-redirect-port" in lrp.options.keys() or
                associated_cr_lrp.strip('cr-') == lrp.logical_port):
            return
        # add missing route/ips for tenant network VMs
        if self._expose_tenant_networks:
            try:
                lrp_ip = lrp.mac[0].strip().split(' ')[1]
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
        if not self._expose_provider_port(ips_without_mask, provider_datapath,
                                          bridge_device, bridge_vlan,
                                          lladdr=mac, proxy_cidrs=ips):
            LOG.debug("Failure adding BGP route for CR-LRP Port %s", ips)
            return False
        LOG.debug("Added BGP route for CR-LRP Port %s", ips)

        # Expose FIPS
        # This is needed in case the router get disabled and enabled
        # In that case there may be FIPs already associated to VMs
        fips, patch_port_row = self.sb_idl.get_cr_lrp_nat_addresses_info(
            cr_lrp_port, self.chassis, self.sb_idl)
        fips = [ip for ip in fips if ip not in ips_without_mask]
        if fips:
            self._expose_ip(fips, patch_port_row, associated_port=cr_lrp_port)

        # Check if there are networks attached to the router,
        # and if so, add the needed routes/rules
        lrp_ports = self.sb_idl.get_lrp_ports_for_router(router_datapath)
        for lrp in lrp_ports:
            self._process_lrp_port(lrp, cr_lrp_port)

        cr_lrp_provider_dp = self.ovn_local_cr_lrps[cr_lrp_port][
            'provider_datapath']
        cr_lrp_router_dp = self.ovn_local_cr_lrps[cr_lrp_port][
            'router_datapath']
        provider_ovn_lbs = self.sb_idl.get_provider_ovn_lbs_on_cr_lrp(
            cr_lrp_provider_dp, cr_lrp_router_dp)
        for ovn_lb, ovn_lb_ip in provider_ovn_lbs.items():
            self._expose_ovn_lb_on_provider(ovn_lb_ip,
                                            ovn_lb,
                                            cr_lrp_port)
        return True

    def _withdraw_cr_lrp_port(self, ips, mac, bridge_device, bridge_vlan,
                              provider_datapath, cr_lrp_port):
        LOG.debug("Deleting BGP route for CR-LRP Port %s", ips)
        # Removing information about the associated network for
        # tenant network advertisement
        ips_without_mask = [ip.split("/")[0] for ip in ips]
        # del proxy ndp config for ipv6
        proxy_cidrs = []
        for ip in ips_without_mask:
            if linux_net.get_ip_version(ip) == constants.IP_VERSION_6:
                cr_lrps_on_same_provider = [
                    p for p in self.ovn_local_cr_lrps.values()
                    if p['provider_datapath'] == provider_datapath]
                # if no other cr-lrp port on the same provider
                # delete the ndp proxy
                if (len(cr_lrps_on_same_provider) <= 1):
                    proxy_cidrs.append(ip)

        if not self._withdraw_provider_port(
                ips_without_mask, provider_datapath,
                bridge_device=bridge_device, bridge_vlan=bridge_vlan,
                lladdr=mac, proxy_cidrs=proxy_cidrs):
            LOG.debug("Failure deleting BGP route for CR-LRP Port %s", ips)
            return False
        LOG.debug("Deleted BGP route for CR-LRP Port %s", ips)

        # Check if there are networks attached to the router,
        # and if so delete the needed routes/rules
        local_cr_lrp_info = self.ovn_local_cr_lrps.get(cr_lrp_port)
        for subnet_cidr in local_cr_lrp_info['subnets_cidr']:
            self._withdraw_lrp_port(subnet_cidr, None, cr_lrp_port)

        # check if there are loadbalancers associated to the router,
        # and if so delete the needed routes/rules
        provider_ovn_lbs = self.ovn_local_cr_lrps[cr_lrp_port][
            'provider_ovn_lbs'].copy()
        for provider_ovn_lb in provider_ovn_lbs:
            self._withdraw_ovn_lb_on_provider(provider_ovn_lb, cr_lrp_port)
        try:
            del self.ovn_local_cr_lrps[cr_lrp_port]
        except KeyError:
            LOG.debug("Gateway port %s already cleanup from the agent.",
                      cr_lrp_port)
        return True

    def _expose_lrp_port(self, ip, lrp, associated_cr_lrp, subnet_datapath,
                         exposed_ips=None, ovn_ip_rules=None):
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
        cr_lrp_info['subnets_datapath'].update({lrp: subnet_datapath})
        cr_lrp_info['subnets_cidr'].append(ip)
        self.ovn_local_lrps.update({lrp: associated_cr_lrp})

        try:
            if not wire_utils.wire_lrp_port(
                    self.ovn_routing_tables_routes, ip, bridge_device,
                    bridge_vlan, self.ovn_routing_tables, cr_lrp_ips):
                LOG.warning("Not able to expose subnet with IP %s", ip)
                return
        except Exception as e:
            LOG.exception("Unexpected exception while wiring lrp port: %s", e)
            return
        if ovn_ip_rules:
            ovn_ip_rules.pop(ip, None)

        # Check if there are VMs on the network
        # and if so expose the route
        ports = self.sb_idl.get_ports_on_datapath(subnet_datapath)
        ip_version = linux_net.get_ip_version(ip)
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
        cr_lrp_info['subnets_datapath'].pop(lrp, None)
        if not exposed_lrp:
            return

        cr_lrp_ips = [ip_address.split('/')[0]
                      for ip_address in cr_lrp_info.get('ips', [])]
        bridge_device = cr_lrp_info.get('bridge_device')
        bridge_vlan = cr_lrp_info.get('bridge_vlan')

        ip_version = linux_net.get_ip_version(ip)
        for cr_lrp_ip in cr_lrp_ips:
            cr_lrp_ip_version = linux_net.get_ip_version(cr_lrp_ip)
            if cr_lrp_ip_version != ip_version:
                continue
            if cr_lrp_ip_version == constants.IP_VERSION_6:
                net = ipaddress.IPv6Network(ip, strict=False)
            else:
                net = ipaddress.IPv4Network(ip, strict=False)
            break

        # Check if there are VMs on the network
        # and if so withdraw the routes
        if net:
            vms_on_net = linux_net.get_exposed_ips_on_network(
                CONF.bgp_nic, net)
            linux_net.delete_exposed_ips(vms_on_net, CONF.bgp_nic)

        # Disconnect the network to OVN
        try:
            wire_utils.unwire_lrp_port(
                self.ovn_routing_tables_routes, ip, bridge_device, bridge_vlan,
                self.ovn_routing_tables, cr_lrp_ips)
        except Exception as e:
            LOG.exception("Unexpected exception while unwiring lrp port: %s",
                          e)

    @lockutils.synchronized('bgp')
    def expose_subnet(self, ip, row):
        try:
            cr_lrp = self.sb_idl.is_router_gateway_on_chassis(
                row.datapath, self.chassis)
        except agent_exc.DatapathNotFound:
            # It seems it may also happen that router gets deleted before the
            # subnet attachment to it gets processed, and in that case there
            # is no need to expose anything
            return
        if not row.options.get('peer'):
            # if there is no peer associated to the port we need to
            # 1) creation: wait for another re-sync to expose it
            # 2) deletion: no need to add it as it being removed
            return
        subnet_datapath = self.sb_idl.get_port_datapath(
            row.options['peer'])

        if not cr_lrp or not self.ovn_local_cr_lrps.get(cr_lrp):
            return

        if not self._address_scope_allowed(ip, row.options['peer']):
            return

        self._expose_lrp_port(ip, row.logical_port, cr_lrp, subnet_datapath)

    @lockutils.synchronized('bgp')
    def withdraw_subnet(self, ip, row):
        try:
            cr_lrp = self.sb_idl.is_router_gateway_on_chassis(
                row.datapath, self.chassis)
        except agent_exc.DatapathNotFound:
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
        if not cr_lrp or not self.ovn_local_cr_lrps.get(cr_lrp):
            # NOTE(ltomasbo) there is a chance the cr-lrp just got moved
            # to this node but was not yet processed. In that case there
            # is no need to withdraw the network as it was not exposed here
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

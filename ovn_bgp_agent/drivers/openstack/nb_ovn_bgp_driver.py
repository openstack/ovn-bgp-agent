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

import collections
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
from ovn_bgp_agent.drivers.openstack.watchers import nb_bgp_watcher as watcher
from ovn_bgp_agent.utils import linux_net


CONF = cfg.CONF
LOG = logging.getLogger(__name__)
# LOG.setLevel(logging.DEBUG)
# logging.basicConfig(level=logging.DEBUG)

OVN_TABLES = ['Logical_Switch_Port', 'NAT', 'Logical_Switch',
              'Logical_Router_Port', 'Load_Balancer']
LOCAL_CLUSTER_OVN_TABLES = ['Logical_Switch', 'Logical_Switch_Port',
                            'Logical_Router', 'Logical_Router_Port',
                            'Logical_Router_Policy',
                            'Logical_Router_Static_Route', 'Gateway_Chassis',
                            'Static_MAC_Binding']


class NBOVNBGPDriver(driver_api.AgentDriverBase):

    def __init__(self):
        self._expose_tenant_networks = (CONF.expose_tenant_networks or
                                        CONF.expose_ipv6_gua_tenant_networks)
        self.allowed_address_scopes = set(CONF.address_scopes or [])

        self._init_vars()

        self._nb_idl = None
        self._local_nb_idl = None
        self._post_start_event = threading.Event()

    @property
    def nb_idl(self):
        if not self._nb_idl:
            self._post_start_event.wait()
        return self._nb_idl

    @property
    def local_nb_idl(self):
        if not self._local_nb_idl:
            self._post_start_event.wait()
        return self._local_nb_idl

    @nb_idl.setter
    def nb_idl(self, val):
        self._nb_idl = val

    @local_nb_idl.setter
    def local_nb_idl(self, val):
        self._local_nb_idl = val

    def _init_vars(self):
        self.ovn_bridge_mappings = {}  # {'public': 'br-ex'}
        self.ovs_flows = {}

        self.ovn_routing_tables = {}  # {'br-ex': 200}
        # {'br-ex': [route1, route2]}
        self.ovn_routing_tables_routes = collections.defaultdict()

        self.ovn_local_cr_lrps = {}
        self.ovn_local_lrps = {}

        # {'ls_name': ['ip': {'bridge_device': X, 'bridge_vlan': Y}]}
        self._exposed_ips = {}
        self._ovs_flows = collections.defaultdict()
        self.ovn_provider_ls = {}
        # dict instead of list to speed up look ups
        self.ovn_tenant_ls = {}  # {'ls_name': True}

    def start(self):
        self.ovs_idl = ovs.OvsIdl()
        self.ovs_idl.start(CONF.ovsdb_connection)
        self.chassis = self.ovs_idl.get_own_chassis_name()
        self.chassis_id = self.ovs_idl.get_own_chassis_id()

        # NOTE(ltomasbo): remote should point to NB DB port instead of SB DB,
        # so changing 6642 by 6641
        self.ovn_remote = self.ovs_idl.get_ovn_remote(nb=True)
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

        events = self._get_events()

        self._post_start_event.clear()
        self.nb_idl = ovn.OvnNbIdl(
            self.ovn_remote,
            tables=OVN_TABLES,
            events=events).start()

        # if local OVN cluster, gets an idl for it
        if CONF.exposing_method == constants.EXPOSE_METHOD_OVN:
            self.local_nb_idl = ovn.OvnNbIdl(
                CONF.local_ovn_cluster.ovn_nb_connection,
                tables=LOCAL_CLUSTER_OVN_TABLES,
                events=[],
                leader_only=True).start()

        # Now IDL connections can be safely used
        self._post_start_event.set()

    def _get_events(self):
        events = {watcher.LogicalSwitchPortProviderCreateEvent(self),
                  watcher.LogicalSwitchPortProviderDeleteEvent(self),
                  watcher.LogicalSwitchPortFIPCreateEvent(self),
                  watcher.LogicalSwitchPortFIPDeleteEvent(self),
                  watcher.LocalnetCreateDeleteEvent(self),
                  watcher.OVNLBCreateEvent(self),
                  watcher.OVNLBDeleteEvent(self)}
        if self._expose_tenant_networks:
            events.update({watcher.ChassisRedirectCreateEvent(self),
                           watcher.ChassisRedirectDeleteEvent(self),
                           watcher.LogicalSwitchPortSubnetAttachEvent(self),
                           watcher.LogicalSwitchPortSubnetDetachEvent(self),
                           watcher.LogicalSwitchPortTenantCreateEvent(self),
                           watcher.LogicalSwitchPortTenantDeleteEvent(self)})
        return events

    @lockutils.synchronized('nbbgp')
    def frr_sync(self):
        LOG.debug("Ensuring VRF configuration for advertising routes")
        # Base BGP configuration
        bgp_utils.ensure_base_bgp_configuration()

    @lockutils.synchronized('nbbgp')
    def sync(self):
        self._expose_tenant_networks = (CONF.expose_tenant_networks or
                                        CONF.expose_ipv6_gua_tenant_networks)
        self._init_vars()

        LOG.debug("Configuring default wiring for each provider network")
        # Apply base configuration for each bridge
        self.ovn_bridge_mappings, self.ovs_flows = (
            wire_utils.ensure_base_wiring_config(
                self.nb_idl, self.ovs_idl, ovn_idl=self.local_nb_idl,
                routing_tables=self.ovn_routing_tables))

        LOG.debug("Syncing current routes.")
        # add missing routes/ips for OVN router gateway ports
        ports = self.nb_idl.get_active_cr_lrp_on_chassis(self.chassis_id)
        for port in ports:
            self._ensure_crlrp_exposed(port)
        # add missing routes/ips for subnets connected to local gateway ports
        ports = self.nb_idl.get_active_local_lrps(
            self.ovn_local_cr_lrps.keys())
        for port in ports:
            ips = port.external_ids.get(constants.OVN_CIDRS_EXT_ID_KEY,
                                        "").split()
            subnet_info = {
                'associated_router': port.external_ids.get(
                    constants.OVN_DEVICE_ID_EXT_ID_KEY),
                'network': port.external_ids.get(
                    constants.OVN_LS_NAME_EXT_ID_KEY),
                'address_scopes': driver_utils.get_addr_scopes(port)}
            self._expose_subnet(ips, subnet_info)

        # add missing routes/ips for IPs on provider network
        ports = self.nb_idl.get_active_lsp_on_chassis(self.chassis)
        for port in ports:
            if port.type not in [constants.OVN_VM_VIF_PORT_TYPE,
                                 constants.OVN_VIRTUAL_VIF_PORT_TYPE]:
                continue
            self._ensure_lsp_exposed(port)

        # add missing routes/ips for OVN loadbalancers
        self._expose_lbs(self.ovn_local_cr_lrps.keys())

        # remove extra wiring leftovers
        wire_utils.cleanup_wiring(self.nb_idl,
                                  self.ovn_bridge_mappings,
                                  self.ovs_flows,
                                  self._exposed_ips,
                                  self.ovn_routing_tables,
                                  self.ovn_routing_tables_routes)

    def _ensure_lsp_exposed(self, port):
        port_fip = port.external_ids.get(constants.OVN_FIP_EXT_ID_KEY)
        if port_fip:
            external_ip, external_mac, ls_name = (
                self.get_port_external_ip_and_ls(port.name))
            if not external_ip or not ls_name:
                return
            return self._expose_fip(external_ip, external_mac, ls_name, port)

        logical_switch = port.external_ids.get(
            constants.OVN_LS_NAME_EXT_ID_KEY)
        if not logical_switch:
            return
        if self.ovn_tenant_ls.get(logical_switch):
            return

        bridge_info = self.ovn_provider_ls.get(logical_switch)
        if bridge_info:
            # already known provider ls
            bridge_device = bridge_info['bridge_device']
            bridge_vlan = bridge_info['bridge_vlan']
        else:
            localnet, bridge_device, bridge_vlan = self._get_ls_localnet_info(
                logical_switch)
            if not bridge_device:
                # This means it is not a provider network
                self.ovn_tenant_ls[logical_switch] = True
                return False
            if not self.ovn_provider_ls.get(logical_switch):
                self.ovn_provider_ls[logical_switch] = {
                    'bridge_device': bridge_device,
                    'bridge_vlan': bridge_vlan,
                    'localnet': localnet}
        ips = port.addresses[0].strip().split(' ')[1:]
        mac = port.addresses[0].strip().split(' ')[0]
        self._expose_ip(ips, mac, logical_switch, bridge_device, bridge_vlan,
                        port.type, port.external_ids.get(
                            constants.OVN_CIDRS_EXT_ID_KEY, "").split())

    def _ensure_crlrp_exposed(self, port):
        if not port.networks:
            return

        logical_switch = port.external_ids.get(
            constants.OVN_LS_NAME_EXT_ID_KEY)
        if not logical_switch:
            return
        localnet, bridge_device, bridge_vlan = self._get_ls_localnet_info(
            logical_switch)

        if not bridge_device:
            return

        self.ovn_provider_ls[logical_switch] = {
            'bridge_device': bridge_device,
            'bridge_vlan': bridge_vlan,
            'localnet': localnet}
        ips = [net.split("/")[0] for net in port.networks]
        router = port.external_ids.get(constants.OVN_LR_NAME_EXT_ID_KEY)
        self._expose_ip(ips, port.mac, logical_switch, bridge_device,
                        bridge_vlan, constants.OVN_CR_LRP_PORT_TYPE,
                        port.networks, router=router)

    def _expose_provider_port(self, port_ips, mac, logical_switch,
                              bridge_device, bridge_vlan, localnet,
                              proxy_cidrs=None):
        if proxy_cidrs is None:
            proxy_cidrs = []
        # Connect to OVN
        try:
            if wire_utils.wire_provider_port(
                    self.ovn_routing_tables_routes, self.ovs_flows, port_ips,
                    bridge_device, bridge_vlan, localnet,
                    self.ovn_routing_tables, proxy_cidrs, mac=mac,
                    ovn_idl=self.local_nb_idl):
                # Expose the IP now that it is connected
                bgp_utils.announce_ips(port_ips)
                for ip in port_ips:
                    self._exposed_ips.setdefault(logical_switch, {}).update(
                        {ip: {'bridge_device': bridge_device,
                              'bridge_vlan': bridge_vlan}})
        except Exception as e:
            LOG.exception("Unexpected exception while wiring provider port: "
                          "%s", e)
            return False
        return True

    def _withdraw_provider_port(self, port_ips, logical_switch, bridge_device,
                                bridge_vlan, proxy_cidrs=None):
        if proxy_cidrs is None:
            proxy_cidrs = []
        # Withdraw IP before disconnecting it
        bgp_utils.withdraw_ips(port_ips)

        # Disconnect IP from OVN
        try:
            wire_utils.unwire_provider_port(
                self.ovn_routing_tables_routes, port_ips, bridge_device,
                bridge_vlan, self.ovn_routing_tables, proxy_cidrs,
                ovn_idl=self.local_nb_idl)
        except Exception as e:
            LOG.exception("Unexpected exception while unwiring provider port: "
                          "%s", e)
        for ip in port_ips:
            if self._exposed_ips.get(logical_switch, {}).get(ip):
                self._exposed_ips[logical_switch].pop(ip)

    def _get_bridge_for_localnet_port(self, localnet):
        bridge_device = None
        bridge_vlan = None
        network_name = localnet.options.get('network_name')
        if network_name:
            bridge_device = self.ovn_bridge_mappings.get(network_name)
        if localnet.tag:
            bridge_vlan = localnet.tag[0]
        return bridge_device, bridge_vlan

    def _expose_lbs(self, router_list):
        lbs = self.nb_idl.get_active_local_lbs(router_list)
        for lb in lbs:
            self._expose_ovn_lb_vip(lb)
            # if vip-fip expose fip too
            if lb.external_ids.get(constants.OVN_LB_VIP_FIP_EXT_ID_KEY):
                self._expose_ovn_lb_fip(lb)

    def _withdraw_lbs(self, router_list):
        lbs = self.nb_idl.get_active_local_lbs(router_list)
        for lb in lbs:
            self._withdraw_ovn_lb_vip(lb)
            # if vip-fip withdraw fip too
            if lb.external_ids.get(constants.OVN_LB_VIP_FIP_EXT_ID_KEY):
                self._withdraw_ovn_lb_fip(lb)

    @lockutils.synchronized('nbbgp')
    def expose_ip(self, ips, ips_info):
        '''Advertice BGP route by adding IP to device.

        This methods ensures BGP advertises the IP of the VM in the provider
        network.
        It relies on Zebra, which creates and advertises a route when an IP
        is added to a local interface.

        This method assumes a device named self.ovn_device exists (inside a
        VRF), and adds the IP of:
        - VM IP on the provider network
        '''
        logical_switch = ips_info.get('logical_switch')
        if not logical_switch:
            return False

        bridge_info = self.ovn_provider_ls.get(logical_switch)
        if bridge_info:
            # already known provider ls
            bridge_device = bridge_info['bridge_device']
            bridge_vlan = bridge_info['bridge_vlan']
            localnet = bridge_info['localnet']
        else:
            localnet, bridge_device, bridge_vlan = self._get_ls_localnet_info(
                logical_switch)
            if not bridge_device:
                # This means it is not a provider network
                self.ovn_tenant_ls[logical_switch] = True
                return False
            if bridge_device not in self.ovn_bridge_mappings.values():
                # This node is not properly configured, no need to expose it
                return False
            if not self.ovn_provider_ls.get(logical_switch):
                self.ovn_provider_ls[logical_switch] = {
                    'bridge_device': bridge_device,
                    'bridge_vlan': bridge_vlan,
                    'localnet': localnet}
        mac = ips_info.get('mac')
        return self._expose_ip(ips, mac, logical_switch, bridge_device,
                               bridge_vlan, port_type=ips_info['type'],
                               cidrs=ips_info['cidrs'],
                               router=ips_info.get('router'))

    def _expose_ip(self, ips, mac, logical_switch, bridge_device, bridge_vlan,
                   port_type, cidrs, router=None):
        LOG.debug("Adding BGP route for logical port with ip %s", ips)
        localnet = self.ovn_provider_ls[logical_switch]['localnet']

        if not self._expose_provider_port(ips, mac, logical_switch,
                                          bridge_device, bridge_vlan,
                                          localnet, cidrs):
            return []

        if router and port_type == constants.OVN_CR_LRP_PORT_TYPE:
            # Store information about local CR-LRPs that will later be used
            # to expose networks
            self.ovn_local_cr_lrps[router] = {
                'bridge_device': bridge_device,
                'bridge_vlan': bridge_vlan,
                'provider_switch': logical_switch,
                'ips': ips,
            }
            # Expose associated subnets
            ports = self.nb_idl.get_active_local_lrps([router])
            for port in ports:
                ips = port.external_ids.get(constants.OVN_CIDRS_EXT_ID_KEY,
                                            "").split()
                subnet_info = {
                    'associated_router': port.external_ids.get(
                        constants.OVN_DEVICE_ID_EXT_ID_KEY),
                    'network': port.external_ids.get(
                        constants.OVN_LS_NAME_EXT_ID_KEY),
                    'address_scopes': driver_utils.get_addr_scopes(port)}
                self._expose_subnet(ips, subnet_info)

            # add missing routes/ips for OVN loadbalancers
            self._expose_lbs([router])

        LOG.debug("Added BGP route for logical port with ip %s", ips)
        return ips

    @lockutils.synchronized('nbbgp')
    def withdraw_ip(self, ips, ips_info):
        '''Withdraw BGP route by removing IP from device.

        This methods ensures BGP withdraw an advertised IP of a VM, either
        in the provider network.
        It relies on Zebra, which withdraws the advertisement as soon as the
        IP is deleted from the local interface.

        This method assumes a device named self.ovn_decice exists (inside a
        VRF), and removes the IP of:
        - VM IP on the provider network
        '''
        logical_switch = ips_info.get('logical_switch')
        if not logical_switch:
            return
        _, bridge_device, bridge_vlan = self._get_ls_localnet_info(
            logical_switch)
        if not bridge_device:
            # This means it is not a provider network
            return

        proxy_cidr = []
        if ips_info['cidrs']:
            if not (self.nb_idl.ls_has_virtual_ports(logical_switch) or
                    self.nb_idl.get_active_lsp_on_chassis(self.chassis)):
                for n_cidr in ips_info['cidrs']:
                    if (linux_net.get_ip_version(n_cidr) ==
                            constants.IP_VERSION_6):
                        proxy_cidr.append(n_cidr)
        LOG.debug("Deleting BGP route for logical port with ip %s", ips)
        self._withdraw_provider_port(ips, logical_switch, bridge_device,
                                     bridge_vlan, proxy_cidr)

        if ips_info.get('router'):
            # It is a Logical Router Port (CR-LRP)
            # Withdraw associated subnets
            ports = self.nb_idl.get_active_local_lrps([ips_info['router']])
            for port in ports:
                ips = port.external_ids.get(constants.OVN_CIDRS_EXT_ID_KEY,
                                            "").split()
                subnet_info = {
                    'associated_router': port.external_ids.get(
                        constants.OVN_DEVICE_ID_EXT_ID_KEY),
                    'network': port.external_ids.get(
                        constants.OVN_LS_NAME_EXT_ID_KEY),
                    'address_scopes': driver_utils.get_addr_scopes(port)}
                self._withdraw_subnet(ips, subnet_info)

            # withdraw routes/ips for OVN loadbalancers
            self._withdraw_lbs([ips_info['router']])

            try:
                del self.ovn_local_cr_lrps[ips_info['router']]
            except KeyError:
                LOG.debug("Gateway port for router %s already cleanup.",
                          ips_info['router'])
        LOG.debug("Deleted BGP route for logical port with ip %s", ips)

    def _get_ls_localnet_info(self, logical_switch):
        localnet_ports = self.nb_idl.ls_get_localnet_ports(
            logical_switch, if_exists=True).execute(check_error=True)
        if not localnet_ports:
            # means it is not a provider network, so no need to expose the IP
            return None, None, None
        bridge_device, bridge_vlan = self._get_bridge_for_localnet_port(
            localnet_ports[0])
        # NOTE: assuming only one localnet per LS exists
        return localnet_ports[0].name, bridge_device, bridge_vlan

    def get_port_external_ip_and_ls(self, port):
        nat_entry = self.nb_idl.get_nat_by_logical_port(port)
        if not nat_entry:
            return None, None, None
        net_id = nat_entry.external_ids.get(constants.OVN_FIP_NET_EXT_ID_KEY)
        if not net_id:
            return nat_entry.external_ip, nat_entry.external_mac, None
        else:
            ls_name = "neutron-{}".format(net_id)
            return nat_entry.external_ip, nat_entry.external_mac, ls_name

    @lockutils.synchronized('nbbgp')
    def expose_fip(self, ip, mac, logical_switch, row):
        '''Advertice BGP route by adding IP to device.

        This methods ensures BGP advertises the FIP associated to a VM in a
        tenant networks.
        It relies on Zebra, which creates and advertises a route when an IP
        is added to a local interface.

        This method assumes a device named self.ovn_device exists (inside a
        VRF), and adds the IP of:
        - VM FIP
        '''
        return self._expose_fip(ip, mac, logical_switch, row)

    def _expose_fip(self, ip, mac, logical_switch, row):
        bridge_info = self.ovn_provider_ls.get(logical_switch)
        if bridge_info:
            # already known provider ls
            bridge_device = bridge_info['bridge_device']
            bridge_vlan = bridge_info['bridge_vlan']
            localnet = bridge_info['localnet']
        else:
            localnet, bridge_device, bridge_vlan = self._get_ls_localnet_info(
                logical_switch)
            if not bridge_device:
                # This means it is not a provider network
                return False
            if bridge_device not in self.ovn_bridge_mappings.values():
                # This node is not properly configured, no need to expose it
                return False
            if not self.ovn_provider_ls.get(logical_switch):
                self.ovn_provider_ls[logical_switch] = {
                    'bridge_device': bridge_device,
                    'bridge_vlan': bridge_vlan,
                    'localnet': localnet}
        tenant_logical_switch = row.external_ids.get(
            constants.OVN_LS_NAME_EXT_ID_KEY)
        if not tenant_logical_switch:
            return
        self.ovn_tenant_ls[tenant_logical_switch] = True
        LOG.debug("Adding BGP route for FIP with ip %s", ip)
        if not self._expose_provider_port([ip], mac, tenant_logical_switch,
                                          bridge_device, bridge_vlan,
                                          localnet):
            return False
        LOG.debug("Added BGP route for FIP with ip %s", ip)
        return True

    @lockutils.synchronized('nbbgp')
    def withdraw_fip(self, ip, row):
        '''Withdraw BGP route by removing IP from device.

        This methods ensures BGP withdraw an advertised the FIP associated to
        a VM in a tenant networks.
        It relies on Zebra, which withdraws the advertisement as soon as the
        IP is deleted from the local interface.

        This method assumes a device named self.ovn_decice exists (inside a
        VRF), and removes the IP of:
        - VM FIP
        '''
        tenant_logical_switch = row.external_ids.get(
            constants.OVN_LS_NAME_EXT_ID_KEY)
        if not tenant_logical_switch:
            return
        fip_info = self._exposed_ips.get(tenant_logical_switch, {}).get(ip)
        if not fip_info:
            # No information to withdraw the FIP
            return
        bridge_device = fip_info['bridge_device']
        bridge_vlan = fip_info['bridge_vlan']

        LOG.debug("Deleting BGP route for FIP with ip %s", ip)
        self._withdraw_provider_port([ip], tenant_logical_switch,
                                     bridge_device, bridge_vlan)
        LOG.debug("Deleted BGP route for FIP with ip %s", ip)

    @lockutils.synchronized('nbbgp')
    def expose_remote_ip(self, ips, ips_info):
        self._expose_remote_ip(ips, ips_info)

    @lockutils.synchronized('nbbgp')
    def withdraw_remote_ip(self, ips, ips_info):
        self._withdraw_remote_ip(ips, ips_info)

    def _expose_remote_ip(self, ips, ips_info):
        ips_to_expose = ips
        if not CONF.expose_tenant_networks:
            # This means CONF.expose_ipv6_gua_tenant_networks is enabled
            gua_ips = [ip for ip in ips if driver_utils.is_ipv6_gua(ip)]
            if not gua_ips:
                return
            ips_to_expose = gua_ips

        LOG.debug("Adding BGP route for tenant IP(s) %s on chassis %s",
                  ips_to_expose, self.chassis)
        bgp_utils.announce_ips(ips_to_expose)
        for ip in ips_to_expose:
            self._exposed_ips.setdefault(
                ips_info['logical_switch'], {}).update({ip: {}})
        LOG.debug("Added BGP route for tenant IP(s) %s on chassis %s",
                  ips_to_expose, self.chassis)

    def _withdraw_remote_ip(self, ips, ips_info):
        ips_to_withdraw = ips
        if not CONF.expose_tenant_networks:
            # This means CONF.expose_ipv6_gua_tenant_networks is enabled
            gua_ips = [ip for ip in ips if driver_utils.is_ipv6_gua(ip)]
            if not gua_ips:
                return
            ips_to_withdraw = gua_ips

        LOG.debug("Deleting BGP route for tenant IP(s) %s on chassis %s",
                  ips_to_withdraw, self.chassis)
        bgp_utils.withdraw_ips(ips_to_withdraw)
        for ip in ips_to_withdraw:
            if self._exposed_ips.get(
                    ips_info['logical_switch'], {}).get(ip):
                self._exposed_ips[
                    ips_info['logical_switch']].pop(ip)
        LOG.debug("Deleted BGP route for tenant IP(s) %s on chassis %s",
                  ips_to_withdraw, self.chassis)

    @lockutils.synchronized('nbbgp')
    def expose_subnet(self, ips, subnet_info):
        return self._expose_subnet(ips, subnet_info)

    @lockutils.synchronized('nbbgp')
    def withdraw_subnet(self, ips, subnet_info):
        return self._withdraw_subnet(ips, subnet_info)

    def _expose_subnet(self, ips, subnet_info):
        gateway_router = subnet_info['associated_router']
        if not gateway_router:
            LOG.debug("Subnet CIDRs %s not exposed as there is no associated "
                      "router", ips)
            return
        cr_lrp_info = self.ovn_local_cr_lrps.get(gateway_router)
        if not cr_lrp_info:
            LOG.debug("Subnet CIDRs %s not exposed as there is no local "
                      "cr-lrp matching %s", ips, gateway_router)
            return

        if not self._expose_router_lsp(ips, subnet_info, cr_lrp_info):
            LOG.debug("Something happen while exposing the Subnet CIRDs %s "
                      "and they have not been properly exposed", ips)
            return

        ports = self.nb_idl.get_active_lsp(subnet_info['network'])
        for port in ports:
            ips = port.addresses[0].split(' ')[1:]
            mac = port.addresses[0].strip().split(' ')[0]
            ips_info = {
                'mac': mac,
                'cidrs': port.external_ids.get(constants.OVN_CIDRS_EXT_ID_KEY,
                                               "").split(),
                'type': port.type,
                'logical_switch': port.external_ids.get(
                    constants.OVN_LS_NAME_EXT_ID_KEY)
            }
            self._expose_remote_ip(ips, ips_info)

    def _withdraw_subnet(self, ips, subnet_info):
        gateway_router = subnet_info['associated_router']
        if not gateway_router:
            LOG.debug("Subnet CIDRs %s not withdrawn as there is no associated"
                      " router", ips)
            return
        cr_lrp_info = self.ovn_local_cr_lrps.get(gateway_router)
        if not cr_lrp_info:
            # NOTE(ltomasbo) there is a chance the cr-lrp just got moved
            # to this node but was not yet processed. In that case there
            # is no need to withdraw the network as it was not exposed here
            LOG.debug("Subnet CIDRs %s not withdrawn as there is no local "
                      "cr-lrp matching %s", ips, gateway_router)
            return

        self._withdraw_router_lsp(ips, subnet_info, cr_lrp_info)
        ports = self.nb_idl.get_active_lsp(subnet_info['network'])
        for port in ports:
            ips = port.addresses[0].split(' ')[1:]
            mac = port.addresses[0].strip().split(' ')[0]
            ips_info = {
                'mac': mac,
                'cidrs': port.external_ids.get(constants.OVN_CIDRS_EXT_ID_KEY,
                                               "").split(),
                'type': port.type,
                'logical_switch': port.external_ids.get(
                    constants.OVN_LS_NAME_EXT_ID_KEY)
            }
            self._withdraw_remote_ip(ips, ips_info)

    def _expose_router_lsp(self, ips, subnet_info, cr_lrp_info):
        if not self._expose_tenant_networks:
            return True
        success = True
        for ip in ips:
            if not CONF.expose_tenant_networks:
                # This means CONF.expose_ipv6_gua_tenant_networks is enabled
                if not driver_utils.is_ipv6_gua(ip):
                    continue
            if not self._address_scope_allowed(ip,
                                               subnet_info['address_scopes']):
                continue
            try:
                if wire_utils.wire_lrp_port(
                        self.ovn_routing_tables_routes, ip,
                        cr_lrp_info.get('bridge_device'),
                        cr_lrp_info.get('bridge_vlan'),
                        self.ovn_routing_tables, cr_lrp_info.get('ips')):
                    self._exposed_ips.setdefault(
                        subnet_info['associated_router'], {}).update(
                        {ip: {
                            'bridge_device': cr_lrp_info.get('bridge_device'),
                            'bridge_vlan': cr_lrp_info.get('bridge_vlan')}})
                    if self.ovn_local_lrps.get(subnet_info['network']):
                        self.ovn_local_lrps[subnet_info['network']].append(ip)
                    else:
                        self.ovn_local_lrps[subnet_info['network']] = [ip]
                else:
                    success = False

            except Exception as e:
                LOG.exception("Unexpected exception while wiring subnet CIDRs"
                              " %s: %s", ip, e)
                success = False
        return success

    def _withdraw_router_lsp(self, ips, subnet_info, cr_lrp_info):
        if not self._expose_tenant_networks:
            return
        for ip in ips:
            if (not CONF.expose_tenant_networks and
                    not driver_utils.is_ipv6_gua(ip)):
                # This means CONF.expose_ipv6_gua_tenant_networks is enabled
                continue
            if not self._address_scope_allowed(ip,
                                               subnet_info['address_scopes']):
                continue
            try:
                if wire_utils.unwire_lrp_port(
                        self.ovn_routing_tables_routes, ip,
                        cr_lrp_info.get('bridge_device'),
                        cr_lrp_info.get('bridge_vlan'),
                        self.ovn_routing_tables, cr_lrp_info.get('ips')):
                    if self._exposed_ips.get(
                            subnet_info['associated_router'], {}).get(ip):
                        self._exposed_ips[
                            subnet_info['associated_router']].pop(ip)
                else:
                    return False
            except Exception as e:
                LOG.exception("Unexpected exception while unwiring subnet "
                              "CIDRs %s: %s", ip, e)
                return False
        try:
            del self.ovn_local_lrps[subnet_info['network']]
        except KeyError:
            # Router port for subnet already cleanup
            pass
        return True

    @lockutils.synchronized('nbbgp')
    def expose_ovn_lb_vip(self, lb):
        self._expose_ovn_lb_vip(lb)

    def _expose_ovn_lb_vip(self, lb):
        vip_port = lb.external_ids.get(constants.OVN_LB_VIP_PORT_EXT_ID_KEY)
        vip_ip = lb.external_ids.get(constants.OVN_LB_VIP_IP_EXT_ID_KEY)
        vip_router = lb.external_ids[
            constants.OVN_LB_LR_REF_EXT_ID_KEY].replace('neutron-', "", 1)
        vip_lsp = self.nb_idl.lsp_get(vip_port).execute(check_error=True)
        if not vip_lsp:
            LOG.debug("Something went wrong, VIP port %s not found", vip_port)
            return
        vip_net = vip_lsp.external_ids.get(constants.OVN_LS_NAME_EXT_ID_KEY)
        if vip_net in self.ovn_local_lrps.keys():
            # It is a VIP on a tenant network
            # NOTE: the LB is exposed through the cr-lrp, so we add the
            # vip_router instead of the logical switch
            ips_info = {'logical_switch': vip_router}
            self._expose_remote_ip([vip_ip], ips_info)
        else:
            # It is a VIP on a provider network
            localnet, bridge_device, bridge_vlan = self._get_ls_localnet_info(
                vip_net)
            self._expose_provider_port([vip_ip], None, vip_net, bridge_device,
                                       bridge_vlan, localnet)

    @lockutils.synchronized('nbbgp')
    def withdraw_ovn_lb_vip(self, lb):
        self._withdraw_ovn_lb_vip(lb)

    def _withdraw_ovn_lb_vip(self, lb):
        vip_ip = lb.external_ids.get(constants.OVN_LB_VIP_IP_EXT_ID_KEY)
        vip_router = lb.external_ids[
            constants.OVN_LB_LR_REF_EXT_ID_KEY].replace('neutron-', "", 1)

        cr_lrp_info = self.ovn_local_cr_lrps.get(vip_router)
        if not cr_lrp_info:
            return
        provider_ls = cr_lrp_info['provider_switch']
        if self._exposed_ips.get(provider_ls, {}).get(vip_ip):
            # VIP is on provider network
            self._withdraw_provider_port([vip_ip],
                                         cr_lrp_info['provider_switch'],
                                         cr_lrp_info['bridge_device'],
                                         cr_lrp_info['bridge_vlan'])
        else:
            # VIP is on tenant network
            ips_info = {'logical_switch': vip_router}
            self._withdraw_remote_ip([vip_ip], ips_info)

    @lockutils.synchronized('nbbgp')
    def expose_ovn_lb_fip(self, lb):
        self._expose_ovn_lb_fip(lb)

    def _expose_ovn_lb_fip(self, lb):
        vip_port = lb.external_ids.get(constants.OVN_LB_VIP_PORT_EXT_ID_KEY)
        vip_lsp = self.nb_idl.lsp_get(vip_port).execute(check_error=True)
        if not vip_lsp:
            LOG.debug("Something went wrong, VIP port %s not found", vip_port)
            return

        external_ip, external_mac, ls_name = (
            self.get_port_external_ip_and_ls(vip_lsp.name))
        if not external_ip or not ls_name:
            LOG.debug("Something went wrong, no NAT entry for the VIP %s",
                      vip_port)
            return
        self._expose_fip(external_ip, external_mac, ls_name, vip_lsp)

    @lockutils.synchronized('nbbgp')
    def withdraw_ovn_lb_fip(self, lb):
        self._withdraw_ovn_lb_fip(lb)

    def _withdraw_ovn_lb_fip(self, lb):
        vip_fip = lb.external_ids.get(constants.OVN_LB_VIP_FIP_EXT_ID_KEY)
        # OVN loadbalancers ARPs are replied by router port
        vip_router = lb.external_ids.get(
            constants.OVN_LB_LR_REF_EXT_ID_KEY, "").replace('neutron-', "", 1)
        if not vip_router:
            return
        cr_lrp_info = self.ovn_local_cr_lrps.get(vip_router)
        if not cr_lrp_info:
            return
        self._withdraw_provider_port([vip_fip],
                                     cr_lrp_info['provider_switch'],
                                     cr_lrp_info['bridge_device'],
                                     cr_lrp_info['bridge_vlan'])

    def _address_scope_allowed(self, ip, address_scopes):
        if not self.allowed_address_scopes:
            # No address scopes to filter on => announce everything
            return True

        # if we should filter on address scopes and this port has no
        # address scopes set we do not need to expose it
        if not any(address_scopes.values()):
            return False
        # if address scope does not match, no need to expose it
        ip_version = linux_net.get_ip_version(ip)

        return address_scopes[ip_version] in self.allowed_address_scopes

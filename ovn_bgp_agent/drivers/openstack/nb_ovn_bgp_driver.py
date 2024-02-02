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
from ovn_bgp_agent.drivers.openstack.watchers import nb_bgp_watcher as watcher
from ovn_bgp_agent import exceptions
from ovn_bgp_agent.utils import linux_net


CONF = cfg.CONF
LOG = logging.getLogger(__name__)
# LOG.setLevel(logging.DEBUG)
# logging.basicConfig(level=logging.DEBUG)

OVN_TABLES = ['Logical_Switch_Port', 'NAT', 'Logical_Switch', 'Logical_Router',
              'Logical_Router_Port', 'Load_Balancer']
LOCAL_CLUSTER_OVN_TABLES = ['Logical_Switch', 'Logical_Switch_Port',
                            'Logical_Router', 'Logical_Router_Port',
                            'Logical_Router_Policy',
                            'Logical_Router_Static_Route', 'Gateway_Chassis',
                            'Static_MAC_Binding']


class NBOVNBGPDriver(driver_api.AgentDriverBase):

    def __init__(self):
        self.allowed_address_scopes = set(CONF.address_scopes or [])

        self._init_vars()

        self._nb_idl = None
        self._local_nb_idl = None
        self._post_start_event = threading.Event()

    @property
    def _expose_tenant_networks(self):
        return (CONF.expose_tenant_networks or
                CONF.expose_ipv6_gua_tenant_networks)

    @property
    def nb_idl(self) -> ovn.OvsdbNbOvnIdl:
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
        self.ovn_routing_tables_routes = collections.defaultdict(list)

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

        self._post_start_event.clear()

        events = self._get_events()
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
                  watcher.OVNLBDeleteEvent(self),
                  watcher.OVNPFCreateEvent(self),
                  watcher.OVNPFDeleteEvent(self)}
        if self._expose_tenant_networks:
            events.update({watcher.ChassisRedirectCreateEvent(self),
                           watcher.ChassisRedirectDeleteEvent(self),
                           watcher.LogicalSwitchPortSubnetAttachEvent(self),
                           watcher.LogicalSwitchPortSubnetDetachEvent(self)})
            if CONF.advertisement_method_tenant_networks == 'host':
                events.update({
                    watcher.LogicalSwitchPortTenantCreateEvent(self),
                    watcher.LogicalSwitchPortTenantDeleteEvent(self)
                })
        return events

    @lockutils.synchronized('nbbgp')
    def frr_sync(self):
        LOG.debug("Ensuring VRF configuration for advertising routes")
        # Base BGP configuration
        bgp_utils.ensure_base_bgp_configuration()

    @lockutils.synchronized('nbbgp')
    def sync(self):
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
        if not self.is_ls_provider(logical_switch):
            return

        _, bridge_device, bridge_vlan = self._get_provider_ls_info(
            logical_switch)

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
        if not self.is_ls_provider(logical_switch):
            return

        _, bridge_device, bridge_vlan = self._get_provider_ls_info(
            logical_switch)

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
            if driver_utils.is_pf_lb(lb):
                self._expose_ovn_pf_lb_fip(lb)
            else:
                self._expose_ovn_lb_vip(lb)
                # if vip-fip expose fip too
                if lb.external_ids.get(constants.OVN_LB_VIP_FIP_EXT_ID_KEY):
                    self._expose_ovn_lb_fip(lb)

    def _withdraw_lbs(self, router_list):
        lbs = self.nb_idl.get_active_local_lbs(router_list)
        for lb in lbs:
            if driver_utils.is_pf_lb(lb):
                self._withdraw_ovn_pf_lb_fip(lb)
            else:
                self._withdraw_ovn_lb_vip(lb)
                # if vip-fip withdraw fip too
                if lb.external_ids.get(constants.OVN_LB_VIP_FIP_EXT_ID_KEY):
                    self._withdraw_ovn_lb_fip(lb)

    def is_ls_provider(self, logical_switch):
        '''Check if given logical switch is a provider network on this host

        It will also validate that the provider network actually has been
        exposed by the driver.
        '''

        if logical_switch is None:
            self.ovn_tenant_ls[logical_switch] = True  # just for caching
            return False

        # Check if the ls has already been identified as a tenant network
        if self.ovn_tenant_ls.get(logical_switch, None) is True:
            return False

        # Check the bridge device from provider network
        _, bridge_device, _ = self._get_provider_ls_info(logical_switch)

        # Check if the bridge device has been exposed by the wiring methods
        if bridge_device not in self.ovn_bridge_mappings.values():
            return False

        return bridge_device is not None

    def is_ip_exposed(self, logical_switch, ips):
        '''Check if the ip(s) from given logical_switch is exported.

        So basically, check if the ips are listed in self._exposed_ips.
        If it is in there, it should be exposed by ovn-bgp-agent.

        This helps a lot in evaluating events.
        '''
        # Ip may be a list
        if not isinstance(ips, (list, tuple, set)):
            ips = [ips]

        for ip in ips:
            if ip in self._exposed_ips.get(logical_switch, {}):
                return True

        return False

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
        if not self.is_ls_provider(logical_switch):
            return False

        _, bridge_device, bridge_vlan = self._get_provider_ls_info(
            logical_switch)

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

    def _get_provider_ls_info(self, logical_switch):
        '''Helper method for _get_ls_localnet_info

        It returns the information from cached self.ovn_provider_ls dictionary
        or calls the method and populates the dictionary for given
        logical_switch.

        It returns a tuple of localnet, bridge_device and bridge_vlan for
        compatibilty with _get_ls_localnet_info
        '''
        if logical_switch is None:
            return None, None, None

        if logical_switch not in self.ovn_provider_ls:
            localnet, bridge_dev, bridge_vlan = self._get_ls_localnet_info(
                logical_switch)

            self.ovn_provider_ls[logical_switch] = {
                'bridge_device': bridge_dev,
                'bridge_vlan': bridge_vlan,
                'localnet': localnet
            }

        ls = self.ovn_provider_ls[logical_switch]
        return ls['localnet'], ls['bridge_device'], ls['bridge_vlan']

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
        if not self.is_ls_provider(logical_switch):
            return False

        localnet, bridge_device, bridge_vlan = self._get_provider_ls_info(
            logical_switch)

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
        if (CONF.advertisement_method_tenant_networks ==
                constants.ADVERTISEMENT_METHOD_SUBNET):
            # Ip should already be exported via cr-lrp subnet announcement.
            return

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
        if (CONF.advertisement_method_tenant_networks ==
                constants.ADVERTISEMENT_METHOD_SUBNET):
            return

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

        if CONF.require_snat_disabled_for_tenant_networks:
            # Check if there is a SNAT entry for this LRP
            router = self.nb_idl.get_router(gateway_router)

            ips_without_snat = set(ips)
            for nat in router.nat:
                if nat.type == constants.OVN_SNAT:
                    net = ipaddress.ip_network(nat.logical_ip, strict=False)
                    for ip in list(ips_without_snat):
                        if ipaddress.ip_address(ip.split('/')[0]) in net:
                            ips_without_snat.discard(ip)

            if len(ips_without_snat) == 0:
                LOG.info('All ips (%s) were removed due to SNAT requirement '
                         'when exposing subnet %s for router %s', ips,
                         subnet_info['network'], gateway_router)
                return

            if len(set(ips)) != len(ips_without_snat):
                LOG.info('When exposing subnet %s for router %s, these ips '
                         'were removed for SNAT: %s', subnet_info['network'],
                         gateway_router, set(ips) - ips_without_snat)
                ips = list(ips_without_snat)

        try:
            self._expose_router_lsp(ips, subnet_info, cr_lrp_info)
        except (exceptions.ExposeDeniedForAddressScope,
                exceptions.WireFailure) as e:
            LOG.debug("Not exposing subnet CIDR's %s: %s", ips, e)
            return

        if (CONF.advertisement_method_tenant_networks ==
                constants.ADVERTISEMENT_METHOD_SUBNET):
            # Networks have been exposed via self._expose_router_lsp
            return

        ports = self.nb_idl.get_active_lsp(subnet_info['network'])
        for port in ports:
            # Check if the ip's on this port match the address scope. As the
            # port can be dual-stack, it could be that v4 is not allowed, but
            # v6 is allowed, so then only v6 address should be exposed.
            ips = self._ips_in_address_scope(port.addresses[0].split(' ')[1:],
                                             subnet_info['address_scopes'])
            if not ips:
                # All ip's have been removed due to address scope requirement
                continue

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

        try:
            self._withdraw_router_lsp(ips, subnet_info, cr_lrp_info)
        except (exceptions.ExposeDeniedForAddressScope,
                exceptions.UnwireFailure) as e:
            # Log a message, but silently continue, to make sure we have
            # it all withdrawn
            LOG.debug("Withdraw router lsp failure for CIDR's %s: %s", ips, e)

        if (CONF.advertisement_method_tenant_networks ==
                constants.ADVERTISEMENT_METHOD_SUBNET):
            # Expose the routes per prefix, rather than per port.
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
            self._withdraw_remote_ip(ips, ips_info)

    def _expose_router_lsp(self, ips, subnet_info, cr_lrp_info):
        '''Expose the tenant router ip address (cidr) for given router

        Will raise WireException if wire_lrp_port raises an exception or
        if it returns False

        Will raise ExposeDeniedForAddressScope if configured address scopes
        do not match the ones in configuration (if configured)
        (and execution should stop)
        '''
        if not self._expose_tenant_networks:
            return True

        if (CONF.advertisement_method_tenant_networks ==
                constants.ADVERTISEMENT_METHOD_SUBNET):
            # Fix ips to be the network address, instead of the lrp address
            # so the cleanup will not remove them, since they match what's
            # in the kernel
            ips = driver_utils.get_prefixes_from_ips(ips)

        ips_to_process = []
        for ip in ips:
            if not CONF.expose_tenant_networks:
                # This means CONF.expose_ipv6_gua_tenant_networks is enabled
                if not driver_utils.is_ipv6_gua(ip):
                    continue

            ips_to_process.append(ip)

        if not ips_to_process:
            # Silently return, since there are no ip's left to process and
            # the address_scope has nothing to do with it.
            return True

        ips = self._ips_in_address_scope(ips_to_process,
                                         subnet_info['address_scopes'])
        if not ips:
            # All ip's failed address scope test, so stop processing this lsp
            raise exceptions.ExposeDeniedForAddressScope(
                addresses=','.join(ips_to_process),
                address_scopes=subnet_info['address_scopes'],
                configured_scopes=self.allowed_address_scopes,
            )

        for ip in ips:
            try:
                if wire_utils.wire_lrp_port(
                        self.ovn_routing_tables_routes, ip,
                        cr_lrp_info.get('bridge_device'),
                        cr_lrp_info.get('bridge_vlan'),
                        self.ovn_routing_tables, cr_lrp_info.get('ips')):

                    logical_switch = cr_lrp_info['provider_switch']
                    self._exposed_ips.setdefault(logical_switch, {}).update(
                        {ip: {
                            'bridge_device': cr_lrp_info.get('bridge_device'),
                            'bridge_vlan': cr_lrp_info.get('bridge_vlan')}})

                    self.ovn_local_lrps.setdefault(
                        subnet_info['network'], []).append(ip)
                else:
                    error_msg = ("Something happen while exposing the subnet"
                                 "and they have not been properly exposed")
                    raise exceptions.WireFailure(cidr=ip, message=error_msg)

            except Exception as e:
                raise exceptions.WireFailure(cidr=ip, message=str(e)) from e

        return True

    def _withdraw_router_lsp(self, ips, subnet_info, cr_lrp_info):
        '''Withdraw the tenant router ip address (cidr) for given router

        Will raise UnwireException if wire_lrp_port raises an exception or
        if it returns False

        Will raise ExposeDeniedForAddressScope if configured address scopes
        do not match the ones in configuration (if configured)
        (and execution should stop)
        '''
        if not self._expose_tenant_networks:
            return True

        if (CONF.advertisement_method_tenant_networks ==
                constants.ADVERTISEMENT_METHOD_SUBNET):
            # Fix ips to be the network address, instead of the lrp address
            # so the cleanup will not remove them, since they match what's
            # in the kernel
            ips = driver_utils.get_prefixes_from_ips(ips)

        ips_to_process = []
        for ip in ips:
            if (not CONF.expose_tenant_networks and
                    not driver_utils.is_ipv6_gua(ip)):
                # This means CONF.expose_ipv6_gua_tenant_networks is enabled
                continue

            ips_to_process.append(ip)

        if not ips_to_process:
            # Silently return, since there are no ip's left to process and
            # the address_scope has nothing to do with it.
            return True

        ips = self._ips_in_address_scope(ips_to_process,
                                         subnet_info['address_scopes'])
        if not ips:
            # All ip's failed address scope test, so stop processing this lsp
            raise exceptions.ExposeDeniedForAddressScope(
                addresses=','.join(ips_to_process),
                address_scopes=subnet_info['address_scopes'],
                configured_scopes=self.allowed_address_scopes,
            )

        for ip in ips:
            try:
                if wire_utils.unwire_lrp_port(
                        self.ovn_routing_tables_routes, ip,
                        cr_lrp_info.get('bridge_device'),
                        cr_lrp_info.get('bridge_vlan'),
                        self.ovn_routing_tables, cr_lrp_info.get('ips')):

                    logical_switch = cr_lrp_info['provider_switch']
                    self._exposed_ips.get(logical_switch, {}).pop(ip, None)
                else:
                    error_msg = ("Something happened while withdrawing subnet"
                                 "and they have not been properly removed")
                    raise exceptions.UnwireFailure(cidr=ip, message=error_msg)
            except Exception as e:
                raise exceptions.UnwireFailure(cidr=ip, message=str(e)) from e

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
            localnet, bridge_device, bridge_vlan = self._get_provider_ls_info(
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

    def _get_parameters_from_lb(self, lb, include_mac_and_localnet=False):
        for fipport in lb.vips.keys():
            fip, port = fipport.split(':')
            break
        else:
            return

        router = lb.external_ids.get(
            constants.OVN_LR_NAME_EXT_ID_KEY, '').replace('neutron-', "", 1)
        if not router:
            return
        cr_lrp_info = self.ovn_local_cr_lrps.get(router)
        if not cr_lrp_info:
            return
        net, bridge_device, bridge_vlan = self._get_ls_localnet_info(
            cr_lrp_info['provider_switch'])
        kwargs = {
            'port_ips': [fip],
            'logical_switch': cr_lrp_info['provider_switch'],
            'bridge_device': bridge_device,
            'bridge_vlan': bridge_vlan}

        if include_mac_and_localnet:
            kwargs['mac'] = None
            kwargs['localnet'] = net

        return kwargs

    @lockutils.synchronized('nbbgp')
    def expose_ovn_pf_lb_fip(self, lb):
        self._expose_ovn_pf_lb_fip(lb)

    @lockutils.synchronized('nbbgp')
    def withdraw_ovn_pf_lb_fip(self, lb):
        self._withdraw_ovn_pf_lb_fip(lb)

    def _withdraw_ovn_pf_lb_fip(self, lb):
        kwargs = self._get_parameters_from_lb(lb)
        self._withdraw_provider_port(**kwargs) if kwargs else None

    def _expose_ovn_pf_lb_fip(self, lb):
        kwargs = self._get_parameters_from_lb(lb, True)
        self._expose_provider_port(**kwargs) if kwargs else None

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

    def _ips_in_address_scope(self, ips, address_scopes):
        return [ip
                for ip in ips
                if self._address_scope_allowed(ip, address_scopes)]

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

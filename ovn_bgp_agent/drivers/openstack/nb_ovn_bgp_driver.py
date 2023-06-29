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
from ovn_bgp_agent.drivers.openstack.utils import ovn
from ovn_bgp_agent.drivers.openstack.utils import ovs
from ovn_bgp_agent.drivers.openstack.utils import wire as wire_utils
from ovn_bgp_agent.drivers.openstack.watchers import nb_bgp_watcher as watcher
from ovn_bgp_agent.utils import linux_net


CONF = cfg.CONF
LOG = logging.getLogger(__name__)
# LOG.setLevel(logging.DEBUG)
# logging.basicConfig(level=logging.DEBUG)

OVN_TABLES = ["Logical_Switch_Port", "NAT", "Logical_Switch"]


class NBOVNBGPDriver(driver_api.AgentDriverBase):

    def __init__(self):
        self._expose_tenant_networks = (CONF.expose_tenant_networks or
                                        CONF.expose_ipv6_gua_tenant_networks)
        self.allowed_address_scopes = set(CONF.address_scopes or [])

        self._init_vars()

        self._nb_idl = None
        self._post_start_event = threading.Event()

    @property
    def nb_idl(self):
        if not self._nb_idl:
            self._post_start_event.wait()
        return self._nb_idl

    @nb_idl.setter
    def nb_idl(self, val):
        self._nb_idl = val

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
        # NOTE(ltomasbo): remote should point to NB DB port instead of SB DB,
        # so changing 6642 by 6641
        self.ovn_remote = self.ovs_idl.get_ovn_remote().replace(":6642",
                                                                ":6641")
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

        events = ()
        for event in self._get_events():
            event_class = getattr(watcher, event)
            events += (event_class(self),)

        self._post_start_event.clear()
        self.nb_idl = ovn.OvnNbIdl(
            self.ovn_remote,
            tables=OVN_TABLES,
            events=events).start()
        # Now IDL connections can be safely used
        self._post_start_event.set()

    def _get_events(self):
        events = set(["LogicalSwitchPortProviderCreateEvent",
                      "LogicalSwitchPortProviderDeleteEvent",
                      "LogicalSwitchPortFIPCreateEvent",
                      "LogicalSwitchPortFIPDeleteEvent",
                      "LocalnetCreateDeleteEvent"])
        if self._expose_tenant_networks:
            events.update([])
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
        # Get bridge mappings: xxxx:br-ex,yyyy:br-ex2
        bridge_mappings = self.ovs_idl.get_ovn_bridge_mappings()

        # Apply base configuration for each bridge
        self.ovn_bridge_mappings, self.ovs_flows = (
            wire_utils.ensure_base_wiring_config(self.nb_idl, bridge_mappings,
                                                 self.ovn_routing_tables))

        LOG.debug("Syncing current routes.")
        # add missing routes/ips for IPs on provider network
        ports = self.nb_idl.get_active_ports_on_chassis(self.chassis)
        for port in ports:
            if port.type not in [constants.OVN_VM_VIF_PORT_TYPE,
                                 constants.OVN_VIRTUAL_VIF_PORT_TYPE]:
                continue
            self._ensure_port_exposed(port)

        # remove extra wiring leftovers
        wire_utils.cleanup_wiring(self.nb_idl,
                                  self.ovn_bridge_mappings,
                                  self.ovs_flows,
                                  self._exposed_ips,
                                  self.ovn_routing_tables,
                                  self.ovn_routing_tables_routes)

    def _ensure_port_exposed(self, port):
        port_fip = port.external_ids.get(constants.OVN_FIP_EXT_ID_KEY)
        if port_fip:
            external_ip, ls_name = self.get_port_external_ip_and_ls(port.name)
            if not external_ip or not ls_name:
                return
            return self._expose_fip(external_ip, ls_name, port)

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
        self._expose_ip(ips, logical_switch, bridge_device, bridge_vlan,
                        port.type, port.external_ids.get(
                            constants.OVN_CIDRS_EXT_ID_KEY))

    def _expose_provider_port(self, port_ips, logical_switch, bridge_device,
                              bridge_vlan, localnet, proxy_cidrs=None):
        # Connect to OVN
        try:
            if wire_utils.wire_provider_port(
                    self.ovn_routing_tables_routes, self.ovs_flows, port_ips,
                    bridge_device, bridge_vlan, localnet,
                    self.ovn_routing_tables, proxy_cidrs):
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

    def _withdraw_provider_port(self, port_ips, logical_switch, bridge_device,
                                bridge_vlan, proxy_cidrs=None):
        # Withdraw IP before disconnecting it
        bgp_utils.withdraw_ips(port_ips)

        # Disconnect IP from OVN
        try:
            wire_utils.unwire_provider_port(
                self.ovn_routing_tables_routes, port_ips, bridge_device,
                bridge_vlan, self.ovn_routing_tables, proxy_cidrs)
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
            bridge_device = self.ovn_bridge_mappings[network_name]
        if localnet.tag:
            bridge_vlan = localnet.tag[0]
        return bridge_device, bridge_vlan

    @lockutils.synchronized('nbbgp')
    def expose_ip(self, ips, row):
        '''Advertice BGP route by adding IP to device.

        This methods ensures BGP advertises the IP of the VM in the provider
        network.
        It relies on Zebra, which creates and advertises a route when an IP
        is added to a local interface.

        This method assumes a device named self.ovn_device exists (inside a
        VRF), and adds the IP of:
        - VM IP on the provider network
        '''
        logical_switch = row.external_ids.get(constants.OVN_LS_NAME_EXT_ID_KEY)
        if not logical_switch:
            return False
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
        return self._expose_ip(ips, logical_switch, bridge_device, bridge_vlan,
                               port_type=row.type, cidr=row.external_ids.get(
                                   constants.OVN_CIDRS_EXT_ID_KEY))

    def _expose_ip(self, ips, logical_switch, bridge_device, bridge_vlan,
                   port_type, cidr):
        LOG.debug("Adding BGP route for logical port with ip %s", ips)
        localnet = self.ovn_provider_ls[logical_switch]['localnet']

        if cidr and port_type == constants.OVN_VIRTUAL_VIF_PORT_TYPE:
            # NOTE: For Amphora Load Balancer with IPv6 VIP on the provider
            # network, we need a NDP Proxy so that the traffic from the
            # amphora can properly be redirected back
            if not self._expose_provider_port(ips, logical_switch,
                                              bridge_device, bridge_vlan,
                                              localnet, [cidr]):
                return []

        else:
            if not self._expose_provider_port(ips, logical_switch,
                                              bridge_device, bridge_vlan,
                                              localnet):
                return []
        LOG.debug("Added BGP route for logical port with ip %s", ips)
        return ips

    @lockutils.synchronized('nbbgp')
    def withdraw_ip(self, ips, row):
        '''Withdraw BGP route by removing IP from device.

        This methods ensures BGP withdraw an advertised IP of a VM, either
        in the provider network.
        It relies on Zebra, which withdraws the advertisement as soon as the
        IP is deleted from the local interface.

        This method assumes a device named self.ovn_decice exists (inside a
        VRF), and removes the IP of:
        - VM IP on the provider network
        '''
        logical_switch = row.external_ids.get(constants.OVN_LS_NAME_EXT_ID_KEY)
        if not logical_switch:
            return
        _, bridge_device, bridge_vlan = self._get_ls_localnet_info(
            logical_switch)
        if not bridge_device:
            # This means it is not a provider network
            return

        proxy_cidr = None
        if row.type == constants.OVN_VIRTUAL_VIF_PORT_TYPE:
            n_cidr = row.external_ids.get(constants.OVN_CIDRS_EXT_ID_KEY)
            if n_cidr and (linux_net.get_ip_version(n_cidr) ==
                           constants.IP_VERSION_6):
                if not self.nb_idl.ls_has_virtual_ports(logical_switch):
                    proxy_cidr = n_cidr
        LOG.debug("Deleting BGP route for logical port with ip %s", ips)
        if proxy_cidr:
            self._withdraw_provider_port(ips, logical_switch, bridge_device,
                                         bridge_vlan, [proxy_cidr])
        else:
            self._withdraw_provider_port(ips, logical_switch, bridge_device,
                                         bridge_vlan)
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
            return
        net_id = nat_entry.external_ids.get(constants.OVN_FIP_NET_EXT_ID_KEY)
        if not net_id:
            return nat_entry.external_ip, None
        else:
            return nat_entry.external_ip, "neutron-{}".format(net_id)

    @lockutils.synchronized('nbbgp')
    def expose_fip(self, ip, logical_switch, row):
        '''Advertice BGP route by adding IP to device.

        This methods ensures BGP advertises the FIP associated to a VM in a
        tenant networks.
        It relies on Zebra, which creates and advertises a route when an IP
        is added to a local interface.

        This method assumes a device named self.ovn_device exists (inside a
        VRF), and adds the IP of:
        - VM FIP
        '''
        return self._expose_fip(ip, logical_switch, row)

    def _expose_fip(self, ip, logical_switch, row):
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
        if not self._expose_provider_port([ip], tenant_logical_switch,
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
    def expose_remote_ip(self, ips, row):
        pass

    @lockutils.synchronized('nbbgp')
    def withdraw_remote_ip(self, ips, row, chassis=None):
        pass

    @lockutils.synchronized('nbbgp')
    def expose_subnet(self, ip, row):
        pass

    @lockutils.synchronized('nbbgp')
    def withdraw_subnet(self, ip, row):
        pass

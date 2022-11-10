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
import pyroute2
import threading

from oslo_concurrency import lockutils
from oslo_config import cfg
from oslo_log import log as logging

from ovn_bgp_agent import constants
from ovn_bgp_agent.drivers import driver_api
from ovn_bgp_agent.drivers.openstack.utils import bgp as bgp_utils
from ovn_bgp_agent.drivers.openstack.utils import frr
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
        self.ovn_routing_tables = {}  # {'br-ex': 200}
        self.ovn_bridge_mappings = {}  # {'public': 'br-ex'}
        self.ovn_local_cr_lrps = {}
        self.ovn_local_lrps = {}
        # {'br-ex': [route1, route2]}
        self.ovn_routing_tables_routes = collections.defaultdict()
        # {ovn_lb: VIP1, VIP2}
        self.ovn_lb_vips = collections.defaultdict()
        self.ovn_fips = {}  # {'fip': {'bridge_device': X, 'bridge_vlan': Y}}
        # {'ls_name': {'bridge_device': X, 'bridge_vlan': Y}}
        self.ovn_provider_ls = {}
        # dict instead of list to speed up look ups
        self.ovn_tenant_ls = {}  # {'ls_name': True}

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
    def sync(self):
        self._expose_tenant_networks = (CONF.expose_tenant_networks or
                                        CONF.expose_ipv6_gua_tenant_networks)
        self.ovn_local_cr_lrps = {}
        self.ovn_local_lrps = {}
        self.ovn_routing_tables_routes = collections.defaultdict()
        self.ovn_lb_vips = collections.defaultdict()
        self.ovn_provider_ls = {}
        self.ovn_tenant_ls = {}

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
                            self.ovn_routing_tables, bridge,
                            CONF.bgp_vrf_table_id))
                vlan_tag = self.nb_idl.get_network_vlan_tag_by_network_name(
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
        ports = self.nb_idl.get_active_ports_on_chassis(self.chassis)
        for port in ports:
            if port.type not in [constants.OVN_VM_VIF_PORT_TYPE,
                                 constants.OVN_VIRTUAL_VIF_PORT_TYPE]:
                continue
            self._ensure_port_exposed(port, exposed_ips, ovn_ip_rules)

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

    def _ensure_port_exposed(self, port, exposed_ips, ovn_ip_rules):
        port_fip = port.external_ids.get(constants.OVN_FIP_EXT_ID_KEY)
        if port_fip:
            external_ip, ls_name = self.get_port_external_ip_and_ls(port.name)
            if not external_ip or not ls_name:
                return
            if self._expose_fip(external_ip, ls_name):
                ip_version = linux_net.get_ip_version(external_ip)
                if ip_version == constants.IP_VERSION_6:
                    ip_dst = "{}/128".format(external_ip)
                else:
                    ip_dst = "{}/32".format(external_ip)
                if external_ip in exposed_ips:
                    exposed_ips.remove(external_ip)
                ovn_ip_rules.pop(ip_dst, None)
            return

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
            bridge_device, bridge_vlan = self._get_ls_localnet_info(
                logical_switch)
            if not bridge_device:
                # This means it is not a provider network
                self.ovn_tenant_ls[logical_switch] = True
                return False
            self.ovn_provider_ls[logical_switch] = {
                'bridge_device': bridge_device,
                'bridge_vlan': bridge_vlan}
        ips = port.addresses[0].strip().split(' ')[1:]
        ips_adv = self._expose_ip(ips, bridge_device, bridge_vlan, port.type,
                                  port.external_ids.get(
                                      constants.OVN_CIDRS_EXT_ID_KEY))
        for ip in ips_adv:
            ip_version = linux_net.get_ip_version(ip)
            if ip_version == constants.IP_VERSION_6:
                ip_dst = "{}/128".format(ip)
            else:
                ip_dst = "{}/32".format(ip)
            if ip in exposed_ips:
                exposed_ips.remove(ip)
            ovn_ip_rules.pop(ip_dst, None)

    def _expose_provider_port(self, port_ips, bridge_device, bridge_vlan,
                              proxy_cidrs=None):
        # Connect to OVN
        if wire_utils.wire_provider_port(
                self.ovn_routing_tables_routes, port_ips, bridge_device,
                bridge_vlan, self.ovn_routing_tables[bridge_device],
                proxy_cidrs):
            # Expose the IP now that it is connected
            bgp_utils.announce_ips(port_ips)

    def _withdraw_provider_port(self, port_ips, bridge_device, bridge_vlan,
                                proxy_cidrs=None):
        # Withdraw IP before disconnecting it
        bgp_utils.withdraw_ips(port_ips)

        # Disconnect IP from OVN
        wire_utils.unwire_provider_port(
            self.ovn_routing_tables_routes, port_ips, bridge_device,
            bridge_vlan, self.ovn_routing_tables[bridge_device], proxy_cidrs)

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
        bridge_device, bridge_vlan = self._get_ls_localnet_info(logical_switch)
        if not bridge_device:
            # This means it is not a provider network
            self.ovn_tenant_ls[logical_switch] = True
            return False
        self.ovn_provider_ls[logical_switch] = {
            'bridge_device': bridge_device,
            'bridge_vlan': bridge_vlan}
        return self._expose_ip(ips, bridge_device, bridge_vlan,
                               port_type=row.type, cidr=row.external_ids.get(
                                   constants.OVN_CIDRS_EXT_ID_KEY))

    def _expose_ip(self, ips, bridge_device, bridge_vlan, port_type, cidr):
        LOG.debug("Adding BGP route for logical port with ip %s", ips)

        if cidr and port_type == constants.OVN_VIRTUAL_VIF_PORT_TYPE:
            # NOTE: For Amphora Load Balancer with IPv6 VIP on the provider
            # network, we need a NDP Proxy so that the traffic from the
            # amphora can properly be redirected back
            self._expose_provider_port(ips, bridge_device, bridge_vlan, [cidr])
        else:
            self._expose_provider_port(ips, bridge_device, bridge_vlan)

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
        bridge_device, bridge_vlan = self._get_ls_localnet_info(logical_switch)
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
            self._withdraw_provider_port(ips, bridge_device, bridge_vlan,
                                         [proxy_cidr])
        else:
            self._withdraw_provider_port(ips, bridge_device, bridge_vlan)
        LOG.debug("Deleted BGP route for logical port with ip %s", ips)

    def _get_ls_localnet_info(self, logical_switch):
        localnet_ports = self.nb_idl.ls_get_localnet_ports(
            logical_switch, if_exists=True).execute(check_error=True)
        if not localnet_ports:
            # means it is not a provider network, so no need to expose the IP
            return None, None
        # NOTE: assuming only one localnet per LS exists
        return self._get_bridge_for_localnet_port(localnet_ports[0])

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
    def expose_fip(self, ip, logical_switch):
        '''Advertice BGP route by adding IP to device.

        This methods ensures BGP advertises the FIP associated to a VM in a
        tenant networks.
        It relies on Zebra, which creates and advertises a route when an IP
        is added to a local interface.

        This method assumes a device named self.ovn_device exists (inside a
        VRF), and adds the IP of:
        - VM FIP
        '''
        return self._expose_fip(ip, logical_switch)

    def _expose_fip(self, ip, logical_switch):
        bridge_device, bridge_vlan = self._get_ls_localnet_info(logical_switch)
        if not bridge_device:
            # This means it is not a provider network
            return False
        LOG.debug("Adding BGP route for FIP with ip %s", ip)
        self._expose_provider_port([ip], bridge_device, bridge_vlan)
        self.ovn_fips[ip] = {'bridge_device': bridge_device,
                             'bridge_vlan': bridge_vlan}
        LOG.debug("Added BGP route for FIP with ip %s", ip)
        return True

    @lockutils.synchronized('nbbgp')
    def withdraw_fip(self, ip):
        '''Withdraw BGP route by removing IP from device.

        This methods ensures BGP withdraw an advertised the FIP associated to
        a VM in a tenant networks.
        It relies on Zebra, which withdraws the advertisement as soon as the
        IP is deleted from the local interface.

        This method assumes a device named self.ovn_decice exists (inside a
        VRF), and removes the IP of:
        - VM FIP
        '''
        fip_info = self.ovn_fips.get(ip)
        if not fip_info:
            # No information to withdraw the FIP
            return
        bridge_device = fip_info['bridge_device']
        bridge_vlan = fip_info['bridge_vlan']

        LOG.debug("Deleting BGP route for FIP with ip %s", ip)
        self._withdraw_provider_port([ip], bridge_device, bridge_vlan)
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

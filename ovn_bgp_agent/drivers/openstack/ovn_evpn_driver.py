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
from ovn_bgp_agent.drivers.openstack.utils import frr
from ovn_bgp_agent.drivers.openstack.utils import ovn
from ovn_bgp_agent.drivers.openstack.utils import ovs
from ovn_bgp_agent.drivers.openstack.watchers import evpn_watcher as \
    watcher
from ovn_bgp_agent.utils import helpers
from ovn_bgp_agent.utils import linux_net


CONF = cfg.CONF
LOG = logging.getLogger(__name__)
# LOG.setLevel(logging.DEBUG)
# logging.basicConfig(level=logging.DEBUG)

OVN_TABLES = ["Port_Binding", "Chassis", "Datapath_Binding", "Chassis_Private"]
EVPN_INFO = collections.namedtuple(
    'EVPNInfo', ['vrf_name', 'lo_name', 'bridge_name', 'vxlan_name',
                 'veth_vrf', 'veth_ovs', 'vlan_name'])


class OVNEVPNDriver(driver_api.AgentDriverBase):

    def __init__(self):
        self.ovn_bridge_mappings = {}  # {'public': 'br-ex'}
        self.ovn_local_cr_lrps = {}
        self.ovn_local_lrps = {}
        # {'br-ex': [route1, route2]}
        self._ovn_routing_tables_routes = collections.defaultdict()
        self._ovn_exposed_evpn_ips = collections.defaultdict()

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
        LOG.debug("Loaded chassis %s.", self.chassis)

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
        return {watcher.PortBindingChassisCreatedEvent(self),
                watcher.PortBindingChassisDeletedEvent(self),
                watcher.SubnetRouterAttachedEvent(self),
                watcher.SubnetRouterDetachedEvent(self),
                watcher.TenantPortCreatedEvent(self),
                watcher.TenantPortDeletedEvent(self),
                watcher.ChassisCreateEvent(self),
                watcher.ChassisPrivateCreateEvent(self),
                watcher.LocalnetCreateDeleteEvent(self)}

    @lockutils.synchronized('evpn')
    def frr_sync(self):
        # Note(ltomasbo): There is no need for resync on this as there is
        # no base configuration to be made, but one added when subnets are
        # exposed, so the sync action takes care of it
        pass

    @lockutils.synchronized('evpn')
    def sync(self):
        self.ovn_local_cr_lrps = {}
        self.ovn_local_lrps = {}
        self._ovn_routing_tables_routes = collections.defaultdict()
        self._ovn_exposed_evpn_ips = collections.defaultdict()

        # 1) Get bridge mappings: xxxx:br-ex,yyyy:br-ex2
        bridge_mappings = self.ovs_idl.get_ovn_bridge_mappings()
        # 2) Get macs for bridge mappings
        for bridge_index, bridge_mapping in enumerate(bridge_mappings, 1):
            network, bridge = helpers.parse_bridge_mapping(bridge_mapping)
            if not network:
                continue
            self.ovn_bridge_mappings[network] = bridge

            linux_net.ensure_arp_ndp_enabled_for_bridge(bridge, bridge_index)

        # TO DO
        # add missing routes/ips for fips/provider VMs
        ports = self.sb_idl.get_ports_on_chassis(self.chassis)
        for port in ports:
            if port.type != constants.OVN_CHASSISREDIRECT_VIF_PORT_TYPE:
                continue
            self._expose_ip(port, cr_lrp=True)

        self._remove_extra_exposed_ips()
        self._remove_extra_routes()
        self._remove_extra_ovs_flows()
        self._remove_extra_vrfs()

    def _ensure_network_exposed(self, router_port, gateway):
        evpn_info = self.sb_idl.get_evpn_info_from_port_name(
            router_port.logical_port)
        if not evpn_info:
            LOG.debug("No EVPN information for LRP Port %s. "
                      "Not exposing it.", router_port)
            return

        gateway_ips = [ip.split('/')[0] for ip in gateway['ips']]
        try:
            router_port_ip = router_port.mac[0].strip().split(' ')[1]
        except IndexError:
            return
        router_ip = router_port_ip.split('/')[0]
        if router_ip in gateway_ips:
            return
        self.ovn_local_lrps[router_port.logical_port] = {
            'datapath': router_port.datapath,
            'ip': router_port_ip
            }
        datapath_bridge, vlan_tag = self._get_bridge_for_datapath(
            gateway['provider_datapath'])

        network_datapath = self.sb_idl.get_port_datapath(
            router_port.options['peer'])

        self._expose_subnet(router_port_ip, gateway_ips, gateway,
                            datapath_bridge, vlan_tag, network_datapath)

    def _get_bridge_for_datapath(self, datapath):
        network_name, network_tag = self.sb_idl.get_network_name_and_tag(
            datapath, self.ovn_bridge_mappings.keys())
        if network_name:
            if network_tag:
                return self.ovn_bridge_mappings[network_name], network_tag[0]
            return self.ovn_bridge_mappings[network_name], None
        return None, None

    @lockutils.synchronized('evpn')
    def expose_ip(self, row, cr_lrp=False):
        '''Advertice BGP route through EVPN.

        This methods ensures BGP advertises the IP through the required
        VRF/Tenant by using the specified VNI/VXLAN id.

        It relies on Zebra, which creates and advertises a route when an IP
        is added to a interface in the related VRF.
        '''
        self._expose_ip(row, cr_lrp)

    def _expose_ip(self, row, cr_lrp=False):
        if cr_lrp:
            cr_lrp_port_name = row.logical_port
            cr_lrp_port = row
        else:
            cr_lrp_port_name = 'cr-lrp-' + row.logical_port
            cr_lrp_port = self.sb_idl.get_port_if_local_chassis(
                cr_lrp_port_name, self.chassis)
            if not cr_lrp_port:
                # Not in local chassis, no need to proccess
                return

        _, cr_lrp_datapath = self.sb_idl.get_fip_associated(
            cr_lrp_port_name)
        if not cr_lrp_datapath:
            return

        if len(cr_lrp_port.mac[0].strip().split(' ')) < 2:
            return
        ips = cr_lrp_port.mac[0].strip().split(' ')[1:]

        if cr_lrp:
            evpn_info = self.sb_idl.get_evpn_info_from_port_name(
                cr_lrp_port_name)
        else:
            evpn_info = self.sb_idl.get_evpn_info(row)
        if not evpn_info:
            LOG.debug("No EVPN information for CR-LRP Port with IPs %s. "
                      "Not exposing it.", ips)
            return

        datapath_bridge, vlan_tag = self._get_bridge_for_datapath(
            cr_lrp_datapath)

        LOG.info("Adding BGP route for CR-LRP Port %s on AS %s and "
                 "VNI %s", ips, evpn_info['bgp_as'], evpn_info['vni'])
        evpn_devices = self._ensure_evpn_devices(datapath_bridge,
                                                 evpn_info['vni'],
                                                 vlan_tag)
        if not evpn_devices.vrf_name or not evpn_devices.lo_name:
            return

        self.ovn_local_cr_lrps[cr_lrp_port_name] = {
            'router_datapath': cr_lrp_port.datapath,
            'provider_datapath': cr_lrp_datapath,
            'ips': ips,
            'mac': cr_lrp_port.mac[0].strip().split(' ')[0],
            'vni': int(evpn_info['vni']),
            'bgp_as': evpn_info['bgp_as'],
            'lo': evpn_devices.lo_name,
            'bridge': evpn_devices.bridge_name,
            'vxlan': evpn_devices.vxlan_name,
            'vrf': evpn_devices.vrf_name,
            'veth_vrf': evpn_devices.veth_vrf,
            'veth_ovs': evpn_devices.veth_ovs,
            'vlan': evpn_devices.vlan_name
        }

        frr.vrf_reconfigure(evpn_info, action="add-vrf")

        self._connect_evpn_to_ovn(evpn_devices.vrf_name, evpn_devices.veth_vrf,
                                  evpn_devices.veth_ovs, ips, datapath_bridge,
                                  evpn_info['vni'], evpn_devices.vlan_name,
                                  vlan_tag)

        ips_without_mask = [ip.split("/")[0] for ip in ips]
        nei_dev = evpn_devices.vlan_name if vlan_tag else evpn_devices.veth_vrf
        for ip in ips_without_mask:
            linux_net.add_ip_nei(
                ip, self.ovn_local_cr_lrps[cr_lrp_port_name]['mac'], nei_dev)

        # Check if there are networks attached to the router,
        # and if so, add the needed routes/rules
        lrp_ports = self.sb_idl.get_lrp_ports_for_router(
            cr_lrp_port.datapath)
        for lrp in lrp_ports:
            if lrp.chassis or "chassis-redirect-port" in lrp.options.keys():
                continue
            self._ensure_network_exposed(
                lrp, self.ovn_local_cr_lrps[cr_lrp_port_name])

    @lockutils.synchronized('evpn')
    def withdraw_ip(self, row, cr_lrp=False):
        '''Withdraw BGP route through EVPN.

        This methods ensures BGP withdraw the IP advertised through the
        required VRF/Tenant by using the specified VNI/VXLAN id.

        It relies on Zebra, which cwithdraws the advertisement as son as the
        IP is deleted from the interface in the related VRF.
        '''
        if cr_lrp:
            cr_lrp_port_name = row.logical_port
        else:
            cr_lrp_port_name = 'cr-lrp-' + row.logical_port

        cr_lrp_info = self.ovn_local_cr_lrps.get(cr_lrp_port_name, {})
        if not cr_lrp_info:
            # This means it is in a different chassis
            return
        cr_lrp_datapath = cr_lrp_info.get('provider_datapath')
        if not cr_lrp_datapath:
            return

        ips = cr_lrp_info.get('ips')
        evpn_vni = cr_lrp_info.get('vni')
        if not evpn_vni:
            LOG.debug("No EVPN information for CR-LRP Port with IPs %s. "
                      "No need to withdraw it.", ips)
            return

        LOG.info("Delete BGP route for CR-LRP Port %s on VNI %s", ips,
                 evpn_vni)
        datapath_bridge, vlan_tag = self._get_bridge_for_datapath(
            cr_lrp_datapath)

        if vlan_tag:
            self._disconnect_evpn_from_ovn(evpn_vni, datapath_bridge, ips,
                                           vlan_tag=vlan_tag)
        else:
            cr_lrps_on_same_provider = [
                p for p in self.ovn_local_cr_lrps.values()
                if p['provider_datapath'] == cr_lrp_datapath]
            if (len(cr_lrps_on_same_provider) > 1):
                # NOTE: no need to remove the NDP proxy if there are other
                # cr-lrp ports on the same chassis connected to the same
                # provider flat network
                self._disconnect_evpn_from_ovn(evpn_vni, datapath_bridge, ips,
                                               cleanup_ndp_proxy=False)
            else:
                self._disconnect_evpn_from_ovn(evpn_vni, datapath_bridge, ips)

        nei_dev = cr_lrp_info['vlan'] if vlan_tag else cr_lrp_info['veth_vrf']
        for ip in ips:
            linux_net.del_ip_nei(ip, cr_lrp_info['mac'], nei_dev)

        self._remove_evpn_devices(evpn_vni)
        ovs.remove_evpn_router_ovs_flows(datapath_bridge,
                                         constants.OVS_VRF_RULE_COOKIE,
                                         cr_lrp_info.get('mac'))

        evpn_info = {'vni': evpn_vni, 'bgp_as': cr_lrp_info.get('bgp_as')}
        frr.vrf_reconfigure(evpn_info, action="del-vrf")

        try:
            del self.ovn_local_cr_lrps[cr_lrp_port_name]
        except KeyError:
            LOG.debug("Gateway port already cleanup from the agent: %s",
                      cr_lrp_port_name)

    @lockutils.synchronized('evpn')
    def expose_remote_ip(self, ips, row):
        if self.sb_idl.is_provider_network(row.datapath):
            return
        port_lrps = self.sb_idl.get_lrps_for_datapath(row.datapath)
        for port_lrp in port_lrps:
            if port_lrp in self.ovn_local_lrps.keys():
                evpn_info = self.sb_idl.get_evpn_info_from_port_name(port_lrp)
                if not evpn_info:
                    LOG.debug("No EVPN information for LRP Port %s. "
                              "Not exposing IPs: %s.", port_lrp, ips)
                    continue
                LOG.info("Add BGP route for tenant IP %s on chassis %s",
                         ips, self.chassis)
                lo_name = constants.OVN_EVPN_LO_PREFIX + str(evpn_info['vni'])
                linux_net.add_ips_to_dev(
                    lo_name, ips, clear_local_route_at_table=evpn_info['vni'])
                self._ovn_exposed_evpn_ips.setdefault(
                    lo_name, []).extend(ips)

    @lockutils.synchronized('evpn')
    def withdraw_remote_ip(self, ips, row):
        if self.sb_idl.is_provider_network(row.datapath):
            return
        port_lrps = self.sb_idl.get_lrps_for_datapath(row.datapath)
        for port_lrp in port_lrps:
            if port_lrp in self.ovn_local_lrps.keys():
                evpn_info = self.sb_idl.get_evpn_info_from_port_name(port_lrp)
                if not evpn_info:
                    LOG.debug("No EVPN information for LRP Port %s. "
                              "Not withdrawing IPs: %s.", port_lrp, ips)
                    continue
                LOG.info("Delete BGP route for tenant IP %s on chassis %s",
                         ips, self.chassis)
                lo_name = constants.OVN_EVPN_LO_PREFIX + str(evpn_info['vni'])
                linux_net.del_ips_from_dev(lo_name, ips)

    @lockutils.synchronized('evpn')
    def expose_subnet(self, row):
        evpn_info = self.sb_idl.get_evpn_info(row)
        ip = self.sb_idl.get_ip_from_port_peer(row)
        if not evpn_info:
            LOG.debug("No EVPN information for LRP Port %s. "
                      "Not exposing IPs: %s.", row.logical_port, ip)
            return

        lrp_logical_port = 'lrp-' + row.logical_port
        lrp_datapath = self.sb_idl.get_port_datapath(lrp_logical_port)

        cr_lrp = self.sb_idl.is_router_gateway_on_chassis(lrp_datapath,
                                                          self.chassis)
        if not cr_lrp:
            return

        LOG.info("Add IP Routes for network %s on chassis %s", ip,
                 self.chassis)
        self.ovn_local_lrps[lrp_logical_port] = {
            'datapath': lrp_datapath,
            'ip': ip
            }

        cr_lrp_info = self.ovn_local_cr_lrps.get(cr_lrp, {})
        cr_lrp_datapath = cr_lrp_info.get('provider_datapath')
        if not cr_lrp_datapath:
            LOG.info("Subnet not connected to the provider network. "
                     "No need to expose it through EVPN")
            return
        if (evpn_info['bgp_as'] != cr_lrp_info.get('bgp_as') or
                evpn_info['vni'] != cr_lrp_info.get('vni')):
            LOG.error("EVPN information at router port (vni: %s, as: %s) does"
                      " not match with information at subnet gateway port:"
                      " %s", cr_lrp_info.get('vni'),
                      cr_lrp_info.get('bgp_as'), evpn_info)
            return

        cr_lrp_ips = [ip_address.split('/')[0]
                      for ip_address in cr_lrp_info.get('ips', [])]
        datapath_bridge, vlan_tag = self._get_bridge_for_datapath(
            cr_lrp_datapath)

        self._expose_subnet(ip, cr_lrp_ips, cr_lrp_info, datapath_bridge,
                            vlan_tag, row.datapath)

    def _expose_subnet(self, router_interface, cr_lrp_ips, cr_lrp_info,
                       datapath_bridge, vlan_tag, network_datapath):
        router_interface_ip_version = linux_net.get_ip_version(
            router_interface)
        if vlan_tag:
            dev = cr_lrp_info['vlan']
            dev_ovs = dev
            strip_vlan = True
        else:
            dev = cr_lrp_info['veth_vrf']
            dev_ovs = cr_lrp_info['veth_ovs']
            strip_vlan = False

        for cr_lrp_ip in cr_lrp_ips:
            if (linux_net.get_ip_version(cr_lrp_ip) ==
                    router_interface_ip_version):
                linux_net.add_ip_route(
                    self._ovn_routing_tables_routes,
                    router_interface.split("/")[0],
                    cr_lrp_info['vni'],
                    dev,
                    mask=router_interface.split("/")[1],
                    via=cr_lrp_ip)
                break

        if router_interface_ip_version == constants.IP_VERSION_6:
            net_ip = '{}'.format(ipaddress.IPv6Network(
                router_interface, strict=False))
        else:
            net_ip = '{}'.format(ipaddress.IPv4Network(
                router_interface, strict=False))

        # NOTE(ltomasbo): strip_vlan is used for subnets/routers associated to
        # provider vlan networks assuming the EVPN VXLAN header is replacing
        # the vlan id in the fabric. If that is not the case, we could simply
        # set this to False in all the cases and have the traffic sent with
        # both vxlan header (for the EVPN) plus the vlan header (related to
        # the provider vlan id being used)
        ovs.ensure_evpn_ovs_flow(datapath_bridge,
                                 constants.OVS_VRF_RULE_COOKIE,
                                 cr_lrp_info['mac'],
                                 dev_ovs,
                                 dev,
                                 net_ip,
                                 strip_vlan=strip_vlan)

        # Check if there are VMs on the network
        # and if so expose the route
        if not network_datapath:
            return
        ports = self.sb_idl.get_ports_on_datapath(
            network_datapath)
        for port in ports:
            if (port.type not in (constants.OVN_VM_VIF_PORT_TYPE,
                                  constants.OVN_VIRTUAL_VIF_PORT_TYPE) or
                (port.type == constants.OVN_VM_VIF_PORT_TYPE and
                 not port.chassis)):
                continue
            try:
                port_ips = port.mac[0].strip().split(' ')[1:]
            except IndexError:
                continue

            for port_ip in port_ips:
                # Only adding the port ips that match the lrp
                # IP version
                port_ip_version = linux_net.get_ip_version(port_ip)
                if port_ip_version == router_interface_ip_version:
                    linux_net.add_ips_to_dev(
                        cr_lrp_info['lo'], [port_ip],
                        clear_local_route_at_table=cr_lrp_info['vni'])
                    self._ovn_exposed_evpn_ips.setdefault(
                        cr_lrp_info['lo'], []).extend([port_ip])

    @lockutils.synchronized('evpn')
    def withdraw_subnet(self, row):
        lrp_logical_port = 'lrp-' + row.logical_port
        lrp_datapath = self.ovn_local_lrps.get(lrp_logical_port, {}).get(
            'datapath')
        ip = self.ovn_local_lrps.get(lrp_logical_port, {}).get('ip')
        if not lrp_datapath:
            return

        cr_lrp = self.sb_idl.is_router_gateway_on_chassis(lrp_datapath,
                                                          self.chassis)
        if not cr_lrp:
            return

        LOG.info("Delete IP Routes for network %s on chassis %s", ip,
                 self.chassis)

        cr_lrp_info = self.ovn_local_cr_lrps.get(cr_lrp, {})
        cr_lrp_datapath = cr_lrp_info.get('provider_datapath')
        if not cr_lrp_datapath:
            LOG.info("Subnet not connected to the provider network. "
                     "No need to withdraw it from EVPN")
            return
        cr_lrp_ips = [ip_address.split('/')[0]
                      for ip_address in cr_lrp_info.get('ips', [])]
        datapath_bridge, vlan_tag = self._get_bridge_for_datapath(
            cr_lrp_datapath)

        if vlan_tag:
            dev = cr_lrp_info['vlan']
        else:
            dev = cr_lrp_info['veth_vrf']

        ip_version = linux_net.get_ip_version(ip)
        for cr_lrp_ip in cr_lrp_ips:
            if linux_net.get_ip_version(cr_lrp_ip) == ip_version:
                linux_net.del_ip_route(
                    self._ovn_routing_tables_routes,
                    ip.split("/")[0],
                    cr_lrp_info['vni'],
                    dev,
                    mask=ip.split("/")[1],
                    via=cr_lrp_ip)
                if (linux_net.get_ip_version(cr_lrp_ip) ==
                        constants.IP_VERSION_6):
                    net = ipaddress.IPv6Network(ip, strict=False)
                else:
                    net = ipaddress.IPv4Network(ip, strict=False)
                break

        ovs.remove_evpn_network_ovs_flow(datapath_bridge,
                                         constants.OVS_VRF_RULE_COOKIE,
                                         cr_lrp_info['mac'],
                                         '{}'.format(net))

        # Check if there are VMs on the network
        # and if so withdraw the routes
        vms_on_net = linux_net.get_exposed_ips_on_network(
            cr_lrp_info['lo'], net)
        linux_net.delete_exposed_ips(vms_on_net,
                                     cr_lrp_info['lo'])

        try:
            del self.ovn_local_lrps[lrp_logical_port]
        except KeyError:
            LOG.debug("Router Interface port already cleanup from the agent "
                      "%s", lrp_logical_port)

    def _ensure_evpn_devices(self, datapath_bridge, vni, vlan_tag):
        '''Create the needed devices for EVPN connectivity

        This method creates and associate the needed devices for EVPN
        connectivity. It creates:
        - VRF device
        - Linux Bridge device, associated to the VRF
        - VXLAN device, using loopback IP, associate to the bridge
        - Dummy device to expose the IPs, associated to the VRF
        - If vlan_tag, create vlan device on OVS bridge, associated to the VRF
        - If no vlan_tag, create veth pair, one end associated to the VRF

        param datapath_bridge: OVS bridge to connect the vlan device
        param vni: VNI number to use for vxlan tunnel ids and vrf routing table
        param vlan_tag: vlan id to use for connectivity

        return: a namedtuple with the name of the devices created: vrf_name,
        lo_name, bridge_name, vxlan_name, veth_vrf, veth_ovs, and vlan_name.
        '''
        # ensure vrf device.
        # NOTE: It uses vni id as table number
        vrf_name = constants.OVN_EVPN_VRF_PREFIX + str(vni)
        linux_net.ensure_vrf(vrf_name, vni)

        # ensure bridge device
        bridge_name = constants.OVN_EVPN_BRIDGE_PREFIX + str(vni)
        linux_net.ensure_bridge(bridge_name)
        # connect bridge to vrf
        linux_net.set_master_for_device(bridge_name, vrf_name)

        # ensure vxlan device
        vxlan_name = constants.OVN_EVPN_VXLAN_PREFIX + str(vni)

        local_ip = CONF.evpn_local_ip
        if not local_ip:
            local_nic = 'lo'
            prefixlen_filter = 32  # assuming IPv4
            if CONF.evpn_nic:
                local_nic = CONF.evpn_nic
                prefixlen_filter = False
            # NOTE(ltomasbo): assuming only 1 IP on the device with /32 prefix
            local_ip = linux_net.get_nic_ip(local_nic, prefixlen_filter)[0]

        if not local_ip:
            LOG.error("EVPN device must have an IP associated for the "
                      "VXLAN local ip")
            return None, None
        linux_net.ensure_vxlan(vxlan_name, vni, local_ip,
                               CONF.evpn_udp_dstport)
        # connect vxlan to bridge
        linux_net.set_master_for_device(vxlan_name, bridge_name)

        # ensure dummy lo interface
        lo_name = constants.OVN_EVPN_LO_PREFIX + str(vni)
        linux_net.ensure_dummy_device(lo_name)
        # connect dummy to vrf
        linux_net.set_master_for_device(lo_name, vrf_name)

        if vlan_tag:
            vlan_name = constants.OVN_EVPN_VLAN_PREFIX + str(vni)
            # add vlan port to OVS bridge
            ovs.add_vlan_port_to_ovs_bridge(datapath_bridge, vlan_name,
                                            vlan_tag)
            linux_net.set_device_status(vlan_name, constants.LINK_UP)
            # connect vlan to vrf
            linux_net.set_master_for_device(vlan_name, vrf_name)
            # ensure proxy NDP is enabled for ipv6 traffic
            linux_net.enable_proxy_ndp(vlan_name)

            return EVPN_INFO(vrf_name, lo_name, bridge_name, vxlan_name, None,
                             None, vlan_name)
        else:
            # ensure veth-pair interfaces
            veth_vrf = constants.OVN_EVPN_VETH_VRF_PREFIX + str(vni)
            veth_ovs = constants.OVN_EVPN_VETH_OVS_PREFIX + str(vni)
            linux_net.ensure_veth(veth_vrf, veth_ovs)
            # connect veth to vrf
            linux_net.set_master_for_device(veth_vrf, vrf_name)

            return EVPN_INFO(vrf_name, lo_name, bridge_name, vxlan_name,
                             veth_vrf, veth_ovs, None)

    def _remove_evpn_devices(self, vni):
        vrf_name = constants.OVN_EVPN_VRF_PREFIX + str(vni)
        bridge_name = constants.OVN_EVPN_BRIDGE_PREFIX + str(vni)
        vxlan_name = constants.OVN_EVPN_VXLAN_PREFIX + str(vni)
        lo_name = constants.OVN_EVPN_LO_PREFIX + str(vni)
        veth_name = constants.OVN_EVPN_VETH_VRF_PREFIX + str(vni)
        vlan_name = constants.OVN_EVPN_VLAN_PREFIX + str(vni)

        for device in [lo_name, vrf_name, bridge_name, vxlan_name, veth_name,
                       vlan_name]:
            linux_net.delete_device(device)

    def _connect_evpn_to_ovn(self, vrf, veth_vrf, veth_ovs, ips,
                             datapath_bridge, vni, vlan, vlan_tag):
        # NOTE(ltomasbo): vlan device is already attached to ovs bridge
        # when created
        if not vlan_tag:
            # add veth to ovs bridge
            ovs.add_device_to_ovs_bridge(veth_ovs, datapath_bridge)

        # add route for ip to ovs provider bridge (at the vrf routing table)
        for ip in ips:
            ip_without_mask = ip.split("/")[0]
            if vlan_tag:
                # ip route add GW_PORT_IP dev VLAN_DEVICE table VRF_TABLE_ID
                linux_net.add_ip_route(
                    self._ovn_routing_tables_routes, ip_without_mask,
                    vni, vlan)
                # add proxy ndp config for ipv6
                if (linux_net.get_ip_version(ip_without_mask) ==
                        constants.IP_VERSION_6):
                    linux_net.add_ndp_proxy(ip, vlan)
            else:
                linux_net.add_ip_route(
                    self._ovn_routing_tables_routes, ip_without_mask,
                    vni, veth_vrf)
                # add proxy ndp config for ipv6
                if (linux_net.get_ip_version(ip_without_mask) ==
                        constants.IP_VERSION_6):
                    linux_net.add_ndp_proxy(ip, datapath_bridge)

        # add unreachable route to vrf
        linux_net.add_unreachable_route(vrf)

    def _disconnect_evpn_from_ovn(self, vni, datapath_bridge, ips,
                                  vlan_tag=None, cleanup_ndp_proxy=True):
        if vlan_tag:
            # remove vlan from ovs bridge
            device = constants.OVN_EVPN_VLAN_PREFIX + str(vni)
        else:
            # remove veth from ovs bridge
            device = constants.OVN_EVPN_VETH_OVS_PREFIX + str(vni)
        ovs.del_device_from_ovs_bridge(device, datapath_bridge)

        linux_net.delete_routes_from_table(vni)

        if cleanup_ndp_proxy:
            for ip in ips:
                if linux_net.get_ip_version(ip) == constants.IP_VERSION_6:
                    linux_net.del_ndp_proxy(ip, datapath_bridge)

    def _remove_extra_vrfs(self):
        vrfs, los, bridges, vxlans, veths, vlans = ([], [], [], [], [], [])
        for cr_lrp_info in self.ovn_local_cr_lrps.values():
            vrfs.append(cr_lrp_info['vrf'])
            los.append(cr_lrp_info['lo'])
            bridges.append(cr_lrp_info['bridge'])
            vxlans.append(cr_lrp_info['vxlan'])
            veths.append(cr_lrp_info['veth_vrf'])
            vlans.append(cr_lrp_info['vlan'])

        filter_out = ["{}.{}".format(key, value[0]['vlan'])
                      for key, value in self._ovn_routing_tables_routes.items()
                      if value[0]['vlan']]

        interfaces = linux_net.get_interfaces(filter_out)
        for interface in interfaces:
            if (interface.startswith(constants.OVN_EVPN_VRF_PREFIX) and
                    interface not in vrfs):
                linux_net.delete_device(interface)
            elif (interface.startswith(constants.OVN_EVPN_LO_PREFIX) and
                    interface not in los):
                linux_net.delete_device(interface)
            elif (interface.startswith(constants.OVN_EVPN_BRIDGE_PREFIX) and
                    (interface not in bridges and
                     interface != constants.OVN_INTEGRATION_BRIDGE and
                     interface not in set(self.ovn_bridge_mappings.values()))):
                linux_net.delete_device(interface)
            elif (interface.startswith(constants.OVN_EVPN_VXLAN_PREFIX) and
                    interface not in vxlans):
                linux_net.delete_device(interface)
            elif (interface.startswith(constants.OVN_EVPN_VETH_VRF_PREFIX) and
                    interface not in veths):
                linux_net.delete_device(interface)
                ovs.del_device_from_ovs_bridge(interface)
            elif (interface.startswith(constants.OVN_EVPN_VLAN_PREFIX) and
                    interface not in vlans):
                ovs.del_device_from_ovs_bridge(interface)

    def _remove_extra_routes(self):
        table_ids = self._get_table_ids()
        vrf_routes = linux_net.get_routes_on_tables(table_ids)
        if not vrf_routes:
            return
        # remove from vrf_routes the routes that should be kept
        for device, routes_info in self._ovn_routing_tables_routes.items():
            for route_info in routes_info:
                oif = linux_net.get_interface_index(device)
                if 'gateway' in route_info['route'].keys():  # subnet route
                    possible_matchings = [
                        r for r in vrf_routes
                        if (r.get('dst') == route_info['route']['dst'] and
                            r['dst_len'] == route_info['route']['dst_len'] and
                            r.get('gateway') == (
                                route_info['route']['gateway']) and
                            r['table'] == route_info['route']['table'])]
                else:  # cr-lrp
                    possible_matchings = [
                        r for r in vrf_routes
                        if (r.get('dst') == route_info['route']['dst'] and
                            r['dst_len'] == route_info['route']['dst_len'] and
                            r.get('oif') == oif and
                            r['table'] == route_info['route']['table'])]
                for r in possible_matchings:
                    vrf_routes.remove(r)

        linux_net.delete_ip_routes(vrf_routes)

    def _remove_extra_ovs_flows(self):
        cr_lrp_mac_mappings = self._get_cr_lrp_mac_mapping()
        cookie_id = "cookie={}/-1".format(constants.OVS_VRF_RULE_COOKIE)
        for bridge in set(self.ovn_bridge_mappings.values()):
            current_flows = ovs.get_bridge_flows(bridge, filter_=cookie_id)
            for flow in current_flows:
                flow_info = ovs.get_flow_info(flow)
                if not flow_info.get('mac'):
                    ovs.del_flow(flow, bridge, constants.OVS_VRF_RULE_COOKIE)
                elif flow_info['mac'] not in cr_lrp_mac_mappings.keys():
                    ovs.del_flow(flow, bridge, constants.OVS_VRF_RULE_COOKIE)
                elif flow_info['port']:
                    if (not flow_info.get('nw_src') and not
                            flow_info.get('ipv6_src')):
                        ovs.del_flow(flow, bridge,
                                     constants.OVS_VRF_RULE_COOKIE)
                    else:
                        dev_info = cr_lrp_mac_mappings[flow_info['mac']]
                        if dev_info.get('vlan'):
                            dev = dev_info['vlan']
                            dev_ovs = dev
                        else:
                            dev = dev_info['veth_vrf']
                            dev_ovs = dev_info['veth_ovs']
                        dev_ovs_port = ovs.get_device_port_at_ovs(
                            dev_ovs)

                        if dev_ovs_port != flow_info['port']:
                            ovs.del_flow(flow, bridge,
                                         constants.OVS_VRF_RULE_COOKIE)
                        nw_src_ip = nw_src_mask = None
                        matching_dst = False
                        if flow_info.get('nw_src'):
                            nw_src_ip = flow_info['nw_src'].split('/')[0]
                            nw_src_mask = int(
                                flow_info['nw_src'].split('/')[1])
                        elif flow_info.get('ipv6_src'):
                            nw_src_ip = flow_info['ipv6_src'].split('/')[0]
                            nw_src_mask = int(
                                flow_info['ipv6_src'].split('/')[1])

                        for route_info in self._ovn_routing_tables_routes[
                                dev]:
                            if (route_info['route']['dst'] == nw_src_ip and
                                    route_info['route'][
                                        'dst_len'] == nw_src_mask):
                                matching_dst = True
                        if not matching_dst:
                            ovs.del_flow(flow, bridge,
                                         constants.OVS_VRF_RULE_COOKIE)

    def _remove_extra_exposed_ips(self):
        for lo, ips in self._ovn_exposed_evpn_ips.items():
            exposed_ips_on_device = linux_net.get_exposed_ips(lo)
            for ip in exposed_ips_on_device:
                if ip not in ips:
                    linux_net.del_ips_from_dev(lo, [ip])

    def _get_table_ids(self):
        table_ids = []
        for cr_lrp_info in self.ovn_local_cr_lrps.values():
            table_ids.append(cr_lrp_info['vni'])
        return table_ids

    def _get_cr_lrp_mac_mapping(self):
        mac_mappings = {}
        for cr_lrp_info in self.ovn_local_cr_lrps.values():
            mac_mappings[cr_lrp_info['mac']] = {
                'veth_vrf': cr_lrp_info['veth_vrf'],
                'veth_ovs': cr_lrp_info['veth_ovs'],
                'vlan': cr_lrp_info['vlan']}
        return mac_mappings

# Copyright 2024 team.blue/nl
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
import netaddr

from oslo_config import cfg
from oslo_log import log as logging

from ovn_bgp_agent import constants
from ovn_bgp_agent.drivers.openstack.utils import driver_utils
from ovn_bgp_agent.drivers.openstack.utils import frr
from ovn_bgp_agent.drivers.openstack.utils import ovs
from ovn_bgp_agent import exceptions
from ovn_bgp_agent.utils import linux_net

CONF = cfg.CONF
LOG = logging.getLogger(__name__)

# dictionary to hold all evpn bridge classes
local_bridges: 'dict[str, EvpnBridge]' = {}

# dictionary to hold all vlandev mappings, based on port uuid
local_vlandevs: 'dict[str, VlanDev]' = {}


class EvpnBridge:
    def __init__(self, ovs_bridge: str, vni: int, evpn_opts: dict,
                 mode=constants.OVN_EVPN_TYPE_L3, ovs_flows: dict = None):

        if not CONF.evpn_local_ip:
            LOG.error("EVPN device must have an IP associated for the "
                      "VXLAN local ip")
            raise exceptions.ConfOptionRequired(option='evpn_local_ip')

        self.ovs_bridge = ovs_bridge
        self.vni = vni
        self.mode = mode
        self.ovs_flows = ovs_flows or {}

        self.vrf_name = '%s%s' % (constants.OVN_EVPN_VRF_PREFIX, vni)
        self.bridge_name = '%s%s' % (constants.OVN_EVPN_BRIDGE_PREFIX, vni)
        self.vxlan_name = '%s%s' % (constants.OVN_EVPN_VXLAN_PREFIX, vni)
        self.local_ip = CONF.evpn_local_ip
        self.evpn_opts = dict(
            vni=self.vni,
            local_ip=self.local_ip,
            vrf_name=self.vrf_name,
            redistribute=['connected', 'kernel'],
        )
        self.evpn_opts.update(evpn_opts)

        self.vlans: dict[str, 'VlanDev'] = {}
        self._setup_done = False

    def setup(self):
        if self._setup_done:
            return

        LOG.debug('Creating bridge %s', self.bridge_name)
        linux_net.ensure_bridge(self.bridge_name)

        LOG.debug('Creating vxlan interface %s for vni %s with local ip %s',
                  self.vxlan_name, self.vni, self.local_ip)
        linux_net.ensure_vxlan(self.vxlan_name, self.vni, self.local_ip,
                               CONF.evpn_udp_dstport)

        LOG.debug('Connect vxlan interface %s to bridge %s',
                  self.vxlan_name, self.bridge_name)
        linux_net.set_master_for_device(self.vxlan_name, self.bridge_name)

        LOG.debug('Disable learning for vxlan device %s', self.vxlan_name)
        linux_net.disable_learning_vxlan_intf(self.vxlan_name)

        LOG.debug('Configure FRR VRF (add)')
        frr.vrf_reconfigure(self.evpn_opts, 'add-vrf')

        if self.mode == constants.OVN_EVPN_TYPE_L3:
            LOG.debug('Create L3 EVPN devices')
            linux_net.ensure_vrf(self.vrf_name, self.vni)

            LOG.debug('Attach bridge %s to vrf %s',
                      self.bridge_name, self.vrf_name)
            linux_net.set_master_for_device(self.bridge_name, self.vrf_name)

        self._setup_done = True

    def _eval_disconnect(self):
        if not self._setup_done:
            return

        connected = [1 for v in self.vlans.values() if v._setup_done]
        if len(connected) == 0:
            # All vlan interfaces are unprovisioned, proceed with disconnect
            return self.disconnect()

        LOG.debug('No disconnect needed, there are still %s vlans active',
                  len(connected))

    def disconnect(self):
        LOG.info('Disconnecting evpn bridge %s',
                 self.vrf_name)

        disconnect_devices = [self.bridge_name, self.vxlan_name]
        if CONF.delete_vrf_on_disconnect:
            disconnect_devices.append(self.vrf_name)

        for devname in disconnect_devices:
            LOG.info('Delete device %s', devname)
            linux_net.delete_device(devname)

        if CONF.delete_vrf_on_disconnect:
            # We need to do the frr reconfigure after deleting all devices.
            # otherwise, frr will throw an error that it can only delete
            # inactive vrf's
            LOG.debug('Configure FRR VRF (del)')
            frr.vrf_reconfigure(self.evpn_opts, action="del-vrf")

        self._setup_done = False

    def connect_vlan(self, port):
        vlan_tag = driver_utils.get_port_vlan(port)
        if vlan_tag not in self.vlans:
            self.vlans[vlan_tag] = VlanDev(self, port)

        return self.vlans[vlan_tag]

    def get_vlan(self, vlan: 'int|str|None') -> 'VlanDev':
        if vlan is None:
            vlan = constants.VLAN_ID_UNTAGGED

        return self.vlans[str(vlan)]


class VlanDev:
    def __init__(self, bridge: 'EvpnBridge', port):
        self.bridge = bridge
        self.port = port  # localnet port

        uuid = str(port.uuid)[0:11]
        self.veth_vrf = constants.OVN_EVPN_VETH_VRF_UUID_PREFIX + uuid
        self.veth_ovs = constants.OVN_EVPN_VETH_OVS_UUID_PREFIX + uuid

        if uuid in local_vlandevs:
            # It already exists, but probably in another vni
            local_vlandevs[uuid].teardown()

        local_vlandevs[uuid] = self

        self.vlan_tag = driver_utils.get_port_vlan(port)

        # Will be filled by the @property with the mac address of
        # the vrf-vlan interface
        self._lladdr = None

        # boolean to indicate if setup is required for this interface
        self._setup_done = False
        self._veth_created = False

        # list of custom addresses to use during setup, before adding the
        # 169.254.x.x address, making another possibly public ip the
        # primary ip in traceroutes
        self._custom_ips = set()

        # list with tuple of (task, args, kwargs) we should execute once the
        # setup has completed. For example to run frr config for
        # ipv6 neighbor discovery, or to add ip's to the interface.
        self._post_setup_tasks = []

        self._agent_routing_tables_routes = collections.defaultdict(list)
        self._route_table_routes = {}

    def _set_agent_cache(self, routing_tables_routes):
        if routing_tables_routes is not None:
            self._agent_routing_tables_routes = (
                routing_tables_routes[self.veth_vrf])

    @property
    def lladdr(self):
        if not self._lladdr:
            if not self._veth_created:
                self.setup()
            self._lladdr = linux_net.get_interface_address(self.veth_vrf)
        return self._lladdr

    def setup(self):
        if self._setup_done:
            return

        # Run the setup of the bridge.
        self.bridge.setup()

        LOG.debug('Create VLAN veth interface %s <-> %s',
                  self.veth_vrf, self.veth_ovs)
        linux_net.ensure_veth(self.veth_vrf, self.veth_ovs)
        self._veth_created = True

        # Connect the veth_ovs to ovs
        ovs_vlan_tag = self.vlan_tag
        if self.vlan_tag == '0':
            ovs_vlan_tag = None

        ovs.add_device_to_ovs_bridge(self.veth_ovs,
                                     self.bridge.ovs_bridge,
                                     vlan_tag=ovs_vlan_tag)

        # Connect veth to bridge for L2
        if self.bridge.mode == constants.OVN_EVPN_TYPE_L2:
            linux_net.set_master_for_device(self.veth_vrf,
                                            self.bridge.bridge_name)
            self._setup_done = True
            return

        # Connect veth to vrf for L3
        # Create vrf interface, connect bridge and veth_vrf to it.
        LOG.debug('Configure L3 for EVPN devices')
        linux_net.set_master_for_device(self.veth_vrf, self.bridge.vrf_name)

        if self._custom_ips:
            linux_net.add_ips_to_dev(self.veth_vrf, ips=list(self._custom_ips))

        # Add 169.254.x.x address to veth_vrf for ipv4 and ipv6
        linux_net.ensure_arp_ndp_enabled_for_bridge(
            self.veth_vrf, offset=int(self.vlan_tag), vlan_tag=self.vlan_tag
        )

        # Configure mac on the veth interface to be the same on all hosts
        offset = _offset_for_vni_and_vlan(self.bridge.vni, self.vlan_tag)
        linux_net.ensure_anycast_mac_for_interface(
            self.veth_vrf, offset=offset
        )

        # Make sure ipv4 and ipv6 forwarding is enabled
        linux_net.enable_routing_for_interfaces(self.veth_vrf,
                                                self.bridge.bridge_name)

        # As long as we use 169.254.x.x addresses, we require proxy arp to be
        # there for initial router discovery
        linux_net.enable_proxy_arp(self.veth_vrf)
        linux_net.enable_proxy_ndp(self.veth_vrf)

        ovs_ok = self._setup_ovs()
        if ovs_ok is False:
            LOG.error('Unable to setup ovs, a retry will pick it up.')
            return

        # Any post-setup tasks to run.
        for method, a, kw in self._post_setup_tasks:
            method(*a, **kw)

        self._setup_done = True

    def _setup_ovs(self):
        try:
            in_port = ovs.get_ovs_patch_port_ofport(self.port.name)
            LOG.debug('ovs in-port: %s', in_port)
        except Exception:
            return False

        ovs_flows = self.bridge.ovs_flows
        ovs_bridge = self.bridge.ovs_bridge

        pmm = ovs_flows[ovs_bridge].setdefault('port-mac-mapping', {})
        pmm[in_port] = self.lladdr

        ovs.ensure_mac_tweak_flows(ovs_bridge,
                                   self.lladdr,
                                   [in_port],
                                   constants.OVS_RULE_COOKIE)

        ovs.remove_extra_ovs_flows(ovs_flows, ovs_bridge,
                                   constants.OVS_RULE_COOKIE)

    def _eval_disconnect(self):
        if not self._setup_done:
            return

        if len(self._agent_routing_tables_routes) == 0:
            return self.disconnect()

        LOG.debug('No disconnect needed, there are still %s announcements',
                  len(self._agent_routing_tables_routes))

    def disconnect(self):
        LOG.info('Disconnecting vlan interface %s.%s',
                 self.bridge.vrf_name, self.vlan_tag)

        LOG.info('Remove device %s from ovs bridge %s', self.veth_ovs,
                 self.bridge.ovs_bridge)
        ovs.del_device_from_ovs_bridge(self.veth_ovs,
                                       self.bridge.ovs_bridge)

        LOG.info('Delete device %s', self.veth_vrf)
        linux_net.delete_device(self.veth_vrf)

        self._veth_created = False
        self._setup_done = False
        self.bridge._eval_disconnect()

    def teardown(self):
        LOG.info('Running teardown for vlandev %s (vni change)', self.veth_vrf)
        self.disconnect()
        del self.bridge.vlans[self.vlan_tag]

    def _run(self, method, *a, **kw):
        # Run the method if setup is done, otherwise, run them when setup
        # is called
        if not self._setup_done:
            self._post_setup_tasks.append([method, a, kw])
        else:
            method(*a, **kw)

    def process_dhcp_opts(self, dhcp_opts):
        '''Add IP's or router advertisements from configured dhcp options

        For networks that have DHCP enabled (and have lsp with dhcp options),
        we can add the IP of the gateway on our vlan interface. Then OVN is
        able to discover the IP.

        Also if IPv6 is configured, we should enable router advertisements
        through FRR (since it has it built-in anyway), so vm's can then
        receive the router information from the 'provider' side.
        '''

        for opt in dhcp_opts:
            ver = netaddr.IPNetwork(opt.cidr).version

            if opt.options.get('router', False):
                LOG.debug('Adding IPv%s gateway ip: %s',
                          ver, opt.options['router'])
                self.add_ips([opt.options['router']])

            if ver == 6 and opt.cidr:
                LOG.debug('Configure ipv6nd for %s and opts %s',
                          opt.cidr, opt.options)
                self.configure_nd(opt.cidr, opts=opt.options)

    def configure_nd(self, cidr, opts):
        self._run(frr.nd_reconfigure, self.veth_vrf, cidr, opts)

    def add_ips(self, ips: list):
        self._custom_ips.update(ips)
        self._run(linux_net.add_ips_to_dev, self.veth_vrf, ips=ips)

    def add_route(self, routing_tables_routes: 'dict | None', ip: str,
                  mac: 'str | None', via: 'str | None' = None):
        '''Will add route to the routing table for this vlan_dev

        Please make sure pass along the routing_tables_routes dictionary at
        least the first time a route is added (for example when exposing the
        lrp or lsp). Then with a expose_remote_ip we can re-use the reference
        from the agent set earlier.
        '''
        self.setup()  # setup the bridge and vlan, if not already done.
        self._set_agent_cache(routing_tables_routes)

        if self.bridge.mode != constants.OVN_EVPN_TYPE_L3:
            return

        mask = None
        if '/' in ip:
            ip, mask = ip.split('/')

        self._agent_routing_tables_routes.append({
            'ip': ip, 'mask': mask, 'mac': mac, 'via': via,
        })
        LOG.debug('Add route %s/%s via %s dev %s table %s',
                  ip, mask, via, self.veth_vrf, self.bridge.vni)
        linux_net.add_ip_route(self._route_table_routes, ip, self.bridge.vni,
                               self.veth_vrf, mask=mask, via=via)

        # When a floating ip is passed along, it is a set of mac
        # addresses, so ensure we are always processing a list.
        for lladdr in _ensure_list(mac):
            LOG.debug('Add neigh %s -> %s dev %s', ip, mac, self.veth_vrf)
            linux_net.add_ip_nei(ip, lladdr, self.veth_vrf)

    def del_route(self, routing_tables_routes: 'dict | None', ip: str,
                  lladdr: 'str | None' = None):
        '''Will remove the route from the routing table for this vlan_dev

        Please make sure pass along the routing_tables_routes dictionary at
        least the first time a route is added (for example when exposing the
        lrp or lsp). Then with a withdraw_remote_ip we can re-use the reference
        from the agent set earlier.

        lladdr is optional, as it will be fetched from the internal
        route table dictionary
        '''

        if self.bridge.mode != constants.OVN_EVPN_TYPE_L3:
            return
        self._set_agent_cache(routing_tables_routes)

        # When a floating ip is passed along, it is a set of mac
        # addresses, so ensure we are always processing a list.

        mask = None
        if '/' in ip:
            ip, mask = ip.split('/')

        route = _find_route_info(self._agent_routing_tables_routes, ip)

        # Remove route from vrf
        linux_net.del_ip_route(self._route_table_routes, ip, self.bridge.vni,
                               self.veth_vrf, mask=mask or route['mask'],
                               via=route['via'])

        # Remove any neighbor information for route.
        for mac in _ensure_list(lladdr or route['mac']):
            linux_net.del_ip_nei(ip, mac, self.veth_vrf)

        if route in self._agent_routing_tables_routes:
            self._agent_routing_tables_routes.remove(route)

        self._eval_disconnect()

    def cleanup_excessive_routes(self, routing_tables_routes: dict):
        if not self._setup_done:
            return

        self._set_agent_cache(routing_tables_routes)

        # Get all routes on host for our vrf and our veth_vrf
        intf_idx = linux_net.get_interface_index(self.veth_vrf)
        current_routes = dict([
            (r.get_attr('RTA_DST'), r)
            for r in linux_net._get_table_routes(self.bridge.vni)
            if r.get_attr('RTA_OIF') == intf_idx and
            r['type'] == constants.ROUTE_TYPE_UNICAST and
            r.get_attr('RTA_DST') not in ('fe80::') and
            not r.get_attr('RTA_DST').startswith(
                constants.NDP_IPV6_PREFIX)
        ])

        # Create set with prefixes currently on host
        prefixes = {r.get_attr('RTA_DST') for r in current_routes.values()}

        # Create set with prefixes we maintain
        exposed_prefixes = {r['ip']
                            for r in self._agent_routing_tables_routes}

        if len(prefixes - exposed_prefixes) == 0:
            LOG.debug('No excessive routes to remove.')

        for ip in prefixes - exposed_prefixes:
            LOG.info('Remove excessive route %s', ip)
            kernel_route = current_routes[ip]
            route = _find_route_info(self._agent_routing_tables_routes, ip)
            if ((route['mask'] and
                    int(route['mask']) != kernel_route['dst_len']) or
                    route['via'] != kernel_route.get_attr('RTA_GATEWAY')):
                self._agent_routing_tables_routes.append({
                    'ip': ip, 'mask': kernel_route['dst_len'], 'mac': None,
                    'via': kernel_route.get_attr('RTA_GATEWAY'),
                })

            self.del_route(routing_tables_routes, ip)


def _ensure_list(var):
    if var is None:
        return []

    if not isinstance(var, (list, tuple, set)):
        var = [var]

    return var


def _find_route_info(routes: 'list[dict]', ip: str):
    for r in routes:
        if r['ip'] == ip:
            return r

    return {'ip': ip, 'mask': None, 'mac': None, 'via': None}


def _offset_for_vni_and_vlan(vni: int, vlan: str):
    '''Generate a offset (in numeric system), based on the vni and vlan

    vni has range 1-16777214 (6 bytes)
    vlan has range 0-4094 (3 bytes)

    It will transform the vni to a 6 digit hex, append the 3 digit vlan hex
    and transform it back to a integer.
    '''
    if vni > 16777214:
        LOG.warning('Configured vni value %d is too big (range 1-16777214)',
                    vni)
        vni = vni % 0xffffff  # reset vni, to prevent overflow.

    if int(vlan) > 4094:
        LOG.warning('Configured vlan value %d is too big (range 0-4094)',
                    int(vlan))
        vlan = int(vlan) % 0xfff  # reset vlan, to prevent overflow.

    return int(''.join([
        ('%x' % vni).zfill(6),
        ('%x' % int(vlan)).zfill(4),
    ]), 16)


def setup(ovs_bridge, vni, evpn_opts, mode=constants.OVN_EVPN_TYPE_L3,
          ovs_flows={}) -> EvpnBridge:
    # This method will either create the EvpnBridge or return the one that
    # already exists for the current vni.

    vni = int(vni)  # make sure the vni is a int, for lookup purposes

    if local_bridges.get(vni, None) is None:
        local_bridges[vni] = EvpnBridge(ovs_bridge, vni, evpn_opts,
                                        mode=mode, ovs_flows=ovs_flows)
    else:
        local_bridges[vni].ovs_flows = ovs_flows

    return local_bridges[vni]


def lookup(ovs_bridge: str, vlan: str) -> EvpnBridge:
    if vlan is None:
        vlan = constants.VLAN_ID_UNTAGGED

    for br in local_bridges.values():
        if br.ovs_bridge == ovs_bridge:
            if str(vlan) in br.vlans:
                return br

    raise KeyError('Could not locate EVPN for bridge %s and/or vlan %s' % (
                   ovs_bridge, vlan))


def lookup_vlan(ovs_bridge: str, vlan: str) -> VlanDev:
    bridge = lookup(ovs_bridge, vlan)
    return bridge.get_vlan(vlan)

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

import re

from oslo_log import log as logging
from ovs.db import idl
from ovsdbapp.backend.ovs_idl import connection
from ovsdbapp.backend.ovs_idl import idlutils
from ovsdbapp.schema.open_vswitch import impl_idl as idl_ovs
import pyroute2

from ovn_bgp_agent import constants
import ovn_bgp_agent.privileged.ovs_vsctl
from ovn_bgp_agent.utils import linux_net

LOG = logging.getLogger(__name__)


def _find_ovs_port(bridge):
    # TODO(ltomasbo): What happens if there are several patch ports on the
    # same bridge?
    ovs_port = None
    ovs_ports = ovn_bgp_agent.privileged.ovs_vsctl.ovs_cmd(
        'ovs-vsctl', ['list-ports', bridge])[0].rstrip()
    for p in ovs_ports.split('\n'):
        if p.startswith(constants.OVS_PATCH_PROVNET_PORT_PREFIX):
            ovs_port = p
    return ovs_port


def get_bridge_flows(bridge, filter_=None):
    args = ['dump-flows', bridge]
    if filter_ is not None:
        args.append(filter_)
    return ovn_bgp_agent.privileged.ovs_vsctl.ovs_cmd(
        'ovs-ofctl', args)[0].split('\n')[1:-1]


def get_device_port_at_ovs(device):
    return ovn_bgp_agent.privileged.ovs_vsctl.ovs_cmd(
        'ovs-vsctl', ['get', 'Interface', device, 'ofport'])[0].rstrip()


def get_ovs_flows_info(bridge, flows_info, cookie):
    ovs_ports = ovn_bgp_agent.privileged.ovs_vsctl.ovs_cmd(
        'ovs-vsctl', ['list-ports', bridge])[0].rstrip()
    if not ovs_ports:
        flow = ("cookie={}/-1").format(cookie)
        ovn_bgp_agent.privileged.ovs_vsctl.ovs_cmd(
            'ovs-ofctl', ['del-flows', bridge, flow])
        return
    for ovs_port in ovs_ports.split("\n"):
        ovs_ofport = get_device_port_at_ovs(ovs_port)
        flows_info[bridge]['in_port'].add(ovs_ofport)


def remove_extra_ovs_flows(flows_info, cookie):
    for bridge, info in flows_info.items():
        for in_port in info.get('in_port'):
            flow = ("cookie={},priority=900,ip,in_port={},"
                    "actions=mod_dl_dst:{},NORMAL".format(
                        cookie, in_port, info['mac']))
            flow_v6 = ("cookie={},priority=900,ipv6,in_port={},"
                       "actions=mod_dl_dst:{},NORMAL".format(
                           cookie, in_port, info['mac']))
            ovn_bgp_agent.privileged.ovs_vsctl.ovs_cmd(
                'ovs-ofctl', ['add-flow', bridge, flow])
            ovn_bgp_agent.privileged.ovs_vsctl.ovs_cmd(
                'ovs-ofctl', ['add-flow', bridge, flow_v6])

            cookie_id = "cookie={}/-1".format(cookie)
            current_flows = get_bridge_flows(bridge, cookie_id)
            for flow in current_flows:
                agent_flow = False
                for port in info.get('in_port'):
                    in_port = 'in_port={}'.format(port)
                    if in_port in flow:
                        agent_flow = True
                        break
                if agent_flow:
                    continue
                in_port = flow.split("in_port=")[1].split(" ")[0]
                del_flow = ('{},in_port={}').format(cookie_id, in_port)
                ovn_bgp_agent.privileged.ovs_vsctl.ovs_cmd(
                    'ovs-ofctl', ['del-flows', bridge, del_flow])


def ensure_evpn_ovs_flow(bridge, cookie, mac, output_port, port_dst, net,
                         strip_vlan=False):
    ovs_port = _find_ovs_port(bridge)
    if not ovs_port:
        return
    ovs_ofport = get_device_port_at_ovs(ovs_port)
    vrf_ofport = get_device_port_at_ovs(output_port)

    strip_vlan_opt = 'strip_vlan,' if strip_vlan else ''
    ip_version = linux_net.get_ip_version(net)
    with pyroute2.NDB() as ndb:
        if ip_version == constants.IP_VERSION_6:
            flow = (
                "cookie={},priority=1000,ipv6,in_port={},dl_src:{},"
                "ipv6_src={} actions=mod_dl_dst:{},{}output={}".format(
                    cookie, ovs_ofport, mac, net,
                    ndb.interfaces[port_dst]['address'], strip_vlan_opt,
                    vrf_ofport))
        else:
            flow = (
                "cookie={},priority=1000,ip,in_port={},dl_src:{},nw_src={}"
                "actions=mod_dl_dst:{},{}output={}".format(
                    cookie, ovs_ofport, mac, net,
                    ndb.interfaces[port_dst]['address'], strip_vlan_opt,
                    vrf_ofport))
    ovn_bgp_agent.privileged.ovs_vsctl.ovs_cmd(
        'ovs-ofctl', ['add-flow', bridge, flow])


def remove_evpn_router_ovs_flows(bridge, cookie, mac):
    ovs_port = _find_ovs_port(bridge)
    if not ovs_port:
        return
    ovs_ofport = get_device_port_at_ovs(ovs_port)
    cookie_id = "cookie={}/-1".format(cookie)
    flow = ("{},ip,in_port={},dl_src:{}".format(
            cookie_id, ovs_ofport, mac))
    ovn_bgp_agent.privileged.ovs_vsctl.ovs_cmd(
        'ovs-ofctl', ['del-flows', bridge, flow])

    flow_v6 = ("{},ipv6,in_port={},dl_src:{}".format(cookie_id, ovs_ofport,
                                                     mac))
    ovn_bgp_agent.privileged.ovs_vsctl.ovs_cmd(
        'ovs-ofctl', ['del-flows', bridge, flow_v6])


def remove_evpn_network_ovs_flow(bridge, cookie, mac, net):
    ovs_port = _find_ovs_port(bridge)
    if not ovs_port:
        return
    ovs_ofport = get_device_port_at_ovs(ovs_port)
    cookie_id = "cookie={}/-1".format(cookie)
    ip_version = linux_net.get_ip_version(net)
    if ip_version == constants.IP_VERSION_6:
        flow = ("{},ipv6,in_port={},dl_src:{},ipv6_src={}".format(
                cookie_id, ovs_ofport, mac, net))
    else:
        flow = ("{},ip,in_port={},dl_src:{},nw_src={}".format(
                cookie_id, ovs_ofport, mac, net))
    ovn_bgp_agent.privileged.ovs_vsctl.ovs_cmd(
        'ovs-ofctl', ['del-flows', bridge, flow])


def ensure_default_ovs_flows(ovn_bridge_mappings, cookie):
    cookie_id = "cookie={}/-1".format(cookie)
    for bridge in ovn_bridge_mappings:
        ovs_port = ovn_bgp_agent.privileged.ovs_vsctl.ovs_cmd(
            'ovs-vsctl', ['list-ports', bridge])[0].rstrip()
        if not ovs_port:
            continue
        ovs_ofport = get_device_port_at_ovs(ovs_port)
        flow_filter = '{},in_port={}'.format(cookie_id, ovs_ofport)
        current_flows = get_bridge_flows(bridge, flow_filter)
        if len(current_flows) == 1:
            # assume the rule is the right one as it has the right cookie
            # and in_port
            continue

        with pyroute2.NDB() as ndb:
            flow = ("cookie={},priority=900,ip,in_port={},"
                    "actions=mod_dl_dst:{},NORMAL".format(
                        cookie, ovs_ofport,
                        ndb.interfaces[bridge]['address']))
            flow_v6 = ("cookie={},priority=900,ipv6,in_port={},"
                       "actions=mod_dl_dst:{},NORMAL".format(
                           cookie, ovs_ofport,
                           ndb.interfaces[bridge]['address']))
        ovn_bgp_agent.privileged.ovs_vsctl.ovs_cmd(
            'ovs-ofctl', ['add-flow', bridge, flow])
        ovn_bgp_agent.privileged.ovs_vsctl.ovs_cmd(
            'ovs-ofctl', ['add-flow', bridge, flow_v6])

        # Remove unneeded flows
        current_flows = get_bridge_flows(bridge, cookie_id)
        # The regex ensures that the next character after the port
        # number is either a comma, end of line or a space. This avoids
        # things like "in_port=1" matching with "in_port=10" for example.
        port_regex = 'in_port={}(,|$| )'.format(ovs_ofport)
        for flow in current_flows:
            if not flow or re.search(port_regex, flow):
                continue
            in_port = flow.split("in_port=")[1].split(" ")[0]
            del_flow = ('{},in_port={}').format(cookie_id, in_port)
            ovn_bgp_agent.privileged.ovs_vsctl.ovs_cmd(
                'ovs-ofctl', ['del-flows', bridge, del_flow])


def add_device_to_ovs_bridge(device, bridge, vlan_tag=None):
    args = ['--may-exist', 'add-port', bridge, device]
    if vlan_tag is not None:
        args.append('tag=%s' % vlan_tag)
    ovn_bgp_agent.privileged.ovs_vsctl.ovs_cmd('ovs-vsctl', args)


def del_device_from_ovs_bridge(device, bridge=None):
    args = ['--if-exists', 'del-port']
    if bridge:
        args.append(bridge)
    args.append(device)
    ovn_bgp_agent.privileged.ovs_vsctl.ovs_cmd('ovs-vsctl', args)


def add_vlan_port_to_ovs_bridge(bridge, vlan, vlan_tag):
    # ovs-vsctl add-port BRIDGE VLAN tag=VALN_ID
    # -- set interface VLAN type=internal
    args = [
        '--may-exist', 'add-port', bridge, vlan, 'tag={}'.format(vlan_tag),
        '--', 'set', 'interface', vlan, 'type=internal']
    ovn_bgp_agent.privileged.ovs_vsctl.ovs_cmd('ovs-vsctl', args)


def del_flow(flow, bridge, cookie):
    cookie_id = "cookie={}/-1".format(cookie)
    f = '{},priority{}'.format(
        cookie_id, flow.split(' actions')[0].split(' priority')[1])
    ovn_bgp_agent.privileged.ovs_vsctl.ovs_cmd(
        'ovs-ofctl', ['--strict', 'del-flows', bridge, f])


def get_flow_info(flow):
    # example:
    # cookie=0x3e7, duration=85.005s, table=0, n_packets=0,
    #  n_bytes=0, idle_age=65534, priority=1000,ip,in_port=1
    #  nw_src=20.0.0.0/24 actions=mod_dl_dst:1a:bd:c3:dc:6a:4c,
    # output:5
    flow_mac = flow_port = flow_nw_src = flow_ipv6_src = None
    try:
        flow_mac = flow.split('dl_src=')[1].split(',')[0]
        flow_port = flow.split('output:')[1].split(',')[0]
    except (IndexError, TypeError):
        pass
    flow_nw = flow.split('nw_src=')
    if len(flow_nw) == 2:
        flow_nw_src = flow_nw[1].split(' ')[0]
    flow_ipv6 = flow.split('ipv6_src=')
    if len(flow_ipv6) == 2:
        flow_ipv6_src = flow_ipv6[1].split(' ')[0]

    return {'mac': flow_mac, 'port': flow_port, 'nw_src': flow_nw_src,
            'ipv6_src': flow_ipv6_src}


class OvsIdl(object):
    def start(self, connection_string):
        helper = idlutils.get_schema_helper(connection_string,
                                            'Open_vSwitch')
        tables = ('Open_vSwitch', 'Bridge', 'Port', 'Interface')
        for table in tables:
            helper.register_table(table)
        ovs_idl = idl.Idl(connection_string, helper)
        ovs_idl._session.reconnect.set_probe_interval(60000)
        conn = connection.Connection(
            ovs_idl, timeout=180)
        self.idl_ovs = idl_ovs.OvsdbIdl(conn)

    def _get_from_ext_ids(self, key):
        return self.idl_ovs.db_get(
            'Open_vSwitch', '.', 'external_ids').execute()[key]

    def get_own_chassis_name(self):
        """Return the external_ids:system-id value of the Open_vSwitch table.

        As long as ovn-controller is running on this node, the key is
        guaranteed to exist and will include the chassis name.
        """
        return self._get_from_ext_ids('system-id')

    def get_ovn_remote(self):
        """Return the external_ids:ovn-remote value of the Open_vSwitch table.

        """
        return self._get_from_ext_ids('ovn-remote')

    def get_ovn_bridge_mappings(self):
        """Return a list of bridge mappings

        Return a list of bridge mappings based on the
        external_ids:ovn-bridge-mappings value of the Open_vSwitch table.
        """
        try:
            return [i.strip() for i in
                    self._get_from_ext_ids('ovn-bridge-mappings').split(',')]
        except KeyError:
            return []

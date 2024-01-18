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

from oslo_config import cfg
from oslo_log import log as logging
from ovs.db import idl
from ovsdbapp.backend.ovs_idl import connection
from ovsdbapp.backend.ovs_idl import idlutils
from ovsdbapp.schema.open_vswitch import impl_idl as idl_ovs
import socket
import tenacity

from ovn_bgp_agent import constants
from ovn_bgp_agent import exceptions as agent_exc
import ovn_bgp_agent.privileged.ovs_vsctl
from ovn_bgp_agent.utils import linux_net

CONF = cfg.CONF
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


def get_ovs_ports_info(bridge):
    ovs_ports = ovn_bgp_agent.privileged.ovs_vsctl.ovs_cmd(
        'ovs-vsctl', ['list-ports', bridge])[0].rstrip()
    return ovs_ports.split("\n")


def get_ovs_patch_ports_info(bridge, prefix='patch-provnet-'):
    in_ports = []
    ovs_ports = get_ovs_ports_info(bridge)
    for ovs_port in ovs_ports:
        if ovs_port.startswith(prefix):
            ovs_ofport = get_device_port_at_ovs(ovs_port)
            in_ports.append(ovs_ofport)
    return in_ports


@tenacity.retry(
    retry=tenacity.retry_if_exception_type(agent_exc.PatchPortNotFound),
    wait=tenacity.wait_fixed(1),
    stop=tenacity.stop_after_delay(5),
    reraise=True)
def get_ovs_patch_port_ofport(patch):
    patch_name = "patch-{}-to-br-int".format(patch)
    try:
        ofport = ovn_bgp_agent.privileged.ovs_vsctl.ovs_cmd(
            'ovs-vsctl', ['get', 'Interface', patch_name, 'ofport']
            )[0].rstrip()
    except Exception:
        raise agent_exc.PatchPortNotFound(localnet=patch)
    if ofport == '[]':
        # NOTE(ltomasbo): there is a chance the patch port interface was
        # created but not yet added to ovs bridge, therefore it exists but
        # has an empty ofport. We should retry in this case
        raise agent_exc.PatchPortNotFound(localnet=patch)
    return ofport


def ensure_mac_tweak_flows(bridge, mac, ports, cookie):
    cookie_id = "cookie={}/-1".format(cookie)
    current_flows = get_bridge_flows(bridge, cookie_id)
    flows_info = [flow.split("priority")[1].replace(" ", ",")
                  for flow in current_flows]

    for in_port in ports:
        exist_flow = False
        exist_flow_v6 = False
        flow = ("cookie={},priority=900,ip,in_port={},"
                "actions=mod_dl_dst:{},NORMAL".format(
                    cookie, in_port, mac))
        flow_v6 = ("cookie={},priority=900,ipv6,in_port={},"
                   "actions=mod_dl_dst:{},NORMAL".format(
                       cookie, in_port, mac))

        if flow.split("priority")[1] in flows_info:
            exist_flow = True
        if flow_v6.split("priority")[1] in flows_info:
            exist_flow_v6 = True

        if not exist_flow:
            ovn_bgp_agent.privileged.ovs_vsctl.ovs_cmd(
                'ovs-ofctl', ['add-flow', bridge, flow])
        if not exist_flow_v6:
            ovn_bgp_agent.privileged.ovs_vsctl.ovs_cmd(
                'ovs-ofctl', ['add-flow', bridge, flow_v6])


def remove_extra_ovs_flows(ovs_flows, bridge, cookie):
    expected_flows = []
    for port in ovs_flows[bridge].get('in_port'):
        flow = ("=900,ip,in_port={} actions=mod_dl_dst:{},NORMAL".format(
            port, ovs_flows[bridge]['mac']))
        expected_flows.append(flow)
        flow_v6 = ("=900,ipv6,in_port={} actions=mod_dl_dst:{},NORMAL".format(
            port, ovs_flows[bridge]['mac']))
        expected_flows.append(flow_v6)

    cookie_id = "cookie={}/-1".format(cookie)
    current_flows = get_bridge_flows(bridge, cookie_id)
    for flow in current_flows:
        if flow.split("priority")[1] not in expected_flows:
            del_flow = ('{},{}').format(
                cookie_id, flow.split("priority=900,")[1].split(" actions")[0])
            ovn_bgp_agent.privileged.ovs_vsctl.ovs_cmd(
                'ovs-ofctl', ['del-flows', bridge, del_flow])


def ensure_flow(bridge, flow):
    ovn_bgp_agent.privileged.ovs_vsctl.ovs_cmd(
        'ovs-ofctl', ['add-flow', bridge, flow])


def ensure_evpn_ovs_flow(bridge, cookie, mac, output_port, port_dst, net,
                         strip_vlan=False):
    ovs_port = _find_ovs_port(bridge)
    if not ovs_port:
        return
    ovs_ofport = get_device_port_at_ovs(ovs_port)
    vrf_ofport = get_device_port_at_ovs(output_port)

    strip_vlan_opt = 'strip_vlan,' if strip_vlan else ''
    ip_version = linux_net.get_ip_version(net)
    port_dst_mac = linux_net.get_interface_address(port_dst)
    if ip_version == constants.IP_VERSION_6:
        flow = (
            "cookie={},priority=1000,ipv6,in_port={},dl_src:{},"
            "ipv6_src={} actions=mod_dl_dst:{},{}output={}".format(
                cookie, ovs_ofport, mac, net, port_dst_mac, strip_vlan_opt,
                vrf_ofport))
    else:
        flow = (
            "cookie={},priority=1000,ip,in_port={},dl_src:{},nw_src={}"
            "actions=mod_dl_dst:{},{}output={}".format(
                cookie, ovs_ofport, mac, net, port_dst_mac, strip_vlan_opt,
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

    def get_own_chassis_id(self):
        """Return the external_ids:system-id value of the Open_vSwitch table.

        """
        return self._get_from_ext_ids('system-id')

    def get_own_chassis_name(self):
        """Return the external_ids:hostname value of the Open_vSwitch table.

        If the value is not configured, it will fetch the hostname from the
        current machine.
        """
        try:
            return self._get_from_ext_ids('hostname')
        except KeyError:
            return socket.gethostname()

    def get_ovn_remote(self, nb=False):
        """Return the external_ids:ovn-remote value of the Open_vSwitch table.

        """
        if nb:
            return (CONF.ovn.ovn_nb_connection if CONF.ovn.ovn_nb_connection
                    else self._get_from_ext_ids('ovn-nb-remote'))
        return (CONF.ovn.ovn_sb_connection if CONF.ovn.ovn_sb_connection
                else self._get_from_ext_ids('ovn-remote'))

    def get_ovn_bridge_mappings(self, bridge=None):
        """Return a list of bridge mappings

        Return a list of bridge mappings based on the
        external_ids:ovn-bridge-mappings value of the Open_vSwitch table.
        """
        key = 'ovn-bridge-mappings'
        if bridge:
            key = key + '-' + str(bridge)
        try:
            return [i.strip() for i in
                    self._get_from_ext_ids(key).split(',')]
        except KeyError:
            return []

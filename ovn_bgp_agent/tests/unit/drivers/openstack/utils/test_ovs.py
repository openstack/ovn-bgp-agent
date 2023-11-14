# Copyright 2021 Red Hat, Inc.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from unittest import mock

from ovsdbapp.schema.open_vswitch import impl_idl as idl_ovs

from ovn_bgp_agent import constants
from ovn_bgp_agent.drivers.openstack.utils import ovs as ovs_utils
from ovn_bgp_agent import exceptions as agent_exc
from ovn_bgp_agent.tests import base as test_base
from ovn_bgp_agent.utils import linux_net


class TestOVS(test_base.TestCase):

    def setUp(self):
        super(TestOVS, self).setUp()
        self.mock_ovs_vsctl = mock.patch(
            'ovn_bgp_agent.privileged.ovs_vsctl').start()

        # Helper variables that are used across multiple methods
        self.bridge = 'br-fake'
        self.flows_info = {self.bridge: {'in_port': set()}}
        self.cookie = 'fake-cookie'
        self.cookie_id = 'cookie=%s/-1' % self.cookie
        self.mac = 'aa:bb:cc:dd:ee:ff'

    def _test_get_bridge_flows(self, has_filter=False):
        port_iface = '1'
        fake_flow_0 = '{},ip,in_port={}'.format(self.cookie_id, port_iface)
        fake_flow_1 = '{},ipv6,in_port={}'.format(self.cookie_id, port_iface)
        fake_filter = 'cookie=fake-cookie/-1' if has_filter else None
        flows = 'HEADER\n%s\n%s\n' % (fake_flow_0, fake_flow_1)
        self.mock_ovs_vsctl.ovs_cmd.return_value = [flows]

        ret = ovs_utils.get_bridge_flows(self.bridge, filter_=fake_filter)

        expected_args = ['dump-flows', self.bridge]
        if has_filter:
            expected_args.append(fake_filter)

        self.mock_ovs_vsctl.ovs_cmd.assert_called_once_with(
            'ovs-ofctl', expected_args)
        self.assertEqual([fake_flow_0, fake_flow_1], ret)

    def test_get_bridge_flows(self):
        self._test_get_bridge_flows()

    def test_get_bridge_flows_with_filters(self):
        self._test_get_bridge_flows(has_filter=True)

    def test_get_device_port_at_ovs(self):
        port = 'fake-port'
        port_iface = '1'
        self.mock_ovs_vsctl.ovs_cmd.return_value = port_iface

        ret = ovs_utils.get_device_port_at_ovs(port)

        self.assertEqual(port_iface, ret)
        self.mock_ovs_vsctl.ovs_cmd.assert_called_once_with(
            'ovs-vsctl', ['get', 'Interface', port, 'ofport'])

    def test_get_ovs_ports_info(self):
        bridge = 'fake-bridge'
        bridge_ports = ['br-ex']
        self.mock_ovs_vsctl.ovs_cmd.return_value = bridge_ports

        ret = ovs_utils.get_ovs_ports_info(bridge)

        self.assertEqual(bridge_ports, ret)
        self.mock_ovs_vsctl.ovs_cmd.assert_called_once_with(
            'ovs-vsctl', ['list-ports', bridge])

    def test_get_ovs_patch_port_ofport(self):
        patch = 'fake-patch'
        ofport = ['1']
        self.mock_ovs_vsctl.ovs_cmd.return_value = ofport

        ret = ovs_utils.get_ovs_patch_port_ofport(patch)

        self.assertEqual(ofport[0], ret)
        self.mock_ovs_vsctl.ovs_cmd.assert_called_once_with(
            'ovs-vsctl',
            ['get', 'Interface', 'patch-fake-patch-to-br-int', 'ofport'])

    def test_get_ovs_patch_port_ofport_exception(self):
        patch = 'fake-patch'
        self.mock_ovs_vsctl.ovs_cmd.side_effect = Exception

        self.assertRaises(agent_exc.PatchPortNotFound,
                          ovs_utils.get_ovs_patch_port_ofport, patch)

        expected_calls = [
            mock.call('ovs-vsctl', ['get', 'Interface',
                                    'patch-fake-patch-to-br-int', 'ofport']),
            mock.call('ovs-vsctl', ['get', 'Interface',
                                    'patch-fake-patch-to-br-int', 'ofport']),
            mock.call('ovs-vsctl', ['get', 'Interface',
                                    'patch-fake-patch-to-br-int', 'ofport']),
            mock.call('ovs-vsctl', ['get', 'Interface',
                                    'patch-fake-patch-to-br-int', 'ofport']),
            mock.call('ovs-vsctl', ['get', 'Interface',
                                    'patch-fake-patch-to-br-int', 'ofport'])]
        self.mock_ovs_vsctl.ovs_cmd.assert_has_calls(expected_calls)

    def test_get_ovs_patch_port_ofport_no_port(self):
        patch = 'fake-patch'
        ofport = ['[]']
        self.mock_ovs_vsctl.ovs_cmd.return_value = ofport

        self.assertRaises(agent_exc.PatchPortNotFound,
                          ovs_utils.get_ovs_patch_port_ofport, patch)

        expected_calls = [
            mock.call('ovs-vsctl', ['get', 'Interface',
                                    'patch-fake-patch-to-br-int', 'ofport']),
            mock.call('ovs-vsctl', ['get', 'Interface',
                                    'patch-fake-patch-to-br-int', 'ofport']),
            mock.call('ovs-vsctl', ['get', 'Interface',
                                    'patch-fake-patch-to-br-int', 'ofport']),
            mock.call('ovs-vsctl', ['get', 'Interface',
                                    'patch-fake-patch-to-br-int', 'ofport']),
            mock.call('ovs-vsctl', ['get', 'Interface',
                                    'patch-fake-patch-to-br-int', 'ofport'])]
        self.mock_ovs_vsctl.ovs_cmd.assert_has_calls(expected_calls)

    @mock.patch.object(ovs_utils, 'get_bridge_flows')
    def test_remove_extra_ovs_flows(self, mock_flows):
        port_iface = '1'
        extra_port_iface = '2'
        extra_mac = 'ff:ee:dd:cc:bb:aa'
        self.flows_info[self.bridge]['in_port'] = {port_iface}
        self.flows_info[self.bridge]['mac'] = self.mac
        expected_flow = ("cookie={},priority=900,ip,in_port={} "
                         "actions=mod_dl_dst:{},NORMAL".format(
                             self.cookie, port_iface, self.mac))
        expected_flow_v6 = ("cookie={},priority=900,ipv6,in_port={} "
                            "actions=mod_dl_dst:{},NORMAL".format(
                                self.cookie, port_iface, self.mac))
        extra_flow = ("cookie={},priority=900,ip,in_port={} "
                      "actions=mod_dl_dst:{},NORMAL".format(
                          self.cookie, extra_port_iface, extra_mac))
        mock_flows.return_value = [expected_flow, expected_flow_v6, extra_flow]

        # Invoke the method
        ovs_utils.remove_extra_ovs_flows(self.flows_info, self.bridge,
                                         self.cookie)

        expected_del_flow = ('%s,ip,in_port=%s' % (self.cookie_id,
                                                   extra_port_iface))
        self.mock_ovs_vsctl.ovs_cmd.assert_called_once_with(
            'ovs-ofctl', ['del-flows', self.bridge, expected_del_flow])
        mock_flows.assert_called_once_with(self.bridge, self.cookie_id)

    def test_ensure_flow(self):
        bridge = 'fake-bridge'
        flow = 'fake-flow'

        ovs_utils.ensure_flow(bridge, flow)

        self.mock_ovs_vsctl.ovs_cmd.assert_called_once_with(
            'ovs-ofctl', ['add-flow', bridge, flow])

    @mock.patch.object(ovs_utils, 'get_device_port_at_ovs')
    @mock.patch.object(linux_net, 'get_interface_address')
    @mock.patch.object(linux_net, 'get_ip_version')
    def _test_ensure_evpn_ovs_flow(self, mock_ip_version, mock_nic_address,
                                   mock_ofport, ip_version, strip_vlan=False):
        address = '00:00:00:00:00:00'
        mock_ip_version.return_value = ip_version
        mock_nic_address.return_value = address
        port = 'fake-port'
        port_dst = 'fake-port-dst'
        ovs_port = constants.OVS_PATCH_PROVNET_PORT_PREFIX + 'fake-port'
        port_iface = '1'
        ovs_port_iface = '2'
        net = 'fake-net'
        self.mock_ovs_vsctl.ovs_cmd.side_effect = (
            ['%s\n%s\n' % (port, ovs_port)], None)
        mock_ofport.side_effect = (ovs_port_iface, port_iface)

        # Invoke the method
        ovs_utils.ensure_evpn_ovs_flow(
            self.bridge, self.cookie, self.mac, port, port_dst, net,
            strip_vlan=strip_vlan)

        mock_ip_version.assert_called_once_with(net)
        strip_vlan_opt = 'strip_vlan,' if strip_vlan else ''
        if ip_version == constants.IP_VERSION_4:
            expected_flow = (
                "cookie={},priority=1000,ip,in_port={},dl_src:{},nw_src={}"
                "actions=mod_dl_dst:{},{}output={}".format(
                    self.cookie, ovs_port_iface, self.mac, net, address,
                    strip_vlan_opt, port_iface))
        else:
            expected_flow = (
                "cookie={},priority=1000,ipv6,in_port={},dl_src:{},"
                "ipv6_src={} actions=mod_dl_dst:{},{}output={}".format(
                    self.cookie, ovs_port_iface, self.mac, net, address,
                    strip_vlan_opt, port_iface))
        expected_calls = [
            mock.call('ovs-vsctl', ['list-ports', self.bridge]),
            mock.call('ovs-ofctl', ['add-flow', self.bridge, expected_flow])]
        self.mock_ovs_vsctl.ovs_cmd.assert_has_calls(expected_calls)
        self.assertEqual(len(expected_calls),
                         self.mock_ovs_vsctl.ovs_cmd.call_count)
        expected_calls_ofport = [mock.call(ovs_port), mock.call(port)]
        mock_ofport.assert_has_calls(expected_calls_ofport)
        self.assertEqual(len(expected_calls_ofport), mock_ofport.call_count)

    def test_ensure_evpn_ovs_flow_ipv4(self):
        self._test_ensure_evpn_ovs_flow(ip_version=constants.IP_VERSION_4)

    def test_ensure_evpn_ovs_flow_ipv4_strip_vlan(self):
        self._test_ensure_evpn_ovs_flow(
            ip_version=constants.IP_VERSION_4, strip_vlan=True)

    def test_ensure_evpn_ovs_flow_ipv6(self):
        self._test_ensure_evpn_ovs_flow(ip_version=constants.IP_VERSION_6)

    def test_ensure_evpn_ovs_flow_ipv6_strip_vlan(self):
        self._test_ensure_evpn_ovs_flow(
            ip_version=constants.IP_VERSION_6, strip_vlan=True)

    def test_ensure_evpn_ovs_flow_no_ovs_ports(self):
        port = 'non-patch-provnet-port'
        self.mock_ovs_vsctl.ovs_cmd.return_value = [port]

        ret = ovs_utils.ensure_evpn_ovs_flow(
            self.bridge, self.cookie, self.mac, port, 'fake-port-dst',
            'fake-net')

        self.assertIsNone(ret)
        self.mock_ovs_vsctl.ovs_cmd.assert_called_once_with(
            'ovs-vsctl', ['list-ports', self.bridge])

    @mock.patch.object(ovs_utils, 'get_device_port_at_ovs')
    def test_remove_evpn_router_ovs_flows(self, mock_ofport):
        ovs_port = constants.OVS_PATCH_PROVNET_PORT_PREFIX + 'fake-port'
        ovs_port_iface = '1'
        self.mock_ovs_vsctl.ovs_cmd.side_effect = ([ovs_port], None, None)
        mock_ofport.return_value = ovs_port_iface

        # Invoke the method
        ovs_utils.remove_evpn_router_ovs_flows(
            self.bridge, self.cookie, self.mac)

        expected_flow = '{},ip,in_port={},dl_src:{}'.format(
            self.cookie_id, ovs_port_iface, self.mac)
        expected_flow_v6 = '{},ipv6,in_port={},dl_src:{}'.format(
            self.cookie_id, ovs_port_iface, self.mac)

        expected_calls = [
            mock.call('ovs-vsctl', ['list-ports', self.bridge]),
            mock.call('ovs-ofctl', ['del-flows', self.bridge, expected_flow]),
            mock.call('ovs-ofctl', ['del-flows', self.bridge,
                                    expected_flow_v6])]
        self.mock_ovs_vsctl.ovs_cmd.assert_has_calls(expected_calls)
        self.assertEqual(len(expected_calls),
                         self.mock_ovs_vsctl.ovs_cmd.call_count)
        mock_ofport.assert_called_once_with(ovs_port)

    def test_remove_evpn_router_ovs_flows_no_ovs_port(self):
        port = 'non-patch-provnet-port'
        self.mock_ovs_vsctl.ovs_cmd.return_value = [port]

        ret = ovs_utils.remove_evpn_router_ovs_flows(
            self.bridge, self.cookie, self.mac)

        self.assertIsNone(ret)
        self.mock_ovs_vsctl.ovs_cmd.assert_called_once_with(
            'ovs-vsctl', ['list-ports', self.bridge])

    @mock.patch.object(ovs_utils, 'get_device_port_at_ovs')
    @mock.patch.object(linux_net, 'get_ip_version')
    def _test_remove_evpn_network_ovs_flow(self, mock_ip_version, mock_ofport,
                                           ip_version):
        ovs_port = constants.OVS_PATCH_PROVNET_PORT_PREFIX + 'fake-port'
        ovs_port_iface = '1'
        net = 'fake-net'
        mock_ip_version.return_value = ip_version
        mock_ofport.return_value = ovs_port_iface
        self.mock_ovs_vsctl.ovs_cmd.side_effect = ([ovs_port], None)

        ovs_utils.remove_evpn_network_ovs_flow(
            self.bridge, self.cookie, self.mac, net)

        if ip_version == constants.IP_VERSION_6:
            expected_flow = ("{},ipv6,in_port={},dl_src:{},ipv6_src={}".format(
                             self.cookie_id, ovs_port_iface, self.mac, net))
        else:
            expected_flow = ("{},ip,in_port={},dl_src:{},nw_src={}".format(
                             self.cookie_id, ovs_port_iface, self.mac, net))

        expected_calls = [
            mock.call('ovs-vsctl', ['list-ports', self.bridge]),
            mock.call('ovs-ofctl', ['del-flows', self.bridge, expected_flow])]
        self.mock_ovs_vsctl.ovs_cmd.assert_has_calls(expected_calls)
        self.assertEqual(len(expected_calls),
                         self.mock_ovs_vsctl.ovs_cmd.call_count)
        mock_ip_version.assert_called_once_with(net)

    def test_remove_evpn_network_ovs_flow_ipv4(self):
        self._test_remove_evpn_network_ovs_flow(
            ip_version=constants.IP_VERSION_4)

    def test_remove_evpn_network_ovs_flow_ipv6(self):
        self._test_remove_evpn_network_ovs_flow(
            ip_version=constants.IP_VERSION_6)

    def test_remove_evpn_network_ovs_flow_no_ovs_port(self):
        port = 'non-patch-provnet-port'
        self.mock_ovs_vsctl.ovs_cmd.return_value = [port]

        ovs_utils.remove_evpn_network_ovs_flow(
            self.bridge, self.cookie, self.mac, 'fake-net')

        self.mock_ovs_vsctl.ovs_cmd.assert_called_once_with(
            'ovs-vsctl', ['list-ports', self.bridge])

    def _test_add_device_to_ovs_bridge(self, vlan_tag=False):
        device = 'ethX'
        vtag = '1001' if vlan_tag else None

        ovs_utils.add_device_to_ovs_bridge(device, self.bridge, vlan_tag=vtag)

        expected_args = ['--may-exist', 'add-port', self.bridge, device]
        if vlan_tag:
            expected_args.append('tag=%s' % vtag)

        self.mock_ovs_vsctl.ovs_cmd.assert_called_once_with(
            'ovs-vsctl', expected_args)

    def test_add_device_to_ovs_bridge(self):
        self._test_add_device_to_ovs_bridge()

    def test_add_device_to_ovs_bridge_vlan_tag(self):
        self._test_add_device_to_ovs_bridge(vlan_tag=True)

    def _test_del_device_from_ovs_bridge(self, bridge=False):
        device = 'ethX'
        br = self.bridge if bridge else None

        ovs_utils.del_device_from_ovs_bridge(device, bridge=br)

        expected_args = ['--if-exists', 'del-port']
        if bridge:
            expected_args.append(br)
        expected_args.append(device)

        self.mock_ovs_vsctl.ovs_cmd.assert_called_once_with(
            'ovs-vsctl', expected_args)

    def test_del_device_from_ovs_bridge(self):
        self._test_del_device_from_ovs_bridge()

    def test_del_device_from_ovs_bridge_specifying_bridge(self):
        self._test_del_device_from_ovs_bridge(bridge=True)

    def test_del_flow(self):
        flow = ('cookie=0x3e6, duration=11.647s, table=0, n_packets=0, '
                'n_bytes=0, idle_age=3378, priority=1000,ip,dl_src=fa:16:3e'
                ':15:9e:f0,nw_src=20.0.0.0/24 actions=mod_dl_dst:d2:33:c5:'
                'fd:7c:42,output:3,in_port=1')
        ovs_utils.del_flow(flow, self.bridge, self.cookie)

        expected_flow = ('{},priority=1000,ip,dl_src=fa:16:3e:15:9e:f0,'
                         'nw_src=20.0.0.0/24'.format(self.cookie_id))
        self.mock_ovs_vsctl.ovs_cmd.assert_called_once_with(
            'ovs-ofctl', ['--strict', 'del-flows', self.bridge, expected_flow])

    def test_get_flow_info(self):
        flow = ('cookie=0x3e6, duration=11.647s, table=0, n_packets=0, '
                'n_bytes=0, idle_age=3378, priority=1000,ip,dl_src=fa:16:3e'
                ':15:9e:f0,nw_src=20.0.0.0/24 actions=mod_dl_dst:d2:33:c5:'
                'fd:7c:42,output:3,in_port=1')

        ret = ovs_utils.get_flow_info(flow)

        expected_ret = {'ipv6_src': None, 'mac': 'fa:16:3e:15:9e:f0',
                        'nw_src': '20.0.0.0/24', 'port': '3'}
        self.assertEqual(expected_ret, ret)

    def test_get_flow_info_ipv6(self):
        flow = ('cookie=0x3e6, duration=9.275s, table=0, n_packets=0, '
                'n_bytes=0, idle_age=14326, priority=1000,ipv6,in_port=1,'
                'dl_src=fa:16:3e:15:9e:f0,ipv6_src=fdaa:4ad8:e8fb::/64 '
                'actions=mod_dl_dst:d2:33:c5:fd:7c:42,output:3')

        ret = ovs_utils.get_flow_info(flow)

        expected_ret = {'ipv6_src': 'fdaa:4ad8:e8fb::/64',
                        'mac': 'fa:16:3e:15:9e:f0', 'nw_src': None,
                        'port': '3'}
        self.assertEqual(expected_ret, ret)


class TestOvsIdl(test_base.TestCase):

    def setUp(self):
        super(TestOvsIdl, self).setUp()
        self.ovs_idl = ovs_utils.OvsIdl()
        self.ovs_idl.idl_ovs = mock.Mock()
        self.execute_ref = self.ovs_idl.idl_ovs.db_get.return_value.execute

    @mock.patch('ovsdbapp.backend.ovs_idl.connection.Connection')
    @mock.patch('ovs.db.idl.Idl')
    @mock.patch('ovsdbapp.backend.ovs_idl.idlutils.get_schema_helper')
    def test_start(self, mock_schema_helper, mock_idl, mock_conn):
        conn_str = 'fake-connection'
        self.ovs_idl.start(conn_str)

        mock_schema_helper.assert_called_once_with(conn_str, 'Open_vSwitch')
        helper = mock_schema_helper.return_value
        expected_calls = [
            mock.call('Open_vSwitch'), mock.call('Bridge'),
            mock.call('Port'), mock.call('Interface')]
        helper.register_table.assert_has_calls(expected_calls)
        mock_idl.assert_called_once_with(conn_str, helper)
        mock_conn.assert_called_once_with(
            mock_idl.return_value, timeout=mock.ANY)
        # Assert the OvsdbIdl instance was created
        self.assertIsInstance(self.ovs_idl.idl_ovs, idl_ovs.OvsdbIdl)

    def _test_ovs_ext_ids_getters(self, method, row, expected_return):
        self.execute_ref.return_value = row
        ret = method()
        self.assertEqual(expected_return, ret)
        self.ovs_idl.idl_ovs.db_get.assert_called_once_with(
            'Open_vSwitch', '.', 'external_ids')

    def test_get_own_chassis_id(self):
        expected_return = 'fake-sys'
        row = {'system-id': expected_return}
        self._test_ovs_ext_ids_getters(
            self.ovs_idl.get_own_chassis_id, row, expected_return)

    def test_get_own_chassis_name(self):
        expected_return = 'fake-name'
        row = {'hostname': expected_return}
        self._test_ovs_ext_ids_getters(
            self.ovs_idl.get_own_chassis_name, row, expected_return)

    def test_get_ovn_remote(self):
        expected_return = 'fake-ovn-remote'
        row = {'ovn-remote': expected_return}
        self._test_ovs_ext_ids_getters(
            self.ovs_idl.get_ovn_remote, row, expected_return)

    def test_get_ovn_remote_nb(self):
        expected_return = 'fake-ovn-remote'
        row = {'ovn-nb-remote': expected_return}
        self.execute_ref.return_value = row
        ret = self.ovs_idl.get_ovn_remote(nb=True)
        self.assertEqual(expected_return, ret)
        self.ovs_idl.idl_ovs.db_get.assert_called_once_with(
            'Open_vSwitch', '.', 'external_ids')

    def test_get_ovn_bridge_mappings(self):
        self.execute_ref.return_value = {
            'ovn-bridge-mappings': 'net0:bridge0,net1:bridge1, net2:bridge2'}
        ret = self.ovs_idl.get_ovn_bridge_mappings()
        self.assertEqual(['net0:bridge0', 'net1:bridge1', 'net2:bridge2'], ret)
        self.ovs_idl.idl_ovs.db_get.assert_called_once_with(
            'Open_vSwitch', '.', 'external_ids')

    def test_get_ovn_bridge_mappings_not_set(self):
        self.execute_ref.return_value = {}
        ret = self.ovs_idl.get_ovn_bridge_mappings()
        self.assertEqual([], ret)
        self.ovs_idl.idl_ovs.db_get.assert_called_once_with(
            'Open_vSwitch', '.', 'external_ids')

    def test_get_ovn_bridge_mappings_bridge(self):
        bridge = 'bgp'
        self.execute_ref.return_value = {
            'ovn-bridge-mappings-bgp':
            'net0:bridge0,net1:bridge1, net2:bridge2'}
        ret = self.ovs_idl.get_ovn_bridge_mappings(bridge=bridge)
        self.assertEqual(['net0:bridge0', 'net1:bridge1', 'net2:bridge2'], ret)
        self.ovs_idl.idl_ovs.db_get.assert_called_once_with(
            'Open_vSwitch', '.', 'external_ids')

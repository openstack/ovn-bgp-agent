# Copyright 2024 team.blue/nl
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

from oslo_config import cfg
from unittest import mock

from ovn_bgp_agent import constants
from ovn_bgp_agent.drivers.openstack.utils import evpn
from ovn_bgp_agent import exceptions
from ovn_bgp_agent.tests import base as test_base
from ovn_bgp_agent.tests import utils


CONF = cfg.CONF


class TestEVPN(test_base.TestCase):

    def setUp(self):
        super(TestEVPN, self).setUp()
        CONF.set_override('evpn_local_ip', '127.0.0.1')

        self.mock_ovs = mock.patch.object(evpn, 'ovs').start()
        self.mock_ovs.get_ovs_patch_port_ofport.return_value = 12

        self.mock_frr = mock.patch.object(evpn, 'frr').start()
        self.mock_linux_net = mock.patch.object(evpn, 'linux_net').start()

        self.fake_mac = fake_mac = 'fe:12:34:56:89:90'
        self.mock_linux_net.get_interface_address.return_value = fake_mac

        self._bridge_args = {
            'ovs_bridge': 'br-ex',
            'vni': 100,
            'evpn_opts': {},
            'mode': constants.OVN_EVPN_TYPE_L3,
            'ovs_flows': {'br-ex': {}},
        }
        self.vrf_name = 'vrf-100'
        self.vxlan_name = 'vxlan-100'
        self.bridge_name = 'br-100'

        self.veth_vrf = '_to_be_set_by__create_bridge_and_vlan'
        self.veth_ovs = '_to_be_set_by__create_bridge_and_vlan'

        # evpn.local_bridges = {}
    def _reset_evpn_local_bridges(self):
        evpn.local_bridges = {}

    def _create_bridge(self, **override_args) -> evpn.EvpnBridge:
        self.addCleanup(self._reset_evpn_local_bridges)
        args = dict(**self._bridge_args)
        args.update(**override_args)
        return evpn.setup(**args)

    def _create_bridge_and_vlan(
        self, vlan_tag=4094, **bridge_args
    ) -> 'tuple[object, evpn.EvpnBridge, evpn.VlanDev]':
        port = utils.create_row(
            name='fake-port-name',
            tag=[vlan_tag]
        )

        uuid = str(port.uuid)[0:11]
        self.veth_vrf = constants.OVN_EVPN_VETH_VRF_UUID_PREFIX + uuid
        self.veth_ovs = constants.OVN_EVPN_VETH_OVS_UUID_PREFIX + uuid

        evpn_bridge = self._create_bridge(**bridge_args)
        return port, evpn_bridge, evpn_bridge.connect_vlan(port)

    def test_setup_no_ip(self):
        CONF.set_override('evpn_local_ip', None)
        self.assertRaises(exceptions.ConfOptionRequired, self._create_bridge)

    def test_setup(self):
        evpn_bridge = self._create_bridge()

        self.assertIsInstance(evpn_bridge, evpn.EvpnBridge)
        self.assertEqual(evpn_bridge.ovs_bridge, 'br-ex')
        self.assertEqual(evpn_bridge.vni, 100)
        self.assertEqual(evpn_bridge.vrf_name, self.vrf_name)
        self.assertEqual(evpn_bridge.bridge_name, self.bridge_name)
        self.assertEqual(evpn_bridge.vxlan_name, self.vxlan_name)

        other_bridge = self._create_bridge()
        self.assertEqual(evpn_bridge, other_bridge)

    def test_lookup_vlan_int(self):
        port = utils.create_row(
            tag=[4094]
        )
        evpn_bridge = self._create_bridge()
        evpn_bridge.connect_vlan(port)

        bridge = evpn.lookup(self._bridge_args['ovs_bridge'], 4094)
        self.assertIsInstance(bridge, evpn.EvpnBridge)

    def test_lookup_vlan_str(self):
        port = utils.create_row(
            tag=[4094]
        )
        evpn_bridge = self._create_bridge()
        evpn_bridge.connect_vlan(port)

        bridge = evpn.lookup(self._bridge_args['ovs_bridge'], '4094')
        self.assertIsInstance(bridge, evpn.EvpnBridge)

    def test_lookup_vlan_None(self):
        port = utils.create_row(
            tag=[]
        )
        evpn_bridge = self._create_bridge()
        evpn_bridge.connect_vlan(port)

        bridge = evpn.lookup(self._bridge_args['ovs_bridge'], None)
        self.assertIsInstance(bridge, evpn.EvpnBridge)

    def test_lookup_vlan_unknown(self):
        self._create_bridge_and_vlan(vlan_tag=123)
        self._create_bridge_and_vlan(vlan_tag=123, vni=123, ovs_bridge='foo')
        self._create_bridge_and_vlan(vlan_tag=4094, vni=123, ovs_bridge='foo')
        self.assertRaises(KeyError, evpn.lookup,
                          self._bridge_args['ovs_bridge'], '4094')

    def test_evpnbridge_setup_l3(self):
        bridge = self._create_bridge()
        bridge.setup()

        self.assertTrue(bridge._setup_done)

        # Create pointer for shorter lines.
        linux_net = self.mock_linux_net

        linux_net.ensure_bridge.assert_called_once_with(self.bridge_name)
        linux_net.ensure_vxlan.assert_called_once_with(self.vxlan_name, 100,
                                                       '127.0.0.1', 4789)
        linux_net.set_master_for_device.assert_has_calls([
            mock.call(self.vxlan_name, self.bridge_name),
            mock.call(self.bridge_name, self.vrf_name),
        ])
        linux_net.disable_learning_vxlan_intf.assert_called_once_with(
            self.vxlan_name)
        linux_net.ensure_vrf.assert_called_once_with(self.vrf_name, 100)

        frr = self.mock_frr
        frr.vrf_reconfigure.assert_called_once_with(mock.ANY, 'add-vrf')

    def test_evpnbridge_setup_l2(self):
        bridge = self._create_bridge(mode=constants.OVN_EVPN_TYPE_L2)
        bridge.setup()

        self.assertTrue(bridge._setup_done)

        # Create pointer for shorter lines.
        linux_net = self.mock_linux_net

        linux_net.ensure_bridge.assert_called_once_with(self.bridge_name)
        linux_net.ensure_vxlan.assert_called_once_with(self.vxlan_name, 100,
                                                       '127.0.0.1', 4789)
        linux_net.set_master_for_device.assert_has_calls([
            mock.call(self.vxlan_name, self.bridge_name),
        ])
        linux_net.disable_learning_vxlan_intf.assert_called_once_with(
            self.vxlan_name)
        linux_net.ensure_vrf.assert_not_called()

        frr = self.mock_frr
        frr.vrf_reconfigure.assert_called_once_with(mock.ANY, 'add-vrf')

    def test_evpnbridge_setup_done(self):
        bridge = self._create_bridge()
        bridge._setup_done = True
        bridge.setup()

        self.mock_linux_net.ensure_bridge.assert_not_called()

    def test_evpnbridge_eval_disconnect(self):
        _, bridge, evpn_vlan = self._create_bridge_and_vlan()

        bridge_disconnect = mock.patch.object(bridge, 'disconnect').start()

        bridge._eval_disconnect()
        bridge_disconnect.assert_not_called()

        bridge._setup_done = True
        evpn_vlan._setup_done = True
        bridge._eval_disconnect()

        bridge_disconnect.assert_not_called()

        evpn_vlan._setup_done = False

        bridge._eval_disconnect()
        bridge_disconnect.assert_called_once()

    def test_evpnbridge_disconnect(self):
        bridge = self._create_bridge()
        bridge._setup_done = True
        bridge.disconnect()

        calls = [mock.call('br-100'),
                 mock.call('vxlan-100'),
                 mock.call('vrf-100')]
        self.mock_linux_net.delete_device.assert_has_calls(calls)
        self.mock_frr.vrf_reconfigure.assert_called_once_with(mock.ANY,
                                                              action='del-vrf')

        self.assertFalse(bridge._setup_done)

    def test_evpnbridge_disconnect_keep_vrf(self):
        bridge = self._create_bridge()
        bridge._setup_done = True
        CONF.set_override('delete_vrf_on_disconnect', False)
        bridge.disconnect()

        calls = [mock.call('br-100'),
                 mock.call('vxlan-100')]
        self.mock_linux_net.delete_device.assert_has_calls(calls)
        self.mock_frr.vrf_reconfigure.assert_not_called()

        self.assertFalse(bridge._setup_done)

    def test_evpnbridge_connect_vlan_again(self):
        port, bridge, evpn_vlan = self._create_bridge_and_vlan()

        vlan = bridge.connect_vlan(port)
        self.assertEqual(vlan, evpn_vlan)

    def test_evpnbridge_get_vlan(self):
        _, bridge, evpn_vlan = self._create_bridge_and_vlan()
        self.assertEqual(bridge.get_vlan(4094), evpn_vlan)

    def test_evpnbridge_vlan_lladdr_property_calls_setup(self):
        _, bridge, evpn_vlan = self._create_bridge_and_vlan()

        evpn_vlan_setup = mock.patch.object(evpn_vlan, 'setup').start()
        self.assertEqual(evpn_vlan.lladdr, self.fake_mac)
        evpn_vlan_setup.assert_called_once()

    def test_evpnbridge_vlan_setup_l2(self):
        vlan_tag = 4094
        vlan_tag_str = '4094'
        _, evpn_bridge, vlan_dev = self._create_bridge_and_vlan(vlan_tag,
                                                                mode='l2')

        evpn_setup = mock.patch.object(evpn_bridge, 'setup').start()

        vlan_dev.setup()

        evpn_setup.assert_called_once()

        linux_net = self.mock_linux_net
        linux_net.ensure_veth.assert_called_once_with(self.veth_vrf,
                                                      self.veth_ovs)
        self.mock_ovs.add_device_to_ovs_bridge(self.veth_ovs, 'br-ex',
                                               vlan_tag=vlan_tag_str)
        linux_net.set_master_for_device.assert_called_once_with(self.veth_vrf,
                                                                'br-100')

        linux_net.ensure_arp_ndp_enabled_for_bridge.assert_not_called()
        linux_net.enable_routing_for_interfaces.assert_not_called()
        linux_net.enable_proxy_arp.assert_not_called()
        linux_net.enable_proxy_ndp.assert_not_called()

        self.mock_ovs.ensure_mac_tweak_flows.assert_not_called()
        self.mock_ovs.remove_extra_ovs_flows.assert_not_called()

        self.assertTrue(vlan_dev._veth_created)
        self.assertTrue(vlan_dev._setup_done)

    def test_evpnbridge_vlan_setup_l3(self, custom_ips=[]):
        vlan_tag = 4094
        vlan_tag_str = '4094'
        _, evpn_bridge, vlan_dev = self._create_bridge_and_vlan(vlan_tag)

        evpn_setup = mock.patch.object(evpn_bridge, 'setup').start()

        if custom_ips:
            vlan_dev.add_ips(list(custom_ips))

        vlan_dev.setup()

        evpn_setup.assert_called_once()

        linux_net = self.mock_linux_net
        linux_net.ensure_veth.assert_called_once_with(self.veth_vrf,
                                                      self.veth_ovs)
        self.mock_ovs.add_device_to_ovs_bridge(self.veth_ovs, 'br-ex',
                                               vlan_tag=vlan_tag_str)
        linux_net.set_master_for_device.assert_called_once_with(self.veth_vrf,
                                                                self.vrf_name)
        linux_net.ensure_arp_ndp_enabled_for_bridge.assert_called_once_with(
            self.veth_vrf, offset=vlan_tag, vlan_tag=vlan_tag_str)

        linux_net.enable_routing_for_interfaces.assert_called_once_with(
            self.veth_vrf, 'br-100')

        linux_net.enable_proxy_arp.assert_called_once_with(self.veth_vrf)
        linux_net.enable_proxy_ndp.assert_called_once_with(self.veth_vrf)

        self.mock_ovs.ensure_mac_tweak_flows.assert_called_once_with(
            'br-ex', self.fake_mac, [12], constants.OVS_RULE_COOKIE)
        self.mock_ovs.remove_extra_ovs_flows.assert_called_once_with(
            mock.ANY, 'br-ex', constants.OVS_RULE_COOKIE)

        self.assertTrue(vlan_dev._veth_created)
        self.assertTrue(vlan_dev._setup_done)

        if custom_ips:
            linux_net.add_ips_to_dev.assert_has_calls([
                mock.call(self.veth_vrf, ips=custom_ips),
            ])

        linux_net.ensure_anycast_mac_for_interface.assert_called_once_with(
            self.veth_vrf, offset=6557694)

    def test_evpnbridge_vlan_setup_l3_with_custom_ips(self):
        self.test_evpnbridge_vlan_setup_l3(custom_ips=['10.10.10.1'])

    def test_evpnbridge_vlan_setup_l3_failed_ovs_call(self):
        vlan_tag = 4094
        _, evpn_bridge, vlan_dev = self._create_bridge_and_vlan(vlan_tag)

        mock.patch.object(evpn_bridge, 'setup').start()

        self.mock_ovs.get_ovs_patch_port_ofport.side_effect = KeyError

        vlan_dev.setup()
        self.assertTrue(vlan_dev._veth_created)
        self.assertFalse(vlan_dev._setup_done)

    def test_evpnbridge_vlan__eval_disconnect(self):
        _, _, vlan_dev = self._create_bridge_and_vlan()

        vlan_dev_disconnect = mock.patch.object(vlan_dev, 'disconnect').start()

        vlan_dev._setup_done = True

        vlan_dev._agent_routing_tables_routes = ['entry']
        vlan_dev._eval_disconnect()
        vlan_dev_disconnect.assert_not_called()

        vlan_dev._agent_routing_tables_routes = []
        vlan_dev._eval_disconnect()
        vlan_dev_disconnect.assert_called_once()

    def test_evpnbridge_vlan__eval_disconnect_not_setup_yet(self):
        _, _, vlan_dev = self._create_bridge_and_vlan()

        vlan_dev_disconnect = mock.patch.object(vlan_dev, 'disconnect').start()

        vlan_dev._agent_routing_tables_routes = []
        vlan_dev._eval_disconnect()

        vlan_dev_disconnect.assert_not_called()

    def test_evpnbridge_vlan_disconnect(self):
        _, evpn_bridge, vlan_dev = self._create_bridge_and_vlan()

        evpn_bridge__eval_disconnect = mock.patch.object(
            evpn_bridge, '_eval_disconnect').start()

        vlan_dev.disconnect()

        evpn_bridge__eval_disconnect.assert_called_once()

        self.mock_ovs.del_device_from_ovs_bridge.assert_called_once_with(
            self.veth_ovs, 'br-ex')
        self.mock_linux_net.delete_device.assert_called_once_with(
            self.veth_vrf)

        self.assertFalse(vlan_dev._veth_created)
        self.assertFalse(vlan_dev._setup_done)

    def test_evpnbridge_vlan_teardown(self):
        _, evpn_bridge, vlan_dev = self._create_bridge_and_vlan()

        vlan_dev_disconnect = mock.patch.object(
            vlan_dev, 'disconnect').start()

        vlan_dev.teardown()

        vlan_dev_disconnect.assert_called_once()
        self.assertNotIn(vlan_dev.vlan_tag, evpn_bridge.vlans)

    def test_evpnbridge_vlan_process_dhcp_opts(self):
        _, _, vlan_dev = self._create_bridge_and_vlan()
        dhcp_opts = [
            utils.create_row(cidr='10.10.10.0/24',
                             options={'router': '10.10.10.1'}),
            utils.create_row(cidr='fe00::/64', options={}),
        ]
        vlan_dev._setup_done = True
        vlan_dev.process_dhcp_opts(dhcp_opts)

        ips = {'10.10.10.1'}
        self.assertSetEqual(vlan_dev._custom_ips, ips)
        self.mock_linux_net.add_ips_to_dev.assert_called_once_with(
            self.veth_vrf, ips=list(ips))
        self.mock_frr.nd_reconfigure.assert_called_once_with(
            self.veth_vrf, 'fe00::/64', {})

    def test_evpnbridge_vlan_process_dhcp_opts_multiple_subnets(self):
        _, _, vlan_dev = self._create_bridge_and_vlan()
        dhcp_opts = [
            utils.create_row(cidr='10.10.10.0/24',
                             options={'router': '10.10.10.1'}),
            utils.create_row(cidr='10.10.20.0/24',
                             options={'router': '10.10.20.1'}),
        ]
        vlan_dev._setup_done = True
        vlan_dev.process_dhcp_opts(dhcp_opts)

        ips = {'10.10.10.1', '10.10.20.1'}
        self.assertSetEqual(vlan_dev._custom_ips, ips)

        calls = [
            mock.call(self.veth_vrf, ips=['10.10.10.1']),
            mock.call(self.veth_vrf, ips=['10.10.20.1']),
        ]
        self.mock_linux_net.add_ips_to_dev.assert_has_calls(calls)

    def test_evpnbridge_vlan_add_route(self, ip='10.10.10.10'):
        _, _, vlan_dev = self._create_bridge_and_vlan()
        vlan_dev._setup_done = True

        routing_tables_routes = {self.veth_vrf: []}
        addr = ip.split('/')[0]
        mask = None if '/' not in ip else ip.split('/')[1]
        mac = 'fe:12:34:56:89:12'
        via = None

        vlan_dev.add_route(routing_tables_routes, ip, mac, via)

        self.assertDictEqual(routing_tables_routes, {self.veth_vrf: [{
            'ip': '10.10.10.10',
            'mask': mask,
            'mac': 'fe:12:34:56:89:12',
            'via': None,
        }]})

        self.mock_linux_net.add_ip_route.assert_called_once_with(
            mock.ANY, addr, 100, self.veth_vrf, mask=mask, via=None)

        self.mock_linux_net.add_ip_nei.assert_called_once_with(
            addr, 'fe:12:34:56:89:12', self.veth_vrf)

    def test_evpnbridge_vlan_add_route_with_prefix(self):
        self.test_evpnbridge_vlan_add_route(ip='10.10.10.10/32')

    def test_evpnbridge_vlan_add_route_l2(self):
        _, _, vlan_dev = self._create_bridge_and_vlan(mode='l2')
        vlan_dev._setup_done = True

        routing_tables_routes = {self.veth_vrf: []}
        ip = '10.10.10.10/32'
        mac = 'fe:12:34:56:89:12'
        via = None

        vlan_dev.add_route(routing_tables_routes, ip, mac, via)

        self.mock_linux_net.add_ip_route.assert_not_called()

    def test_evpnbridge_vlan_del_route(self, ip='10.10.10.10'):
        _, _, vlan_dev = self._create_bridge_and_vlan()
        vlan_dev._setup_done = True

        addr = ip.split('/')[0]
        routing_tables_routes = {self.veth_vrf: [{
            'ip': addr,
            'mask': '32',
            'mac': 'fe:12:34:56:89:12',
            'via': '10.10.20.10',
        }, {
            'ip': '10.10.10.11',
            'mask': '32',
            'mac': 'fe:12:34:56:89:12',
            'via': '10.10.20.10',
        }]}
        mac = 'fe:12:34:56:89:12'
        vlan_dev__eval_disconnect = mock.patch.object(
            vlan_dev, '_eval_disconnect').start()

        vlan_dev.del_route(routing_tables_routes, ip, mac)

        self.assertDictEqual(routing_tables_routes, {self.veth_vrf: [{
            'ip': '10.10.10.11',
            'mask': '32',
            'mac': 'fe:12:34:56:89:12',
            'via': '10.10.20.10',
        }]})

        self.mock_linux_net.del_ip_route.assert_called_once_with(
            mock.ANY, addr, 100, self.veth_vrf, mask='32', via='10.10.20.10')

        self.mock_linux_net.del_ip_nei.assert_called_once_with(
            addr, 'fe:12:34:56:89:12', self.veth_vrf)

        vlan_dev__eval_disconnect.assert_called()

    def test_evpnbridge_vlan_del_route_with_prefix(self):
        self.test_evpnbridge_vlan_del_route('10.10.10.10/32')

    def test_evpnbridge_vlan_del_route_no_route_table(self):
        _, _, vlan_dev = self._create_bridge_and_vlan()
        vlan_dev._setup_done = True

        addr = '10.10.10.10'
        routing_tables_routes = {
            self.veth_vrf: [{
                'ip': '10.10.10.11',
                'mask': '32',
                'mac': 'fe:12:34:56:89:12',
                'via': '10.10.20.10',
            }]
        }
        mac = 'fe:12:34:56:89:12'
        vlan_dev__eval_disconnect = mock.patch.object(
            vlan_dev, '_eval_disconnect').start()

        vlan_dev.del_route(routing_tables_routes, addr, mac)

        self.assertDictEqual(routing_tables_routes, {self.veth_vrf: [{
            'ip': '10.10.10.11',
            'mask': '32',
            'mac': 'fe:12:34:56:89:12',
            'via': '10.10.20.10',
        }]})

        self.mock_linux_net.del_ip_route.assert_called_once_with(
            mock.ANY, addr, 100, self.veth_vrf, mask=None, via=None)

        self.mock_linux_net.del_ip_nei.assert_called_once_with(
            addr, 'fe:12:34:56:89:12', self.veth_vrf)

        vlan_dev__eval_disconnect.assert_called()

    def test_evpnbridge_vlan_del_route_l2(self):
        _, _, vlan_dev = self._create_bridge_and_vlan(mode='l2')
        vlan_dev._setup_done = True

        routing_tables_routes = {self.veth_vrf: [{
            'ip': '10.10.10.10',
            'mask': '32',
            'mac': 'fe:12:34:56:89:12',
            'via': '10.10.20.10',
        }]}
        ip = '10.10.10.10'
        mac = 'fe:12:34:56:89:12'

        vlan_dev.del_route(routing_tables_routes, ip, mac)

        self.assertDictEqual(routing_tables_routes, {self.veth_vrf: [{
            'ip': '10.10.10.10',
            'mask': '32',
            'mac': 'fe:12:34:56:89:12',
            'via': '10.10.20.10',
        }]})

        self.mock_linux_net.del_ip_route.assert_not_called()

    def test_evpnbridge_vlan_cleanup_excessive_routes(self):
        _, _, vlan_dev = self._create_bridge_and_vlan()
        vlan_dev._setup_done = True

        intf_idx = 1337
        self.mock_linux_net.get_interface_index.return_value = intf_idx

        routes = utils.create_linux_routes([{
            '_attrs': [
                ('RTA_DST', '198.51.100.0'), ('RTA_OIF', intf_idx),
                ('RTA_GATEWAY', '100.64.0.102')
            ],
            'dst_len': 28, 'type': 1,
        }, {
            'attrs': [('RTA_DST', '198.51.100.136'), ('RTA_OIF', intf_idx)],
            'dst_len': 32, 'type': 1,
        }, {
            'attrs': [('RTA_DST', '198.51.100.158'), ('RTA_OIF', intf_idx)],
            'dst_len': 32, 'type': 1,
        }])
        self.mock_linux_net._get_table_routes.return_value = routes

        routing_tables_routes = {self.veth_vrf: [{
            'ip': '198.51.100.0',
            'mask': '28',
            'mac': 'fe:12:34:56:89:12',
            'via': '100.64.0.102',
        }]}
        del_route = mock.patch.object(vlan_dev, 'del_route').start()

        vlan_dev.cleanup_excessive_routes(routing_tables_routes)

        calls = [
            mock.call(mock.ANY, '198.51.100.136'),
            mock.call(mock.ANY, '198.51.100.158'),
        ]
        del_route.assert_has_calls(calls, any_order=True)

    def test_evpnbridge_vlan_cleanup_excessive_routes_in_sync(self):
        _, _, vlan_dev = self._create_bridge_and_vlan()
        vlan_dev._setup_done = True

        intf_idx = 1337
        self.mock_linux_net.get_interface_index.return_value = intf_idx

        routes = utils.create_linux_routes([{
            '_attrs': [
                ('RTA_DST', '198.51.100.0'), ('RTA_OIF', intf_idx),
                ('RTA_GATEWAY', '100.64.0.102')
            ],
            'dst_len': 28, 'type': 1,
        }])
        self.mock_linux_net._get_table_routes.return_value = routes

        routing_tables_routes = {self.veth_vrf: [{
            'ip': '198.51.100.0',
            'mask': '28',
            'mac': 'fe:12:34:56:89:12',
            'via': '100.64.0.102',
        }]}
        del_route = mock.patch.object(vlan_dev, 'del_route').start()

        vlan_dev.cleanup_excessive_routes(routing_tables_routes)
        del_route.assert_not_called()

    def test_evpnbridge_vlan_cleanup_excessive_routes_not_setup_yet(self):
        _, _, vlan_dev = self._create_bridge_and_vlan()
        vlan_dev.cleanup_excessive_routes({})
        self.mock_linux_net._get_table_routes.assert_not_called()

    def test_evpn__find_route_info(self):
        result = evpn._find_route_info([
            {'ip': '198.51.100.136', 'mask': '32', 'mac': None, 'via': None},
            {'ip': '198.51.100.158', 'mask': '24', 'mac': None, 'via': None},
            {'ip': '127.0.0.1', 'mask': '8', 'mac': None, 'via': None},
            {'ip': '198.51.100.0', 'mask': '28', 'mac': None, 'via': None},
        ], '127.0.0.1')
        self.assertDictEqual(result, {'ip': '127.0.0.1', 'mask': '8',
                                      'mac': None, 'via': None})

    def test_evpn__find_route_info_not_found(self):
        result = evpn._find_route_info([], '127.0.0.1')
        self.assertDictEqual(result, {'ip': '127.0.0.1', 'mask': None,
                                      'mac': None, 'via': None})

    def test_evpn__ensure_list(self):
        self.assertListEqual(evpn._ensure_list(None), [])
        self.assertListEqual(evpn._ensure_list('aa'), ['aa'])
        self.assertListEqual(evpn._ensure_list(['aa']), ['aa'])
        self.assertSetEqual(evpn._ensure_list({'aa'}), {'aa'})
        self.assertTupleEqual(evpn._ensure_list(('a', 'b',)), ('a', 'b'))

    def test__offset_for_vni_and_vlan(self):
        vni = 100
        vlan = 100
        exp = int(('%x' % vni).zfill(6) + ('%x' % vlan).zfill(4), 16)
        self.assertEqual(exp, evpn._offset_for_vni_and_vlan(vni, vlan))

        vni = 16777214
        vlan = 4094
        exp = int(('%x' % vni).zfill(6) + ('%x' % vlan).zfill(4), 16)
        self.assertEqual(exp, evpn._offset_for_vni_and_vlan(vni, vlan))

        # Below value is 1 too much, so it is being modulo'd, and should be
        # calculated to 0
        vni = 16777215
        vlan = 4095
        exp = int(('%x' % vni).zfill(6) + ('%x' % vlan).zfill(4), 16)
        self.assertNotEqual(exp, evpn._offset_for_vni_and_vlan(vni, vlan))
        self.assertEqual(0, evpn._offset_for_vni_and_vlan(vni, vlan))

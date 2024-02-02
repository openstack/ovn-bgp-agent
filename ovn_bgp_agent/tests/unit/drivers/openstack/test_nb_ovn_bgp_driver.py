# Copyright 2023 Red Hat, Inc.
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

from oslo_config import cfg

from ovn_bgp_agent import constants
from ovn_bgp_agent.drivers.openstack import nb_ovn_bgp_driver
from ovn_bgp_agent.drivers.openstack.utils import bgp as bgp_utils
from ovn_bgp_agent.drivers.openstack.utils import driver_utils
from ovn_bgp_agent.drivers.openstack.utils import frr
from ovn_bgp_agent.drivers.openstack.utils import ovn
from ovn_bgp_agent.drivers.openstack.utils import ovs
from ovn_bgp_agent.drivers.openstack.utils import wire as wire_utils
from ovn_bgp_agent import exceptions
from ovn_bgp_agent.tests import base as test_base
from ovn_bgp_agent.tests.unit import fakes
from ovn_bgp_agent.tests import utils
from ovn_bgp_agent.utils import linux_net


CONF = cfg.CONF


class TestNBOVNBGPDriver(test_base.TestCase):

    def setUp(self):
        super(TestNBOVNBGPDriver, self).setUp()
        CONF.set_override('expose_tenant_networks', True)
        self.bridge = 'fake-bridge'
        self.nb_bgp_driver = nb_ovn_bgp_driver.NBOVNBGPDriver()
        self.nb_bgp_driver._post_start_event = mock.Mock()
        self.nb_bgp_driver.nb_idl = mock.Mock()
        self.nb_bgp_driver.allowed_address_scopes = None
        self.nb_idl = self.nb_bgp_driver.nb_idl
        self.nb_bgp_driver.chassis = 'fake-chassis'
        self.nb_bgp_driver.chassis_id = 'fake-chassis-id'
        self.nb_bgp_driver.ovn_bridge_mappings = {'fake-network': self.bridge}

        self.mock_nbdb = mock.patch.object(ovn, 'OvnNbIdl').start()
        self.mock_ovs_idl = mock.patch.object(ovs, 'OvsIdl').start()
        self.nb_bgp_driver.ovs_idl = self.mock_ovs_idl

        self.ipv4 = '192.168.1.17'
        self.ipv6 = '2002::1234:abcd:ffff:c0a8:101'
        self.fip = '172.24.4.33'
        self.mac = 'aa:bb:cc:dd:ee:ff'

        self.router1_info = {'bridge_device': self.bridge,
                             'bridge_vlan': 100,
                             'ips': ['172.24.4.11'],
                             'provider_switch': 'provider-ls'}
        self.nb_bgp_driver.ovn_local_cr_lrps = {
            'router1': self.router1_info}
        self.ovn_routing_tables = {
            self.bridge: 100,
            'br-vlan': 200}
        self.nb_bgp_driver.ovn_routing_tables = self.ovn_routing_tables
        self.ovn_routing_tables_routes = mock.Mock()
        self.nb_bgp_driver.ovn_routing_tables_routes = (
            self.ovn_routing_tables_routes)

        self.conf_ovsdb_connection = 'tcp:127.0.0.1:6642'

    @mock.patch.object(linux_net, 'ensure_vrf')
    @mock.patch.object(frr, 'vrf_leak')
    @mock.patch.object(linux_net, 'ensure_ovn_device')
    @mock.patch.object(linux_net, 'delete_routes_from_table')
    def test_start(self, mock_delete_routes_from_table,
                   mock_ensure_ovn_device, mock_vrf_leak, mock_ensure_vrf):
        CONF.set_override('clear_vrf_routes_on_startup', True)
        self.addCleanup(CONF.clear_override, 'clear_vrf_routes_on_startup')
        self.mock_ovs_idl.get_own_chassis_name.return_value = 'chassis-name'
        self.mock_ovs_idl.get_own_chassis_id.return_value = 'chassis-id'
        self.mock_ovs_idl.get_ovn_remote.return_value = (
            self.conf_ovsdb_connection)

        self.nb_bgp_driver.start()

        # Verify mock object method calls and arguments
        self.mock_ovs_idl().start.assert_called_once_with(
            CONF.ovsdb_connection)
        self.mock_ovs_idl().get_own_chassis_name.assert_called_once()
        self.mock_ovs_idl().get_own_chassis_id.assert_called_once()

        self.mock_ovs_idl().get_ovn_remote.assert_called_once()

        mock_ensure_vrf.assert_called_once_with(
            CONF.bgp_vrf, CONF.bgp_vrf_table_id)
        mock_vrf_leak.assert_called_once_with(
            CONF.bgp_vrf, CONF.bgp_AS, CONF.bgp_router_id,
            template=frr.LEAK_VRF_TEMPLATE)
        mock_ensure_ovn_device.assert_called_once_with(CONF.bgp_nic,
                                                       CONF.bgp_vrf)
        mock_delete_routes_from_table.assert_called_once_with(
            CONF.bgp_vrf_table_id)
        self.mock_nbdb().start.assert_called_once_with()

    @mock.patch.object(linux_net, 'ensure_ovn_device')
    @mock.patch.object(frr, 'vrf_leak')
    @mock.patch.object(linux_net, 'ensure_vrf')
    def test_frr_sync(self, mock_ensure_vrf, mock_vrf_leak,
                      mock_ensure_ovn_dev):
        self.nb_bgp_driver.frr_sync()

        mock_ensure_vrf.assert_called_once_with(
            CONF.bgp_vrf, CONF.bgp_vrf_table_id)
        mock_vrf_leak.assert_called_once_with(
            CONF.bgp_vrf, CONF.bgp_AS, CONF.bgp_router_id,
            template=frr.LEAK_VRF_TEMPLATE)
        mock_ensure_ovn_dev.assert_called_once_with(
            CONF.bgp_nic, CONF.bgp_vrf)

    @mock.patch.object(linux_net, 'delete_vlan_device_for_network')
    @mock.patch.object(linux_net, 'get_bridge_vlans')
    @mock.patch.object(linux_net, 'get_extra_routing_table_for_bridge')
    @mock.patch.object(linux_net, 'delete_bridge_ip_routes')
    @mock.patch.object(linux_net, 'delete_ip_rules')
    @mock.patch.object(linux_net, 'delete_exposed_ips')
    @mock.patch.object(linux_net, 'get_ovn_ip_rules')
    @mock.patch.object(linux_net, 'get_exposed_ips')
    @mock.patch.object(ovs, 'remove_extra_ovs_flows')
    @mock.patch.object(ovs, 'ensure_mac_tweak_flows')
    @mock.patch.object(ovs, 'get_ovs_patch_ports_info')
    @mock.patch.object(linux_net, 'get_interface_address')
    @mock.patch.object(linux_net, 'ensure_arp_ndp_enabled_for_bridge')
    @mock.patch.object(linux_net, 'ensure_vlan_device_for_network')
    @mock.patch.object(linux_net, 'ensure_routing_table_for_bridge')
    def test_sync(self, mock_routing_bridge, mock_ensure_vlan_network,
                  mock_ensure_arp, mock_nic_address, mock_get_patch_ports,
                  mock_ensure_mac, mock_remove_flows, mock_exposed_ips,
                  mock_get_ip_rules, mock_del_exposed_ips, mock_del_ip_rules,
                  mock_del_ip_routes, mock_get_extra_route,
                  mock_get_bridge_vlans, mock_delete_vlan_dev):
        self.mock_ovs_idl.get_ovn_bridge_mappings.return_value = [
            'net0:bridge0', 'net1:bridge1']
        self.nb_idl.get_network_vlan_tag_by_network_name.side_effect = (
            [10], [11])
        fake_ip_rules = 'fake-ip-rules'
        mock_get_ip_rules.return_value = fake_ip_rules
        ips = [self.ipv4, self.ipv6]
        mock_exposed_ips.return_value = ips

        crlrp_port = fakes.create_object({
            'name': 'crlrp_port'})
        lrp0 = fakes.create_object({
            'name': 'lrp_port',
            'external_ids': {
                constants.OVN_CIDRS_EXT_ID_KEY: "10.0.0.1/24",
                constants.OVN_LS_NAME_EXT_ID_KEY: 'network1',
                constants.OVN_DEVICE_ID_EXT_ID_KEY: 'fake-router'}})
        port0 = fakes.create_object({
            'name': 'port-0',
            'type': constants.OVN_VM_VIF_PORT_TYPE})
        port1 = fakes.create_object({
            'name': 'port-1',
            'type': constants.OVN_CHASSISREDIRECT_VIF_PORT_TYPE})
        lb1 = fakes.create_object({
            'name': 'lb1',
            'external_ids': {constants.OVN_LB_VIP_FIP_EXT_ID_KEY: 'fake-fip'}
        })
        self.nb_idl.get_active_cr_lrp_on_chassis.return_value = [crlrp_port]
        self.nb_idl.get_active_local_lrps.return_value = [lrp0]
        self.nb_idl.get_active_lsp_on_chassis.return_value = [
            port0, port1]
        self.nb_idl.get_active_local_lbs.return_value = [lb1]
        mock_ensure_crlrp_exposed = mock.patch.object(
            self.nb_bgp_driver, '_ensure_crlrp_exposed').start()
        mock_expose_subnet = mock.patch.object(
            self.nb_bgp_driver, '_expose_subnet').start()
        mock_ensure_lsp_exposed = mock.patch.object(
            self.nb_bgp_driver, '_ensure_lsp_exposed').start()
        mock_expose_ovn_lb_vip = mock.patch.object(
            self.nb_bgp_driver, '_expose_ovn_lb_vip').start()
        mock_expose_ovn_lb_fip = mock.patch.object(
            self.nb_bgp_driver, '_expose_ovn_lb_fip').start()
        mock_routing_bridge.return_value = ['fake-route']
        mock_nic_address.return_value = self.mac
        mock_get_patch_ports.return_value = [1, 2]

        self.nb_idl.get_network_vlan_tags.return_value = [10, 11]
        mock_get_bridge_vlans.side_effect = [[10, 12], [11]]

        self.nb_bgp_driver.sync()

        expected_calls = [mock.call({}, 'bridge0', CONF.bgp_vrf_table_id),
                          mock.call({}, 'bridge1', CONF.bgp_vrf_table_id)]
        mock_routing_bridge.assert_has_calls(expected_calls)
        expected_calls = [mock.call('bridge0', 10), mock.call('bridge1', 11)]
        mock_ensure_vlan_network.assert_has_calls(expected_calls)
        expected_calls = [mock.call('bridge0', 1, [10]),
                          mock.call('bridge1', 2, [11])]
        mock_ensure_arp.assert_has_calls(expected_calls)
        expected_calls = [
            mock.call('bridge0'), mock.call('bridge1')]
        mock_get_patch_ports.assert_has_calls(expected_calls)
        expected_calls = [
            mock.call('bridge0', mock.ANY, [1, 2], constants.OVS_RULE_COOKIE),
            mock.call('bridge1', mock.ANY, [1, 2], constants.OVS_RULE_COOKIE)]
        mock_ensure_mac.assert_has_calls(expected_calls)
        expected_calls = [
            mock.call(mock.ANY, 'bridge0', constants.OVS_RULE_COOKIE),
            mock.call(mock.ANY, 'bridge1', constants.OVS_RULE_COOKIE)]
        mock_remove_flows.assert_has_calls(expected_calls)
        mock_get_ip_rules.assert_called_once()
        mock_ensure_crlrp_exposed.assert_called_once_with(crlrp_port)
        mock_expose_subnet.assert_called_once_with(
            ["10.0.0.1/24"],
            {'associated_router': 'fake-router',
             'network': 'network1',
             'address_scopes': {4: None, 6: None}})
        mock_ensure_lsp_exposed.assert_called_once_with(port0)
        mock_expose_ovn_lb_vip.assert_called_once_with(lb1)
        mock_expose_ovn_lb_fip.assert_called_once_with(lb1)
        mock_del_exposed_ips.assert_called_once_with(
            ips, CONF.bgp_nic)
        mock_del_ip_rules.assert_called_once_with(fake_ip_rules)
        mock_del_ip_routes.assert_called_once()
        bridge = set(self.nb_bgp_driver.ovn_bridge_mappings.values()).pop()
        mock_delete_vlan_dev.assert_called_once_with(bridge, 12)

    def test__ensure_lsp_exposed_fip(self):
        port0 = fakes.create_object({
            'name': 'port-0',
            'external_ids': {constants.OVN_FIP_EXT_ID_KEY: "fip"}})

        mock_get_port_external_ip_and_ls = mock.patch.object(
            self.nb_bgp_driver, 'get_port_external_ip_and_ls').start()
        mock_get_port_external_ip_and_ls.return_value = ("192.168.0.10",
                                                         "fake-mac",
                                                         "test-ls")
        mock_expose_fip = mock.patch.object(
            self.nb_bgp_driver, '_expose_fip').start()
        mock_expose_ip = mock.patch.object(
            self.nb_bgp_driver, '_expose_ip').start()

        self.nb_bgp_driver._ensure_lsp_exposed(port0)

        mock_get_port_external_ip_and_ls.assert_called_once_with(port0.name)
        mock_expose_fip.assert_called_once_with("192.168.0.10", "fake-mac",
                                                "test-ls", port0)
        mock_expose_ip.assert_not_called()

    def test__ensure_lsp_exposed_tenant_ls(self):
        port0 = fakes.create_object({
            'name': 'port-0',
            'external_ids': {constants.OVN_LS_NAME_EXT_ID_KEY: "test-ls"}})
        self.nb_bgp_driver.ovn_tenant_ls = {"test-ls": True}

        mock_get_port_external_ip_and_ls = mock.patch.object(
            self.nb_bgp_driver, 'get_port_external_ip_and_ls').start()
        mock_expose_fip = mock.patch.object(
            self.nb_bgp_driver, '_expose_fip').start()
        mock_expose_ip = mock.patch.object(
            self.nb_bgp_driver, '_expose_ip').start()

        self.nb_bgp_driver._ensure_lsp_exposed(port0)

        mock_get_port_external_ip_and_ls.assert_not_called()
        mock_expose_fip.assert_not_called()
        mock_expose_ip.assert_not_called()

    @mock.patch.object(linux_net, 'get_ip_version')
    def test__ensure_lsp_exposed_no_fip_no_tenant_ls(self, mock_ip_version):
        port0 = utils.create_row(
            name='port-0',
            addresses=["fake_mac 192.168.0.10"],
            type=constants.OVN_VM_VIF_PORT_TYPE,
            external_ids={constants.OVN_LS_NAME_EXT_ID_KEY: "test-ls"})

        self.nb_bgp_driver.ovn_tenant_ls = {}
        self.nb_bgp_driver.ovn_provider_ls = {}

        mock_get_port_external_ip_and_ls = mock.patch.object(
            self.nb_bgp_driver, 'get_port_external_ip_and_ls').start()
        mock_expose_fip = mock.patch.object(
            self.nb_bgp_driver, '_expose_fip').start()
        mock_expose_ip = mock.patch.object(
            self.nb_bgp_driver, '_expose_ip').start()
        mock_expose_ip.return_value = ['192.168.0.10']
        mock_is_ls_provider = mock.patch.object(
            self.nb_bgp_driver, 'is_ls_provider', return_value=True).start()
        mock_get_ls_localnet_info = mock.patch.object(
            self.nb_bgp_driver, '_get_ls_localnet_info').start()
        mock_get_ls_localnet_info.return_value = ('fake-localnet', 'br-ex', 10)
        mock_ip_version.return_value = constants.IP_VERSION_4

        self.nb_bgp_driver._ensure_lsp_exposed(port0)

        mock_get_port_external_ip_and_ls.assert_not_called()
        mock_is_ls_provider.assert_called_once_with('test-ls')
        mock_get_ls_localnet_info.assert_called_once_with('test-ls')
        mock_expose_fip.assert_not_called()
        mock_expose_ip.assert_called_once_with(
            ['192.168.0.10'], 'fake_mac', 'test-ls', 'br-ex', 10,
            constants.OVN_VM_VIF_PORT_TYPE, [])

    def test__ensure_crlrp_exposed(self):
        port = fakes.create_object({
            'name': 'lrp-port',
            'networks': ['172.24.16.2/24'],
            'mac': "fake_mac",
            'status': {'hosting-chassis': self.nb_bgp_driver.chassis_id},
            'external_ids': {constants.OVN_LS_NAME_EXT_ID_KEY: "test-ls"}})
        mock_get_ls_localnet_info = mock.patch.object(
            self.nb_bgp_driver, '_get_ls_localnet_info').start()
        mock_get_ls_localnet_info.return_value = ('fake-localnet', 'br-ex', 10)
        mock_expose_ip = mock.patch.object(
            self.nb_bgp_driver, '_expose_ip').start()
        mock_is_ls_provider = mock.patch.object(
            self.nb_bgp_driver, 'is_ls_provider', return_value=True).start()

        self.nb_bgp_driver._ensure_crlrp_exposed(port)

        mock_is_ls_provider.assert_called_once_with('test-ls')
        mock_expose_ip.assert_called_once_with(
            ['172.24.16.2'], 'fake_mac', 'test-ls', 'br-ex', 10,
            constants.OVN_CR_LRP_PORT_TYPE, ['172.24.16.2/24'], router=None)

    def test__ensure_crlrp_exposed_no_networks(self):
        port = fakes.create_object({
            'name': 'lrp-port',
            'networks': [],
            'mac': "fake_mac",
            'status': {'hosting-chassis': self.nb_bgp_driver.chassis_id},
            'external_ids': {constants.OVN_LS_NAME_EXT_ID_KEY: "test-ls"}})
        mock_expose_ip = mock.patch.object(
            self.nb_bgp_driver, '_expose_ip').start()

        self.nb_bgp_driver._ensure_crlrp_exposed(port)

        mock_expose_ip.assert_not_called()

    def test__ensure_crlrp_exposed_no_logical_switch(self):
        port = fakes.create_object({
            'name': 'lrp-port',
            'networks': ['172.24.16.2/24'],
            'mac': "fake_mac",
            'status': {'hosting-chassis': self.nb_bgp_driver.chassis_id},
            'external_ids': {}})

        mock_expose_ip = mock.patch.object(
            self.nb_bgp_driver, '_expose_ip').start()

        self.nb_bgp_driver._ensure_crlrp_exposed(port)

        mock_expose_ip.assert_not_called()

    def test__ensure_crlrp_exposed_no_bridge(self):
        port = fakes.create_object({
            'name': 'lrp-port',
            'networks': ['172.24.16.2/24'],
            'mac': "fake_mac",
            'status': {'hosting-chassis': self.nb_bgp_driver.chassis_id},
            'external_ids': {constants.OVN_LS_NAME_EXT_ID_KEY: "test-ls"}})
        mock_get_ls_localnet_info = mock.patch.object(
            self.nb_bgp_driver, '_get_ls_localnet_info').start()
        mock_get_ls_localnet_info.return_value = (None, None, None)
        mock_expose_ip = mock.patch.object(
            self.nb_bgp_driver, '_expose_ip').start()

        self.nb_bgp_driver._ensure_crlrp_exposed(port)

        mock_expose_ip.assert_not_called()

    @mock.patch.object(wire_utils, 'wire_provider_port')
    @mock.patch.object(bgp_utils, 'announce_ips')
    def test__expose_provider_port_successful(self, mock_announce_ips,
                                              mock_wire_provider_port):
        mock_wire_provider_port.return_value = True
        port_ips = ['192.168.0.1', '192.168.0.2']
        bridge_device = self.bridge
        bridge_vlan = None
        proxy_cidrs = ['192.168.0.0/24']

        self.nb_bgp_driver._expose_provider_port(
            port_ips, 'fake-mac', 'test-ls', bridge_device, bridge_vlan,
            'fake-localnet', proxy_cidrs)

        mock_wire_provider_port.assert_called_once_with(
            self.ovn_routing_tables_routes, {}, port_ips, bridge_device,
            bridge_vlan, 'fake-localnet', self.ovn_routing_tables,
            proxy_cidrs, mac='fake-mac', ovn_idl=mock.ANY)
        mock_announce_ips.assert_called_once_with(port_ips)

    @mock.patch.object(wire_utils, 'wire_provider_port')
    @mock.patch.object(bgp_utils, 'announce_ips')
    def test__expose_provider_port_failure(self, mock_announce_ips,
                                           mock_wire_provider_port):
        mock_wire_provider_port.return_value = False
        port_ips = ['192.168.0.1', '192.168.0.2']
        bridge_device = self.bridge
        bridge_vlan = None
        proxy_cidrs = ['192.168.0.0/24']

        self.nb_bgp_driver._expose_provider_port(
            port_ips, 'fake-mac', 'test-ls', bridge_device, bridge_vlan,
            'fake-localnet', proxy_cidrs)

        mock_wire_provider_port.assert_called_once_with(
            self.ovn_routing_tables_routes, {}, port_ips, bridge_device,
            bridge_vlan, 'fake-localnet', self.ovn_routing_tables, proxy_cidrs,
            mac='fake-mac', ovn_idl=mock.ANY)
        mock_announce_ips.assert_not_called()

    @mock.patch.object(wire_utils, 'unwire_provider_port')
    @mock.patch.object(bgp_utils, 'withdraw_ips')
    def test__withdraw_provider_port(self, mock_withdraw_ips,
                                     mock_unwire_provider_port):
        port_ips = ['192.168.0.1', '192.168.0.2']
        bridge_device = self.bridge
        bridge_vlan = None
        proxy_cidrs = ['192.168.0.0/24']

        self.nb_bgp_driver._withdraw_provider_port(
            port_ips, 'test-ls', bridge_device, bridge_vlan, proxy_cidrs)

        mock_withdraw_ips.assert_called_once_with(port_ips)
        mock_unwire_provider_port.assert_called_once_with(
            self.ovn_routing_tables_routes, port_ips, bridge_device,
            bridge_vlan, self.ovn_routing_tables, proxy_cidrs,
            ovn_idl=mock.ANY)

    def test__get_bridge_for_localnet_port(self):
        localnet = fakes.create_object({
            'options': {'network_name': 'fake-network'},
            'tag': [10]})

        bridge_device, bridge_vlan = (
            self.nb_bgp_driver._get_bridge_for_localnet_port(localnet))
        self.assertEqual(bridge_device, self.bridge)
        self.assertEqual(bridge_vlan, 10)

    def test__get_bridge_for_localnet_port_no_network_no_tag(self):
        localnet = fakes.create_object({
            'options': {},
            'tag': None})

        bridge_device, bridge_vlan = (
            self.nb_bgp_driver._get_bridge_for_localnet_port(localnet))
        self.assertEqual(bridge_device, None)
        self.assertEqual(bridge_vlan, None)

    def test_is_ip_exposed(self):
        self.nb_bgp_driver._exposed_ips['fake-switch'] = {'fake-ip': {}}
        self.assertTrue(self.nb_bgp_driver.is_ip_exposed('fake-switch',
                                                         'fake-ip'))
        self.assertFalse(self.nb_bgp_driver.is_ip_exposed('no-switch',
                                                          'fake-ip'))
        self.assertFalse(self.nb_bgp_driver.is_ip_exposed('fake-switch',
                                                          'other-ip'))

    def _test_expose_ip(self, ips, ips_info):
        mock_expose_provider_port = mock.patch.object(
            self.nb_bgp_driver, '_expose_provider_port').start()
        mock_get_ls_localnet_info = mock.patch.object(
            self.nb_bgp_driver, '_get_ls_localnet_info').start()
        mock_get_ls_localnet_info.return_value = ('fake-localnet', 'br-ex', 10)
        self.nb_bgp_driver.ovn_bridge_mappings = {'fake-localnet': 'br-ex'}
        mock_expose_subnet = mock.patch.object(
            self.nb_bgp_driver, '_expose_subnet').start()

        if (ips_info.get('router') and
                ips_info['type'] == constants.OVN_CR_LRP_PORT_TYPE):
            lrp0 = fakes.create_object({
                'name': 'lrp_port',
                'external_ids': {
                    constants.OVN_CIDRS_EXT_ID_KEY: "10.0.0.1/24",
                    constants.OVN_LS_NAME_EXT_ID_KEY: 'network1',
                    constants.OVN_DEVICE_ID_EXT_ID_KEY: 'router1'}})
            self.nb_idl.get_active_local_lrps.return_value = [lrp0]
            lb1 = fakes.create_object({
                'name': 'lb1', 'external_ids': {
                    constants.OVN_LB_VIP_FIP_EXT_ID_KEY: 'fake-fip'}})
            self.nb_idl.get_active_local_lbs.return_value = [lb1]
            mock_expose_ovn_lb_vip = mock.patch.object(
                self.nb_bgp_driver, '_expose_ovn_lb_vip').start()
            mock_expose_ovn_lb_fip = mock.patch.object(
                self.nb_bgp_driver, '_expose_ovn_lb_fip').start()

        self.nb_bgp_driver.expose_ip(ips, ips_info)

        if not ips_info['logical_switch']:
            mock_expose_provider_port.assert_not_called()
            mock_get_ls_localnet_info.assert_not_called()
            return

        mock_get_ls_localnet_info.assert_called_once_with(
            ips_info['logical_switch'])
        self.assertEqual(
            self.nb_bgp_driver.ovn_provider_ls[ips_info['logical_switch']],
            {'bridge_device': 'br-ex', 'bridge_vlan': 10,
             'localnet': 'fake-localnet'})
        if (ips_info['type'] in [constants.OVN_VIRTUAL_VIF_PORT_TYPE,
                                 constants.OVN_CR_LRP_PORT_TYPE] and
                ips_info['cidrs']):
            mock_expose_provider_port.assert_called_once_with(
                ips, 'fake-mac', 'test-ls', 'br-ex', 10, 'fake-localnet',
                ips_info['cidrs'])
        else:
            mock_expose_provider_port.assert_called_once_with(
                ips, 'fake-mac', 'test-ls', 'br-ex', 10, 'fake-localnet', [])

        if (ips_info.get('router') and
                ips_info['type'] == constants.OVN_CR_LRP_PORT_TYPE):
            mock_expose_subnet.assert_called_once_with(
                ["10.0.0.1/24"], {'associated_router': 'router1',
                                  'network': 'network1',
                                  'address_scopes': {4: None, 6: None}})
            mock_expose_ovn_lb_vip.assert_called_once_with(lb1)
            mock_expose_ovn_lb_fip.assert_called_once_with(lb1)

    def test_expose_ip(self):
        ips = [self.ipv4, self.ipv6]
        ips_info = {
            'mac': 'fake-mac',
            'cidrs': [],
            'type': constants.OVN_VM_VIF_PORT_TYPE,
            'logical_switch': 'test-ls'
        }

        self._test_expose_ip(ips, ips_info)

    def test_expose_ip_virtual(self):
        ips = [self.ipv4, self.ipv6]
        ips_info = {
            'mac': 'fake-mac',
            'cidrs': ['test-cidr'],
            'type': constants.OVN_VIRTUAL_VIF_PORT_TYPE,
            'logical_switch': 'test-ls'
        }

        self._test_expose_ip(ips, ips_info)

    def test_expose_ip_no_switch(self):
        ips = [self.ipv4, self.ipv6]
        ips_info = {
            'mac': 'fake-mac',
            'cidrs': [],
            'type': constants.OVN_VM_VIF_PORT_TYPE,
            'logical_switch': None
        }

        self._test_expose_ip(ips, ips_info)

    def test_expose_ip_router(self):
        ips = [self.ipv4, self.ipv6]
        ips_info = {
            'mac': 'fake-mac',
            'cidrs': ['test-cidr'],
            'type': constants.OVN_CR_LRP_PORT_TYPE,
            'logical_switch': 'test-ls',
            'router': 'router1'
        }

        self._test_expose_ip(ips, ips_info)

    @mock.patch.object(linux_net, 'get_ip_version')
    def _test_withdraw_ip(self, ips, ips_info, provider, mock_ip_version):
        mock_withdraw_provider_port = mock.patch.object(
            self.nb_bgp_driver, '_withdraw_provider_port').start()
        mock_get_ls_localnet_info = mock.patch.object(
            self.nb_bgp_driver, '_get_ls_localnet_info').start()
        mock_ip_version.return_value = constants.IP_VERSION_6
        self.nb_idl.ls_has_virtual_ports.return_value = False
        self.nb_idl.get_active_lsp_on_chassis.return_value = False
        if provider:
            mock_get_ls_localnet_info.return_value = ('fake-localnet', 'br-ex',
                                                      10)
        else:
            mock_get_ls_localnet_info.return_value = (None, None, None)

        mock_withdraw_subnet = mock.patch.object(
            self.nb_bgp_driver, '_withdraw_subnet').start()
        if (ips_info.get('router') and
                ips_info['type'] == constants.OVN_CR_LRP_PORT_TYPE):
            lrp0 = fakes.create_object({
                'name': 'lrp_port',
                'external_ids': {
                    constants.OVN_CIDRS_EXT_ID_KEY: "10.0.0.1/24",
                    constants.OVN_LS_NAME_EXT_ID_KEY: 'network1',
                    constants.OVN_DEVICE_ID_EXT_ID_KEY: 'router1'}})
            self.nb_idl.get_active_local_lrps.return_value = [lrp0]
            lb1 = fakes.create_object({
                'name': 'lb1', 'external_ids': {
                    constants.OVN_LB_VIP_FIP_EXT_ID_KEY: 'fake-fip'}})
            self.nb_idl.get_active_local_lbs.return_value = [lb1]
            mock_withdraw_ovn_lb_vip = mock.patch.object(
                self.nb_bgp_driver, '_withdraw_ovn_lb_vip').start()
            mock_withdraw_ovn_lb_fip = mock.patch.object(
                self.nb_bgp_driver, '_withdraw_ovn_lb_fip').start()

        self.nb_bgp_driver.withdraw_ip(ips, ips_info)

        if not ips_info['logical_switch']:
            mock_get_ls_localnet_info.assert_not_called()
            mock_withdraw_provider_port.assert_not_called()
            return
        if not provider:
            mock_get_ls_localnet_info.assert_called_once_with(
                ips_info['logical_switch'])
            mock_withdraw_provider_port.assert_not_called()
            return

        mock_get_ls_localnet_info.assert_called_once_with(
            ips_info['logical_switch'])
        if (ips_info['type'] in [constants.OVN_VIRTUAL_VIF_PORT_TYPE,
                                 constants.OVN_CR_LRP_PORT_TYPE] and
                ips_info['cidrs']):
            mock_withdraw_provider_port.assert_called_once_with(
                ips, 'test-ls', 'br-ex', 10, ips_info['cidrs'])
        else:
            mock_withdraw_provider_port.assert_called_once_with(
                ips, 'test-ls', 'br-ex', 10, [])

        if ips_info.get('router'):
            mock_withdraw_subnet.assert_called_once_with(
                ["10.0.0.1/24"], {'associated_router': 'router1',
                                  'network': 'network1',
                                  'address_scopes': {4: None, 6: None}})
            mock_withdraw_ovn_lb_vip.assert_called_once_with(lb1)
            mock_withdraw_ovn_lb_fip.assert_called_once_with(lb1)

    def test_withdraw_ip(self):
        ips = [self.ipv4, self.ipv6]
        ips_info = {
            'mac': 'fake-mac',
            'cidrs': [],
            'type': constants.OVN_VM_VIF_PORT_TYPE,
            'logical_switch': 'test-ls'
        }

        self._test_withdraw_ip(ips, ips_info, True)

    def test_withdraw_ip_no_provider(self):
        ips = [self.ipv4, self.ipv6]
        ips_info = {
            'mac': 'fake-mac',
            'cidrs': [],
            'type': constants.OVN_VM_VIF_PORT_TYPE,
            'logical_switch': 'test-ls'
        }

        self._test_withdraw_ip(ips, ips_info, False)

    def test_withdraw_ip_virtual(self):
        ips = [self.ipv4, self.ipv6]
        ips_info = {
            'mac': 'fake-mac',
            'cidrs': ['test-cidr'],
            'type': constants.OVN_VIRTUAL_VIF_PORT_TYPE,
            'logical_switch': 'test-ls'
        }

        self._test_withdraw_ip(ips, ips_info, True)

    def test_withdraw_ip_no_switch(self):
        ips = [self.ipv4, self.ipv6]
        ips_info = {
            'mac': 'fake-mac',
            'cidrs': [],
            'type': constants.OVN_VM_VIF_PORT_TYPE,
            'logical_switch': None
        }

        self._test_withdraw_ip(ips, ips_info, True)

    def test_withdraw_ip_router(self):
        ips = [self.ipv4, self.ipv6]
        ips_info = {
            'mac': 'fake-mac',
            'cidrs': ['test-cidr'],
            'type': constants.OVN_CR_LRP_PORT_TYPE,
            'logical_switch': 'test-ls',
            'router': 'router1'
        }

        self._test_withdraw_ip(ips, ips_info, True)

    def test__get_ls_localnet_info(self):
        logical_switch = 'lswitch1'
        fake_localnet_port = fakes.create_object({
            'name': 'fake-localnet-port'})
        localnet_ports = [fake_localnet_port]
        self.nb_idl.ls_get_localnet_ports.return_value.execute.return_value = (
            localnet_ports)
        mock_get_bridge_for_localnet_port = mock.patch.object(
            self.nb_bgp_driver, '_get_bridge_for_localnet_port').start()
        mock_get_bridge_for_localnet_port.return_value = ('br-ex', 10)

        ret = self.nb_bgp_driver._get_ls_localnet_info(logical_switch)

        self.assertEqual(ret, (fake_localnet_port.name, 'br-ex', 10))
        self.nb_idl.ls_get_localnet_ports.assert_called_once_with(
            logical_switch, if_exists=True)
        mock_get_bridge_for_localnet_port.assert_called_once_with(
            localnet_ports[0])

    def test_get_ls_localnet_info_not_provider_network(self):
        logical_switch = 'lswitch1'
        localnet_ports = []
        self.nb_idl.ls_get_localnet_ports.return_value.execute.return_value = (
            localnet_ports)
        mock_get_bridge_for_localnet_port = mock.patch.object(
            self.nb_bgp_driver, '_get_bridge_for_localnet_port').start()

        ret = self.nb_bgp_driver._get_ls_localnet_info(logical_switch)

        self.nb_idl.ls_get_localnet_ports.assert_called_once_with(
            logical_switch, if_exists=True)
        mock_get_bridge_for_localnet_port.assert_not_called()
        self.assertEqual(ret, (None, None, None))

    def test_get_port_external_ip_and_ls(self):
        nat_entry = fakes.create_object({
            'external_ids': {constants.OVN_FIP_NET_EXT_ID_KEY: 'net1'},
            'external_ip': 'fake-ip',
            'external_mac': 'fake-mac'})
        self.nb_idl.get_nat_by_logical_port.return_value = nat_entry

        ret = self.nb_bgp_driver.get_port_external_ip_and_ls('fake-port')

        expected_result = (nat_entry.external_ip, nat_entry.external_mac,
                           "neutron-net1")
        self.assertEqual(ret, expected_result)

    def test_get_port_external_ip_and_ls_no_nat_entry(self):
        self.nb_idl.get_nat_by_logical_port.return_value = None

        ret = self.nb_bgp_driver.get_port_external_ip_and_ls('fake-port')

        self.assertEqual(ret, (None, None, None))

    def test_get_port_external_ip_and_ls_no_external_id(self):
        nat_entry = fakes.create_object({
            'external_ids': {},
            'external_ip': 'fake-ip',
            'external_mac': 'fake-mac'})
        self.nb_idl.get_nat_by_logical_port.return_value = nat_entry

        ret = self.nb_bgp_driver.get_port_external_ip_and_ls('fake-port')

        self.assertEqual(ret,
                         (nat_entry.external_ip, nat_entry.external_mac, None))

    def test_expose_fip(self):
        ip = '10.0.0.1'
        mac = 'fake-mac'
        logical_switch = 'lswitch1'
        mock_get_ls_localnet_info = mock.patch.object(
            self.nb_bgp_driver, '_get_ls_localnet_info').start()
        mock_get_ls_localnet_info.return_value = ('fake-localnet', 'br-ex',
                                                  100)
        self.nb_bgp_driver.ovn_bridge_mappings = {'fake-localnet': 'br-ex'}
        mock_expose_provider_port = mock.patch.object(
            self.nb_bgp_driver, '_expose_provider_port').start()
        row = fakes.create_object({
            'external_ids': {constants.OVN_LS_NAME_EXT_ID_KEY: 'test-ls'}})

        ret = self.nb_bgp_driver.expose_fip(ip, mac, logical_switch, row)

        mock_get_ls_localnet_info.assert_called_once_with(logical_switch)
        mock_expose_provider_port.assert_called_once_with([ip], mac, 'test-ls',
                                                          'br-ex', 100,
                                                          'fake-localnet')
        self.assertTrue(ret)

    def test_expose_fip_no_device(self):
        ip = '10.0.0.1'
        mac = 'fake-mac'
        logical_switch = 'lswitch1'
        mock_get_ls_localnet_info = mock.patch.object(
            self.nb_bgp_driver, '_get_ls_localnet_info').start()
        mock_get_ls_localnet_info.return_value = (None, None, None)
        mock_expose_provider_port = mock.patch.object(
            self.nb_bgp_driver, '_expose_provider_port').start()
        row = fakes.create_object({
            'external_ids': {constants.OVN_LS_NAME_EXT_ID_KEY: 'test-ls'}})

        ret = self.nb_bgp_driver.expose_fip(ip, mac, logical_switch, row)

        mock_get_ls_localnet_info.assert_called_once_with(logical_switch)
        mock_expose_provider_port.assert_not_called()
        self.assertNotIn(
            ip, self.nb_bgp_driver._exposed_ips.get('test-ls', {}).keys())
        self.assertFalse(ret)

    def test_withdraw_fip(self):
        ip = '10.0.0.1'
        self.nb_bgp_driver._exposed_ips['test-ls'] = {
            ip: {'bridge_device': 'br-ex', 'bridge_vlan': 100}}
        mock_withdraw_provider_port = mock.patch.object(
            self.nb_bgp_driver, '_withdraw_provider_port').start()
        row = fakes.create_object({
            'external_ids': {constants.OVN_LS_NAME_EXT_ID_KEY: 'test-ls'}})

        self.nb_bgp_driver.withdraw_fip(ip, row)
        mock_withdraw_provider_port.assert_called_once_with([ip], 'test-ls',
                                                            'br-ex', 100)

    def test_withdraw_fip_not_found(self):
        ip = '10.0.0.1'
        self.nb_bgp_driver._exposed_ips = {}
        mock_withdraw_provider_port = mock.patch.object(
            self.nb_bgp_driver, '_withdraw_provider_port').start()
        row = fakes.create_object({
            'external_ids': {constants.OVN_LS_NAME_EXT_ID_KEY: 'test-ls'}})

        self.nb_bgp_driver.withdraw_fip(ip, row)
        mock_withdraw_provider_port.assert_not_called()

    @mock.patch.object(bgp_utils, 'announce_ips')
    def test_expose_remote_ip(self, m_announce_ips):
        ips = [self.ipv4, self.ipv6]
        ips_info = {
            'mac': 'fake-mac',
            'cidrs': [],
            'type': constants.OVN_VM_VIF_PORT_TYPE,
            'logical_switch': 'test-ls'
        }
        self.nb_bgp_driver.expose_remote_ip(ips, ips_info)

        m_announce_ips.assert_called_once_with(ips)

    @mock.patch.object(driver_utils, 'is_ipv6_gua')
    @mock.patch.object(bgp_utils, 'announce_ips')
    def test_expose_remote_ip_gua(self, m_announce_ips, m_gua):
        CONF.set_override('expose_tenant_networks', False)
        self.addCleanup(CONF.clear_override, 'expose_tenant_networks')
        CONF.set_override('expose_ipv6_gua_tenant_networks', True)
        self.addCleanup(CONF.clear_override, 'expose_ipv6_gua_tenant_networks')
        ips = [self.ipv4, self.ipv6]
        ips_info = {
            'mac': 'fake-mac',
            'cidrs': [],
            'type': constants.OVN_VM_VIF_PORT_TYPE,
            'logical_switch': 'test-ls'
        }
        m_gua.side_effect = [False, True]
        self.nb_bgp_driver.expose_remote_ip(ips, ips_info)

        m_announce_ips.assert_called_once_with([self.ipv6])

    @mock.patch.object(bgp_utils, 'withdraw_ips')
    def test_withdraw_remote_ip(self, m_withdraw_ips):
        ips = [self.ipv4, self.ipv6]
        ips_info = {
            'mac': 'fake-mac',
            'cidrs': [],
            'type': constants.OVN_VM_VIF_PORT_TYPE,
            'logical_switch': 'test-ls'
        }
        self.nb_bgp_driver.withdraw_remote_ip(ips, ips_info)

        m_withdraw_ips.assert_called_once_with(ips)

    @mock.patch.object(driver_utils, 'is_ipv6_gua')
    @mock.patch.object(bgp_utils, 'withdraw_ips')
    def test_withdraw_remote_ip_gua(self, m_withdraw_ips, m_gua):
        CONF.set_override('expose_tenant_networks', False)
        self.addCleanup(CONF.clear_override, 'expose_tenant_networks')
        CONF.set_override('expose_ipv6_gua_tenant_networks', True)
        self.addCleanup(CONF.clear_override, 'expose_ipv6_gua_tenant_networks')
        ips = [self.ipv4, self.ipv6]
        ips_info = {
            'mac': 'fake-mac',
            'cidrs': [],
            'type': constants.OVN_VM_VIF_PORT_TYPE,
            'logical_switch': 'test-ls'
        }
        m_gua.side_effect = [False, True]
        self.nb_bgp_driver.withdraw_remote_ip(ips, ips_info)

        m_withdraw_ips.assert_called_once_with([self.ipv6])

    def test_expose_subnet(self):
        ips = ['10.0.0.1/24']
        subnet_info = {
            'associated_router': 'router1',
            'network': 'network1',
            'address_scopes': {4: None, 6: None}}
        mock_expose_router_lsp = mock.patch.object(
            self.nb_bgp_driver, '_expose_router_lsp').start()
        mock_expose_remote_ip = mock.patch.object(
            self.nb_bgp_driver, '_expose_remote_ip').start()

        port0 = utils.create_row(
            type=constants.OVN_VM_VIF_PORT_TYPE,
            addresses=['mac 192.168.0.5'],
            external_ids={
                constants.OVN_CIDRS_EXT_ID_KEY: "192.168.0.5/24",
                constants.OVN_LS_NAME_EXT_ID_KEY: 'network1'
            })
        port1 = utils.create_row(
            type=constants.OVN_VIRTUAL_VIF_PORT_TYPE,
            addresses=['mac 192.168.0.6'],
            external_ids={
                constants.OVN_CIDRS_EXT_ID_KEY: "192.168.0.6/24",
                constants.OVN_LS_NAME_EXT_ID_KEY: 'network1'
            })
        self.nb_idl.get_active_lsp.return_value = [port0, port1]

        self.nb_bgp_driver.expose_subnet(ips, subnet_info)
        mock_expose_router_lsp.assert_called_once_with(
            ips, subnet_info, self.router1_info)
        ips_info0 = {'mac': 'mac',
                     'cidrs': ['192.168.0.5/24'],
                     'type': constants.OVN_VM_VIF_PORT_TYPE,
                     'logical_switch': 'network1'}
        ips_info1 = {'mac': 'mac',
                     'cidrs': ['192.168.0.6/24'],
                     'type': constants.OVN_VIRTUAL_VIF_PORT_TYPE,
                     'logical_switch': 'network1'}
        expected_calls = [mock.call(['192.168.0.5'], ips_info0),
                          mock.call(['192.168.0.6'], ips_info1)]
        mock_expose_remote_ip.assert_has_calls(expected_calls)

    def test_expose_subnet_no_router(self):
        ips = ['10.0.0.1/24']
        subnet_info = {
            'associated_router': None,
            'network': 'network1',
            'address_scopes': {4: None, 6: None}}
        mock_expose_router_lsp = mock.patch.object(
            self.nb_bgp_driver, '_expose_router_lsp').start()

        self.nb_bgp_driver.expose_subnet(ips, subnet_info)
        mock_expose_router_lsp.assert_not_called()

    def test_expose_subnet_no_cr_lrp(self):
        ips = ['10.0.0.1/24']
        subnet_info = {
            'associated_router': 'other-router',
            'network': 'network1',
            'address_scopes': {4: None, 6: None}}
        mock_expose_router_lsp = mock.patch.object(
            self.nb_bgp_driver, '_expose_router_lsp').start()

        self.nb_bgp_driver.expose_subnet(ips, subnet_info)
        mock_expose_router_lsp.assert_not_called()

    def test_expose_subnet_not_per_lsp(self):

        CONF.set_override('advertisement_method_tenant_networks',
                          constants.ADVERTISEMENT_METHOD_SUBNET)
        self.addCleanup(CONF.clear_override,
                        'advertisement_method_tenant_networks')

        ips = ['10.0.0.1/24']
        subnet_info = {
            'associated_router': 'router1',
            'network': 'network1',
            'address_scopes': {4: None, 6: None}}
        mock_expose_router_lsp = mock.patch.object(
            self.nb_bgp_driver, '_expose_router_lsp').start()
        mock_expose_remote_ip = mock.patch.object(
            self.nb_bgp_driver, '_expose_remote_ip').start()

        self.nb_bgp_driver.expose_subnet(ips, subnet_info)

        mock_expose_router_lsp.assert_called_once_with(ips, subnet_info,
                                                       self.router1_info)

        self.nb_idl.get_active_lsp.assert_not_called()
        mock_expose_remote_ip.assert_not_called()

    def _test_expose_subnet_require_snat_disabled(self,
                                                  partial_continue=False):
        CONF.set_override('require_snat_disabled_for_tenant_networks', True)
        self.addCleanup(CONF.clear_override,
                        'require_snat_disabled_for_tenant_networks')

        ips = ['10.0.0.1/24']
        if partial_continue:
            ips.append(self.ipv6 + '/64')

        subnet_info = {
            'associated_router': 'router1',
            'network': 'network1',
            'address_scopes': {4: None, 6: None}}
        mock_expose_router_lsp = mock.patch.object(
            self.nb_bgp_driver, '_expose_router_lsp').start()
        mock_expose_remote_ip = mock.patch.object(
            self.nb_bgp_driver, '_expose_remote_ip').start()

        router = utils.create_row(
            nat=[utils.create_row(
                type=constants.OVN_SNAT,
                logical_ip='10.0.0.0/24',
            )],
        )
        self.nb_idl.get_router.return_value = router

        self.nb_bgp_driver.expose_subnet(ips, subnet_info)

        gateway_router = subnet_info['associated_router']
        self.nb_idl.get_router.assert_called_once_with(gateway_router)

        if not partial_continue:
            self.nb_idl.get_active_lsp.assert_not_called()
            mock_expose_remote_ip.assert_not_called()
            mock_expose_router_lsp.assert_not_called()
        else:
            # partial continue scenario is when SNAT is not enabled for the
            # router, so only the ipv6 should match
            mock_expose_router_lsp.assert_called_once_with(
                [self.ipv6 + '/64'], subnet_info, self.router1_info)

            ips_info0 = {'mac': 'mac',
                         'cidrs': ['192.168.0.5/24'],
                         'type': constants.OVN_VM_VIF_PORT_TYPE,
                         'logical_switch': 'network1'}
            ips_info1 = {'mac': 'mac',
                         'cidrs': ['192.168.0.6/24'],
                         'type': constants.OVN_VIRTUAL_VIF_PORT_TYPE,
                         'logical_switch': 'network1'}
            expected_calls = [mock.call(['192.168.0.5'], ips_info0),
                              mock.call(['192.168.0.6'], ips_info1)]
            mock_expose_remote_ip.assert_has_calls(expected_calls)

    def test_expose_subnet_require_snat_disabled(self):
        self._test_expose_subnet_require_snat_disabled(
            partial_continue=False,
        )

    def test_expose_subnet_require_snat_disabled_partial_continue(self):
        # Setup get_active_lsp for partial_continue scenario
        port0 = utils.create_row(
            type=constants.OVN_VM_VIF_PORT_TYPE,
            addresses=['mac 192.168.0.5'],
            external_ids={
                constants.OVN_CIDRS_EXT_ID_KEY: "192.168.0.5/24",
                constants.OVN_LS_NAME_EXT_ID_KEY: 'network1'
            })
        port1 = utils.create_row(
            type=constants.OVN_VIRTUAL_VIF_PORT_TYPE,
            addresses=['mac 192.168.0.6'],
            external_ids={
                constants.OVN_CIDRS_EXT_ID_KEY: "192.168.0.6/24",
                constants.OVN_LS_NAME_EXT_ID_KEY: 'network1'
            })
        self.nb_idl.get_active_lsp.return_value = [port0, port1]

        self._test_expose_subnet_require_snat_disabled(
            partial_continue=True,
        )

    def test_withdraw_subnet(self):
        ips = ['10.0.0.1/24']
        subnet_info = {
            'associated_router': 'router1',
            'network': 'network1',
            'address_scopes': {4: None, 6: None}}
        mock_withdraw_router_lsp = mock.patch.object(
            self.nb_bgp_driver, '_withdraw_router_lsp').start()
        mock_withdraw_remote_ip = mock.patch.object(
            self.nb_bgp_driver, '_withdraw_remote_ip').start()

        port0 = utils.create_row(
            type=constants.OVN_VM_VIF_PORT_TYPE,
            addresses=['mac 192.168.0.5'],
            external_ids={
                constants.OVN_CIDRS_EXT_ID_KEY: "192.168.0.5/24",
                constants.OVN_LS_NAME_EXT_ID_KEY: 'network1'
            })
        port1 = utils.create_row(
            type=constants.OVN_VIRTUAL_VIF_PORT_TYPE,
            addresses=['mac 192.168.0.6'],
            external_ids={
                constants.OVN_CIDRS_EXT_ID_KEY: "192.168.0.6/24",
                constants.OVN_LS_NAME_EXT_ID_KEY: 'network1'
            })
        self.nb_idl.get_active_lsp.return_value = [port0, port1]

        self.nb_bgp_driver.withdraw_subnet(ips, subnet_info)
        mock_withdraw_router_lsp.assert_called_once_with(
            ips, subnet_info, self.router1_info)
        ips_info0 = {'mac': 'mac',
                     'cidrs': ['192.168.0.5/24'],
                     'type': constants.OVN_VM_VIF_PORT_TYPE,
                     'logical_switch': 'network1'}
        ips_info1 = {'mac': 'mac',
                     'cidrs': ['192.168.0.6/24'],
                     'type': constants.OVN_VIRTUAL_VIF_PORT_TYPE,
                     'logical_switch': 'network1'}
        expected_calls = [mock.call(['192.168.0.5'], ips_info0),
                          mock.call(['192.168.0.6'], ips_info1)]
        mock_withdraw_remote_ip.assert_has_calls(expected_calls)

    def test_withdraw_subnet_no_router(self):
        ips = ['10.0.0.1/24']
        subnet_info = {
            'associated_router': None,
            'network': 'network1',
            'address_scopes': {4: None, 6: None}}
        mock_withdraw_router_lsp = mock.patch.object(
            self.nb_bgp_driver, '_withdraw_router_lsp').start()

        self.nb_bgp_driver.withdraw_subnet(ips, subnet_info)
        mock_withdraw_router_lsp.assert_not_called()

    def test_withdraw_subnet_no_cr_lrp(self):
        ips = ['10.0.0.1/24']
        subnet_info = {
            'associated_router': 'other-router',
            'network': 'network1',
            'address_scopes': {4: None, 6: None}}
        mock_withdraw_router_lsp = mock.patch.object(
            self.nb_bgp_driver, '_withdraw_router_lsp').start()

        self.nb_bgp_driver.withdraw_subnet(ips, subnet_info)
        mock_withdraw_router_lsp.assert_not_called()

    @mock.patch.object(wire_utils, 'wire_lrp_port')
    def test__expose_router_lsp(self, mock_wire):
        ips = ['10.0.0.1/24']
        subnet_info = {
            'associated_router': 'other-router',
            'network': 'network1',
            'address_scopes': {4: None, 6: None}}

        CONF.set_override('advertisement_method_tenant_networks',
                          constants.ADVERTISEMENT_METHOD_SUBNET)
        self.addCleanup(CONF.clear_override,
                        'advertisement_method_tenant_networks')

        ret = self.nb_bgp_driver._expose_router_lsp(ips, subnet_info,
                                                    self.router1_info)

        self.assertTrue(ret)
        mock_wire.assert_called_once_with(
            mock.ANY, '10.0.0.0/24', self.router1_info['bridge_device'],
            self.router1_info['bridge_vlan'], mock.ANY,
            self.router1_info['ips'])

    @mock.patch.object(wire_utils, 'wire_lrp_port')
    def test__expose_router_lsp_per_host(self, mock_wire):
        ips = ['10.0.0.1/24']
        subnet_info = {
            'associated_router': 'other-router',
            'network': 'network1',
            'address_scopes': {4: None, 6: None}}

        ret = self.nb_bgp_driver._expose_router_lsp(ips, subnet_info,
                                                    self.router1_info)

        self.assertTrue(ret)
        mock_wire.assert_called_once_with(
            mock.ANY, '10.0.0.1/24', self.router1_info['bridge_device'],
            self.router1_info['bridge_vlan'], mock.ANY,
            self.router1_info['ips'])

    @mock.patch.object(wire_utils, 'wire_lrp_port')
    def test__expose_router_lsp_exception(self, mock_wire):
        ips = ['10.0.0.1/24']
        subnet_info = {
            'associated_router': 'other-router',
            'network': 'network1',
            'address_scopes': {4: None, 6: None}}
        mock_wire.side_effect = Exception

        CONF.set_override('advertisement_method_tenant_networks',
                          constants.ADVERTISEMENT_METHOD_SUBNET)
        self.addCleanup(CONF.clear_override,
                        'advertisement_method_tenant_networks')

        self.assertRaises(exceptions.WireFailure,
                          self.nb_bgp_driver._expose_router_lsp,
                          ips, subnet_info, self.router1_info)

        mock_wire.assert_called_once_with(
            mock.ANY, '10.0.0.0/24', self.router1_info['bridge_device'],
            self.router1_info['bridge_vlan'], mock.ANY,
            self.router1_info['ips'])

    @mock.patch.object(wire_utils, 'wire_lrp_port')
    def test__expose_router_lsp_no_tenants(self, mock_wire):
        CONF.set_override('expose_tenant_networks', False)
        self.addCleanup(CONF.clear_override, 'expose_tenant_networks')
        ips = ['10.0.0.1/24']
        subnet_info = {
            'associated_router': 'other-router',
            'network': 'network1',
            'address_scopes': {4: None, 6: None}}

        ret = self.nb_bgp_driver._expose_router_lsp(ips, subnet_info,
                                                    self.router1_info)

        self.assertTrue(ret)
        mock_wire.assert_not_called()

    @mock.patch.object(driver_utils, 'is_ipv6_gua')
    @mock.patch.object(wire_utils, 'wire_lrp_port')
    def test__expose_router_lsp_no_tenants_but_gua(self, mock_wire, mock_gua):
        CONF.set_override('expose_tenant_networks', False)
        self.addCleanup(CONF.clear_override, 'expose_tenant_networks')
        CONF.set_override('expose_ipv6_gua_tenant_networks', True)
        self.addCleanup(CONF.clear_override, 'expose_ipv6_gua_tenant_networks')
        CONF.set_override('advertisement_method_tenant_networks',
                          constants.ADVERTISEMENT_METHOD_SUBNET)
        self.addCleanup(CONF.clear_override,
                        'advertisement_method_tenant_networks')

        ips = ['10.0.0.1/24', '2002::1/64']
        subnet_info = {
            'associated_router': 'other-router',
            'network': 'network1',
            'address_scopes': {4: None, 6: None}}
        mock_gua.side_effect = [False, True]

        ret = self.nb_bgp_driver._expose_router_lsp(ips, subnet_info,
                                                    self.router1_info)

        self.assertTrue(ret)
        mock_wire.assert_called_once_with(
            mock.ANY, '2002::/64', self.router1_info['bridge_device'],
            self.router1_info['bridge_vlan'], mock.ANY,
            self.router1_info['ips'])

    @mock.patch.object(wire_utils, 'unwire_lrp_port')
    def test__withdraw_router_lsp(self, mock_unwire):
        ips = ['10.0.0.1/24']
        subnet_info = {
            'associated_router': 'other-router',
            'network': 'network1',
            'address_scopes': {4: None, 6: None}}

        CONF.set_override('advertisement_method_tenant_networks',
                          constants.ADVERTISEMENT_METHOD_SUBNET)
        self.addCleanup(CONF.clear_override,
                        'advertisement_method_tenant_networks')

        ret = self.nb_bgp_driver._withdraw_router_lsp(ips, subnet_info,
                                                      self.router1_info)

        self.assertTrue(ret)
        mock_unwire.assert_called_once_with(
            mock.ANY, '10.0.0.0/24', self.router1_info['bridge_device'],
            self.router1_info['bridge_vlan'], mock.ANY,
            self.router1_info['ips'])

    @mock.patch.object(wire_utils, 'unwire_lrp_port')
    def test__withdraw_router_lsp_per_host(self, mock_unwire):
        ips = ['10.0.0.1/24']
        subnet_info = {
            'associated_router': 'other-router',
            'network': 'network1',
            'address_scopes': {4: None, 6: None}}

        ret = self.nb_bgp_driver._withdraw_router_lsp(ips, subnet_info,
                                                      self.router1_info)

        self.assertTrue(ret)
        mock_unwire.assert_called_once_with(
            mock.ANY, '10.0.0.1/24', self.router1_info['bridge_device'],
            self.router1_info['bridge_vlan'], mock.ANY,
            self.router1_info['ips'])

    @mock.patch.object(wire_utils, 'unwire_lrp_port')
    def test__withdraw_router_lsp_exception(self, mock_unwire):
        ips = ['10.0.0.1/24']
        subnet_info = {
            'associated_router': 'other-router',
            'network': 'network1',
            'address_scopes': {4: None, 6: None}}
        mock_unwire.side_effect = Exception

        CONF.set_override('advertisement_method_tenant_networks',
                          constants.ADVERTISEMENT_METHOD_SUBNET)
        self.addCleanup(CONF.clear_override,
                        'advertisement_method_tenant_networks')

        self.assertRaises(
            exceptions.UnwireFailure, self.nb_bgp_driver._withdraw_router_lsp,
            ips, subnet_info, self.router1_info)

        mock_unwire.assert_called_once_with(
            mock.ANY, '10.0.0.0/24', self.router1_info['bridge_device'],
            self.router1_info['bridge_vlan'], mock.ANY,
            self.router1_info['ips'])

    @mock.patch.object(wire_utils, 'unwire_lrp_port')
    def test__withdraw_router_lsp_no_tenants(self, mock_unwire):
        CONF.set_override('expose_tenant_networks', False)
        self.addCleanup(CONF.clear_override, 'expose_tenant_networks')
        ips = ['10.0.0.1/24']
        subnet_info = {
            'associated_router': 'other-router',
            'network': 'network1',
            'address_scopes': {4: None, 6: None}}

        CONF.set_override('advertisement_method_tenant_networks',
                          constants.ADVERTISEMENT_METHOD_SUBNET)
        self.addCleanup(CONF.clear_override,
                        'advertisement_method_tenant_networks')

        ret = self.nb_bgp_driver._withdraw_router_lsp(ips, subnet_info,
                                                      self.router1_info)

        self.assertTrue(ret)
        mock_unwire.assert_not_called()

    @mock.patch.object(driver_utils, 'is_ipv6_gua')
    @mock.patch.object(wire_utils, 'unwire_lrp_port')
    def test__withdraw_router_lsp_no_tenants_but_gua(self, mock_unwire,
                                                     mock_gua):
        CONF.set_override('expose_tenant_networks', False)
        self.addCleanup(CONF.clear_override, 'expose_tenant_networks')
        CONF.set_override('expose_ipv6_gua_tenant_networks', True)
        self.addCleanup(CONF.clear_override, 'expose_ipv6_gua_tenant_networks')
        CONF.set_override('advertisement_method_tenant_networks',
                          constants.ADVERTISEMENT_METHOD_SUBNET)
        self.addCleanup(CONF.clear_override,
                        'advertisement_method_tenant_networks')

        ips = ['10.0.0.1/24', '2002::1/64']
        subnet_info = {
            'associated_router': 'other-router',
            'network': 'network1',
            'address_scopes': {4: None, 6: None}}
        mock_gua.side_effect = [False, True]

        ret = self.nb_bgp_driver._withdraw_router_lsp(ips, subnet_info,
                                                      self.router1_info)

        self.assertTrue(ret)
        mock_unwire.assert_called_once_with(
            mock.ANY, '2002::/64', self.router1_info['bridge_device'],
            self.router1_info['bridge_vlan'], mock.ANY,
            self.router1_info['ips'])

    def test__ips_in_address_scope(self):
        subnet_pool_addr_scope4 = '88e8aec3-da29-402d-becf-9fa2c38e69b8'
        subnet_pool_addr_scope6 = 'b7834aeb-2aa2-40ac-a8b5-2cded713cb58'
        _scopes = {
            constants.IP_VERSION_4: subnet_pool_addr_scope4,
            constants.IP_VERSION_6: subnet_pool_addr_scope6,
        }

        self.nb_bgp_driver.allowed_address_scopes = [subnet_pool_addr_scope4]

        ips = ['10.0.0.1/24', '2002::1/64']

        # Allowed address scope is v4, so v6 should be removed.
        ret = self.nb_bgp_driver._ips_in_address_scope(ips, _scopes)
        self.assertListEqual(ret, ['10.0.0.1/24'])

    def test__address_scope_allowed(self):
        subnet_pool_addr_scope4 = '88e8aec3-da29-402d-becf-9fa2c38e69b8'
        subnet_pool_addr_scope6 = 'b7834aeb-2aa2-40ac-a8b5-2cded713cb58'
        _scopes = {
            constants.IP_VERSION_4: subnet_pool_addr_scope4,
            constants.IP_VERSION_6: subnet_pool_addr_scope6,
        }

        # Configure ipv4 scope to be allowed
        self.nb_bgp_driver.allowed_address_scopes = [subnet_pool_addr_scope4]

        # Check if ipv4 address with correct scope matches
        self.assertTrue(self.nb_bgp_driver._address_scope_allowed(self.ipv4,
                                                                  _scopes))

    def test__address_scope_allowed_not_configured(self):
        # Check not configured (should always return True)
        self.assertTrue(self.nb_bgp_driver._address_scope_allowed(self.ipv4,
                                                                  {}))

    def test__address_scope_allowed_no_match(self):
        subnet_pool_addr_scope4 = '88e8aec3-da29-402d-becf-9fa2c38e69b8'
        subnet_pool_addr_scope6 = 'b7834aeb-2aa2-40ac-a8b5-2cded713cb58'
        _scopes = {
            constants.IP_VERSION_4: subnet_pool_addr_scope4,
            constants.IP_VERSION_6: subnet_pool_addr_scope6,
        }

        self.nb_bgp_driver.allowed_address_scopes = [subnet_pool_addr_scope4]

        # Make sure ipv6 address with scope not in list fails
        self.assertFalse(self.nb_bgp_driver._address_scope_allowed(self.ipv6,
                                                                   _scopes))
        # Check IPv4 address without scope given, should fail
        self.assertFalse(self.nb_bgp_driver._address_scope_allowed(self.ipv4,
                                                                   {}))

    def test_expose_ovn_lb_vip_tenant(self):
        self.nb_bgp_driver.ovn_local_lrps = {'net1': ['ip1']}
        lb = utils.create_row(
            external_ids={
                constants.OVN_LB_LR_REF_EXT_ID_KEY: 'neutron-router1',
                constants.OVN_LB_VIP_PORT_EXT_ID_KEY: 'vip_port',
                constants.OVN_LB_VIP_IP_EXT_ID_KEY: 'vip'},
            vips={'vip': 'member', 'fip': 'member'})

        vip_lsp = utils.create_row(
            external_ids={
                constants.OVN_LS_NAME_EXT_ID_KEY: 'net1'
            })
        self.nb_idl.lsp_get.return_value.execute.return_value = vip_lsp
        mock_expose_remote_ip = mock.patch.object(
            self.nb_bgp_driver, '_expose_remote_ip').start()
        mock_expose_provider_port = mock.patch.object(
            self.nb_bgp_driver, '_expose_provider_port').start()

        self.nb_bgp_driver.expose_ovn_lb_vip(lb)

        mock_expose_remote_ip.assert_called_once_with(
            ['vip'], {'logical_switch': 'router1'}
        )
        mock_expose_provider_port.assert_not_called()

    def test_expose_ovn_lb_vip_provider(self):
        self.nb_bgp_driver.ovn_local_lrps = {'net1': ['ip1']}
        lb = utils.create_row(
            external_ids={
                constants.OVN_LB_LR_REF_EXT_ID_KEY: 'neutron-router1',
                constants.OVN_LB_VIP_PORT_EXT_ID_KEY: 'vip_port',
                constants.OVN_LB_VIP_IP_EXT_ID_KEY: 'vip'},
            vips={'vip': 'member', 'fip': 'member'})

        vip_lsp = utils.create_row(
            external_ids={
                constants.OVN_LS_NAME_EXT_ID_KEY: 'net2'
            })
        self.nb_idl.lsp_get.return_value.execute.return_value = vip_lsp
        mock_expose_remote_ip = mock.patch.object(
            self.nb_bgp_driver, '_expose_remote_ip').start()
        mock_expose_provider_port = mock.patch.object(
            self.nb_bgp_driver, '_expose_provider_port').start()
        mock_get_ls_localnet_info = mock.patch.object(
            self.nb_bgp_driver, '_get_ls_localnet_info').start()
        mock_get_ls_localnet_info.return_value = (None, None, None)

        self.nb_bgp_driver.expose_ovn_lb_vip(lb)

        mock_expose_remote_ip.assert_not_called()
        mock_get_ls_localnet_info.assert_called_once_with('net2')
        mock_expose_provider_port.assert_called_once_with(
            ['vip'], None, 'net2', mock.ANY, mock.ANY, mock.ANY)

    def test_expose_ovn_lb_vip_no_vip(self):
        self.nb_bgp_driver.ovn_local_lrps = {'net1': ['ip1']}
        lb = utils.create_row(
            external_ids={
                constants.OVN_LB_LR_REF_EXT_ID_KEY: 'neutron-router1',
                constants.OVN_LB_VIP_PORT_EXT_ID_KEY: 'vip_port',
                constants.OVN_LB_VIP_IP_EXT_ID_KEY: 'vip'},
            vips={'vip': 'member', 'fip': 'member'})

        self.nb_idl.lsp_get.return_value.execute.return_value = None
        mock_expose_remote_ip = mock.patch.object(
            self.nb_bgp_driver, '_expose_remote_ip').start()
        mock_expose_provider_port = mock.patch.object(
            self.nb_bgp_driver, '_expose_provider_port').start()

        self.nb_bgp_driver.expose_ovn_lb_vip(lb)

        mock_expose_remote_ip.assert_not_called()
        mock_expose_provider_port.assert_not_called()

    def test_withdraw_ovn_lb_vip_tenant(self):
        lb = utils.create_row(
            external_ids={
                constants.OVN_LB_LR_REF_EXT_ID_KEY: 'neutron-router1',
                constants.OVN_LB_VIP_PORT_EXT_ID_KEY: 'vip_port',
                constants.OVN_LB_VIP_IP_EXT_ID_KEY: 'vip'},
            vips={'vip': 'member', 'fip': 'member'})
        mock_withdraw_remote_ip = mock.patch.object(
            self.nb_bgp_driver, '_withdraw_remote_ip').start()
        mock_withdraw_provider_port = mock.patch.object(
            self.nb_bgp_driver, '_withdraw_provider_port').start()

        self.nb_bgp_driver.withdraw_ovn_lb_vip(lb)

        mock_withdraw_provider_port.assert_not_called()
        mock_withdraw_remote_ip.assert_called_once_with(
            ['vip'], {'logical_switch': 'router1'})

    def test_withdraw_ovn_lb_vip_provider(self):
        self.nb_bgp_driver._exposed_ips = {
            'provider-ls': {'vip': {'bridge_device': self.bridge,
                                    'bridge_vlan': None}}}
        lb = utils.create_row(
            external_ids={
                constants.OVN_LB_LR_REF_EXT_ID_KEY: 'neutron-router1',
                constants.OVN_LB_VIP_PORT_EXT_ID_KEY: 'vip_port',
                constants.OVN_LB_VIP_IP_EXT_ID_KEY: 'vip'},
            vips={'vip': 'member', 'fip': 'member'})
        mock_withdraw_remote_ip = mock.patch.object(
            self.nb_bgp_driver, '_withdraw_remote_ip').start()
        mock_withdraw_provider_port = mock.patch.object(
            self.nb_bgp_driver, '_withdraw_provider_port').start()

        self.nb_bgp_driver.withdraw_ovn_lb_vip(lb)

        mock_withdraw_provider_port.assert_called_once_with(
            ['vip'],
            self.router1_info['provider_switch'],
            self.router1_info['bridge_device'],
            self.router1_info['bridge_vlan'])
        mock_withdraw_remote_ip.assert_not_called()

    def test_withdraw_ovn_lb_vip_no_router(self):
        lb = utils.create_row(
            external_ids={
                constants.OVN_LB_LR_REF_EXT_ID_KEY: 'neutron-router2',
                constants.OVN_LB_VIP_PORT_EXT_ID_KEY: 'vip_port',
                constants.OVN_LB_VIP_IP_EXT_ID_KEY: 'vip'},
            vips={'vip': 'member', 'fip': 'member'})
        mock_withdraw_remote_ip = mock.patch.object(
            self.nb_bgp_driver, '_withdraw_remote_ip').start()
        mock_withdraw_provider_port = mock.patch.object(
            self.nb_bgp_driver, '_withdraw_provider_port').start()

        self.nb_bgp_driver.withdraw_ovn_lb_vip(lb)

        mock_withdraw_remote_ip.assert_not_called()
        mock_withdraw_provider_port.assert_not_called()

    def test_expose_ovn_pf_lb_fip(self):
        lb = utils.create_row(
            external_ids={
                constants.OVN_LR_NAME_EXT_ID_KEY: 'neutron-router1'},
            name='pf-floatingip-uuid-tcp',
            vips={'fip:port': 'member:port'})

        mock_get_ls_localnet_info = mock.patch.object(
            self.nb_bgp_driver, '_get_ls_localnet_info').start()
        mock_get_ls_localnet_info.return_value = ('provider-ls', 'br-ex',
                                                  100)
        mock_expose_provider_port = mock.patch.object(
            self.nb_bgp_driver, '_expose_provider_port').start()

        self.nb_bgp_driver.expose_ovn_pf_lb_fip(lb)
        kwargs = {
            'port_ips': ['fip'],
            'mac': None,
            'logical_switch': 'provider-ls',
            'bridge_device': 'br-ex',
            'bridge_vlan': 100,
            'localnet': 'provider-ls'}
        mock_expose_provider_port.assert_called_once_with(**kwargs)

    def test_expose_ovn_pf_lb_fip_no_router(self):
        lb = utils.create_row(
            external_ids={},
            name='pf-floatingip-uuid-tcp',
            vips={'fip:port': 'member:port'})

        mock_expose_provider_port = mock.patch.object(
            self.nb_bgp_driver, '_expose_provider_port').start()

        self.nb_bgp_driver.expose_ovn_pf_lb_fip(lb)
        mock_expose_provider_port.assert_not_called()

    def test_expose_ovn_pf_lb_fip_no_router_cr_lrp(self):
        lb = utils.create_row(
            external_ids={
                constants.OVN_LR_NAME_EXT_ID_KEY: 'neutron-router2'},
            name='pf-floatingip-uuid-tcp',
            vips={'fip:port': 'member:port'})

        mock_expose_provider_port = mock.patch.object(
            self.nb_bgp_driver, '_expose_provider_port').start()

        self.nb_bgp_driver.expose_ovn_pf_lb_fip(lb)
        mock_expose_provider_port.assert_not_called()

    def test_expose_ovn_lb_fip(self):
        lb = utils.create_row(
            external_ids={
                constants.OVN_LB_LR_REF_EXT_ID_KEY: 'neutron-router1',
                constants.OVN_LB_VIP_PORT_EXT_ID_KEY: 'vip_port',
                constants.OVN_LB_VIP_IP_EXT_ID_KEY: 'vip'},
            vips={'vip': 'member', 'fip': 'member'})
        vip_lsp = utils.create_row(
            name='vip-port-name',
            external_ids={
                constants.OVN_LS_NAME_EXT_ID_KEY: 'net2'
            })
        self.nb_idl.lsp_get.return_value.execute.return_value = vip_lsp
        mock_get_port_external_ip_and_ls = mock.patch.object(
            self.nb_bgp_driver, 'get_port_external_ip_and_ls').start()
        mock_get_port_external_ip_and_ls.return_value = ('fip',
                                                         'fip-mac',
                                                         'provider-ls')
        mock_expose_fip = mock.patch.object(
            self.nb_bgp_driver, '_expose_fip').start()

        self.nb_bgp_driver.expose_ovn_lb_fip(lb)
        mock_expose_fip.assert_called_once_with(
            'fip', 'fip-mac', 'provider-ls', vip_lsp)

    def test_expose_ovn_lb_fip_no_vip_port(self):
        lb = utils.create_row(
            external_ids={
                constants.OVN_LB_LR_REF_EXT_ID_KEY: 'neutron-router1',
                constants.OVN_LB_VIP_PORT_EXT_ID_KEY: 'vip_port',
                constants.OVN_LB_VIP_IP_EXT_ID_KEY: 'vip'},
            vips={'vip': 'member', 'fip': 'member'})
        self.nb_idl.lsp_get.return_value.execute.return_value = None
        mock_expose_fip = mock.patch.object(
            self.nb_bgp_driver, '_expose_fip').start()

        self.nb_bgp_driver.expose_ovn_lb_fip(lb)
        mock_expose_fip.assert_not_called()

    def test_expose_ovn_lb_fip_no_external_ip(self):
        lb = utils.create_row(
            external_ids={
                constants.OVN_LB_LR_REF_EXT_ID_KEY: 'neutron-router1',
                constants.OVN_LB_VIP_PORT_EXT_ID_KEY: 'vip_port',
                constants.OVN_LB_VIP_IP_EXT_ID_KEY: 'vip'},
            vips={'vip': 'member', 'fip': 'member'})
        vip_lsp = utils.create_row(
            name='vip-port-name',
            external_ids={
                constants.OVN_LS_NAME_EXT_ID_KEY: 'net2'
            })
        self.nb_idl.lsp_get.return_value.execute.return_value = vip_lsp
        mock_get_port_external_ip_and_ls = mock.patch.object(
            self.nb_bgp_driver, 'get_port_external_ip_and_ls').start()
        mock_get_port_external_ip_and_ls.return_value = (None, None, None)
        mock_expose_fip = mock.patch.object(
            self.nb_bgp_driver, '_expose_fip').start()

        self.nb_bgp_driver.expose_ovn_lb_fip(lb)
        mock_expose_fip.assert_not_called()

    def test_withdraw_ovn_lb_fip(self):
        lb = utils.create_row(
            external_ids={
                constants.OVN_LB_LR_REF_EXT_ID_KEY: 'neutron-router1',
                constants.OVN_LB_VIP_PORT_EXT_ID_KEY: 'vip_port',
                constants.OVN_LB_VIP_IP_EXT_ID_KEY: 'vip',
                constants.OVN_LB_VIP_FIP_EXT_ID_KEY: 'vip-fip'},
            vips={'vip': 'member', 'fip': 'member'})
        mock_withdraw_provider_port = mock.patch.object(
            self.nb_bgp_driver, '_withdraw_provider_port').start()

        self.nb_bgp_driver.withdraw_ovn_lb_fip(lb)
        mock_withdraw_provider_port.assert_called_once_with(
            ['vip-fip'],
            self.router1_info['provider_switch'],
            self.router1_info['bridge_device'],
            self.router1_info['bridge_vlan'])

    def test_withdraw_ovn_lb_fip_no_vip_router(self):
        lb = utils.create_row(
            external_ids={
                constants.OVN_LB_VIP_PORT_EXT_ID_KEY: 'vip_port',
                constants.OVN_LB_VIP_IP_EXT_ID_KEY: 'vip',
                constants.OVN_LB_VIP_FIP_EXT_ID_KEY: 'vip-fip'},
            vips={'vip': 'member', 'fip': 'member'})
        mock_withdraw_provider_port = mock.patch.object(
            self.nb_bgp_driver, '_withdraw_provider_port').start()

        self.nb_bgp_driver.withdraw_ovn_lb_fip(lb)
        mock_withdraw_provider_port.assert_not_called()

    def test_withdraw_ovn_lb_fip_no_cr_lrp(self):
        lb = utils.create_row(
            external_ids={
                constants.OVN_LB_LR_REF_EXT_ID_KEY: 'neutron-router2',
                constants.OVN_LB_VIP_PORT_EXT_ID_KEY: 'vip_port',
                constants.OVN_LB_VIP_IP_EXT_ID_KEY: 'vip',
                constants.OVN_LB_VIP_FIP_EXT_ID_KEY: 'vip-fip'},
            vips={'vip': 'member', 'fip': 'member'})
        mock_withdraw_provider_port = mock.patch.object(
            self.nb_bgp_driver, '_withdraw_provider_port').start()

        self.nb_bgp_driver.withdraw_ovn_lb_fip(lb)
        mock_withdraw_provider_port.assert_not_called()

    def test_withdraw_ovn_pf_lb_fip(self):
        lb = utils.create_row(
            external_ids={
                constants.OVN_LR_NAME_EXT_ID_KEY: 'neutron-router1'},
            name='pf-floatingip-uuid-tcp',
            vips={'fip:port': 'member:port'})

        mock_get_ls_localnet_info = mock.patch.object(
            self.nb_bgp_driver, '_get_ls_localnet_info').start()
        mock_get_ls_localnet_info.return_value = ('provider-ls', 'br-ex', 100)

        mock_withdraw_provider_port = mock.patch.object(
            self.nb_bgp_driver, '_withdraw_provider_port').start()

        self.nb_bgp_driver.withdraw_ovn_pf_lb_fip(lb)
        kwargs = {
            'port_ips': ['fip'],
            'logical_switch': 'provider-ls',
            'bridge_device': 'br-ex',
            'bridge_vlan': 100}
        mock_withdraw_provider_port.assert_called_once_with(**kwargs)

    def test_withdraw_ovn_pf_lb_fip_no_router(self):
        lb = utils.create_row(
            external_ids={},
            name='pf-floatingip-uuid-tcp',
            vips={'fip:port': 'member:port'})

        mock_withdraw_provider_port = mock.patch.object(
            self.nb_bgp_driver, '_withdraw_provider_port').start()

        self.nb_bgp_driver.withdraw_ovn_pf_lb_fip(lb)
        mock_withdraw_provider_port.assert_not_called()

    def test_withdraw_ovn_pf_lb_fip_no_cr_lrp(self):
        lb = utils.create_row(
            external_ids={
                constants.OVN_LR_NAME_EXT_ID_KEY: 'neutron-router2'},
            name='pf-floatingip-uuid-tcp',
            vips={'fip:port': 'member:port'})

        mock_withdraw_provider_port = mock.patch.object(
            self.nb_bgp_driver, '_withdraw_provider_port').start()

        self.nb_bgp_driver.withdraw_ovn_pf_lb_fip(lb)
        mock_withdraw_provider_port.assert_not_called()

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
from ovn_bgp_agent.drivers.openstack.utils import frr
from ovn_bgp_agent.drivers.openstack.utils import ovn
from ovn_bgp_agent.drivers.openstack.utils import ovs
from ovn_bgp_agent.drivers.openstack.utils import wire as wire_utils
from ovn_bgp_agent.tests import base as test_base
from ovn_bgp_agent.tests.unit import fakes
from ovn_bgp_agent.utils import linux_net

CONF = cfg.CONF


class TestNBOVNBGPDriver(test_base.TestCase):

    def setUp(self):
        super(TestNBOVNBGPDriver, self).setUp()
        self.bridge = 'fake-bridge'
        self.nb_bgp_driver = nb_ovn_bgp_driver.NBOVNBGPDriver()
        self.nb_bgp_driver._post_start_event = mock.Mock()
        self.nb_bgp_driver.nb_idl = mock.Mock()
        self.nb_idl = self.nb_bgp_driver.nb_idl
        self.nb_bgp_driver.chassis = 'fake-chassis'
        self.nb_bgp_driver.ovn_bridge_mappings = {'fake-network': self.bridge}

        self.mock_nbdb = mock.patch.object(ovn, 'OvnNbIdl').start()
        self.mock_ovs_idl = mock.patch.object(ovs, 'OvsIdl').start()
        self.nb_bgp_driver.ovs_idl = self.mock_ovs_idl

        self.ipv4 = '192.168.1.17'
        self.ipv6 = '2002::1234:abcd:ffff:c0a8:101'
        self.fip = '172.24.4.33'
        self.mac = 'aa:bb:cc:dd:ee:ff'

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
        self.mock_ovs_idl.get_ovn_remote.return_value = (
            self.conf_ovsdb_connection)

        self.nb_bgp_driver.start()

        # Verify mock object method calls and arguments
        self.mock_ovs_idl().start.assert_called_once_with(
            CONF.ovsdb_connection)
        self.mock_ovs_idl().get_own_chassis_name.assert_called_once()
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

        port0 = fakes.create_object({
            'name': 'port-0',
            'type': constants.OVN_VM_VIF_PORT_TYPE})
        port1 = fakes.create_object({
            'name': 'port-1',
            'type': constants.OVN_CHASSISREDIRECT_VIF_PORT_TYPE})
        self.nb_idl.get_active_ports_on_chassis.return_value = [
            port0, port1]
        mock_ensure_port_exposed = mock.patch.object(
            self.nb_bgp_driver, '_ensure_port_exposed').start()
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
        mock_ensure_port_exposed.assert_called_once_with(port0)
        mock_del_exposed_ips.assert_called_once_with(
            ips, CONF.bgp_nic)
        mock_del_ip_rules.assert_called_once_with(fake_ip_rules)
        mock_del_ip_routes.assert_called_once()

        bridge = set(self.nb_bgp_driver.ovn_bridge_mappings.values()).pop()
        mock_delete_vlan_dev.assert_called_once_with(bridge, 12)

    def test__ensure_port_exposed_fip(self):
        port0 = fakes.create_object({
            'name': 'port-0',
            'external_ids': {constants.OVN_FIP_EXT_ID_KEY: "fip"}})

        mock_get_port_external_ip_and_ls = mock.patch.object(
            self.nb_bgp_driver, 'get_port_external_ip_and_ls').start()
        mock_get_port_external_ip_and_ls.return_value = ("192.168.0.10",
                                                         "test-ls")
        mock_expose_fip = mock.patch.object(
            self.nb_bgp_driver, '_expose_fip').start()
        mock_expose_ip = mock.patch.object(
            self.nb_bgp_driver, '_expose_ip').start()

        self.nb_bgp_driver._ensure_port_exposed(port0)

        mock_get_port_external_ip_and_ls.assert_called_once_with(port0.name)
        mock_expose_fip.assert_called_once_with("192.168.0.10", "test-ls",
                                                port0)
        mock_expose_ip.assert_not_called()

    def test__ensure_port_exposed_tenant_ls(self):
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

        self.nb_bgp_driver._ensure_port_exposed(port0)

        mock_get_port_external_ip_and_ls.assert_not_called()
        mock_expose_fip.assert_not_called()
        mock_expose_ip.assert_not_called()

    @mock.patch.object(linux_net, 'get_ip_version')
    def test__ensure_port_exposed_no_fip_no_tenant_ls(self, mock_ip_version):
        port0 = fakes.create_object({
            'name': 'port-0',
            'addresses': ["fake_mac 192.168.0.10"],
            'type': constants.OVN_VM_VIF_PORT_TYPE,
            'external_ids': {constants.OVN_LS_NAME_EXT_ID_KEY: "test-ls"}})

        self.nb_bgp_driver.ovn_tenant_ls = {}
        self.nb_bgp_driver.ovn_provider_ls = {}

        mock_get_port_external_ip_and_ls = mock.patch.object(
            self.nb_bgp_driver, 'get_port_external_ip_and_ls').start()
        mock_expose_fip = mock.patch.object(
            self.nb_bgp_driver, '_expose_fip').start()
        mock_expose_ip = mock.patch.object(
            self.nb_bgp_driver, '_expose_ip').start()
        mock_expose_ip.return_value = ['192.168.0.10']
        mock_get_ls_localnet_info = mock.patch.object(
            self.nb_bgp_driver, '_get_ls_localnet_info').start()
        mock_get_ls_localnet_info.return_value = ('fake-localnet', 'br-ex', 10)
        mock_ip_version.return_value = constants.IP_VERSION_4

        self.nb_bgp_driver._ensure_port_exposed(port0)

        mock_get_port_external_ip_and_ls.assert_not_called()
        mock_get_ls_localnet_info.assert_called_once_with('test-ls')
        mock_expose_fip.assert_not_called()
        mock_expose_ip.assert_called_once_with(
            ['192.168.0.10'], 'test-ls', 'br-ex', 10,
            constants.OVN_VM_VIF_PORT_TYPE, None)

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
            port_ips, 'teset-ls', bridge_device, bridge_vlan, 'fake-localnet',
            proxy_cidrs)

        mock_wire_provider_port.assert_called_once_with(
            self.ovn_routing_tables_routes, {}, port_ips, bridge_device,
            bridge_vlan, 'fake-localnet', self.ovn_routing_tables, proxy_cidrs)
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
            port_ips, 'test-ls', bridge_device, bridge_vlan, 'fake-localnet',
            proxy_cidrs)

        mock_wire_provider_port.assert_called_once_with(
            self.ovn_routing_tables_routes, {}, port_ips, bridge_device,
            bridge_vlan, 'fake-localnet', self.ovn_routing_tables, proxy_cidrs)
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
            bridge_vlan, self.ovn_routing_tables, proxy_cidrs)

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

    def _test_expose_ip(self, ips, row):
        mock_expose_provider_port = mock.patch.object(
            self.nb_bgp_driver, '_expose_provider_port').start()
        mock_get_ls_localnet_info = mock.patch.object(
            self.nb_bgp_driver, '_get_ls_localnet_info').start()
        mock_get_ls_localnet_info.return_value = ('fake-localnet', 'br-ex', 10)
        self.nb_bgp_driver.ovn_bridge_mappings = {'fake-localnet': 'br-ex'}

        cidr = row.external_ids.get(constants.OVN_CIDRS_EXT_ID_KEY)
        logical_switch = row.external_ids.get(constants.OVN_LS_NAME_EXT_ID_KEY)

        self.nb_bgp_driver.expose_ip(ips, row)

        if not logical_switch:
            mock_expose_provider_port.assert_not_called()
            mock_get_ls_localnet_info.assert_not_called()
            return

        mock_get_ls_localnet_info.assert_called_once_with(logical_switch)
        self.assertEqual(self.nb_bgp_driver.ovn_provider_ls[logical_switch],
                         {'bridge_device': 'br-ex', 'bridge_vlan': 10,
                          'localnet': 'fake-localnet'})
        if row.type == constants.OVN_VIRTUAL_VIF_PORT_TYPE and cidr:
            mock_expose_provider_port.assert_called_once_with(
                ips, 'test-ls', 'br-ex', 10, 'fake-localnet', [cidr])
        else:
            mock_expose_provider_port.assert_called_once_with(
                ips, 'test-ls', 'br-ex', 10, 'fake-localnet')

    def test_expose_ip(self):
        ips = [self.ipv4, self.ipv6]
        row = fakes.create_object({
            'type': constants.OVN_VM_VIF_PORT_TYPE,
            'external_ids': {constants.OVN_LS_NAME_EXT_ID_KEY: 'test-ls'}})

        self._test_expose_ip(ips, row)

    def test_expose_ip_virtual(self):
        ips = [self.ipv4, self.ipv6]
        row = fakes.create_object({
            'type': constants.OVN_VIRTUAL_VIF_PORT_TYPE,
            'external_ids': {constants.OVN_LS_NAME_EXT_ID_KEY: 'test-ls',
                             constants.OVN_CIDRS_EXT_ID_KEY: 'test-cidr'}})

        self._test_expose_ip(ips, row)

    def test_expose_ip_no_switch(self):
        ips = [self.ipv4, self.ipv6]
        row = fakes.create_object({
            'type': constants.OVN_VM_VIF_PORT_TYPE,
            'external_ids': {}})

        self._test_expose_ip(ips, row)

    @mock.patch.object(linux_net, 'get_ip_version')
    def _test_withdraw_ip(self, ips, row, provider, mock_ip_version):
        mock_withdraw_provider_port = mock.patch.object(
            self.nb_bgp_driver, '_withdraw_provider_port').start()
        mock_get_ls_localnet_info = mock.patch.object(
            self.nb_bgp_driver, '_get_ls_localnet_info').start()
        mock_ip_version.return_value = constants.IP_VERSION_6
        self.nb_idl.ls_has_virtual_ports.return_value = False
        if provider:
            mock_get_ls_localnet_info.return_value = ('fake-localnet', 'br-ex',
                                                      10)
        else:
            mock_get_ls_localnet_info.return_value = (None, None, None)

        cidr = row.external_ids.get(constants.OVN_CIDRS_EXT_ID_KEY)
        logical_switch = row.external_ids.get(constants.OVN_LS_NAME_EXT_ID_KEY)

        self.nb_bgp_driver.withdraw_ip(ips, row)

        if not logical_switch:
            mock_get_ls_localnet_info.assert_not_called()
            mock_withdraw_provider_port.assert_not_called()
            return
        if not provider:
            mock_get_ls_localnet_info.assert_called_once_with(logical_switch)
            mock_withdraw_provider_port.assert_not_called()
            return

        mock_get_ls_localnet_info.assert_called_once_with(logical_switch)
        if row.type == constants.OVN_VIRTUAL_VIF_PORT_TYPE and cidr:
            mock_withdraw_provider_port.assert_called_once_with(
                ips, 'test-ls', 'br-ex', 10, [cidr])
        else:
            mock_withdraw_provider_port.assert_called_once_with(
                ips, 'test-ls', 'br-ex', 10)

    def test_withdraw_ip(self):
        ips = [self.ipv4, self.ipv6]
        row = fakes.create_object({
            'type': constants.OVN_VM_VIF_PORT_TYPE,
            'external_ids': {constants.OVN_LS_NAME_EXT_ID_KEY: 'test-ls'}})

        self._test_withdraw_ip(ips, row, True)

    def test_withdraw_ip_no_provider(self):
        ips = [self.ipv4, self.ipv6]
        row = fakes.create_object({
            'type': constants.OVN_VM_VIF_PORT_TYPE,
            'external_ids': {constants.OVN_LS_NAME_EXT_ID_KEY: 'test-ls'}})

        self._test_withdraw_ip(ips, row, False)

    def test_withdraw_ip_virtual(self):
        ips = [self.ipv4, self.ipv6]
        row = fakes.create_object({
            'type': constants.OVN_VIRTUAL_VIF_PORT_TYPE,
            'external_ids': {constants.OVN_LS_NAME_EXT_ID_KEY: 'test-ls',
                             constants.OVN_CIDRS_EXT_ID_KEY: 'test-cidr'}})

        self._test_withdraw_ip(ips, row, True)

    def test_withdraw_ip_no_switch(self):
        ips = [self.ipv4, self.ipv6]
        row = fakes.create_object({
            'type': constants.OVN_VM_VIF_PORT_TYPE,
            'external_ids': {}})

        self._test_withdraw_ip(ips, row, True)

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
            'external_ip': 'fake-ip'})
        self.nb_idl.get_nat_by_logical_port.return_value = nat_entry

        ret = self.nb_bgp_driver.get_port_external_ip_and_ls('fake-port')

        expected_result = (nat_entry.external_ip, "neutron-net1")
        self.assertEqual(ret, expected_result)

    def test_get_port_external_ip_and_ls_no_nat_entry(self):
        self.nb_idl.get_nat_by_logical_port.return_value = None

        ret = self.nb_bgp_driver.get_port_external_ip_and_ls('fake-port')

        self.assertIsNone(ret)

    def test_get_port_external_ip_and_ls_no_external_id(self):
        nat_entry = fakes.create_object({
            'external_ids': {},
            'external_ip': 'fake-ip'})
        self.nb_idl.get_nat_by_logical_port.return_value = nat_entry

        ret = self.nb_bgp_driver.get_port_external_ip_and_ls('fake-port')

        self.assertEqual(ret, (nat_entry.external_ip, None))

    def test_expose_fip(self):
        ip = '10.0.0.1'
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

        ret = self.nb_bgp_driver.expose_fip(ip, logical_switch, row)

        mock_get_ls_localnet_info.assert_called_once_with(logical_switch)
        mock_expose_provider_port.assert_called_once_with([ip], 'test-ls',
                                                          'br-ex', 100,
                                                          'fake-localnet')
        self.assertTrue(ret)

    def test_expose_fip_no_device(self):
        ip = '10.0.0.1'
        logical_switch = 'lswitch1'
        mock_get_ls_localnet_info = mock.patch.object(
            self.nb_bgp_driver, '_get_ls_localnet_info').start()
        mock_get_ls_localnet_info.return_value = (None, None, None)
        mock_expose_provider_port = mock.patch.object(
            self.nb_bgp_driver, '_expose_provider_port').start()
        row = fakes.create_object({
            'external_ids': {constants.OVN_LS_NAME_EXT_ID_KEY: 'test-ls'}})

        ret = self.nb_bgp_driver.expose_fip(ip, logical_switch, row)

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

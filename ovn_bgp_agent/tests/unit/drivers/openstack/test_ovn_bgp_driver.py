# Copyright 2022 Red Hat, Inc.
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

from ovn_bgp_agent import config
from ovn_bgp_agent import constants
from ovn_bgp_agent.drivers.openstack import ovn_bgp_driver
from ovn_bgp_agent.drivers.openstack.utils import driver_utils
from ovn_bgp_agent.drivers.openstack.utils import frr
from ovn_bgp_agent.drivers.openstack.utils import ovn
from ovn_bgp_agent.drivers.openstack.utils import ovs
from ovn_bgp_agent import exceptions as agent_exc
from ovn_bgp_agent.tests import base as test_base
from ovn_bgp_agent.tests.unit import fakes
from ovn_bgp_agent.utils import linux_net

CONF = cfg.CONF


class TestOVNBGPDriver(test_base.TestCase):

    def setUp(self):
        super(TestOVNBGPDriver, self).setUp()
        config.register_opts()
        CONF.set_override('expose_tenant_networks', True)
        self.bridge = 'fake-bridge'
        self.bgp_driver = ovn_bgp_driver.OVNBGPDriver()
        self.bgp_driver._post_fork_event = mock.Mock()
        self.bgp_driver.sb_idl = mock.Mock()
        self.sb_idl = self.bgp_driver.sb_idl
        self.bgp_driver.chassis = 'fake-chassis'
        self.bgp_driver.ovn_routing_tables = {self.bridge: 'fake-table'}
        self.bgp_driver.ovn_bridge_mappings = {'fake-network': self.bridge}

        self.mock_sbdb = mock.patch.object(ovn, 'OvnSbIdl').start()
        self.mock_ovs_idl = mock.patch.object(ovs, 'OvsIdl').start()
        self.ipv4 = '192.168.1.17'
        self.ipv6 = '2002::1234:abcd:ffff:c0a8:101'
        self.fip = '172.24.4.33'
        self.mac = 'aa:bb:cc:dd:ee:ff'
        self.loadbalancer = 'fake-lb'
        self.bgp_driver.ovn_lb_vips = {
            self.loadbalancer: [self.ipv4, self.ipv6]}
        self.bgp_driver.ovs_idl = self.mock_ovs_idl

        self.cr_lrp0 = 'cr-fake-logical-port'
        self.cr_lrp1 = 'cr-fake-logical-port1'
        self.lrp0 = 'lrp-fake-logical-port'
        self.bgp_driver.ovn_local_cr_lrps = {
            self.cr_lrp0: {'provider_datapath': 'fake-provider-dp',
                           'ips': [self.fip],
                           'subnets_datapath': {self.lrp0: 'fake-lrp-dp'},
                           'subnets_cidr': ['192.168.1.1/24'],
                           'ovn_lbs': [],
                           'bridge_device': self.bridge,
                           'bridge_vlan': None},
            self.cr_lrp1: {'provider_datapath': 'fake-provider-dp'}}

        # Mock pyroute2.NDB context manager object
        self.mock_ndb = mock.patch.object(linux_net.pyroute2, 'NDB').start()
        self.fake_ndb = self.mock_ndb().__enter__()

    @mock.patch.object(frr, 'vrf_leak')
    def test_start(self, mock_vrf):
        self.bgp_driver.start()

        mock_vrf.assert_called_once_with(
            CONF.bgp_vrf, CONF.bgp_AS, CONF.bgp_router_id)
        # Assert connections were started
        self.mock_ovs_idl().start.assert_called_once_with(
            CONF.ovsdb_connection)
        self.mock_sbdb().start.assert_called_once_with()

    @mock.patch.object(linux_net, 'delete_bridge_ip_routes')
    @mock.patch.object(linux_net, 'delete_ip_rules')
    @mock.patch.object(linux_net, 'delete_exposed_ips')
    @mock.patch.object(ovs, 'remove_extra_ovs_flows')
    @mock.patch.object(ovs, 'get_ovs_flows_info')
    @mock.patch.object(linux_net, 'get_ovn_ip_rules')
    @mock.patch.object(linux_net, 'get_exposed_ips')
    @mock.patch.object(linux_net, 'ensure_vlan_device_for_network')
    @mock.patch.object(linux_net, 'ensure_routing_table_for_bridge')
    @mock.patch.object(linux_net, 'ensure_arp_ndp_enabed_for_bridge')
    @mock.patch.object(linux_net, 'ensure_ovn_device')
    @mock.patch.object(linux_net, 'ensure_vrf')
    def test_sync(
            self, mock_ensure_vrf, mock_ensure_ovn_dev, mock_ensure_arp,
            mock_routing_bridge, mock_ensure_vlan_network, mock_exposed_ips,
            mock_get_ip_rules, mock_flows_info, mock_remove_flows,
            mock_del_exposed_ips, mock_del_ip_riles, moock_del_ip_routes):
        self.mock_ovs_idl.get_ovn_bridge_mappings.return_value = [
            'net0:bridge0', 'net1:bridge1']
        self.sb_idl.get_network_vlan_tag_by_network_name.side_effect = (
            [10], [11])
        fake_ip_rules = 'fake-ip-rules'
        mock_get_ip_rules.return_value = fake_ip_rules
        ips = [self.ipv4, self.ipv6]
        mock_exposed_ips.return_value = ips
        self.sb_idl.get_ports_on_chassis.return_value = [
            'fake-port0', 'fake-port1']
        self.sb_idl.get_cr_lrp_ports_on_chassis.return_value = [
            'fake-cr-port0', 'fake-cr-port1']

        mock_ensure_port_exposed = mock.patch.object(
            self.bgp_driver, '_ensure_port_exposed').start()
        mock_ensure_cr_port_exposed = mock.patch.object(
            self.bgp_driver, '_ensure_cr_lrp_associated_ports_exposed').start()

        self.bgp_driver.sync()

        mock_ensure_vrf.assert_called_once_with(
            CONF.bgp_vrf, CONF.bgp_vrf_table_id)
        mock_ensure_ovn_dev.assert_called_once_with(
            CONF.bgp_nic, CONF.bgp_vrf)

        expected_calls = [mock.call('bridge0', 1, 10),
                          mock.call('bridge1', 2, 11)]
        mock_ensure_arp.assert_has_calls(expected_calls)

        expected_calls = [mock.call({'fake-bridge': 'fake-table'}, 'bridge0'),
                          mock.call({'fake-bridge': 'fake-table'}, 'bridge1')]
        mock_routing_bridge.assert_has_calls(expected_calls)

        expected_calls = [mock.call('bridge0', 10), mock.call('bridge1', 11)]
        mock_ensure_vlan_network.assert_has_calls(expected_calls)

        expected_calls = [
            mock.call(
                'bridge0', {'bridge0': {'mac': mock.ANY, 'in_port': set()},
                            'bridge1': {'mac': mock.ANY, 'in_port': set()}},
                constants.OVS_RULE_COOKIE),
            mock.call(
                'bridge1', {'bridge0': {'mac': mock.ANY, 'in_port': set()},
                            'bridge1': {'mac': mock.ANY, 'in_port': set()}},
                constants.OVS_RULE_COOKIE)]
        mock_flows_info.assert_has_calls(expected_calls)

        mock_remove_flows.assert_called_once_with({
            'bridge0': {'mac': mock.ANY, 'in_port': set()},
            'bridge1': {'mac': mock.ANY, 'in_port': set()}},
            constants.OVS_RULE_COOKIE)

        expected_calls = [mock.call('fake-port0', ips, fake_ip_rules),
                          mock.call('fake-port1', ips, fake_ip_rules)]
        mock_ensure_port_exposed.assert_has_calls(expected_calls)

        expected_calls = [mock.call('fake-cr-port0', ips, fake_ip_rules),
                          mock.call('fake-cr-port1', ips, fake_ip_rules)]
        mock_ensure_cr_port_exposed.assert_has_calls(expected_calls)

        mock_del_exposed_ips.assert_called_once_with(
            ips, CONF.bgp_nic)
        mock_del_ip_riles.assert_called_once_with(fake_ip_rules)
        moock_del_ip_routes.assert_called_once_with(
            {self.bridge: 'fake-table'}, mock.ANY,
            {'bridge0': mock.ANY, 'bridge1': mock.ANY})

        mock_get_ip_rules.assert_called_once_with(mock.ANY)

    @mock.patch.object(linux_net, 'get_ip_version')
    def test__ensure_cr_lrp_associated_ports_exposed(self, mock_ip_version):
        mock_expose_ip = mock.patch.object(
            self.bgp_driver, '_expose_ip').start()
        mock_ip_version.side_effect = (constants.IP_VERSION_4,
                                       constants.IP_VERSION_6)
        patch_port_row = fakes.create_object({'name': 'patch-port'})
        self.sb_idl.get_cr_lrp_nat_addresses_info.return_value = (
            [self.ipv4, self.ipv6], patch_port_row)

        exposed_ips = [self.ipv4, '192.168.1.20']
        ip_rules = {"{}/128".format(self.ipv6): 'fake-rules'}
        self.bgp_driver._ensure_cr_lrp_associated_ports_exposed(
            'fake-cr-lrp', exposed_ips, ip_rules)

        mock_expose_ip.assert_called_once_with(
            [self.ipv4, self.ipv6], patch_port_row,
            associated_port='fake-cr-lrp')
        self.assertEqual(['192.168.1.20'], exposed_ips)
        self.assertEqual({}, ip_rules)

    def test__ensure_port_exposed(self):
        mock_expose_ip = mock.patch.object(
            self.bgp_driver, '_expose_ip').start()
        mock_expose_ip.return_value = [self.ipv4, self.ipv6]
        port = fakes.create_object({
            'name': 'fake-port',
            'type': '',
            'mac': ['{} {} {}'.format(self.mac, self.ipv4, self.ipv6)]})

        exposed_ips = [self.ipv4, self.ipv6]
        ip_rules = {"{}/128".format(self.ipv6): 'fake-rules'}
        self.bgp_driver._ensure_port_exposed(port, exposed_ips, ip_rules)

        mock_expose_ip.assert_called_once_with(
            [self.ipv4, self.ipv6], port)
        self.assertEqual([], exposed_ips)
        self.assertEqual({}, ip_rules)

    def test__ensure_port_exposed_fip(self):
        fip = '172.24.4.225'
        mock_expose_ip = mock.patch.object(
            self.bgp_driver, '_expose_ip').start()
        mock_expose_ip.return_value = [fip]
        port = fakes.create_object({
            'name': 'fake-port',
            'type': '',
            'mac': ['{} {} {}'.format(self.mac, self.ipv4, self.ipv6)]})

        exposed_ips = [self.ipv4, fip]
        ip_rules = {"{}/128".format(self.ipv6): 'fake-rules'}
        self.bgp_driver._ensure_port_exposed(port, exposed_ips, ip_rules)

        mock_expose_ip.assert_called_once_with(
            [self.ipv4, self.ipv6], port)
        self.assertEqual([self.ipv4], exposed_ips)
        self.assertEqual({"{}/128".format(self.ipv6): 'fake-rules'}, ip_rules)

    def test__ensure_port_exposed_wrong_port_type(self):
        mock_expose_ip = mock.patch.object(
            self.bgp_driver, '_expose_ip').start()
        port = fakes.create_object({
            'name': 'fake-port',
            'type': 'non-existing-type',
            'mac': ['{} {} {}'.format(self.mac, self.ipv4, self.ipv6)]})

        self.bgp_driver._ensure_port_exposed(port, [], {})

        # Assert it was never called, the method should just return if
        # the port type is not OVN_VIF_PORT_TYPES
        mock_expose_ip.assert_not_called()

    @mock.patch.object(linux_net, 'add_ips_to_dev')
    @mock.patch.object(linux_net, 'get_ip_version')
    def test__expose_tenant_port(self, mock_ip_version, mock_add_ips_dev):
        tenant_port = fakes.create_object({
            'name': 'fake-port',
            'type': constants.OVN_VM_VIF_PORT_TYPE,
            'mac': ['aa:bb:cc:dd:ee:ee 192.168.1.10 192.168.1.11'],
            'chassis': 'fake-chassis1',
            'external_ids': {}})
        ip_version = constants.IP_VERSION_4

        mock_ip_version.return_value = constants.IP_VERSION_4

        self.bgp_driver._expose_tenant_port(tenant_port, ip_version)

        expected_calls = [mock.call(CONF.bgp_nic, ['192.168.1.10']),
                          mock.call(CONF.bgp_nic, ['192.168.1.11'])]
        mock_add_ips_dev.assert_has_calls(expected_calls)

    @mock.patch.object(linux_net, 'add_ips_to_dev')
    @mock.patch.object(linux_net, 'get_ip_version')
    def test__expose_tenant_port_ovn_lb(self, mock_ip_version,
                                        mock_add_ips_dev):
        tenant_port = fakes.create_object({
            'name': 'fake-port',
            'type': constants.OVN_VM_VIF_PORT_TYPE,
            'mac': [],
            'chassis': '',
            'external_ids': {'neutron:cidrs': '192.168.1.10/24'},
            'up': [False]})
        ip_version = constants.IP_VERSION_4

        mock_ip_version.return_value = constants.IP_VERSION_4

        self.bgp_driver._expose_tenant_port(tenant_port, ip_version)

        mock_add_ips_dev.assert_called_once_with(CONF.bgp_nic,
                                                 ['192.168.1.10'])

    @mock.patch.object(linux_net, 'add_ips_to_dev')
    @mock.patch.object(linux_net, 'get_ip_version')
    def test__expose_tenant_port_no_ip(self, mock_ip_version,
                                       mock_add_ips_dev):
        tenant_port = fakes.create_object({
            'name': 'fake-port',
            'type': constants.OVN_VM_VIF_PORT_TYPE,
            'mac': ['aa:bb:cc:dd:ee:ee'],
            'chassis': 'fake-chassis1',
            'external_ids': {}})
        ip_version = constants.IP_VERSION_4

        mock_ip_version.return_value = constants.IP_VERSION_4

        self.bgp_driver._expose_tenant_port(tenant_port, ip_version)

        mock_ip_version.assert_not_called()
        mock_add_ips_dev.assert_not_called()

    @mock.patch.object(linux_net, 'add_ips_to_dev')
    @mock.patch.object(linux_net, 'get_ip_version')
    def test__expose_tenant_port_no_mac(self, mock_ip_version,
                                        mock_add_ips_dev):
        tenant_port = fakes.create_object({
            'name': 'fake-port',
            'type': constants.OVN_VM_VIF_PORT_TYPE,
            'mac': [],
            'chassis': 'fake-chassis1',
            'external_ids': {}})
        ip_version = constants.IP_VERSION_4

        mock_ip_version.return_value = constants.IP_VERSION_4

        self.bgp_driver._expose_tenant_port(tenant_port, ip_version)

        mock_ip_version.assert_not_called()
        mock_add_ips_dev.assert_not_called()

    @mock.patch.object(linux_net, 'add_ips_to_dev')
    @mock.patch.object(linux_net, 'get_ip_version')
    def test__expose_tenant_port_wrong_type(self, mock_ip_version,
                                            mock_add_ips_dev):
        tenant_port = fakes.create_object({
            'name': 'fake-port',
            'type': constants.OVN_CHASSISREDIRECT_VIF_PORT_TYPE,
            'mac': ['aa:bb:cc:dd:ee:ee 192.168.1.10 192.168.1.11'],
            'chassis': 'fake-chassis1',
            'external_ids': {}})
        ip_version = constants.IP_VERSION_4

        mock_ip_version.return_value = constants.IP_VERSION_4

        self.bgp_driver._expose_tenant_port(tenant_port, ip_version)

        mock_ip_version.assert_not_called()
        mock_add_ips_dev.assert_not_called()

    @mock.patch.object(linux_net, 'add_ips_to_dev')
    @mock.patch.object(linux_net, 'get_ip_version')
    def test__expose_tenant_port_no_chassis(self, mock_ip_version,
                                            mock_add_ips_dev):
        tenant_port = fakes.create_object({
            'name': 'fake-port',
            'type': constants.OVN_VM_VIF_PORT_TYPE,
            'mac': ['aa:bb:cc:dd:ee:ee 192.168.1.10 192.168.1.11'],
            'chassis': '',
            'external_ids': {}})
        ip_version = constants.IP_VERSION_4

        mock_ip_version.return_value = constants.IP_VERSION_4

        self.bgp_driver._expose_tenant_port(tenant_port, ip_version)

        mock_ip_version.assert_not_called()
        mock_add_ips_dev.assert_not_called()

    @mock.patch.object(linux_net, 'add_ips_to_dev')
    @mock.patch.object(linux_net, 'add_ip_route')
    @mock.patch.object(linux_net, 'add_ip_rule')
    @mock.patch.object(linux_net, 'get_ip_version')
    def test__ensure_network_exposed(self, mock_ip_version, mock_add_rule,
                                     mock_add_route, mock_add_ips_dev):
        mock_ip_version.return_value = constants.IP_VERSION_4
        gateway = {}
        gateway['ips'] = ['{}/32'.format(self.fip),
                          '2003::1234:abcd:ffff:c0a8:102/128']
        gateway['provider_datapath'] = 'bc6780f4-9510-4270-b4d2-b8d5c6802713'
        self.bgp_driver.ovn_local_cr_lrps = {'gateway_port': gateway}

        router_port = fakes.create_object({
            'name': 'fake-router-port',
            'mac': ['{} {}/32'.format(self.mac, self.ipv4)],
            'logical_port': 'fake-logical-port',
            'options': {'peer': 'fake-peer'}})

        mock_get_bridge = mock.patch.object(
            self.bgp_driver, '_get_bridge_for_datapath').start()
        mock_get_bridge.return_value = (self.bridge, 10)

        dp_port0 = fakes.create_object({
            'name': 'fake-port-dp0',
            'type': constants.OVN_VM_VIF_PORT_TYPE,
            'mac': ['aa:bb:cc:dd:ee:ee 192.168.1.10 192.168.1.11'],
            'chassis': 'fake-chassis1',
            'external_ids': {}})
        dp_port1 = fakes.create_object({
            'name': 'fake-port-dp1',
            'type': 'fake-type',
            'mac': ['aa:bb:cc:dd:ee:ee 192.168.1.12 192.168.1.13'],
            'chassis': 'fake-chassis2',
            'external_ids': {}})
        dp_port2 = fakes.create_object({
            'name': 'fake-port-dp2',
            'type': constants.OVN_VM_VIF_PORT_TYPE,
            'mac': [],
            'chassis': 'fake-chassis2',
            'external_ids': {}})
        dp_port3 = fakes.create_object({
            'name': 'fake-port-dp3',
            'type': constants.OVN_VM_VIF_PORT_TYPE,
            'mac': [],
            'chassis': '',
            'up': [False],
            'external_ids': {}})
        dp_port4 = fakes.create_object({
            'name': 'fake-port-dp4',
            'type': constants.OVN_VM_VIF_PORT_TYPE,
            'mac': [],
            'chassis': '',
            'up': [False],
            'external_ids': {
                constants.OVN_CIDRS_EXT_ID_KEY: "192.168.1.13/24"}})
        self.sb_idl.get_ports_on_datapath.return_value = [dp_port0, dp_port1,
                                                          dp_port2, dp_port3,
                                                          dp_port4]

        self.bgp_driver._ensure_network_exposed(router_port, 'gateway_port')

        # Assert that the add methods were called
        mock_add_rule.assert_called_once_with(
            '{}/32'.format(self.ipv4), 'fake-table', self.bridge)
        mock_add_route.assert_called_once_with(
            mock.ANY, self.ipv4, 'fake-table', self.bridge,
            vlan=10, mask='32', via=self.fip)
        expected_calls = [mock.call(CONF.bgp_nic, ['192.168.1.10']),
                          mock.call(CONF.bgp_nic, ['192.168.1.11']),
                          mock.call(CONF.bgp_nic, ['192.168.1.13'])]
        mock_add_ips_dev.assert_has_calls(expected_calls)

    @mock.patch.object(linux_net, 'add_ips_to_dev')
    @mock.patch.object(linux_net, 'add_ip_route')
    @mock.patch.object(linux_net, 'add_ip_rule')
    @mock.patch.object(linux_net, 'get_ip_version')
    @mock.patch.object(driver_utils, 'is_ipv6_gua')
    def test__ensure_network_exposed_gua(self, mock_ipv6_gua, mock_ip_version,
                                         mock_add_rule, mock_add_route,
                                         mock_add_ips_dev):
        CONF.set_override('expose_tenant_networks', False)
        self.addCleanup(CONF.clear_override, 'expose_tenant_networks')
        CONF.set_override('expose_ipv6_gua_tenant_networks', True)
        self.addCleanup(CONF.clear_override, 'expose_ipv6_gua_tenant_networks')

        mock_ipv6_gua.return_value = True
        mock_ip_version.return_value = constants.IP_VERSION_6
        gateway = {}
        gateway['ips'] = ['{}/32'.format(self.fip),
                          '2003::1234:abcd:ffff:c0a8:102/128']
        gateway['provider_datapath'] = 'bc6780f4-9510-4270-b4d2-b8d5c6802713'
        self.bgp_driver.ovn_local_cr_lrps = {'gateway_port': gateway}

        router_port = fakes.create_object({
            'name': 'fake-router-port',
            'mac': ['{} {}/128'.format(self.mac, self.ipv6)],
            'logical_port': 'fake-logical-port',
            'options': {'peer': 'fake-peer'}})

        mock_get_bridge = mock.patch.object(
            self.bgp_driver, '_get_bridge_for_datapath').start()
        mock_get_bridge.return_value = (self.bridge, 10)

        dp_port0 = fakes.create_object({
            'name': 'fake-port-dp0',
            'type': constants.OVN_VM_VIF_PORT_TYPE,
            'mac': ['aa:bb:cc:dd:ee:ee 2002::1234:abcd:ffff:c0a8:111'],
            'chassis': 'fake-chassis1',
            'external_ids': {}})
        dp_port1 = fakes.create_object({
            'name': 'fake-port-dp1',
            'type': 'fake-type',
            'mac': ['aa:bb:cc:dd:ee:ee 2002::1234:abcd:ffff:c0a8:112'],
            'chassis': 'fake-chassis2',
            'external_ids': {}})
        dp_port2 = fakes.create_object({
            'name': 'fake-port-dp2',
            'type': constants.OVN_VM_VIF_PORT_TYPE,
            'mac': [],
            'chassis': 'fake-chassis2',
            'external_ids': {}})
        dp_port3 = fakes.create_object({
            'name': 'fake-port-dp3',
            'type': constants.OVN_VM_VIF_PORT_TYPE,
            'mac': [],
            'chassis': '',
            'up': [False],
            'external_ids': {}})
        dp_port4 = fakes.create_object({
            'name': 'fake-port-dp4',
            'type': constants.OVN_VM_VIF_PORT_TYPE,
            'mac': [],
            'chassis': '',
            'up': [False],
            'external_ids': {
                constants.OVN_CIDRS_EXT_ID_KEY:
                    "2002::1234:abcd:ffff:c0a8:121/64"}})
        self.sb_idl.get_ports_on_datapath.return_value = [dp_port0, dp_port1,
                                                          dp_port2, dp_port3,
                                                          dp_port4]

        self.bgp_driver._ensure_network_exposed(router_port, 'gateway_port')

        # Assert that the add methods were called
        mock_ipv6_gua.assert_called_once_with('{}/128'.format(self.ipv6))
        mock_add_rule.assert_called_once_with(
            '{}/128'.format(self.ipv6), 'fake-table', self.bridge)
        mock_add_route.assert_called_once_with(
            mock.ANY, self.ipv6, 'fake-table', self.bridge,
            vlan=10, mask='128', via=self.fip)
        expected_calls = [mock.call(CONF.bgp_nic,
                                    ['2002::1234:abcd:ffff:c0a8:111']),
                          mock.call(CONF.bgp_nic,
                                    ['2002::1234:abcd:ffff:c0a8:121'])]
        mock_add_ips_dev.assert_has_calls(expected_calls)

    @mock.patch.object(linux_net, 'add_ips_to_dev')
    @mock.patch.object(linux_net, 'add_ip_route')
    @mock.patch.object(linux_net, 'add_ip_rule')
    @mock.patch.object(driver_utils, 'is_ipv6_gua')
    def test__ensure_network_exposed_not_gua(
            self, mock_ipv6_gua, mock_add_rule,
            mock_add_route, mock_add_ips_dev):
        CONF.set_override('expose_tenant_networks', False)
        self.addCleanup(CONF.clear_override, 'expose_tenant_networks')
        CONF.set_override('expose_ipv6_gua_tenant_networks', True)
        self.addCleanup(CONF.clear_override, 'expose_ipv6_gua_tenant_networks')
        mock_ipv6_gua.return_value = False
        gateway = {}
        gateway['ips'] = ['{}/32'.format(self.fip),
                          '2003::1234:abcd:ffff:c0a8:102/128']
        gateway['provider_datapath'] = 'bc6780f4-9510-4270-b4d2-b8d5c6802713'
        self.bgp_driver.ovn_local_cr_lrps = {'gateway_port': gateway}

        router_port = fakes.create_object({
            'name': 'fake-router-port',
            'mac': ['{} fdab:4ad8:e8fb:0:f816:3eff:fec6:469c/128'.format(
                self.mac)],
            'logical_port': 'fake-logical-port',
            'options': {'peer': 'fake-peer'}})

        mock_get_bridge = mock.patch.object(
            self.bgp_driver, '_get_bridge_for_datapath').start()
        mock_get_bridge.return_value = (self.bridge, 10)

        self.bgp_driver._ensure_network_exposed(router_port, 'gateway_port')

        # Assert that the add methods were called
        mock_ipv6_gua.assert_called_once_with(
            'fdab:4ad8:e8fb:0:f816:3eff:fec6:469c/128')
        mock_add_rule.assert_not_called()
        mock_add_route.assert_not_called()
        mock_add_ips_dev.assert_not_called()

    @mock.patch.object(linux_net, 'add_ip_route')
    @mock.patch.object(linux_net, 'add_ip_rule')
    @mock.patch.object(linux_net, 'get_ip_version')
    def test__ensure_network_exposed_invalid_ip(
            self, mock_ip_version, mock_add_rule, mock_add_route):
        mock_ip_version.return_value = constants.IP_VERSION_4
        gateway = {}
        gateway['ips'] = ['{}/32'.format(self.fip),
                          '2003::1234:abcd:ffff:c0a8:102/128']
        gateway['provider_datapath'] = 'bc6780f4-9510-4270-b4d2-b8d5c6802713'
        self.bgp_driver.ovn_local_cr_lrps = {'gateway_port': gateway}

        router_port = fakes.create_object({
            'name': 'fake-router-port',
            'mac': ['{} {}/32'.format(self.mac, self.ipv4)],
            'logical_port': 'fake-logical-port',
            'options': {'peer': 'fake-peer'}})

        mock_get_bridge = mock.patch.object(
            self.bgp_driver, '_get_bridge_for_datapath').start()
        mock_get_bridge.return_value = (self.bridge, 10)

        # Raise an exception on add_ip_rule()
        mock_add_rule.side_effect = agent_exc.InvalidPortIP(ip=self.ipv4)

        self.bgp_driver._ensure_network_exposed(router_port, 'gateway_port')

        mock_add_rule.assert_called_once_with(
            '{}/32'.format(self.ipv4), 'fake-table', self.bridge)
        # Assert that add_ip_route() was not called
        mock_add_route.assert_not_called()

    @mock.patch.object(linux_net, 'del_ip_route')
    @mock.patch.object(linux_net, 'del_ip_rule')
    @mock.patch.object(linux_net, 'get_ip_version')
    def test__remove_network_exposed(
            self, mock_ip_version, mock_del_rule, mock_del_route):
        mock_ip_version.return_value = constants.IP_VERSION_4
        lrp = 'fake-lrp'
        self.bgp_driver.ovn_local_lrps = {lrp: 'fake-subnet-datapath'}
        gateway = {
            'provider_datapath': 'bc6780f4-9510-4270-b4d2-b8d5c6802713',
            'subnets_datapath': {lrp: 'fake-subnet-datapath'},
            'bridge_device': self.bridge,
            'bridge_vlan': 10
        }
        gateway['ips'] = ['{}/32'.format(self.fip),
                          '2003::1234:abcd:ffff:c0a8:102/128']
        subnet_cidr = "192.168.1.1/24"

        self.bgp_driver._remove_network_exposed(subnet_cidr, gateway)

        # Assert that the del methods were called
        mock_del_rule.assert_called_once_with(
            subnet_cidr, 'fake-table', self.bridge)
        mock_del_route.assert_called_once_with(
            mock.ANY, subnet_cidr.split('/')[0], 'fake-table', self.bridge,
            vlan=10, mask='24', via=self.fip)

    def test__get_bridge_for_datapath(self):
        self.sb_idl.get_network_name_and_tag.return_value = (
            'fake-network', [10])
        ret = self.bgp_driver._get_bridge_for_datapath('fake-dp')
        self.assertEqual((self.bridge, 10), ret)

    def test__get_bridge_for_datapath_no_tag(self):
        self.sb_idl.get_network_name_and_tag.return_value = (
            'fake-network', None)
        ret = self.bgp_driver._get_bridge_for_datapath('fake-dp')
        self.assertEqual((self.bridge, None), ret)

    def test__get_bridge_for_datapath_no_network_name(self):
        self.sb_idl.get_network_name_and_tag.return_value = (None, None)
        ret = self.bgp_driver._get_bridge_for_datapath('fake-dp')
        self.assertEqual((None, None), ret)

    @mock.patch.object(linux_net, 'add_ip_route')
    @mock.patch.object(linux_net, 'add_ip_rule')
    @mock.patch.object(linux_net, 'add_ips_to_dev')
    def test_expose_ovn_lb_on_provider(
            self, mock_add_ip_dev, mock_add_rule, mock_add_route):
        self.bgp_driver.expose_ovn_lb_on_provider(
            self.loadbalancer, self.ipv4, self.cr_lrp0)

        # Assert that the add methods were called
        mock_add_ip_dev.assert_called_once_with(
            CONF.bgp_nic, [self.ipv4])
        mock_add_rule.assert_called_once_with(
            self.ipv4, 'fake-table', self.bridge)
        mock_add_route.assert_called_once_with(
            mock.ANY, self.ipv4, 'fake-table', self.bridge, vlan=None)

    @mock.patch.object(linux_net, 'add_ip_route')
    @mock.patch.object(linux_net, 'add_ip_rule')
    @mock.patch.object(linux_net, 'add_ips_to_dev')
    def test_expose_ovn_lb_on_provider_invalid_ip(
            self, mock_add_ip_dev, mock_add_rule, mock_add_route):
        # Raise an exception on add_ip_rule()
        mock_add_rule.side_effect = agent_exc.InvalidPortIP(ip=self.ipv4)

        self.bgp_driver.expose_ovn_lb_on_provider(
            self.loadbalancer, self.ipv4, self.cr_lrp0)

        # Assert that the add methods were called
        mock_add_ip_dev.assert_called_once_with(
            CONF.bgp_nic, [self.ipv4])
        mock_add_rule.assert_called_once_with(
            self.ipv4, 'fake-table', self.bridge)
        mock_add_route.assert_not_called()

    @mock.patch.object(linux_net, 'del_ip_route')
    @mock.patch.object(linux_net, 'del_ip_rule')
    @mock.patch.object(linux_net, 'del_ips_from_dev')
    def test_withdraw_ovn_lb_on_provider(
            self, mock_del_ip_dev, mock_del_rule, mock_del_route):
        self.bgp_driver.withdraw_ovn_lb_on_provider(
            self.loadbalancer, self.cr_lrp0)

        # Assert that the del methods were called
        expected_calls = [mock.call(CONF.bgp_nic, [self.ipv4]),
                          mock.call(CONF.bgp_nic, [self.ipv6])]
        mock_del_ip_dev.assert_has_calls(expected_calls)

        expected_calls = [mock.call(self.ipv4, 'fake-table', self.bridge),
                          mock.call(self.ipv6, 'fake-table', self.bridge)]
        mock_del_rule.assert_has_calls(expected_calls)

        expected_calls = [mock.call(mock.ANY, self.ipv4, 'fake-table',
                                    self.bridge, vlan=None),
                          mock.call(mock.ANY, self.ipv6, 'fake-table',
                                    self.bridge, vlan=None)]
        mock_del_route.assert_has_calls(expected_calls)

    @mock.patch.object(linux_net, 'add_ip_route')
    @mock.patch.object(linux_net, 'add_ip_rule')
    @mock.patch.object(linux_net, 'add_ips_to_dev')
    def test_expose_ip_vm_on_provider_network(
            self, mock_add_ip_dev, mock_add_rule, mock_add_route):
        self.sb_idl.is_provider_network.return_value = True
        mock_get_bridge = mock.patch.object(
            self.bgp_driver, '_get_bridge_for_datapath').start()
        mock_get_bridge.return_value = (self.bridge, 10)
        row = fakes.create_object({
            'name': 'fake-row',
            'type': constants.OVN_VM_VIF_PORT_TYPE,
            'datapath': 'fake-dp'})

        ips = [self.ipv4, self.ipv6]
        self.bgp_driver.expose_ip(ips, row)

        # Assert that the add methods were called
        mock_add_ip_dev.assert_called_once_with(
            CONF.bgp_nic, ips)

        expected_calls = [mock.call(self.ipv4, 'fake-table', self.bridge),
                          mock.call(self.ipv6, 'fake-table', self.bridge)]
        mock_add_rule.assert_has_calls(expected_calls)

        expected_calls = [mock.call(mock.ANY, self.ipv4, 'fake-table',
                                    self.bridge, vlan=10),
                          mock.call(mock.ANY, self.ipv6, 'fake-table',
                                    self.bridge, vlan=10)]
        mock_add_route.assert_has_calls(expected_calls)

    @mock.patch.object(linux_net, 'add_ip_route')
    @mock.patch.object(linux_net, 'add_ip_rule')
    @mock.patch.object(linux_net, 'add_ips_to_dev')
    def test_expose_ip_vm_with_fip(
            self, mock_add_ip_dev, mock_add_rule, mock_add_route):
        self.sb_idl.is_provider_network.return_value = False
        self.sb_idl.get_fip_associated.return_value = (
            self.fip, 'fake-dp')
        mock_get_bridge = mock.patch.object(
            self.bgp_driver, '_get_bridge_for_datapath').start()
        mock_get_bridge.return_value = (self.bridge, 10)
        row = fakes.create_object({
            'name': 'fake-row',
            'type': constants.OVN_VM_VIF_PORT_TYPE,
            'logical_port': 'fake-logical-port',
            'datapath': 'fake-dp'})

        ips = [self.ipv4, self.ipv6]
        self.bgp_driver.expose_ip(ips, row)

        # Assert that the add methods were called
        mock_add_ip_dev.assert_called_once_with(
            CONF.bgp_nic, [self.fip])
        mock_add_rule.assert_called_once_with(
            self.fip, 'fake-table', self.bridge)
        mock_add_route.assert_called_once_with(
            mock.ANY, self.fip, 'fake-table', self.bridge, vlan=10)

    @mock.patch.object(ovs, 'ensure_default_ovs_flows')
    @mock.patch.object(linux_net, 'add_ip_route')
    @mock.patch.object(linux_net, 'add_ip_rule')
    @mock.patch.object(linux_net, 'add_ips_to_dev')
    def test_expose_ip_vm_with_fip_no_fip_address(
            self, mock_add_ip_dev, mock_add_rule, mock_add_route,
            mock_ovs_flows):
        self.sb_idl.is_provider_network.return_value = False
        self.sb_idl.get_fip_associated.return_value = (None, None)
        row = fakes.create_object({
            'name': 'fake-row',
            'type': constants.OVN_VM_VIF_PORT_TYPE,
            'logical_port': 'fake-logical-port',
            'datapath': 'fake-dp'})

        ips = [self.ipv4, self.ipv6]
        self.bgp_driver.expose_ip(ips, row)

        # Assert that the add methods were not called
        mock_add_ip_dev.assert_not_called()
        mock_add_rule.assert_not_called()
        mock_add_route.assert_not_called()

        # Assert ensure_default_ovs_flows() is called instead
        mock_ovs_flows.assert_called_once_with(
            mock.ANY, constants.OVS_RULE_COOKIE)

    @mock.patch.object(linux_net, 'add_ip_route')
    @mock.patch.object(linux_net, 'add_ip_rule')
    @mock.patch.object(linux_net, 'add_ips_to_dev')
    def test_expose_ip_fip_association_to_vm(
            self, mock_add_ip_dev, mock_add_rule, mock_add_route):
        self.sb_idl.is_provider_network.return_value = False
        self.sb_idl.is_port_on_chassis.return_value = True
        mock_get_bridge = mock.patch.object(
            self.bgp_driver, '_get_bridge_for_datapath').start()
        mock_get_bridge.return_value = (self.bridge, 10)
        row = fakes.create_object({
            'name': 'fake-row',
            'type': constants.OVN_PATCH_VIF_PORT_TYPE,
            'logical_port': 'fake-logical-port',
            'datapath': 'fake-dp'})

        ips = [self.ipv4, self.ipv6]
        self.bgp_driver.expose_ip(ips, row, associated_port=True)

        # Assert that the add methods were called
        mock_add_ip_dev.assert_called_once_with(
            CONF.bgp_nic, ips)

        expected_calls = [mock.call(self.ipv4, 'fake-table', self.bridge),
                          mock.call(self.ipv6, 'fake-table', self.bridge)]
        mock_add_rule.assert_has_calls(expected_calls)

        expected_calls = [mock.call(mock.ANY, self.ipv4, 'fake-table',
                                    self.bridge, vlan=10),
                          mock.call(mock.ANY, self.ipv6, 'fake-table',
                                    self.bridge, vlan=10)]
        mock_add_route.assert_has_calls(expected_calls)

    @mock.patch.object(driver_utils, 'parse_vip_from_lb_table')
    @mock.patch.object(linux_net, 'add_ndp_proxy')
    @mock.patch.object(linux_net, 'get_ip_version')
    @mock.patch.object(linux_net, 'add_ip_route')
    @mock.patch.object(linux_net, 'add_ip_rule')
    @mock.patch.object(linux_net, 'add_ips_to_dev')
    def test_expose_ip_chassisredirect_port(
            self, mock_add_ip_dev, mock_add_rule, mock_add_route,
            mock_ip_version, mock_ndp_proxy, mock_parse_vip):
        self.sb_idl.get_provider_datapath_from_cr_lrp.return_value = (
            'fake-provider-dp')
        mock_get_bridge = mock.patch.object(
            self.bgp_driver, '_get_bridge_for_datapath').start()
        mock_get_bridge.return_value = (self.bridge, 10)

        lrp0 = fakes.create_object({
            'logical_port': self.lrp0,
            'chassis': '',
            'mac': ["fa:16:3e:50:ec:81 192.168.1.1/24"],
            'options': {}})
        lrp1 = fakes.create_object({'logical_port': 'lrp-1',
                                    'chassis': 'fake-chassis',
                                    'options': {}})
        lrp2 = fakes.create_object({'logical_port': 'fake-lrp',
                                    'chassis': '',
                                    'options': {}})
        self.sb_idl.get_lrp_ports_for_router.return_value = [lrp0, lrp1, lrp2]

        self.sb_idl.get_port_datapath.return_value = 'fake-lrp-dp'

        mock_ensure_net_exposed = mock.patch.object(
            self.bgp_driver, '_ensure_network_exposed').start()

        mock_ip_version.side_effect = (constants.IP_VERSION_4,
                                       constants.IP_VERSION_6)
        row = fakes.create_object({
            'name': 'fake-row',
            'type': constants.OVN_CHASSISREDIRECT_VIF_PORT_TYPE,
            'logical_port': self.cr_lrp0,
            'mac': ['{} {} {}'.format(self.mac, self.ipv4, self.ipv6)],
            'datapath': 'fake-router-dp'})

        ovn_lb_vip = '172.24.4.5'
        ovn_lb_vip_port = ovn_lb_vip + ':80'
        ovn_lb1 = fakes.create_object({
            'name': 'ovn_lb1', 'datapaths': [self.cr_lrp0, 'fake-lrp-dp'],
            'vips': {ovn_lb_vip_port: '192.168.100.5:::8080'}})
        ovn_lb2 = fakes.create_object({
            'name': 'ovn_lb2', 'datapaths': [self.cr_lrp0, 'fake-lrp1-db'],
            'vips': {'172.24.4.6:80': '192.168.200.5:::8080'}})
        self.sb_idl.get_ovn_lb_on_provider_datapath.return_value = [ovn_lb1,
                                                                    ovn_lb2]
        mock_expose_ovn_lb_on_provider = mock.patch.object(
            self.bgp_driver, '_expose_ovn_lb_on_provider').start()
        mock_parse_vip.return_value = ovn_lb_vip

        ips = [self.ipv4, self.ipv6]
        self.bgp_driver.expose_ip(ips, row)

        # Assert that the add methods were called
        mock_add_ip_dev.assert_called_once_with(
            CONF.bgp_nic, ips)

        expected_calls = [mock.call(self.ipv4, 'fake-table', self.bridge,
                          lladdr=self.mac),
                          mock.call(self.ipv6, 'fake-table', self.bridge,
                          lladdr=self.mac)]
        mock_add_rule.assert_has_calls(expected_calls)

        expected_calls = [mock.call(mock.ANY, self.ipv4, 'fake-table',
                                    self.bridge, vlan=10),
                          mock.call(mock.ANY, self.ipv6, 'fake-table',
                                    self.bridge, vlan=10)]
        mock_add_route.assert_has_calls(expected_calls)

        mock_ndp_proxy.assert_called_once_with(self.ipv6, self.bridge, 10)

        mock_ensure_net_exposed.assert_called_once_with(
            lrp0, self.cr_lrp0)

        mock_parse_vip.assert_called_once_with(ovn_lb_vip_port)
        mock_expose_ovn_lb_on_provider.assert_called_once_with(
            'ovn_lb1', ovn_lb_vip, row.logical_port)

    @mock.patch.object(linux_net, 'del_ip_route')
    @mock.patch.object(linux_net, 'del_ip_rule')
    @mock.patch.object(linux_net, 'del_ips_from_dev')
    def test_withdraw_ip_vm_on_provider_network(
            self, mock_del_ip_dev, mock_del_rule, mock_del_route):
        self.sb_idl.is_provider_network.return_value = True
        mock_get_bridge = mock.patch.object(
            self.bgp_driver, '_get_bridge_for_datapath').start()
        mock_get_bridge.return_value = (self.bridge, 10)
        row = fakes.create_object({
            'name': 'fake-row',
            'type': constants.OVN_VM_VIF_PORT_TYPE,
            'datapath': 'fake-dp'})

        ips = [self.ipv4, self.ipv6]
        self.bgp_driver.withdraw_ip(ips, row)

        # Assert that the del methods were called
        mock_del_ip_dev.assert_called_once_with(
            CONF.bgp_nic, ips)

        expected_calls = [mock.call(self.ipv4, 'fake-table', self.bridge),
                          mock.call(self.ipv6, 'fake-table', self.bridge)]
        mock_del_rule.assert_has_calls(expected_calls)

        expected_calls = [mock.call(mock.ANY, self.ipv4, 'fake-table',
                                    self.bridge, vlan=10),
                          mock.call(mock.ANY, self.ipv6, 'fake-table',
                                    self.bridge, vlan=10)]
        mock_del_route.assert_has_calls(expected_calls)

    @mock.patch.object(linux_net, 'del_ip_route')
    @mock.patch.object(linux_net, 'del_ip_rule')
    @mock.patch.object(linux_net, 'del_ips_from_dev')
    def test_withdraw_ip_vm_with_fip(
            self, mock_del_ip_dev, mock_del_rule, mock_del_route):
        self.sb_idl.is_provider_network.return_value = False
        self.sb_idl.get_fip_associated.return_value = (
            self.fip, 'fake-dp')
        mock_get_bridge = mock.patch.object(
            self.bgp_driver, '_get_bridge_for_datapath').start()
        mock_get_bridge.return_value = (self.bridge, 10)
        row = fakes.create_object({
            'name': 'fake-row',
            'type': constants.OVN_VM_VIF_PORT_TYPE,
            'logical_port': 'fake-logical-port',
            'datapath': 'fake-dp'})

        ips = [self.ipv4, self.ipv6]
        self.bgp_driver.withdraw_ip(ips, row)

        # Assert that the del methods were called
        mock_del_ip_dev.assert_called_once_with(
            CONF.bgp_nic, [self.fip])
        mock_del_rule.assert_called_once_with(
            self.fip, 'fake-table', self.bridge)
        mock_del_route.assert_called_once_with(
            mock.ANY, self.fip, 'fake-table', self.bridge, vlan=10)

    @mock.patch.object(linux_net, 'del_ip_route')
    @mock.patch.object(linux_net, 'del_ip_rule')
    @mock.patch.object(linux_net, 'del_ips_from_dev')
    def test_withdraw_ip_vm_with_fip_no_fip_address(
            self, mock_del_ip_dev, mock_del_rule, mock_del_route):
        self.sb_idl.is_provider_network.return_value = False
        self.sb_idl.get_fip_associated.return_value = (None, None)
        row = fakes.create_object({
            'name': 'fake-row',
            'type': constants.OVN_VM_VIF_PORT_TYPE,
            'logical_port': 'fake-logical-port',
            'datapath': 'fake-dp'})

        ips = [self.ipv4, self.ipv6]
        self.bgp_driver.withdraw_ip(ips, row)

        # Assert that the del methods were not called
        mock_del_ip_dev.assert_not_called()
        mock_del_rule.assert_not_called()
        mock_del_route.assert_not_called()

    @mock.patch.object(linux_net, 'del_ip_route')
    @mock.patch.object(linux_net, 'del_ip_rule')
    @mock.patch.object(linux_net, 'del_ips_from_dev')
    def test_withdraw_ip_fip_association_to_vm(
            self, mock_del_ip_dev, mock_del_rule, mock_del_route):
        self.sb_idl.is_provider_network.return_value = False
        self.sb_idl.is_port_on_chassis.return_value = True
        mock_get_bridge = mock.patch.object(
            self.bgp_driver, '_get_bridge_for_datapath').start()
        mock_get_bridge.return_value = (self.bridge, 10)
        row = fakes.create_object({
            'name': 'fake-row',
            'type': constants.OVN_PATCH_VIF_PORT_TYPE,
            'logical_port': 'fake-logical-port',
            'datapath': 'fake-dp'})

        ips = [self.ipv4, self.ipv6]
        self.bgp_driver.withdraw_ip(ips, row, associated_port=True)

        # Assert that the del methods were called
        mock_del_ip_dev.assert_called_once_with(
            CONF.bgp_nic, ips)

        expected_calls = [mock.call(self.ipv4, 'fake-table', self.bridge),
                          mock.call(self.ipv6, 'fake-table', self.bridge)]
        mock_del_rule.assert_has_calls(expected_calls)

        expected_calls = [mock.call(mock.ANY, self.ipv4, 'fake-table',
                                    self.bridge, vlan=10),
                          mock.call(mock.ANY, self.ipv6, 'fake-table',
                                    self.bridge, vlan=10)]
        mock_del_route.assert_has_calls(expected_calls)

    @mock.patch.object(linux_net, 'del_ndp_proxy')
    @mock.patch.object(linux_net, 'get_ip_version')
    @mock.patch.object(linux_net, 'del_ip_route')
    @mock.patch.object(linux_net, 'del_ip_rule')
    @mock.patch.object(linux_net, 'del_ips_from_dev')
    def test_withdraw_ip_chassisredirect_port(
            self, mock_del_ip_dev, mock_del_rule, mock_del_route,
            mock_ip_version, mock_ndp_proxy):
        mock_remove_net_exposed = mock.patch.object(
            self.bgp_driver, '_remove_network_exposed').start()

        mock_ip_version.side_effect = (constants.IP_VERSION_4,
                                       constants.IP_VERSION_4,
                                       constants.IP_VERSION_6,
                                       constants.IP_VERSION_6)
        row = fakes.create_object({
            'name': 'fake-row',
            'type': constants.OVN_CHASSISREDIRECT_VIF_PORT_TYPE,
            'logical_port': self.cr_lrp0,
            'mac': ['{} {} {}'.format(self.mac, self.ipv4, self.ipv6)],
            'datapath': 'fake-router-dp'})

        ips = [self.ipv4, self.ipv6]
        self.bgp_driver.withdraw_ip(ips, row)

        # Assert that the del methods were called
        mock_del_ip_dev.assert_called_once_with(
            CONF.bgp_nic, ips)

        expected_calls = [mock.call('{}/32'.format(self.ipv4), 'fake-table',
                          self.bridge, lladdr=self.mac),
                          mock.call('{}/128'.format(self.ipv6), 'fake-table',
                          self.bridge, lladdr=self.mac)]
        mock_del_rule.assert_has_calls(expected_calls)

        expected_calls = [mock.call(mock.ANY, self.ipv4, 'fake-table',
                                    self.bridge, vlan=None),
                          mock.call(mock.ANY, self.ipv6, 'fake-table',
                                    self.bridge, vlan=None)]
        mock_del_route.assert_has_calls(expected_calls)

        mock_ndp_proxy.assert_called_once_with(self.ipv6, self.bridge, None)

        mock_remove_net_exposed.assert_called_once_with(
            '192.168.1.1/24',
            {'provider_datapath': 'fake-provider-dp', 'ips': [self.fip],
             'subnets_datapath': {self.lrp0: 'fake-lrp-dp'},
             'subnets_cidr': ['192.168.1.1/24'],
             'ovn_lbs': [], 'bridge_vlan': None,
             'bridge_device': self.bridge})

    @mock.patch.object(linux_net, 'add_ips_to_dev')
    def test_expose_remote_ip(self, mock_add_ip_dev):
        self.sb_idl.is_provider_network.return_value = False
        lrp = 'fake-lrp'
        self.sb_idl.get_lrp_port_for_datapath.return_value = lrp
        self.bgp_driver.ovn_local_lrps = {lrp: 'fake-cr-lrp'}
        row = fakes.create_object({
            'name': 'fake-row', 'datapath': 'fake-dp'})

        ips = [self.ipv4, self.ipv6]
        self.bgp_driver.expose_remote_ip(ips, row)

        mock_add_ip_dev.assert_called_once_with(CONF.bgp_nic, ips)

    @mock.patch.object(linux_net, 'add_ips_to_dev')
    def test_expose_remote_ip_is_provider_network(self, mock_add_ip_dev):
        self.sb_idl.is_provider_network.return_value = True
        row = fakes.create_object({
            'name': 'fake-row', 'datapath': 'fake-dp'})

        ips = [self.ipv4, self.ipv6]
        self.bgp_driver.expose_remote_ip(ips, row)

        mock_add_ip_dev.assert_not_called()

    @mock.patch.object(linux_net, 'add_ips_to_dev')
    def test_expose_remote_ip_not_local(self, mock_add_ip_dev):
        self.sb_idl.is_provider_network.return_value = False
        lrp = 'fake-lrp'
        self.sb_idl.get_lrp_port_for_datapath.return_value = lrp
        self.bgp_driver.ovn_local_lrps = {}
        row = fakes.create_object({
            'name': 'fake-row', 'datapath': 'fake-dp'})

        ips = [self.ipv4, self.ipv6]
        self.bgp_driver.expose_remote_ip(ips, row)

        mock_add_ip_dev.assert_not_called()

    @mock.patch.object(linux_net, 'add_ips_to_dev')
    @mock.patch.object(driver_utils, 'is_ipv6_gua')
    def test_expose_remote_ip_gua(self, mock_ipv6_gua, mock_add_ip_dev):
        CONF.set_override('expose_tenant_networks', False)
        self.addCleanup(CONF.clear_override, 'expose_tenant_networks')
        CONF.set_override('expose_ipv6_gua_tenant_networks', True)
        self.addCleanup(CONF.clear_override, 'expose_ipv6_gua_tenant_networks')
        mock_ipv6_gua.side_effect = [False, True]
        self.sb_idl.is_provider_network.return_value = False
        lrp = 'fake-lrp'
        self.sb_idl.get_lrp_port_for_datapath.return_value = lrp
        self.bgp_driver.ovn_local_lrps = {lrp: 'fake-cr-lrp'}
        row = fakes.create_object({
            'name': 'fake-row', 'datapath': 'fake-dp'})

        ips = [self.ipv4, self.ipv6]
        self.bgp_driver.expose_remote_ip(ips, row)

        mock_add_ip_dev.assert_called_once_with(CONF.bgp_nic, [self.ipv6])

    @mock.patch.object(linux_net, 'add_ips_to_dev')
    @mock.patch.object(driver_utils, 'is_ipv6_gua')
    def test_expose_remote_ip_not_gua(self, mock_ipv6_gua, mock_add_ip_dev):
        CONF.set_override('expose_tenant_networks', False)
        self.addCleanup(CONF.clear_override, 'expose_tenant_networks')
        CONF.set_override('expose_ipv6_gua_tenant_networks', True)
        self.addCleanup(CONF.clear_override, 'expose_ipv6_gua_tenant_networks')
        mock_ipv6_gua.side_effect = [False, False]
        self.sb_idl.is_provider_network.return_value = False
        lrp = 'fake-lrp'
        self.sb_idl.get_lrp_port_for_datapath.return_value = lrp
        self.bgp_driver.ovn_local_lrps = {lrp: 'fake-cr-lrp'}
        row = fakes.create_object({
            'name': 'fake-row', 'datapath': 'fake-dp'})

        ips = [self.ipv4, 'fdab:4ad8:e8fb:0:f816:3eff:fec6:469c']
        self.bgp_driver.expose_remote_ip(ips, row)

        mock_add_ip_dev.assert_not_called()

    @mock.patch.object(linux_net, 'del_ips_from_dev')
    def test_withdraw_remote_ip(self, mock_del_ip_dev):
        self.sb_idl.is_provider_network.return_value = False
        lrp = 'fake-lrp'
        self.sb_idl.get_lrp_port_for_datapath.return_value = lrp
        self.bgp_driver.ovn_local_lrps = {lrp: 'fake-cr-lrp'}
        row = fakes.create_object({
            'name': 'fake-row', 'datapath': 'fake-dp'})

        ips = [self.ipv4, self.ipv6]
        self.bgp_driver.withdraw_remote_ip(ips, row)

        mock_del_ip_dev.assert_called_once_with(CONF.bgp_nic, ips)

    @mock.patch.object(linux_net, 'del_ips_from_dev')
    def test_withdraw_remote_ip_is_provider_network(self, mock_del_ip_dev):
        self.sb_idl.is_provider_network.return_value = True
        row = fakes.create_object({
            'name': 'fake-row', 'datapath': 'fake-dp'})

        ips = [self.ipv4, self.ipv6]
        self.bgp_driver.withdraw_remote_ip(ips, row)

        mock_del_ip_dev.assert_not_called()

    @mock.patch.object(linux_net, 'del_ips_from_dev')
    def test_withdraw_remote_ip_not_local(self, mock_del_ip_dev):
        self.sb_idl.is_provider_network.return_value = False
        lrp = 'fake-lrp'
        self.sb_idl.get_lrp_port_for_datapath.return_value = lrp
        self.bgp_driver.ovn_local_lrps = {}
        row = fakes.create_object({
            'name': 'fake-row', 'datapath': 'fake-dp'})

        ips = [self.ipv4, self.ipv6]
        self.bgp_driver.withdraw_remote_ip(ips, row)

        mock_del_ip_dev.assert_not_called()

    @mock.patch.object(linux_net, 'del_ips_from_dev')
    @mock.patch.object(driver_utils, 'is_ipv6_gua')
    def test_withdraw_remote_ip_gua(self, mock_ipv6_gua, mock_del_ip_dev):
        CONF.set_override('expose_tenant_networks', False)
        self.addCleanup(CONF.clear_override, 'expose_tenant_networks')
        CONF.set_override('expose_ipv6_gua_tenant_networks', True)
        self.addCleanup(CONF.clear_override, 'expose_ipv6_gua_tenant_networks')
        mock_ipv6_gua.side_effect = [False, True]
        self.sb_idl.is_provider_network.return_value = False
        lrp = 'fake-lrp'
        self.sb_idl.get_lrp_port_for_datapath.return_value = lrp
        self.bgp_driver.ovn_local_lrps = {lrp: 'fake-cr-lrp'}
        row = fakes.create_object({
            'name': 'fake-row', 'datapath': 'fake-dp'})

        ips = [self.ipv4, self.ipv6]
        self.bgp_driver.withdraw_remote_ip(ips, row)

        mock_del_ip_dev.assert_called_once_with(CONF.bgp_nic, [self.ipv6])

    @mock.patch.object(linux_net, 'del_ips_from_dev')
    @mock.patch.object(driver_utils, 'is_ipv6_gua')
    def test_withdraw_remote_ip_not_gua(self, mock_ipv6_gua, mock_del_ip_dev):
        CONF.set_override('expose_tenant_networks', False)
        self.addCleanup(CONF.clear_override, 'expose_tenant_networks')
        CONF.set_override('expose_ipv6_gua_tenant_networks', True)
        self.addCleanup(CONF.clear_override, 'expose_ipv6_gua_tenant_networks')
        mock_ipv6_gua.side_effect = [False, False]
        self.sb_idl.is_provider_network.return_value = False
        lrp = 'fake-lrp'
        self.sb_idl.get_lrp_port_for_datapath.return_value = lrp
        self.bgp_driver.ovn_local_lrps = {lrp: 'fake-cr-lrp'}
        row = fakes.create_object({
            'name': 'fake-row', 'datapath': 'fake-dp'})

        ips = [self.ipv4, 'fdab:4ad8:e8fb:0:f816:3eff:fec6:469c']
        self.bgp_driver.withdraw_remote_ip(ips, row)

        mock_del_ip_dev.assert_not_called()

    @mock.patch.object(linux_net, 'add_ip_route')
    @mock.patch.object(linux_net, 'add_ip_rule')
    @mock.patch.object(linux_net, 'get_ip_version')
    def test_expose_subnet(
            self, mock_ip_version, mock_add_rule, mock_add_route):
        mock_ip_version.return_value = constants.IP_VERSION_4
        self.sb_idl.is_router_gateway_on_chassis.return_value = self.cr_lrp0
        self.sb_idl.get_port_datapath.return_value = 'fake-port-dp'
        row = fakes.create_object({
            'name': 'fake-row',
            'logical_port': self.cr_lrp0,
            'datapath': 'fake-dp',
            'options': {'peer': 'fake-peer'}})
        dp_port0 = fakes.create_object({
            'name': 'fake-port-dp0',
            'type': constants.OVN_VM_VIF_PORT_TYPE,
            'mac': ['aa:bb:cc:dd:ee:ee 192.168.1.10 192.168.1.11'],
            'chassis': 'fake-chassis1'})
        dp_port1 = fakes.create_object({
            'name': 'fake-port-dp1',
            'type': 'fake-type',
            'mac': ['aa:bb:cc:dd:ee:ee 192.168.1.12 192.168.1.13'],
            'chassis': 'fake-chassis2'})
        dp_port2 = fakes.create_object({
            'name': 'fake-port-dp1',
            'type': constants.OVN_VM_VIF_PORT_TYPE,
            'mac': [],
            'chassis': 'fake-chassis2'})
        self.sb_idl.get_ports_on_datapath.return_value = [dp_port0, dp_port1,
                                                          dp_port2]
        mock_expose_tenant_port = mock.patch.object(
            self.bgp_driver, '_expose_tenant_port').start()

        self.bgp_driver.expose_subnet('{}/32'.format(self.ipv4), row)

        mock_add_rule.assert_called_once_with(
            '{}/32'.format(self.ipv4), 'fake-table', self.bridge)
        mock_add_route.assert_called_once_with(
            mock.ANY, self.ipv4, 'fake-table', self.bridge, vlan=None,
            mask='32', via=self.fip)
        expected_calls = [
            mock.call(dp_port0, ip_version=constants.IP_VERSION_4),
            mock.call(dp_port1, ip_version=constants.IP_VERSION_4),
            mock.call(dp_port2, ip_version=constants.IP_VERSION_4)]
        mock_expose_tenant_port.assert_has_calls(expected_calls)

    @mock.patch.object(linux_net, 'add_ip_route')
    @mock.patch.object(linux_net, 'add_ip_rule')
    @mock.patch.object(linux_net, 'get_ip_version')
    @mock.patch.object(driver_utils, 'is_ipv6_gua')
    def test_expose_subnet_gua(
            self, mock_ipv6_gua, mock_ip_version, mock_add_rule,
            mock_add_route):
        CONF.set_override('expose_tenant_networks', False)
        self.addCleanup(CONF.clear_override, 'expose_tenant_networks')
        CONF.set_override('expose_ipv6_gua_tenant_networks', True)
        self.addCleanup(CONF.clear_override, 'expose_ipv6_gua_tenant_networks')
        mock_ipv6_gua.return_value = True
        mock_ip_version.return_value = constants.IP_VERSION_6
        self.sb_idl.is_router_gateway_on_chassis.return_value = self.cr_lrp0
        self.sb_idl.get_port_datapath.return_value = 'fake-port-dp'
        row = fakes.create_object({
            'name': 'fake-row',
            'logical_port': self.cr_lrp0,
            'datapath': 'fake-dp',
            'options': {'peer': 'fake-peer'}})
        dp_port0 = fakes.create_object({
            'name': 'fake-port-dp0',
            'type': constants.OVN_VM_VIF_PORT_TYPE,
            'mac': ['aa:bb:cc:dd:ee:ee 2002::1234:abcd:ffff:c0a8:111'],
            'chassis': 'fake-chassis1'})
        dp_port1 = fakes.create_object({
            'name': 'fake-port-dp1',
            'type': 'fake-type',
            'mac': ['aa:bb:cc:dd:ee:ee 192.168.1.12 192.168.1.13'],
            'chassis': 'fake-chassis2'})
        dp_port2 = fakes.create_object({
            'name': 'fake-port-dp1',
            'type': constants.OVN_VM_VIF_PORT_TYPE,
            'mac': [],
            'chassis': 'fake-chassis2'})
        self.sb_idl.get_ports_on_datapath.return_value = [dp_port0, dp_port1,
                                                          dp_port2]
        mock_expose_tenant_port = mock.patch.object(
            self.bgp_driver, '_expose_tenant_port').start()

        self.bgp_driver.expose_subnet('{}/128'.format(self.ipv6), row)

        mock_add_rule.assert_called_once_with(
            '{}/128'.format(self.ipv6), 'fake-table', self.bridge)
        mock_add_route.assert_called_once_with(
            mock.ANY, self.ipv6, 'fake-table', self.bridge, vlan=None,
            mask='128', via=self.fip)
        expected_calls = [
            mock.call(dp_port0, ip_version=constants.IP_VERSION_6),
            mock.call(dp_port1, ip_version=constants.IP_VERSION_6),
            mock.call(dp_port2, ip_version=constants.IP_VERSION_6)]
        mock_expose_tenant_port.assert_has_calls(expected_calls)

    @mock.patch.object(linux_net, 'add_ip_route')
    @mock.patch.object(linux_net, 'add_ip_rule')
    @mock.patch.object(driver_utils, 'is_ipv6_gua')
    def test_expose_subnet_no_gua(
            self, mock_ipv6_gua, mock_add_rule, mock_add_route):
        CONF.set_override('expose_tenant_networks', False)
        self.addCleanup(CONF.clear_override, 'expose_tenant_networks')
        CONF.set_override('expose_ipv6_gua_tenant_networks', True)
        self.addCleanup(CONF.clear_override, 'expose_ipv6_gua_tenant_networks')
        mock_ipv6_gua.return_value = False
        self.sb_idl.is_router_gateway_on_chassis.return_value = self.cr_lrp0
        self.sb_idl.get_port_datapath.return_value = 'fake-port-dp'
        row = fakes.create_object({
            'name': 'fake-row',
            'logical_port': self.cr_lrp0,
            'datapath': 'fake-dp',
            'options': {'peer': 'fake-peer'}})
        dp_port0 = fakes.create_object({
            'name': 'fake-port-dp0',
            'type': constants.OVN_VM_VIF_PORT_TYPE,
            'mac': ['aa:bb:cc:dd:ee:ee 2002::1234:abcd:ffff:c0a8:111'],
            'chassis': 'fake-chassis1'})
        dp_port1 = fakes.create_object({
            'name': 'fake-port-dp1',
            'type': 'fake-type',
            'mac': ['aa:bb:cc:dd:ee:ee 192.168.1.12 192.168.1.13'],
            'chassis': 'fake-chassis2'})
        dp_port2 = fakes.create_object({
            'name': 'fake-port-dp1',
            'type': constants.OVN_VM_VIF_PORT_TYPE,
            'mac': [],
            'chassis': 'fake-chassis2'})
        self.sb_idl.get_ports_on_datapath.return_value = [dp_port0, dp_port1,
                                                          dp_port2]
        mock_expose_tenant_port = mock.patch.object(
            self.bgp_driver, '_expose_tenant_port').start()

        self.bgp_driver.expose_subnet(
            'fdab:4ad8:e8fb:0:f816:3eff:fec6:469c/128', row)

        mock_add_rule.assert_not_called()
        mock_add_route.assert_not_called()
        mock_expose_tenant_port.assert_not_called()

    @mock.patch.object(linux_net, 'get_exposed_ips_on_network')
    @mock.patch.object(linux_net, 'delete_exposed_ips')
    @mock.patch.object(linux_net, 'del_ip_route')
    @mock.patch.object(linux_net, 'del_ip_rule')
    @mock.patch.object(linux_net, 'get_ip_version')
    def test_withdraw_subnet(
            self, mock_ip_version, mock_del_rule, mock_del_route,
            mock_del_exposed_ips, mock_get_exposed_ips):
        mock_ip_version.return_value = constants.IP_VERSION_4
        mock_get_exposed_ips.return_value = [self.ipv4]
        self.sb_idl.is_router_gateway_on_chassis.return_value = self.cr_lrp0
        self.bgp_driver.ovn_local_lrps = {self.lrp0: self.cr_lrp0}
        row = fakes.create_object({
            'name': 'fake-row',
            'logical_port': self.cr_lrp0,
            'datapath': 'fake-dp'})

        self.bgp_driver.withdraw_subnet('{}/32'.format(self.ipv4), row)

        mock_del_rule.assert_called_once_with(
            '{}/32'.format(self.ipv4), 'fake-table', self.bridge)
        mock_del_route.assert_called_once_with(
            mock.ANY, self.ipv4, 'fake-table', self.bridge, vlan=None,
            mask='32', via=self.fip)
        mock_del_exposed_ips.assert_called_once_with(
            [self.ipv4], CONF.bgp_nic)

    @mock.patch.object(linux_net, 'get_exposed_ips_on_network')
    @mock.patch.object(linux_net, 'delete_exposed_ips')
    @mock.patch.object(linux_net, 'del_ip_route')
    @mock.patch.object(linux_net, 'del_ip_rule')
    @mock.patch.object(linux_net, 'get_ip_version')
    @mock.patch.object(driver_utils, 'is_ipv6_gua')
    def test_withdraw_subnet_gua(
            self, mock_ipv6_gua, mock_ip_version, mock_del_rule,
            mock_del_route, mock_del_exposed_ips, mock_get_exposed_ips):
        CONF.set_override('expose_tenant_networks', False)
        self.addCleanup(CONF.clear_override, 'expose_tenant_networks')
        CONF.set_override('expose_ipv6_gua_tenant_networks', True)
        self.addCleanup(CONF.clear_override, 'expose_ipv6_gua_tenant_networks')
        mock_ipv6_gua.return_value = True
        mock_ip_version.return_value = constants.IP_VERSION_6
        mock_get_exposed_ips.return_value = [self.ipv6]
        self.sb_idl.is_router_gateway_on_chassis.return_value = self.cr_lrp0
        self.bgp_driver.ovn_local_lrps = {self.lrp0: self.cr_lrp0}
        row = fakes.create_object({
            'name': 'fake-row',
            'logical_port': self.cr_lrp0,
            'datapath': 'fake-dp'})

        self.bgp_driver.withdraw_subnet('{}/128'.format(self.ipv6), row)

        mock_del_rule.assert_called_once_with(
            '{}/128'.format(self.ipv6), 'fake-table', self.bridge)
        mock_del_route.assert_called_once_with(
            mock.ANY, self.ipv6, 'fake-table', self.bridge, vlan=None,
            mask='128', via=self.fip)
        mock_del_exposed_ips.assert_called_once_with(
            [self.ipv6], CONF.bgp_nic)

    @mock.patch.object(linux_net, 'get_exposed_ips_on_network')
    @mock.patch.object(linux_net, 'delete_exposed_ips')
    @mock.patch.object(linux_net, 'del_ip_route')
    @mock.patch.object(linux_net, 'del_ip_rule')
    @mock.patch.object(driver_utils, 'is_ipv6_gua')
    def test_withdraw_subnet_no_gua(
            self, mock_ipv6_gua, mock_del_rule, mock_del_route,
            mock_del_exposed_ips, mock_get_exposed_ips):
        CONF.set_override('expose_tenant_networks', False)
        self.addCleanup(CONF.clear_override, 'expose_tenant_networks')
        CONF.set_override('expose_ipv6_gua_tenant_networks', True)
        self.addCleanup(CONF.clear_override, 'expose_ipv6_gua_tenant_networks')
        mock_ipv6_gua.return_value = False
        mock_get_exposed_ips.return_value = [self.ipv6]
        self.sb_idl.is_router_gateway_on_chassis.return_value = self.cr_lrp0
        self.bgp_driver.ovn_local_lrps = {self.lrp0: self.cr_lrp0}
        row = fakes.create_object({
            'name': 'fake-row',
            'logical_port': self.cr_lrp0,
            'datapath': 'fake-dp'})

        self.bgp_driver.withdraw_subnet(
            'fdab:4ad8:e8fb:0:f816:3eff:fec6:469c/128', row)

        mock_del_rule.assert_not_called()
        mock_del_route.assert_not_called()
        mock_del_exposed_ips.assert_not_called()

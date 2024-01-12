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

from ovn_bgp_agent import constants
from ovn_bgp_agent.drivers.openstack import ovn_bgp_driver
from ovn_bgp_agent.drivers.openstack.utils import bgp as bgp_utils
from ovn_bgp_agent.drivers.openstack.utils import driver_utils
from ovn_bgp_agent.drivers.openstack.utils import frr
from ovn_bgp_agent.drivers.openstack.utils import ovn
from ovn_bgp_agent.drivers.openstack.utils import ovs
from ovn_bgp_agent.drivers.openstack.utils import wire as wire_utils
from ovn_bgp_agent import exceptions as agent_exc
from ovn_bgp_agent.tests import base as test_base
from ovn_bgp_agent.tests.unit import fakes
from ovn_bgp_agent.utils import linux_net

CONF = cfg.CONF


class TestOVNBGPDriver(test_base.TestCase):

    def setUp(self):
        super(TestOVNBGPDriver, self).setUp()
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
        self.loadbalancer_vip_port = 'fake-lb-vip-port'
        self.bgp_driver.ovs_idl = self.mock_ovs_idl

        self.cr_lrp0 = 'cr-fake-logical-port'
        self.cr_lrp1 = 'cr-fake-logical-port1'
        self.lrp0 = 'lrp-fake-logical-port'
        self.bgp_driver.ovn_local_cr_lrps = {
            self.cr_lrp0: {'provider_datapath': 'fake-provider-dp',
                           'router_datapath': 'fake-router-dp',
                           'ips': [self.fip],
                           'subnets_datapath': {self.lrp0: 'fake-lrp-dp'},
                           'subnets_cidr': ['192.168.1.1/24'],
                           'provider_ovn_lbs': [],
                           'bridge_device': self.bridge,
                           'bridge_vlan': None},
            self.cr_lrp1: {'provider_datapath': 'fake-provider-dp2'}}
        self.bgp_driver.provider_ovn_lbs = {
            self.loadbalancer_vip_port: {'ips': [self.ipv4, self.ipv6],
                                         'gateway_port': self.cr_lrp0}}

    @mock.patch.object(linux_net, 'ensure_ovn_device')
    @mock.patch.object(linux_net, 'ensure_vrf')
    @mock.patch.object(frr, 'vrf_leak')
    def test_start(self, mock_vrf, *args):
        self.bgp_driver.start()

        mock_vrf.assert_called_once_with(
            CONF.bgp_vrf, CONF.bgp_AS, CONF.bgp_router_id,
            template=frr.LEAK_VRF_TEMPLATE)
        # Assert connections were started
        self.mock_ovs_idl().start.assert_called_once_with(
            CONF.ovsdb_connection)
        self.mock_sbdb().start.assert_called_once_with()

    @mock.patch.object(linux_net, 'ensure_ovn_device')
    @mock.patch.object(frr, 'vrf_leak')
    @mock.patch.object(linux_net, 'ensure_vrf')
    def test_frr_sync(self, mock_ensure_vrf, mock_vrf_leak,
                      mock_ensure_ovn_dev):
        self.bgp_driver.frr_sync()

        mock_ensure_vrf.assert_called_once_with(
            CONF.bgp_vrf, CONF.bgp_vrf_table_id)
        mock_vrf_leak.assert_called_once_with(
            CONF.bgp_vrf, CONF.bgp_AS, CONF.bgp_router_id,
            template=frr.LEAK_VRF_TEMPLATE)
        mock_ensure_ovn_dev.assert_called_once_with(
            CONF.bgp_nic, CONF.bgp_vrf)

    @mock.patch.object(wire_utils, 'delete_vlan_devices_leftovers')
    @mock.patch.object(linux_net, 'delete_bridge_ip_routes')
    @mock.patch.object(linux_net, 'delete_ip_rules')
    @mock.patch.object(linux_net, 'delete_exposed_ips')
    @mock.patch.object(ovs, 'remove_extra_ovs_flows')
    @mock.patch.object(ovs, 'ensure_mac_tweak_flows')
    @mock.patch.object(ovs, 'get_ovs_patch_ports_info')
    @mock.patch.object(linux_net, 'get_ovn_ip_rules')
    @mock.patch.object(linux_net, 'get_exposed_ips')
    @mock.patch.object(linux_net, 'get_interface_address')
    @mock.patch.object(linux_net, 'ensure_vlan_device_for_network')
    @mock.patch.object(linux_net, 'ensure_routing_table_for_bridge')
    @mock.patch.object(linux_net, 'ensure_arp_ndp_enabled_for_bridge')
    def test_sync(
            self, mock_ensure_arp, mock_routing_bridge,
            mock_ensure_vlan_network, mock_nic_address, mock_exposed_ips,
            mock_get_ip_rules, mock_get_patch_ports, mock_ensure_mac,
            mock_remove_flows, mock_del_exposed_ips, mock_del_ip_rules,
            mock_del_ip_routes, mock_vlan_leftovers):
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
        mock_routing_bridge.return_value = ['fake-route']
        mock_nic_address.return_value = self.mac
        mock_get_patch_ports.return_value = [1, 2]

        self.bgp_driver.sync()

        expected_calls = [mock.call('bridge0', 1, [10]),
                          mock.call('bridge1', 2, [11])]
        mock_ensure_arp.assert_has_calls(expected_calls)

        expected_calls = [mock.call({}, 'bridge0', CONF.bgp_vrf_table_id),
                          mock.call({}, 'bridge1', CONF.bgp_vrf_table_id)]
        mock_routing_bridge.assert_has_calls(expected_calls)

        expected_calls = [mock.call('bridge0', 10), mock.call('bridge1', 11)]
        mock_ensure_vlan_network.assert_has_calls(expected_calls)

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

        expected_calls = [mock.call('fake-port0', ips, fake_ip_rules),
                          mock.call('fake-port1', ips, fake_ip_rules)]
        mock_ensure_port_exposed.assert_has_calls(expected_calls)

        expected_calls = [mock.call('fake-cr-port0', ips, fake_ip_rules),
                          mock.call('fake-cr-port1', ips, fake_ip_rules)]
        mock_ensure_cr_port_exposed.assert_has_calls(expected_calls)

        mock_del_exposed_ips.assert_called_once_with(
            ips, CONF.bgp_nic)
        mock_del_ip_rules.assert_called_once_with(fake_ip_rules)
        mock_del_ip_routes.assert_called_once_with(
            {}, mock.ANY,
            {'bridge0': ['fake-route'], 'bridge1': ['fake-route']})

        mock_get_ip_rules.assert_called_once_with(mock.ANY)
        mock_vlan_leftovers.assert_called_once_with(
            self.sb_idl, self.bgp_driver.ovn_bridge_mappings)

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
        mock_expose_ip.return_value = exposed_ips
        ip_rules = {"{}/128".format(self.ipv6): 'fake-rules'}
        self.bgp_driver._ensure_cr_lrp_associated_ports_exposed(
            'fake-cr-lrp', exposed_ips, ip_rules)

        mock_expose_ip.assert_called_once_with(
            [self.ipv4, self.ipv6], patch_port_row,
            associated_port='fake-cr-lrp')
        self.assertEqual(['192.168.1.20'], exposed_ips)

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

    def test__ensure_port_exposed_fip_unknown_mac(self):
        fip = '172.24.4.225'
        mock_expose_ip = mock.patch.object(
            self.bgp_driver, '_expose_ip').start()
        mock_expose_ip.return_value = [fip]
        port = fakes.create_object({
            'name': 'fake-port',
            'type': '',
            'mac': ['unknown'],
            'datapath': 'fake-dp'})

        exposed_ips = [self.ipv4, fip]
        ip_rules = {"{}/128".format(self.ipv6): 'fake-rules'}
        self.sb_idl.is_provider_network.return_value = False

        self.bgp_driver._ensure_port_exposed(port, exposed_ips, ip_rules)

        mock_expose_ip.assert_called_once_with([], port)
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

    @mock.patch.object(wire_utils, '_ensure_updated_mac_tweak_flows')
    @mock.patch.object(linux_net, 'add_ips_to_dev')
    @mock.patch.object(linux_net, 'add_ip_route')
    @mock.patch.object(linux_net, 'add_ip_rule')
    def test__expose_provider_port(self, mock_add_rule, mock_add_route,
                                   mock_add_ips_dev, mock_ensure_mac_tweak):
        port_ips = [self.ipv4]
        provider_datapath = 'fake-provider-dp'
        mock_get_bridge = mock.patch.object(
            self.bgp_driver, '_get_bridge_for_datapath').start()
        mock_get_bridge.return_value = (self.bridge, 10)
        self.bgp_driver._expose_provider_port(port_ips, provider_datapath)

        mock_ensure_mac_tweak.assert_called_once_with(mock.ANY, self.bridge,
                                                      {})
        mock_add_ips_dev.assert_called_once_with(
            CONF.bgp_nic, [self.ipv4])
        mock_add_rule.assert_called_once_with(
            self.ipv4, 'fake-table')
        mock_add_route.assert_called_once_with(
            mock.ANY, self.ipv4, 'fake-table', self.bridge, vlan=10)

    @mock.patch.object(linux_net, 'add_ips_to_dev')
    @mock.patch.object(linux_net, 'add_ip_route')
    @mock.patch.object(linux_net, 'add_ip_rule')
    def test__expose_provider_port_no_device(self, mock_add_rule,
                                             mock_add_route, mock_add_ips_dev):
        port_ips = [self.ipv4]
        provider_datapath = 'fake-provider-dp'
        mock_get_bridge = mock.patch.object(
            self.bgp_driver, '_get_bridge_for_datapath').start()
        mock_get_bridge.return_value = (None, None)
        ret = self.bgp_driver._expose_provider_port(port_ips,
                                                    provider_datapath)

        self.assertEqual(False, ret)
        mock_add_ips_dev.assert_not_called()
        mock_add_rule.assert_not_called()
        mock_add_route.assert_not_called()

    @mock.patch.object(wire_utils, '_ensure_updated_mac_tweak_flows')
    @mock.patch.object(linux_net, 'add_ips_to_dev')
    @mock.patch.object(linux_net, 'add_ip_route')
    @mock.patch.object(linux_net, 'add_ip_rule')
    def test__expose_provider_port_invalid_ip(
            self, mock_add_rule, mock_add_route, mock_add_ips_dev,
            mock_ensure_mac_tweak):
        port_ips = [self.ipv4]
        provider_datapath = 'fake-provider-dp'
        mock_get_bridge = mock.patch.object(
            self.bgp_driver, '_get_bridge_for_datapath').start()
        mock_get_bridge.return_value = (self.bridge, 10)
        mock_add_rule.side_effect = agent_exc.InvalidPortIP(ip=self.ipv4)
        self.sb_idl.get_localnet_for_datapath.return_value = 'fake-localnet'
        ret = self.bgp_driver._expose_provider_port(port_ips,
                                                    provider_datapath)

        self.assertEqual(False, ret)
        mock_add_ips_dev.assert_not_called()
        mock_add_rule.assert_called_once_with(
            self.ipv4, 'fake-table')
        mock_add_route.assert_not_called()
        mock_ensure_mac_tweak.assert_not_called()

    @mock.patch.object(wire_utils, '_ensure_updated_mac_tweak_flows')
    @mock.patch.object(linux_net, 'add_ips_to_dev')
    @mock.patch.object(linux_net, 'add_ip_route')
    @mock.patch.object(linux_net, 'add_ip_rule')
    def test__expose_provider_port_with_lladdr(
            self, mock_add_rule, mock_add_route, mock_add_ips_dev,
            mock_ensure_mac_tweak):
        port_ips = [self.ipv4]
        provider_datapath = 'fake-provider-dp'
        mock_get_bridge = mock.patch.object(
            self.bgp_driver, '_get_bridge_for_datapath').start()
        mock_get_bridge.return_value = (self.bridge, 10)
        self.bgp_driver._expose_provider_port(port_ips, provider_datapath,
                                              lladdr='fake-mac')
        mock_ensure_mac_tweak.assert_called_once_with(mock.ANY, self.bridge,
                                                      {})
        mock_add_ips_dev.assert_called_once_with(
            CONF.bgp_nic, [self.ipv4])
        mock_add_rule.assert_called_once_with(
            self.ipv4, 'fake-table', dev='{}.{}'.format(self.bridge, 10),
            lladdr='fake-mac')
        mock_add_route.assert_called_once_with(
            mock.ANY, self.ipv4, 'fake-table', self.bridge, vlan=10)

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
    def test__expose_tenant_port_unknown_mac(self, mock_ip_version,
                                             mock_add_ips_dev):
        tenant_port = fakes.create_object({
            'name': 'fake-port',
            'type': constants.OVN_VM_VIF_PORT_TYPE,
            'mac': ['unknown'],
            'chassis': 'fake-chassis1',
            'external_ids': {'neutron:cidrs': '192.168.1.10/24'},
            'up': [False]})
        ip_version = constants.IP_VERSION_4

        mock_ip_version.return_value = constants.IP_VERSION_4

        self.bgp_driver._expose_tenant_port(tenant_port, ip_version)

        mock_add_ips_dev.assert_called_once_with(CONF.bgp_nic,
                                                 ['192.168.1.10'])

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

    @mock.patch.object(linux_net, 'del_ips_from_dev')
    @mock.patch.object(linux_net, 'del_ip_route')
    @mock.patch.object(linux_net, 'del_ip_rule')
    def test__withdraw_provider_port(self, mock_del_rule, mock_del_route,
                                     mock_del_ips_dev):
        port_ips = [self.ipv4]
        provider_datapath = 'fake-provider-dp'
        mock_get_bridge = mock.patch.object(
            self.bgp_driver, '_get_bridge_for_datapath').start()
        mock_get_bridge.return_value = (self.bridge, 10)
        self.bgp_driver._withdraw_provider_port(port_ips, provider_datapath)

        mock_del_ips_dev.assert_called_once_with(
            CONF.bgp_nic, [self.ipv4])
        mock_del_rule.assert_called_once_with(
            self.ipv4, 'fake-table')
        mock_del_route.assert_called_once_with(
            mock.ANY, self.ipv4, 'fake-table', self.bridge, vlan=10)

    @mock.patch.object(linux_net, 'del_ips_from_dev')
    @mock.patch.object(linux_net, 'del_ip_route')
    @mock.patch.object(linux_net, 'del_ip_rule')
    def test__withdraw_provider_port_no_device(self, mock_del_rule,
                                               mock_del_route,
                                               mock_del_ips_dev):
        port_ips = [self.ipv4]
        provider_datapath = 'fake-provider-dp'
        mock_get_bridge = mock.patch.object(
            self.bgp_driver, '_get_bridge_for_datapath').start()
        mock_get_bridge.return_value = (None, None)
        ret = self.bgp_driver._withdraw_provider_port(port_ips,
                                                      provider_datapath)

        self.assertEqual(False, ret)
        mock_del_ips_dev.assert_called_once_with(
            CONF.bgp_nic, [self.ipv4])
        mock_del_rule.assert_not_called()
        mock_del_route.assert_not_called()

    @mock.patch.object(linux_net, 'get_ip_version')
    @mock.patch.object(linux_net, 'del_ips_from_dev')
    @mock.patch.object(linux_net, 'del_ip_route')
    @mock.patch.object(linux_net, 'del_ip_rule')
    def test__withdraw_provider_port_lladdr(
            self, mock_del_rule, mock_del_route, mock_del_ips_dev,
            mock_ip_version):
        port_ips = [self.ipv4]
        provider_datapath = 'fake-provider-dp'
        mock_get_bridge = mock.patch.object(
            self.bgp_driver, '_get_bridge_for_datapath').start()
        mock_get_bridge.return_value = (self.bridge, 10)
        dev = '{}.{}'.format(self.bridge, 10)
        mock_ip_version.return_value = constants.IP_VERSION_4
        self.bgp_driver._withdraw_provider_port(port_ips, provider_datapath,
                                                lladdr='fake-mac')

        mock_del_ips_dev.assert_called_once_with(
            CONF.bgp_nic, [self.ipv4])
        mock_del_rule.assert_called_once_with(
            '{}/32'.format(self.ipv4), 'fake-table', dev=dev,
            lladdr='fake-mac')
        mock_del_route.assert_called_once_with(
            mock.ANY, self.ipv4, 'fake-table', self.bridge, vlan=10)

    @mock.patch.object(linux_net, 'get_ip_version')
    @mock.patch.object(linux_net, 'del_ips_from_dev')
    @mock.patch.object(linux_net, 'del_ip_route')
    @mock.patch.object(linux_net, 'del_ip_rule')
    def test__withdraw_provider_port_lladdr_ipv6(
            self, mock_del_rule, mock_del_route, mock_del_ips_dev,
            mock_ip_version):
        port_ips = [self.ipv6]
        provider_datapath = 'fake-provider-dp'
        mock_get_bridge = mock.patch.object(
            self.bgp_driver, '_get_bridge_for_datapath').start()
        mock_get_bridge.return_value = (self.bridge, 10)
        dev = '{}.{}'.format(self.bridge, 10)
        mock_ip_version.return_value = constants.IP_VERSION_6
        self.bgp_driver._withdraw_provider_port(port_ips, provider_datapath,
                                                lladdr='fake-mac')

        mock_del_ips_dev.assert_called_once_with(
            CONF.bgp_nic, [self.ipv6])
        mock_del_rule.assert_called_once_with(
            '{}/128'.format(self.ipv6), 'fake-table', dev=dev,
            lladdr='fake-mac')
        mock_del_route.assert_called_once_with(
            mock.ANY, self.ipv6, 'fake-table', self.bridge, vlan=10)

    @mock.patch.object(linux_net, 'add_ips_to_dev')
    @mock.patch.object(linux_net, 'add_ip_route')
    @mock.patch.object(linux_net, 'add_ip_rule')
    @mock.patch.object(linux_net, 'get_ip_version')
    def test__process_lrp_port(self, mock_ip_version, mock_add_rule,
                               mock_add_route, mock_add_ips_dev):
        mock_ip_version.return_value = constants.IP_VERSION_4
        gateway = {}
        gateway['ips'] = ['{}/32'.format(self.fip),
                          '2003::1234:abcd:ffff:c0a8:102/128']
        gateway['provider_datapath'] = 'bc6780f4-9510-4270-b4d2-b8d5c6802713'
        gateway['subnets_datapath'] = {}
        gateway['subnets_cidr'] = []
        gateway['bridge_device'] = self.bridge
        gateway['bridge_vlan'] = 10
        self.bgp_driver.ovn_local_cr_lrps = {'gateway_port': gateway}

        router_port = fakes.create_object({
            'chassis': [],
            'mac': ['{} {}/32'.format(self.mac, self.ipv4)],
            'logical_port': 'lrp-fake-logical-port',
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

        self.bgp_driver._process_lrp_port(router_port, 'gateway_port')

        # Assert that the add methods were called
        mock_add_rule.assert_called_once_with(
            '{}/32'.format(self.ipv4), 'fake-table')
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
    def test__process_lrp_port_gua(self, mock_ipv6_gua, mock_ip_version,
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
        gateway['subnets_datapath'] = {}
        gateway['subnets_cidr'] = []
        gateway['bridge_device'] = self.bridge
        gateway['bridge_vlan'] = 10
        self.bgp_driver.ovn_local_cr_lrps = {'gateway_port': gateway}

        router_port = fakes.create_object({
            'chassis': [],
            'mac': ['{} {}/128'.format(self.mac, self.ipv6)],
            'logical_port': 'lrp-fake-logical-port',
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

        self.bgp_driver._process_lrp_port(router_port, 'gateway_port')

        # Assert that the add methods were called
        mock_ipv6_gua.assert_called_once_with('{}/128'.format(self.ipv6))
        mock_add_rule.assert_called_once_with(
            '{}/128'.format(self.ipv6), 'fake-table')
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
    def test__process_lrp_port_not_gua(
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
        gateway['subnets_datapath'] = {}
        gateway['subnets_cidr'] = []
        gateway['bridge_device'] = self.bridge
        gateway['bridge_vlan'] = 10
        self.bgp_driver.ovn_local_cr_lrps = {'gateway_port': gateway}

        router_port = fakes.create_object({
            'chassis': [],
            'mac': ['{} fdab:4ad8:e8fb:0:f816:3eff:fec6:469c/128'.format(
                self.mac)],
            'logical_port': 'lrp-fake-logical-port',
            'options': {'peer': 'fake-peer'}})

        mock_get_bridge = mock.patch.object(
            self.bgp_driver, '_get_bridge_for_datapath').start()
        mock_get_bridge.return_value = (self.bridge, 10)

        self.bgp_driver._process_lrp_port(router_port, 'gateway_port')

        # Assert that the add methods were called
        mock_ipv6_gua.assert_called_once_with(
            'fdab:4ad8:e8fb:0:f816:3eff:fec6:469c/128')
        mock_add_rule.assert_not_called()
        mock_add_route.assert_not_called()
        mock_add_ips_dev.assert_not_called()

    @mock.patch.object(linux_net, 'add_ip_route')
    @mock.patch.object(linux_net, 'add_ip_rule')
    @mock.patch.object(linux_net, 'get_ip_version')
    def test__process_lrp_port_invalid_ip(
            self, mock_ip_version, mock_add_rule, mock_add_route):
        mock_ip_version.return_value = constants.IP_VERSION_4
        gateway = {}
        gateway['ips'] = ['{}/32'.format(self.fip),
                          '2003::1234:abcd:ffff:c0a8:102/128']
        gateway['provider_datapath'] = 'bc6780f4-9510-4270-b4d2-b8d5c6802713'
        gateway['subnets_datapath'] = {}
        gateway['subnets_cidr'] = []
        gateway['bridge_device'] = self.bridge
        gateway['bridge_vlan'] = 10
        self.bgp_driver.ovn_local_cr_lrps = {'gateway_port': gateway}

        router_port = fakes.create_object({
            'chassis': [],
            'mac': ['{} {}/32'.format(self.mac, self.ipv4)],
            'logical_port': 'lrp-fake-logical-port',
            'options': {'peer': 'fake-peer'}})

        mock_get_bridge = mock.patch.object(
            self.bgp_driver, '_get_bridge_for_datapath').start()
        mock_get_bridge.return_value = (self.bridge, 10)

        # Raise an exception on add_ip_rule()
        mock_add_rule.side_effect = agent_exc.InvalidPortIP(ip=self.ipv4)

        self.bgp_driver._process_lrp_port(router_port, 'gateway_port')

        mock_add_rule.assert_called_once_with(
            '{}/32'.format(self.ipv4), 'fake-table')
        # Assert that add_ip_route() was not called
        mock_add_route.assert_not_called()

    @mock.patch.object(linux_net, 'add_ips_to_dev')
    @mock.patch.object(linux_net, 'add_ip_route')
    @mock.patch.object(linux_net, 'add_ip_rule')
    def test__process_lrp_port_address_scopes(
            self, mock_add_rule, mock_add_route, mock_add_ips_dev):
        gateway = {}
        gateway['ips'] = ['{}/32'.format(self.fip),
                          '2003::1234:abcd:ffff:c0a8:102/128']
        gateway['provider_datapath'] = 'bc6780f4-9510-4270-b4d2-b8d5c6802713'
        gateway['subnets_datapath'] = {}
        gateway['subnets_cidr'] = []
        gateway['bridge_device'] = self.bridge
        gateway['bridge_vlan'] = 10
        self.bgp_driver.ovn_local_cr_lrps = {'gateway_port': gateway}
        mock_address_scope_allowed = mock.patch.object(
            self.bgp_driver, '_address_scope_allowed').start()
        mock_address_scope_allowed.return_value = False

        router_port = fakes.create_object({
            'chassis': [],
            'mac': ['{} {}/32'.format(self.mac, self.ipv4)],
            'logical_port': 'lrp-fake-logical-port',
            'options': {'peer': 'fake-peer'}})

        self.bgp_driver._process_lrp_port(router_port, 'gateway_port')

        # Assert that the add methods were called
        mock_add_rule.assert_not_called()
        mock_add_route.assert_not_called()
        mock_add_ips_dev.assert_not_called()

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

    def test_expose_ovn_lb(self):
        mock_process_ovn_lb = mock.patch.object(
            self.bgp_driver, '_process_ovn_lb').start()
        self.bgp_driver.expose_ovn_lb('fake-ip', 'fake-row')
        mock_process_ovn_lb.assert_called_once_with(
            'fake-ip', 'fake-row', constants.EXPOSE)

    def test_withdraw_ovn_lb(self):
        mock_process_ovn_lb = mock.patch.object(
            self.bgp_driver, '_process_ovn_lb').start()
        self.bgp_driver.withdraw_ovn_lb('fake-ip', 'fake-row')
        mock_process_ovn_lb.assert_called_once_with(
            'fake-ip', 'fake-row', constants.WITHDRAW)

    def _test_process_ovn_lb(self, action, provider=False):
        mock_expose_remote_ip = mock.patch.object(
            self.bgp_driver, '_expose_remote_ip').start()
        mock_withdraw_remote_ip = mock.patch.object(
            self.bgp_driver, '_withdraw_remote_ip').start()

        self.sb_idl.is_provider_network.return_value = provider
        ip = 'fake-vip-ip'
        row = fakes.create_object({
            'logical_port': 'fake-vip',
            'type': constants.OVN_VM_VIF_PORT_TYPE,
            'datapath': 'fake-provider-dp'})

        self.bgp_driver._process_ovn_lb(ip, row, action)

        if provider:
            mock_expose_remote_ip.assert_not_called()
            mock_withdraw_remote_ip.assert_not_called()
        else:
            if action == constants.EXPOSE:
                mock_expose_remote_ip.assert_called_once_with([ip], row)
                mock_withdraw_remote_ip.assert_not_called()

            elif action == constants.WITHDRAW:
                mock_expose_remote_ip.assert_not_called()
                mock_withdraw_remote_ip.assert_called_once_with([ip], row)
            else:
                mock_expose_remote_ip.assert_not_called()
                mock_withdraw_remote_ip.assert_not_called()

    def test__process_ovn_lb_expose_provider(self):
        self._test_process_ovn_lb(action=constants.EXPOSE, provider=True)

    def test__process_ovn_lb_expose_no_provider(self):
        self._test_process_ovn_lb(action=constants.EXPOSE)

    def test__process_ovn_lb_withdraw_provider(self):
        self._test_process_ovn_lb(action=constants.WITHDRAW, provider=True)

    def test__process_ovn_lb_withdraw_no_provider(self):
        self._test_process_ovn_lb(action=constants.WITHDRAW)

    def test__process_ovn_lb_unknown_action(self):
        self._test_process_ovn_lb(action="fake-action")

    def test__process_ovn_lb_datapath_exception(self):
        ip = 'fake-vip-ip'
        row = fakes.create_object({
            'logical_port': 'fake-vip',
            'type': constants.OVN_VM_VIF_PORT_TYPE,
            'datapath': 'fake-provider-dp'})
        mock_expose_remote_ip = mock.patch.object(
            self.bgp_driver, '_expose_remote_ip').start()
        mock_withdraw_remote_ip = mock.patch.object(
            self.bgp_driver, '_withdraw_remote_ip').start()
        self.sb_idl.is_provider_network.side_effect = (
            agent_exc.DatapathNotFound(datapath=row.datapath))

        self.bgp_driver._process_ovn_lb(ip, row, mock.ANY)

        mock_expose_remote_ip.assert_not_called()
        mock_withdraw_remote_ip.assert_not_called()

    def test_expose_ovn_lb_on_provider(self):
        mock_expose_provider_port = mock.patch.object(
            self.bgp_driver, '_expose_provider_port').start()
        self.bgp_driver.expose_ovn_lb_on_provider(
            self.ipv4, 'ovn-lb-2', self.cr_lrp0)

        # Assert that the add methods were called
        mock_expose_provider_port.assert_called_once_with(
            [self.ipv4], self.bgp_driver.ovn_local_cr_lrps[self.cr_lrp0][
                'provider_datapath'], bridge_device=self.bridge,
            bridge_vlan=None)

    def test__expose_ovn_lb_on_provider_failure(self):
        mock_expose_provider_port = mock.patch.object(
            self.bgp_driver, '_expose_provider_port').start()
        mock_expose_provider_port.return_value = False
        ret = self.bgp_driver._expose_ovn_lb_on_provider(
            self.ipv4, self.loadbalancer_vip_port, self.cr_lrp0)

        # Assert that the add methods were called
        mock_expose_provider_port.assert_called_once_with(
            [self.ipv4], self.bgp_driver.ovn_local_cr_lrps[self.cr_lrp0][
                'provider_datapath'], bridge_device=self.bridge,
            bridge_vlan=None)
        self.assertEqual(False, ret)

    def test__expose_ovn_lb_on_provider_keyerror(self):
        mock_expose_provider_port = mock.patch.object(
            self.bgp_driver, '_expose_provider_port').start()
        ret = self.bgp_driver._expose_ovn_lb_on_provider(
            self.ipv4, self.loadbalancer_vip_port, 'wrong-cr-logical-port')

        # Assert that the add methods were called
        mock_expose_provider_port.assert_not_called()
        self.assertEqual(False, ret)

    @mock.patch.object(linux_net, 'del_ip_route')
    @mock.patch.object(linux_net, 'del_ip_rule')
    @mock.patch.object(linux_net, 'del_ips_from_dev')
    def test_withdraw_ovn_lb_on_provider(
            self, mock_del_ip_dev, mock_del_rule, mock_del_route):
        self.bgp_driver.withdraw_ovn_lb_on_provider(
            self.loadbalancer_vip_port, self.cr_lrp0)

        # Assert that the del methods were called
        expected_calls = [mock.call(CONF.bgp_nic, [self.ipv4]),
                          mock.call(CONF.bgp_nic, [self.ipv6])]
        mock_del_ip_dev.assert_has_calls(expected_calls)

        expected_calls = [mock.call(self.ipv4, 'fake-table'),
                          mock.call(self.ipv6, 'fake-table')]
        mock_del_rule.assert_has_calls(expected_calls)

        expected_calls = [mock.call(mock.ANY, self.ipv4, 'fake-table',
                                    self.bridge, vlan=None),
                          mock.call(mock.ANY, self.ipv6, 'fake-table',
                                    self.bridge, vlan=None)]
        mock_del_route.assert_has_calls(expected_calls)

    @mock.patch.object(linux_net, 'del_ip_route')
    @mock.patch.object(linux_net, 'del_ip_rule')
    @mock.patch.object(linux_net, 'del_ips_from_dev')
    def test__withdraw_ovn_lb_on_provider_keyerror(
            self, mock_del_ip_dev, mock_del_rule, mock_del_route):
        ret = self.bgp_driver._withdraw_ovn_lb_on_provider(
            self.loadbalancer_vip_port, 'wrong-cr-logical-port')

        # Assert that the del methods were called
        self.assertEqual(False, ret)
        mock_del_ip_dev.assert_not_called()
        mock_del_rule.assert_not_called()
        mock_del_route.assert_not_called()

    def test__withdraw_ovn_lb_on_provider_failure(self):
        mock_withdraw_provider_port = mock.patch.object(
            self.bgp_driver, '_withdraw_provider_port').start()
        mock_withdraw_provider_port.return_value = False
        ret = self.bgp_driver._withdraw_ovn_lb_on_provider(
            self.loadbalancer_vip_port, self.cr_lrp0)
        self.assertEqual(False, ret)

    @mock.patch.object(wire_utils, '_ensure_updated_mac_tweak_flows')
    @mock.patch.object(linux_net, 'add_ip_route')
    @mock.patch.object(linux_net, 'add_ip_rule')
    @mock.patch.object(linux_net, 'add_ips_to_dev')
    def test_expose_ip_vm_on_provider_network(
            self, mock_add_ip_dev, mock_add_rule, mock_add_route,
            mock_ensure_mac_tweak):
        self.sb_idl.is_provider_network.return_value = True
        mock_get_bridge = mock.patch.object(
            self.bgp_driver, '_get_bridge_for_datapath').start()
        mock_get_bridge.return_value = (self.bridge, 10)
        row = fakes.create_object({
            'logical_port': 'fake-row',
            'type': constants.OVN_VM_VIF_PORT_TYPE,
            'datapath': 'fake-dp'})

        ips = [self.ipv4, self.ipv6]
        self.bgp_driver.expose_ip(ips, row)

        # Assert that the add methods were called
        mock_ensure_mac_tweak.assert_called_once_with(mock.ANY, self.bridge,
                                                      {})
        mock_add_ip_dev.assert_called_once_with(
            CONF.bgp_nic, ips)

        expected_calls = [mock.call(self.ipv4, 'fake-table'),
                          mock.call(self.ipv6, 'fake-table')]
        mock_add_rule.assert_has_calls(expected_calls)

        expected_calls = [mock.call(mock.ANY, self.ipv4, 'fake-table',
                                    self.bridge, vlan=10),
                          mock.call(mock.ANY, self.ipv6, 'fake-table',
                                    self.bridge, vlan=10)]
        mock_add_route.assert_has_calls(expected_calls)

    @mock.patch.object(linux_net, 'add_ip_route')
    @mock.patch.object(linux_net, 'add_ip_rule')
    @mock.patch.object(linux_net, 'add_ips_to_dev')
    def test__expose_ip_vm_on_provider_network_datapath_not_found(
            self, mock_add_ip_dev, mock_add_rule, mock_add_route):
        self.sb_idl.is_provider_network.side_effect = (
            agent_exc.DatapathNotFound(datapath="fake-dp"))
        row = fakes.create_object({
            'logical_port': 'fake-row',
            'type': constants.OVN_VM_VIF_PORT_TYPE,
            'datapath': 'fake-dp'})

        ips = [self.ipv4, self.ipv6]
        ret = self.bgp_driver._expose_ip(ips, row)

        # Assert that the add methods were called
        self.assertEqual([], ret)
        mock_add_ip_dev.assert_not_called()
        mock_add_rule.assert_not_called()
        mock_add_route.assert_not_called()

    @mock.patch.object(wire_utils, 'wire_provider_port')
    @mock.patch.object(bgp_utils, 'announce_ips')
    def test__expose_ip_vm_on_provider_network_expose_failure(
            self, mock_bgp_announce, mock_wire_port):
        self.sb_idl.is_provider_network.return_value = True
        mock_get_bridge = mock.patch.object(
            self.bgp_driver, '_get_bridge_for_datapath').start()
        mock_get_bridge.return_value = (self.bridge, 10)
        mock_wire_port.return_value = False
        row = fakes.create_object({
            'logical_port': 'fake-row',
            'type': constants.OVN_VM_VIF_PORT_TYPE,
            'datapath': 'fake-dp'})

        ips = [self.ipv4, self.ipv6]
        ret = self.bgp_driver._expose_ip(ips, row)

        # Assert that the add methods were called
        self.assertEqual([], ret)
        mock_wire_port.assert_called_once()
        mock_bgp_announce.assert_not_called()

    @mock.patch.object(wire_utils, '_ensure_updated_mac_tweak_flows')
    @mock.patch.object(linux_net, 'add_ndp_proxy')
    @mock.patch.object(linux_net, 'get_ip_version')
    @mock.patch.object(linux_net, 'add_ip_route')
    @mock.patch.object(linux_net, 'add_ip_rule')
    @mock.patch.object(linux_net, 'add_ips_to_dev')
    def test__expose_ip_virtual_port_on_provider_network(
            self, mock_add_ip_dev, mock_add_rule, mock_add_route,
            mock_ip_version, mock_add_ndp_proxy, mock_ensure_mac_tweak):
        self.sb_idl.is_provider_network.return_value = True
        mock_get_bridge = mock.patch.object(
            self.bgp_driver, '_get_bridge_for_datapath').start()
        mock_get_bridge.return_value = (self.bridge, 10)
        mock_ip_version.return_value = constants.IP_VERSION_6
        row = fakes.create_object({
            'logical_port': 'fake-row',
            'type': constants.OVN_VIRTUAL_VIF_PORT_TYPE,
            'datapath': 'fake-dp',
            'external_ids': {'neutron:cidrs': '{}/128'.format(self.ipv6)}})

        ips = [self.ipv4, self.ipv6]
        ret = self.bgp_driver._expose_ip(ips, row)

        # Assert that the add methods were called
        mock_ensure_mac_tweak.assert_called_once_with(mock.ANY, self.bridge,
                                                      {})
        self.assertEqual(ips, ret)
        mock_add_ip_dev.assert_called_once_with(
            CONF.bgp_nic, ips)

        expected_calls = [mock.call(self.ipv4, 'fake-table'),
                          mock.call(self.ipv6, 'fake-table')]
        mock_add_rule.assert_has_calls(expected_calls)

        expected_calls = [mock.call(mock.ANY, self.ipv4, 'fake-table',
                                    self.bridge, vlan=10),
                          mock.call(mock.ANY, self.ipv6, 'fake-table',
                                    self.bridge, vlan=10)]
        mock_add_route.assert_has_calls(expected_calls)
        mock_add_ndp_proxy.assert_called_once_with(
            '{}/128'.format(self.ipv6), self.bridge, 10)

    @mock.patch.object(linux_net, 'add_ndp_proxy')
    @mock.patch.object(linux_net, 'get_ip_version')
    @mock.patch.object(linux_net, 'add_ip_route')
    @mock.patch.object(linux_net, 'add_ip_rule')
    @mock.patch.object(linux_net, 'add_ips_to_dev')
    def test__expose_ip_virtual_port_on_provider_network_expose_failure(
            self, mock_add_ip_dev, mock_add_rule, mock_add_route,
            mock_ip_version, mock_add_ndp_proxy):
        self.sb_idl.is_provider_network.return_value = True
        mock_get_bridge = mock.patch.object(
            self.bgp_driver, '_get_bridge_for_datapath').start()
        mock_get_bridge.return_value = (None, None)
        mock_ip_version.return_value = constants.IP_VERSION_6
        row = fakes.create_object({
            'logical_port': 'fake-row',
            'type': constants.OVN_VIRTUAL_VIF_PORT_TYPE,
            'datapath': 'fake-dp',
            'external_ids': {'neutron:cidrs': '{}/128'.format(self.ipv6)}})

        ips = [self.ipv4, self.ipv6]
        ret = self.bgp_driver._expose_ip(ips, row)

        # Assert that the add methods were called
        self.assertEqual([], ret)
        mock_add_ip_dev.assert_not_called()
        mock_add_rule.assert_not_called()
        mock_add_route.assert_not_called()
        mock_add_ndp_proxy.assert_not_called()

    @mock.patch.object(wire_utils, '_ensure_updated_mac_tweak_flows')
    @mock.patch.object(linux_net, 'add_ip_route')
    @mock.patch.object(linux_net, 'add_ip_rule')
    @mock.patch.object(linux_net, 'add_ips_to_dev')
    def test__expose_ip_vm_with_fip(
            self, mock_add_ip_dev, mock_add_rule, mock_add_route,
            mock_ensure_mac_tweak):
        self.sb_idl.is_provider_network.side_effect = [False, True]
        self.sb_idl.get_fip_associated.return_value = (
            self.fip, 'fake-dp')
        mock_get_bridge = mock.patch.object(
            self.bgp_driver, '_get_bridge_for_datapath').start()
        mock_get_bridge.return_value = (self.bridge, 10)
        row = fakes.create_object({
            'type': constants.OVN_VM_VIF_PORT_TYPE,
            'logical_port': 'fake-logical-port',
            'datapath': 'fake-dp'})

        ips = [self.ipv4, self.ipv6]
        ret = self.bgp_driver._expose_ip(ips, row)

        # Assert that the add methods were called
        self.assertEqual([self.fip], ret)
        mock_ensure_mac_tweak.assert_called_once_with(mock.ANY, self.bridge,
                                                      {})
        mock_add_ip_dev.assert_called_once_with(
            CONF.bgp_nic, [self.fip])
        mock_add_rule.assert_called_once_with(
            self.fip, 'fake-table')
        mock_add_route.assert_called_once_with(
            mock.ANY, self.fip, 'fake-table', self.bridge, vlan=10)

    @mock.patch.object(linux_net, 'add_ip_route')
    @mock.patch.object(linux_net, 'add_ip_rule')
    @mock.patch.object(linux_net, 'add_ips_to_dev')
    def test__expose_ip_vm_with_fip_no_provider(
            self, mock_add_ip_dev, mock_add_rule, mock_add_route):
        self.sb_idl.is_provider_network.side_effect = [False, False]
        self.sb_idl.get_fip_associated.return_value = (
            self.fip, 'fake-dp')
        mock_get_bridge = mock.patch.object(
            self.bgp_driver, '_get_bridge_for_datapath').start()
        mock_get_bridge.return_value = (self.bridge, 10)
        row = fakes.create_object({
            'type': constants.OVN_VM_VIF_PORT_TYPE,
            'logical_port': 'fake-logical-port',
            'datapath': 'fake-dp'})

        ips = [self.ipv4, self.ipv6]
        ret = self.bgp_driver._expose_ip(ips, row)

        # Assert that the add methods were called
        self.assertEqual([], ret)
        mock_add_ip_dev.assert_not_called()
        mock_add_rule.assert_not_called()
        mock_add_route.assert_not_called()

    @mock.patch.object(linux_net, 'add_ip_route')
    @mock.patch.object(linux_net, 'add_ip_rule')
    @mock.patch.object(linux_net, 'add_ips_to_dev')
    def test__expose_ip_vm_with_fip_no_fip_address(
            self, mock_add_ip_dev, mock_add_rule, mock_add_route):
        self.sb_idl.is_provider_network.return_value = False
        self.sb_idl.get_fip_associated.return_value = (None, None)
        row = fakes.create_object({
            'type': constants.OVN_VM_VIF_PORT_TYPE,
            'logical_port': 'fake-logical-port',
            'datapath': 'fake-dp'})

        ips = [self.ipv4, self.ipv6]
        ret = self.bgp_driver._expose_ip(ips, row)

        # Assert that the add methods were not called
        self.assertEqual([], ret)
        mock_add_ip_dev.assert_not_called()
        mock_add_rule.assert_not_called()
        mock_add_route.assert_not_called()

    @mock.patch.object(wire_utils, '_ensure_updated_mac_tweak_flows')
    @mock.patch.object(linux_net, 'add_ip_route')
    @mock.patch.object(linux_net, 'add_ip_rule')
    @mock.patch.object(linux_net, 'add_ips_to_dev')
    def test__expose_ip_fip_association_to_vm(
            self, mock_add_ip_dev, mock_add_rule, mock_add_route,
            mock_ensure_mac_tweak):
        self.sb_idl.is_provider_network.return_value = True
        self.sb_idl.is_port_on_chassis.return_value = True
        mock_get_bridge = mock.patch.object(
            self.bgp_driver, '_get_bridge_for_datapath').start()
        mock_get_bridge.return_value = (self.bridge, 10)
        row = fakes.create_object({
            'type': constants.OVN_PATCH_VIF_PORT_TYPE,
            'logical_port': 'fake-logical-port',
            'datapath': 'fake-dp'})

        ips = [self.ipv4, self.ipv6]
        ret = self.bgp_driver._expose_ip(ips, row,
                                         associated_port=self.cr_lrp0)

        # Assert that the add methods were called
        self.assertEqual(ips, ret)
        mock_ensure_mac_tweak.assert_called_once_with(mock.ANY, self.bridge,
                                                      {})
        mock_add_ip_dev.assert_called_once_with(
            CONF.bgp_nic, ips)

        expected_calls = [mock.call(self.ipv4, 'fake-table'),
                          mock.call(self.ipv6, 'fake-table')]
        mock_add_rule.assert_has_calls(expected_calls)

        expected_calls = [mock.call(mock.ANY, self.ipv4, 'fake-table',
                                    self.bridge, vlan=10),
                          mock.call(mock.ANY, self.ipv6, 'fake-table',
                                    self.bridge, vlan=10)]
        mock_add_route.assert_has_calls(expected_calls)

    @mock.patch.object(wire_utils, '_ensure_updated_mac_tweak_flows')
    @mock.patch.object(linux_net, 'add_ndp_proxy')
    @mock.patch.object(linux_net, 'get_ip_version')
    @mock.patch.object(linux_net, 'add_ip_route')
    @mock.patch.object(linux_net, 'add_ip_rule')
    @mock.patch.object(linux_net, 'add_ips_to_dev')
    def test__expose_ip_chassisredirect_port(
            self, mock_add_ip_dev, mock_add_rule, mock_add_route,
            mock_ip_version, mock_ndp_proxy, mock_ensure_mac_tweak):
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

        self.sb_idl.get_cr_lrp_nat_addresses_info.return_value = (
            [], self.cr_lrp0)

        mock_process_lrp_port = mock.patch.object(
            self.bgp_driver, '_process_lrp_port').start()

        mock_ip_version.side_effect = (constants.IP_VERSION_4,
                                       constants.IP_VERSION_6)
        row = fakes.create_object({
            'type': constants.OVN_CHASSISREDIRECT_VIF_PORT_TYPE,
            'logical_port': self.cr_lrp0,
            'mac': ['{} {} {}'.format(self.mac, self.ipv4, self.ipv6)],
            'datapath': 'fake-router-dp'})

        ovn_lb_vip = '172.24.4.5'
        ovn_lbs = {'fake-vip-port': ovn_lb_vip}
        self.sb_idl.get_provider_ovn_lbs_on_cr_lrp.return_value = (
            ovn_lbs)
        mock_expose_ovn_lb = mock.patch.object(
            self.bgp_driver, '_expose_ovn_lb_on_provider').start()

        ips = [self.ipv4, self.ipv6]
        ret = self.bgp_driver._expose_ip(ips, row)

        # Assert that the add methods were called
        self.assertEqual(ips, ret)
        mock_ensure_mac_tweak.assert_called_once_with(mock.ANY, self.bridge,
                                                      {})
        mock_add_ip_dev.assert_called_once_with(
            CONF.bgp_nic, ips)

        expected_calls = [mock.call(self.ipv4, 'fake-table',
                          dev='{}.{}'.format(self.bridge, 10),
                          lladdr=self.mac),
                          mock.call(self.ipv6, 'fake-table',
                          dev='{}.{}'.format(self.bridge, 10),
                          lladdr=self.mac)]
        mock_add_rule.assert_has_calls(expected_calls)

        expected_calls = [mock.call(mock.ANY, self.ipv4, 'fake-table',
                                    self.bridge, vlan=10),
                          mock.call(mock.ANY, self.ipv6, 'fake-table',
                                    self.bridge, vlan=10)]
        mock_add_route.assert_has_calls(expected_calls)

        mock_ndp_proxy.assert_called_once_with(self.ipv6, self.bridge, 10)

        expected_calls = [mock.call(lrp0, self.cr_lrp0),
                          mock.call(lrp1, self.cr_lrp0),
                          mock.call(lrp2, self.cr_lrp0)]
        mock_process_lrp_port.assert_has_calls(expected_calls)
        mock_expose_ovn_lb.assert_called_once_with(
            ovn_lb_vip, 'fake-vip-port', self.cr_lrp0)

    @mock.patch.object(linux_net, 'add_ndp_proxy')
    @mock.patch.object(linux_net, 'add_ip_route')
    @mock.patch.object(linux_net, 'add_ip_rule')
    @mock.patch.object(linux_net, 'add_ips_to_dev')
    def test__expose_ip_chassisredirect_port_no_datapath(
            self, mock_add_ip_dev, mock_add_rule, mock_add_route,
            mock_ndp_proxy):
        self.sb_idl.get_provider_datapath_from_cr_lrp.return_value = None

        row = fakes.create_object({
            'type': constants.OVN_CHASSISREDIRECT_VIF_PORT_TYPE,
            'logical_port': self.cr_lrp0,
            'mac': ['{} {} {}'.format(self.mac, self.ipv4, self.ipv6)],
            'datapath': 'fake-router-dp'})

        ips = [self.ipv4, self.ipv6]
        ret = self.bgp_driver._expose_ip(ips, row)

        # Assert that the add methods were called
        self.assertEqual([], ret)
        mock_add_ip_dev.assert_not_called()
        mock_add_rule.assert_not_called()
        mock_add_route.assert_not_called()
        mock_ndp_proxy.assert_not_called()

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
            'logical_port': 'fake-row',
            'type': constants.OVN_VM_VIF_PORT_TYPE,
            'datapath': 'fake-dp'})

        ips = [self.ipv4, self.ipv6]
        self.bgp_driver.withdraw_ip(ips, row)

        # Assert that the del methods were called
        mock_del_ip_dev.assert_called_once_with(
            CONF.bgp_nic, ips)

        expected_calls = [mock.call(self.ipv4, 'fake-table'),
                          mock.call(self.ipv6, 'fake-table')]
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
    def test_withdraw_ip_virtual_port_on_provider_network(
            self, mock_del_ip_dev, mock_del_rule, mock_del_route,
            mock_ip_version, mock_del_ndp_proxy):
        self.sb_idl.is_provider_network.return_value = True
        mock_get_bridge = mock.patch.object(
            self.bgp_driver, '_get_bridge_for_datapath').start()
        mock_get_bridge.return_value = (self.bridge, 10)
        row = fakes.create_object({
            'logical_port': 'fake-row',
            'type': constants.OVN_VIRTUAL_VIF_PORT_TYPE,
            'datapath': 'fake-dp',
            'external_ids': {'neutron:cidrs': '{}/128'.format(self.ipv6)}})

        ips = [self.ipv4, self.ipv6]
        self.sb_idl.get_virtual_ports_on_datapath_by_chassis.return_value = []
        mock_ip_version.return_value = constants.IP_VERSION_6

        self.bgp_driver.withdraw_ip(ips, row)

        # Assert that the del methods were called
        mock_del_ip_dev.assert_called_once_with(
            CONF.bgp_nic, ips)

        expected_calls = [mock.call(self.ipv4, 'fake-table'),
                          mock.call(self.ipv6, 'fake-table')]
        mock_del_rule.assert_has_calls(expected_calls)

        expected_calls = [mock.call(mock.ANY, self.ipv4, 'fake-table',
                                    self.bridge, vlan=10),
                          mock.call(mock.ANY, self.ipv6, 'fake-table',
                                    self.bridge, vlan=10)]
        mock_del_route.assert_has_calls(expected_calls)
        mock_del_ndp_proxy.assert_called_once_with(
            '{}/128'.format(self.ipv6), self.bridge, 10)

    @mock.patch.object(linux_net, 'del_ip_route')
    @mock.patch.object(linux_net, 'del_ip_rule')
    @mock.patch.object(linux_net, 'del_ips_from_dev')
    def test_withdraw_ip_vm_with_fip(
            self, mock_del_ip_dev, mock_del_rule, mock_del_route):
        self.sb_idl.is_provider_network.side_effect = [False, True]
        self.sb_idl.get_fip_associated.return_value = (
            self.fip, 'fake-dp')
        mock_get_bridge = mock.patch.object(
            self.bgp_driver, '_get_bridge_for_datapath').start()
        mock_get_bridge.return_value = (self.bridge, 10)
        row = fakes.create_object({
            'type': constants.OVN_VM_VIF_PORT_TYPE,
            'logical_port': 'fake-logical-port',
            'datapath': 'fake-dp'})

        ips = [self.ipv4, self.ipv6]
        self.bgp_driver.withdraw_ip(ips, row)

        # Assert that the del methods were called
        mock_del_ip_dev.assert_called_once_with(
            CONF.bgp_nic, [self.fip])
        mock_del_rule.assert_called_once_with(
            self.fip, 'fake-table')
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
        self.sb_idl.is_provider_network.return_value = True
        self.sb_idl.is_port_on_chassis.return_value = True
        mock_get_bridge = mock.patch.object(
            self.bgp_driver, '_get_bridge_for_datapath').start()
        mock_get_bridge.return_value = (self.bridge, 10)
        row = fakes.create_object({
            'type': constants.OVN_PATCH_VIF_PORT_TYPE,
            'logical_port': 'fake-logical-port',
            'datapath': 'fake-dp'})

        ips = [self.ipv4, self.ipv6]
        self.bgp_driver.withdraw_ip(ips, row, associated_port=self.cr_lrp0)

        # Assert that the del methods were called
        mock_del_ip_dev.assert_called_once_with(
            CONF.bgp_nic, ips)

        expected_calls = [mock.call(self.ipv4, 'fake-table'),
                          mock.call(self.ipv6, 'fake-table')]
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
        mock_withdraw_lrp_port = mock.patch.object(
            self.bgp_driver, '_withdraw_lrp_port').start()

        mock_ip_version.side_effect = (constants.IP_VERSION_4,
                                       constants.IP_VERSION_6,
                                       constants.IP_VERSION_4,
                                       constants.IP_VERSION_6,
                                       constants.IP_VERSION_6)
        row = fakes.create_object({
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
                          dev=self.bridge, lladdr=self.mac),
                          mock.call('{}/128'.format(self.ipv6), 'fake-table',
                          dev=self.bridge, lladdr=self.mac)]
        mock_del_rule.assert_has_calls(expected_calls)

        expected_calls = [mock.call(mock.ANY, self.ipv4, 'fake-table',
                                    self.bridge, vlan=None),
                          mock.call(mock.ANY, self.ipv6, 'fake-table',
                                    self.bridge, vlan=None)]
        mock_del_route.assert_has_calls(expected_calls)

        mock_ndp_proxy.assert_called_once_with(self.ipv6, self.bridge, None)

        mock_withdraw_lrp_port.assert_called_once_with(
            '192.168.1.1/24', None, self.cr_lrp0)

    @mock.patch.object(linux_net, 'add_ips_to_dev')
    def test_expose_remote_ip(self, mock_add_ip_dev):
        self.sb_idl.is_provider_network.return_value = False
        lrp = 'fake-lrp'
        self.sb_idl.get_lrps_for_datapath.return_value = [lrp]
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
        self.sb_idl.get_lrps_for_datapath.return_value = [lrp]
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
        self.sb_idl.get_lrps_for_datapath.return_value = [lrp]
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
        self.sb_idl.get_lrps_for_datapath.return_value = [lrp]
        self.bgp_driver.ovn_local_lrps = {lrp: 'fake-cr-lrp'}
        row = fakes.create_object({
            'name': 'fake-row', 'datapath': 'fake-dp'})

        ips = [self.ipv4, 'fdab:4ad8:e8fb:0:f816:3eff:fec6:469c']
        self.bgp_driver.expose_remote_ip(ips, row)

        mock_add_ip_dev.assert_not_called()

    @mock.patch.object(linux_net, 'add_ips_to_dev')
    def test_expose_remote_ip_address_scope(self, mock_add_ip_dev):
        self.sb_idl.is_provider_network.return_value = False
        lrp = 'fake-lrp'
        self.sb_idl.get_lrps_for_datapath.return_value = [lrp]
        self.bgp_driver.ovn_local_lrps = {lrp: 'fake-cr-lrp'}
        row = fakes.create_object({
            'name': 'fake-row', 'datapath': 'fake-dp'})

        mock_address_scope_allowed = mock.patch.object(
            self.bgp_driver, '_address_scope_allowed').start()
        mock_address_scope_allowed.side_effect = [False, True]

        ips = [self.ipv4, self.ipv6]
        self.bgp_driver.expose_remote_ip(ips, row)

        mock_add_ip_dev.assert_called_once_with(CONF.bgp_nic, [self.ipv6])

    @mock.patch.object(linux_net, 'del_ips_from_dev')
    def test_withdraw_remote_ip(self, mock_del_ip_dev):
        self.sb_idl.is_provider_network.return_value = False
        lrp = 'fake-lrp'
        self.sb_idl.get_lrps_for_datapath.return_value = [lrp]
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
        self.sb_idl.get_lrps_for_datapath.return_value = [lrp]
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
        self.sb_idl.get_lrps_for_datapath.return_value = [lrp]
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
        self.sb_idl.get_lrps_for_datapath.return_value = [lrp]
        self.bgp_driver.ovn_local_lrps = {lrp: 'fake-cr-lrp'}
        row = fakes.create_object({
            'name': 'fake-row', 'datapath': 'fake-dp'})

        ips = [self.ipv4, 'fdab:4ad8:e8fb:0:f816:3eff:fec6:469c']
        self.bgp_driver.withdraw_remote_ip(ips, row)

        mock_del_ip_dev.assert_not_called()

    @mock.patch.object(linux_net, 'del_ips_from_dev')
    def test_withdraw_remote_ip_address_scope(self, mock_del_ip_dev):
        self.sb_idl.is_provider_network.return_value = False
        lrp = 'fake-lrp'
        self.sb_idl.get_lrps_for_datapath.return_value = [lrp]
        self.bgp_driver.ovn_local_lrps = {lrp: 'fake-cr-lrp'}
        row = fakes.create_object({
            'name': 'fake-row', 'datapath': 'fake-dp'})

        mock_address_scope_allowed = mock.patch.object(
            self.bgp_driver, '_address_scope_allowed').start()
        mock_address_scope_allowed.side_effect = [False, True]

        ips = [self.ipv4, self.ipv6]
        self.bgp_driver.withdraw_remote_ip(ips, row)

        mock_del_ip_dev.assert_called_once_with(CONF.bgp_nic, [self.ipv6])

    @mock.patch.object(linux_net, 'get_ip_version')
    def test__expose_cr_lrp_port(self, mock_ip_version):
        mock_expose_provider_port = mock.patch.object(
            self.bgp_driver, '_expose_provider_port').start()
        mock_process_lrp_port = mock.patch.object(
            self.bgp_driver, '_process_lrp_port').start()
        mock_expose_ovn_lb = mock.patch.object(
            self.bgp_driver, '_expose_ovn_lb_on_provider').start()
        ips = [self.ipv4, self.ipv6]
        mock_ip_version.side_effect = [constants.IP_VERSION_4,
                                       constants.IP_VERSION_6]

        dp_port0 = mock.Mock()
        self.sb_idl.get_lrp_ports_for_router.return_value = [dp_port0]
        ovn_lbs = {'fake-vip-port': 'fake-vip-ip'}
        self.sb_idl.get_provider_ovn_lbs_on_cr_lrp.return_value = (
            ovn_lbs)

        ips_without_mask = [ip.split("/")[0] for ip in ips]
        self.sb_idl.get_cr_lrp_nat_addresses_info.return_value = (
            [ips_without_mask[0]], self.cr_lrp0)

        self.bgp_driver._expose_cr_lrp_port(
            ips, self.mac, self.bridge, None, router_datapath='fake-router-dp',
            provider_datapath='fake-provider-dp', cr_lrp_port=self.cr_lrp0)

        mock_expose_provider_port.assert_called_once_with(
            ips_without_mask, 'fake-provider-dp', self.bridge, None,
            lladdr=self.mac, proxy_cidrs=ips)
        mock_process_lrp_port.assert_called_once_with(dp_port0, self.cr_lrp0)
        mock_expose_ovn_lb.assert_called_once_with(
            'fake-vip-ip', 'fake-vip-port', self.cr_lrp0)

    def test__expose_cr_lrp_port_failure(self):
        mock_expose_provider_port = mock.patch.object(
            self.bgp_driver, '_expose_provider_port').start()
        mock_expose_provider_port.return_value = False
        mock_process_lrp_port = mock.patch.object(
            self.bgp_driver, '_process_lrp_port').start()
        mock_expose_ovn_lb = mock.patch.object(
            self.bgp_driver, '_expose_ovn_lb_on_provider').start()
        ips = [self.ipv4, self.ipv6]

        ret = self.bgp_driver._expose_cr_lrp_port(
            ips, self.mac, self.bridge, None, router_datapath='fake-router-dp',
            provider_datapath='fake-provider-dp', cr_lrp_port=self.cr_lrp0)

        self.assertEqual(False, ret)

        ips_without_mask = [ip.split("/")[0] for ip in ips]
        mock_expose_provider_port.assert_called_once_with(
            ips_without_mask, 'fake-provider-dp', self.bridge, None,
            lladdr=self.mac, proxy_cidrs=ips)
        mock_process_lrp_port.assert_not_called()
        mock_expose_ovn_lb.assert_not_called()

    @mock.patch.object(linux_net, 'get_ip_version')
    def test__withdraw_cr_lrp_port(self, mock_ip_version):
        mock_withdraw_provider_port = mock.patch.object(
            self.bgp_driver, '_withdraw_provider_port').start()
        mock_withdraw_lrp_port = mock.patch.object(
            self.bgp_driver, '_withdraw_lrp_port').start()
        mock_withdraw_ovn_lb_on_provider = mock.patch.object(
            self.bgp_driver, '_withdraw_ovn_lb_on_provider').start()

        ips = [self.ipv4, self.ipv6]
        mock_ip_version.side_effect = [constants.IP_VERSION_4,
                                       constants.IP_VERSION_6]
        ovn_lb_vip_port = mock.Mock()
        gateway = {
            'ips': ips,
            'provider_datapath': 'fake-provider-dp',
            'subnets_cidr': ['192.168.1.1/24'],
            'bridge_device': self.bridge,
            'bridge_vlan': 10,
            'mac': self.mac,
            'provider_ovn_lbs': [ovn_lb_vip_port]}
        self.bgp_driver.ovn_local_cr_lrps = {'gateway_port': gateway}

        self.bgp_driver._withdraw_cr_lrp_port(
            ips, self.mac, self.bridge, 10,
            provider_datapath='fake-provider-dp', cr_lrp_port='gateway_port')

        ips_without_mask = [ip.split("/")[0] for ip in ips]
        mock_withdraw_provider_port.assert_called_once_with(
            ips_without_mask, 'fake-provider-dp', bridge_device=self.bridge,
            bridge_vlan=10, lladdr=self.mac, proxy_cidrs=[self.ipv6])
        mock_withdraw_lrp_port.assert_called_once_with('192.168.1.1/24', None,
                                                       'gateway_port')
        mock_withdraw_ovn_lb_on_provider.assert_called_once_with(
            ovn_lb_vip_port, 'gateway_port')

    @mock.patch.object(linux_net, 'get_ip_version')
    def test__withdraw_cr_lrp_port_withdraw_failure(self, mock_ip_version):
        mock_withdraw_provider_port = mock.patch.object(
            self.bgp_driver, '_withdraw_provider_port').start()
        mock_withdraw_provider_port.return_value = False
        mock_withdraw_lrp_port = mock.patch.object(
            self.bgp_driver, '_withdraw_lrp_port').start()
        mock_withdraw_ovn_lb_on_provider = mock.patch.object(
            self.bgp_driver, '_withdraw_ovn_lb_on_provider').start()

        ips = [self.ipv4, self.ipv6]
        mock_ip_version.side_effect = [constants.IP_VERSION_4,
                                       constants.IP_VERSION_6]
        ovn_lb_vip_port = mock.Mock()
        gateway = {
            'ips': ips,
            'provider_datapath': 'fake-provider-dp',
            'subnets_cidr': ['192.168.1.1/24'],
            'bridge_device': self.bridge,
            'bridge_vlan': 10,
            'mac': self.mac,
            'provider_ovn_lbs': [ovn_lb_vip_port]}
        self.bgp_driver.ovn_local_cr_lrps = {'gateway_port': gateway}

        ret = self.bgp_driver._withdraw_cr_lrp_port(
            ips, self.mac, self.bridge, 10,
            provider_datapath='fake-provider-dp', cr_lrp_port='gateway_port')

        self.assertEqual(False, ret)
        ips_without_mask = [ip.split("/")[0] for ip in ips]
        mock_withdraw_provider_port.assert_called_once_with(
            ips_without_mask, 'fake-provider-dp', bridge_device=self.bridge,
            bridge_vlan=10, lladdr=self.mac, proxy_cidrs=[self.ipv6])
        mock_withdraw_lrp_port.assert_not_called()
        mock_withdraw_ovn_lb_on_provider.assert_not_called()

    @mock.patch.object(linux_net, 'add_ip_route')
    @mock.patch.object(linux_net, 'add_ip_rule')
    @mock.patch.object(linux_net, 'get_ip_version')
    def test__expose_lrp_port(
            self, mock_ip_version, mock_add_rule, mock_add_route):
        mock_ip_version.return_value = constants.IP_VERSION_4
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

        self.bgp_driver._expose_lrp_port(
            '{}/32'.format(self.ipv4), self.lrp0, self.cr_lrp0, 'fake-lrp-dp')

        mock_add_rule.assert_called_once_with(
            '{}/32'.format(self.ipv4), 'fake-table')
        mock_add_route.assert_called_once_with(
            mock.ANY, self.ipv4, 'fake-table', self.bridge, vlan=None,
            mask='32', via=self.fip)
        expected_calls = [
            mock.call(dp_port0, ip_version=constants.IP_VERSION_4,
                      exposed_ips=None, ovn_ip_rules=None),
            mock.call(dp_port1, ip_version=constants.IP_VERSION_4,
                      exposed_ips=None, ovn_ip_rules=None),
            mock.call(dp_port2, ip_version=constants.IP_VERSION_4,
                      exposed_ips=None, ovn_ip_rules=None)]
        mock_expose_tenant_port.assert_has_calls(expected_calls)

    @mock.patch.object(linux_net, 'add_ip_route')
    @mock.patch.object(linux_net, 'add_ip_rule')
    @mock.patch.object(linux_net, 'get_ip_version')
    def test__expose_lrp_port_invalid_ip(
            self, mock_ip_version, mock_add_rule, mock_add_route):
        mock_ip_version.return_value = constants.IP_VERSION_4
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

        mock_add_rule.side_effect = agent_exc.InvalidPortIP(ip=self.ipv4)

        self.bgp_driver._expose_lrp_port(
            '{}/32'.format(self.ipv4), self.lrp0, self.cr_lrp0, 'fake-lrp-dp')

        mock_add_rule.assert_called_once_with(
            '{}/32'.format(self.ipv4), 'fake-table')
        mock_add_route.assert_not_called()
        mock_expose_tenant_port.assert_not_called()

    @mock.patch.object(linux_net, 'add_ip_route')
    @mock.patch.object(linux_net, 'add_ip_rule')
    @mock.patch.object(linux_net, 'get_ip_version')
    @mock.patch.object(driver_utils, 'is_ipv6_gua')
    def test__expose_lrp_port_gua(
            self, mock_ipv6_gua, mock_ip_version, mock_add_rule,
            mock_add_route):
        CONF.set_override('expose_tenant_networks', False)
        self.addCleanup(CONF.clear_override, 'expose_tenant_networks')
        CONF.set_override('expose_ipv6_gua_tenant_networks', True)
        self.addCleanup(CONF.clear_override, 'expose_ipv6_gua_tenant_networks')
        mock_ipv6_gua.return_value = True
        mock_ip_version.return_value = constants.IP_VERSION_6
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

        self.bgp_driver._expose_lrp_port(
            '{}/128'.format(self.ipv6), self.lrp0, self.cr_lrp0, 'fake-lrp-dp')

        mock_add_rule.assert_called_once_with(
            '{}/128'.format(self.ipv6), 'fake-table')
        mock_add_route.assert_called_once_with(
            mock.ANY, self.ipv6, 'fake-table', self.bridge, vlan=None,
            mask='128', via=self.fip)
        expected_calls = [
            mock.call(dp_port0, ip_version=constants.IP_VERSION_6,
                      exposed_ips=None, ovn_ip_rules=None),
            mock.call(dp_port1, ip_version=constants.IP_VERSION_6,
                      exposed_ips=None, ovn_ip_rules=None),
            mock.call(dp_port2, ip_version=constants.IP_VERSION_6,
                      exposed_ips=None, ovn_ip_rules=None)]
        mock_expose_tenant_port.assert_has_calls(expected_calls)

    @mock.patch.object(linux_net, 'add_ip_route')
    @mock.patch.object(linux_net, 'add_ip_rule')
    @mock.patch.object(driver_utils, 'is_ipv6_gua')
    def test__expose_lrp_port_no_gua(
            self, mock_ipv6_gua, mock_add_rule, mock_add_route):
        CONF.set_override('expose_tenant_networks', False)
        self.addCleanup(CONF.clear_override, 'expose_tenant_networks')
        CONF.set_override('expose_ipv6_gua_tenant_networks', True)
        self.addCleanup(CONF.clear_override, 'expose_ipv6_gua_tenant_networks')
        mock_ipv6_gua.return_value = False
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

        self.bgp_driver._expose_lrp_port(
            'fdab:4ad8:e8fb:0:f816:3eff:fec6:469c/128', self.lrp0,
            self.cr_lrp0, 'fake-lrp-dp')

        mock_add_rule.assert_not_called()
        mock_add_route.assert_not_called()
        mock_expose_tenant_port.assert_not_called()

    def test_expose_subnet(self):
        self.sb_idl.is_router_gateway_on_chassis.return_value = self.cr_lrp0
        self.sb_idl.get_port_datapath.return_value = 'fake-port-dp'
        row = fakes.create_object({
            'name': 'fake-row',
            'logical_port': 'subnet_port',
            'datapath': 'fake-dp',
            'options': {'peer': 'fake-peer'}})

        mock_expose_lrp_port = mock.patch.object(
            self.bgp_driver, '_expose_lrp_port').start()

        self.bgp_driver.expose_subnet('fake-ip', row)

        mock_expose_lrp_port.assert_called_once_with(
            'fake-ip', row.logical_port, self.cr_lrp0, 'fake-port-dp')

    def test_expose_subnet_no_cr_lrp(self):
        self.sb_idl.is_router_gateway_on_chassis.return_value = None
        self.sb_idl.get_port_datapath.return_value = 'fake-port-dp'
        row = fakes.create_object({
            'name': 'fake-row',
            'logical_port': 'subnet_port',
            'datapath': 'fake-dp',
            'options': {'peer': 'fake-peer'}})

        mock_expose_lrp_port = mock.patch.object(
            self.bgp_driver, '_expose_lrp_port').start()

        self.bgp_driver.expose_subnet('fake-ip', row)

        mock_expose_lrp_port.assert_not_called()

    def test_expose_subnet_address_scope(self):
        self.sb_idl.is_router_gateway_on_chassis.return_value = self.cr_lrp0
        self.sb_idl.get_port_datapath.return_value = 'fake-port-dp'
        row = fakes.create_object({
            'name': 'fake-row',
            'logical_port': 'subnet_port',
            'datapath': 'fake-dp',
            'options': {'peer': 'fake-peer'}})

        mock_expose_lrp_port = mock.patch.object(
            self.bgp_driver, '_expose_lrp_port').start()

        mock_address_scope_allowed = mock.patch.object(
            self.bgp_driver, '_address_scope_allowed').start()
        mock_address_scope_allowed.return_value = False

        self.bgp_driver.expose_subnet('fake-ip', row)

        mock_expose_lrp_port.assert_not_called()

    def test_withdraw_subnet(self):
        row = fakes.create_object({
            'name': 'fake-row',
            'logical_port': 'subnet_port',
            'datapath': 'fake-dp'})
        self.sb_idl.is_router_gateway_on_chassis.return_value = self.cr_lrp0
        mock_withdraw_lrp_port = mock.patch.object(
            self.bgp_driver, '_withdraw_lrp_port').start()

        self.bgp_driver.withdraw_subnet('{}/32'.format(self.ipv4), row)

        mock_withdraw_lrp_port.assert_called_once_with(
            '{}/32'.format(self.ipv4), row.logical_port, self.cr_lrp0)

    def test_withdraw_subnet_no_cr_lrp(self):
        row = fakes.create_object({
            'name': 'fake-row',
            'logical_port': 'subnet_port',
            'datapath': 'fake-dp'})
        self.sb_idl.is_router_gateway_on_chassis.return_value = None
        mock_withdraw_lrp_port = mock.patch.object(
            self.bgp_driver, '_withdraw_lrp_port').start()

        self.bgp_driver.withdraw_subnet('{}/32'.format(self.ipv4), row)

        mock_withdraw_lrp_port.assert_not_called()

    def test_withdraw_subnet_no_datapath_error(self):
        row = fakes.create_object({
            'name': 'fake-row',
            'logical_port': 'fake-logical-port',  # to match the cr-lrp name
            'datapath': 'fake-dp'})
        self.sb_idl.is_router_gateway_on_chassis.side_effect = (
            agent_exc.DatapathNotFound(datapath="fake-dp"))
        mock_withdraw_lrp_port = mock.patch.object(
            self.bgp_driver, '_withdraw_lrp_port').start()

        self.bgp_driver.withdraw_subnet('{}/32'.format(self.ipv4), row)

        mock_withdraw_lrp_port.assert_not_called()

    @mock.patch.object(linux_net, 'get_exposed_ips_on_network')
    @mock.patch.object(linux_net, 'delete_exposed_ips')
    @mock.patch.object(linux_net, 'del_ip_route')
    @mock.patch.object(linux_net, 'del_ip_rule')
    @mock.patch.object(linux_net, 'get_ip_version')
    def test__withdraw_lrp_port(
            self, mock_ip_version, mock_del_rule, mock_del_route,
            mock_del_exposed_ips, mock_get_exposed_ips):
        mock_ip_version.return_value = constants.IP_VERSION_4
        mock_get_exposed_ips.return_value = [self.ipv4]
        self.bgp_driver.ovn_local_lrps = {self.lrp0: self.cr_lrp0}

        self.bgp_driver._withdraw_lrp_port(
            '{}/32'.format(self.ipv4), self.lrp0, self.cr_lrp0)

        mock_del_rule.assert_called_once_with(
            '{}/32'.format(self.ipv4), 'fake-table')
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
    def test__withdraw_lrp_port_gua(
            self, mock_ipv6_gua, mock_ip_version, mock_del_rule,
            mock_del_route, mock_del_exposed_ips, mock_get_exposed_ips):
        CONF.set_override('expose_tenant_networks', False)
        self.addCleanup(CONF.clear_override, 'expose_tenant_networks')
        CONF.set_override('expose_ipv6_gua_tenant_networks', True)
        self.addCleanup(CONF.clear_override, 'expose_ipv6_gua_tenant_networks')
        mock_ipv6_gua.return_value = True
        mock_ip_version.return_value = constants.IP_VERSION_6
        mock_get_exposed_ips.return_value = [self.ipv6]
        self.bgp_driver.ovn_local_lrps = {self.lrp0: self.cr_lrp0}

        self.bgp_driver._withdraw_lrp_port(
            '{}/128'.format(self.ipv6), self.lrp0, self.cr_lrp0)

        mock_del_rule.assert_called_once_with(
            '{}/128'.format(self.ipv6), 'fake-table')
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
    def test__withdraw_lrp_port_no_gua(
            self, mock_ipv6_gua, mock_del_rule, mock_del_route,
            mock_del_exposed_ips, mock_get_exposed_ips):
        CONF.set_override('expose_tenant_networks', False)
        self.addCleanup(CONF.clear_override, 'expose_tenant_networks')
        CONF.set_override('expose_ipv6_gua_tenant_networks', True)
        self.addCleanup(CONF.clear_override, 'expose_ipv6_gua_tenant_networks')
        mock_ipv6_gua.return_value = False
        mock_get_exposed_ips.return_value = [self.ipv6]
        self.bgp_driver.ovn_local_lrps = {self.lrp0: self.cr_lrp0}

        self.bgp_driver._withdraw_lrp_port(
            'fdab:4ad8:e8fb:0:f816:3eff:fec6:469c/128', self.lrp0,
            self.cr_lrp0)

        mock_del_rule.assert_not_called()
        mock_del_route.assert_not_called()
        mock_del_exposed_ips.assert_not_called()

    @mock.patch.object(driver_utils, 'get_addr_scopes')
    def test__address_scope_allowed(self, m_addr_scopes):
        self.bgp_driver.allowed_address_scopes = {"fake_address_scope"}
        port_ip = self.ipv4
        port_name = "fake-port"
        sb_port = "fake-sb-port"
        self.sb_idl.get_port_by_name.return_value = sb_port
        address_scopes = {
            constants.IP_VERSION_4: "fake_address_scope",
            constants.IP_VERSION_6: "fake_ipv6_address_scope"}
        m_addr_scopes.return_value = address_scopes

        ret = self.bgp_driver._address_scope_allowed(port_ip, port_name)

        self.assertEqual(True, ret)
        m_addr_scopes.assert_called_once_with(sb_port)

    def test__address_scope_allowed_not_configured(self):
        self.bgp_driver.allowed_address_scopes = set()
        port_ip = self.ipv4
        port_name = "fake-port"
        sb_port = "fake-sb-port"

        ret = self.bgp_driver._address_scope_allowed(
            port_ip, port_name, sb_port)

        self.assertEqual(True, ret)

    @mock.patch.object(driver_utils, 'get_addr_scopes')
    def test__address_scope_allowed_no_match(self, m_addr_scopes):
        self.bgp_driver.allowed_address_scopes = {"fake_address_scope"}
        port_ip = self.ipv4
        port_name = "fake-port"
        sb_port = "fake-sb-port"
        self.sb_idl.get_port_by_name.return_value = sb_port
        address_scopes = {
            constants.IP_VERSION_4: "different_fake_address_scope",
            constants.IP_VERSION_6: "fake_ipv6_address_scope"}
        m_addr_scopes.return_value = address_scopes

        ret = self.bgp_driver._address_scope_allowed(port_ip, port_name)

        self.assertEqual(False, ret)
        m_addr_scopes.assert_called_once_with(sb_port)

    @mock.patch.object(driver_utils, 'get_addr_scopes')
    def test__address_scope_allowed_no_port(self, m_addr_scopes):
        self.bgp_driver.allowed_address_scopes = {"fake_address_scope"}
        port_ip = self.ipv4
        port_name = "fake-port"
        self.sb_idl.get_port_by_name.return_value = []

        ret = self.bgp_driver._address_scope_allowed(port_ip, port_name)

        self.assertEqual(False, ret)
        m_addr_scopes.assert_not_called()

    @mock.patch.object(driver_utils, 'get_addr_scopes')
    def test__address_scope_allowed_no_address_scope(self, m_addr_scopes):
        self.bgp_driver.allowed_address_scopes = {"fake_address_scope"}
        port_ip = self.ipv4
        port_name = "fake-port"
        sb_port = "fake-sb-port"
        self.sb_idl.get_port_by_name.return_value = sb_port
        address_scopes = {
            constants.IP_VERSION_4: "",
            constants.IP_VERSION_6: ""}
        m_addr_scopes.return_value = address_scopes

        ret = self.bgp_driver._address_scope_allowed(port_ip, port_name)

        self.assertEqual(False, ret)
        m_addr_scopes.assert_called_once_with(sb_port)

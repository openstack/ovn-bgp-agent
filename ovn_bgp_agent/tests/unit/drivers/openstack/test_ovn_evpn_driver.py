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
from ovn_bgp_agent.drivers.openstack import ovn_evpn_driver
from ovn_bgp_agent.drivers.openstack.utils import frr
from ovn_bgp_agent.drivers.openstack.utils import ovn
from ovn_bgp_agent.drivers.openstack.utils import ovs
from ovn_bgp_agent.tests import base as test_base
from ovn_bgp_agent.tests.unit import fakes
from ovn_bgp_agent.utils import linux_net

CONF = cfg.CONF


class TestOVNEVPNDriver(test_base.TestCase):

    def setUp(self):
        super(TestOVNEVPNDriver, self).setUp()
        self.evpn_driver = ovn_evpn_driver.OVNEVPNDriver()
        self.mock_sbdb = mock.patch.object(ovn, 'OvnSbIdl').start()
        self.mock_ovs_idl = mock.patch.object(ovs, 'OvsIdl').start()
        self.evpn_driver.ovs_idl = self.mock_ovs_idl
        self.evpn_driver.sb_idl = mock.Mock()
        self.sb_idl = self.evpn_driver.sb_idl
        self.evpn_driver.chassis = 'fake-chassis'
        self.ipv4 = '192.168.1.17'
        self.ipv6 = '2002::1234:abcd:ffff:c0a8:101'
        self.fip = '172.24.4.33'
        self.mac = 'aa:bb:cc:dd:ee:ff'
        self.mac1 = 'aa:bb:cc:dd:ee:ee'
        self.bridge = 'fake-bridge'
        self.vni = 77
        self.vni1 = 88
        self.vlan_tag = 10
        self.evpn_driver.ovn_bridge_mappings = {'fake-network': self.bridge}
        self.evpn_info = {'bgp_as': 'fake-bgp-as', 'vni': self.vni}
        self.evpn_device = fakes.create_object({
            'lo_name': 'fake-lo-name',
            'bridge_name': self.bridge,
            'vxlan_name': 'fake-vxlan-name',
            'vrf_name': 'fake-vrf-name',
            'veth_vrf': 'fake-veth-vrf',
            'veth_ovs': 'fake-veth-ovs',
            'vlan_name': 'fake-vlan-name'})
        self.cr_lrp = 'cr-fake-logical-port'
        self.cr_lrp1 = 'cr-fake-logical-port1'
        self.evpn_driver.ovn_local_cr_lrps = {
            self.cr_lrp: {
                'provider_datapath': 'fake-provider-dp',
                'ips': [self.fip],
                'vni': self.vni,
                'bgp_as': 'fake-bgp-as',
                'bridge': self.bridge,
                'vlan': 'fake-vlan',
                'vxlan': 'fake-vxlan',
                'vrf': 'fake-vrf',
                'veth_vrf': 'fake-veth-vrf',
                'veth_ovs': 'fake-veth-ovs',
                'lo': 'fake-lo',
                'mac': self.mac},
            self.cr_lrp1: {
                'provider_datapath': 'fake-provider-dp1',
                'ips': [self.fip],
                'vni': self.vni1,
                'bgp_as': 'fake-bgp-as1',
                'bridge': self.bridge,
                'vlan': 'fake-vlan1',
                'vxlan': 'fake-vxlan1',
                'vrf': 'fake-vrf1',
                'veth_vrf': 'fake-veth-vrf1',
                'veth_ovs': 'fake-veth-ovs1',
                'lo': 'fake-lo1',
                'mac': self.mac1},
        }
        self.evpn_driver._ovn_routing_tables_routes = {
            'fake-vlan': [{
                'route': {
                    'oif': 'fake-oif',
                    'gateway': 'fake-gateway',
                    'dst': '{}/32'.format(self.ipv4),
                    'dst_len': 32,
                    'table': 'fake-table'},
                'vlan': 88,
                }]
            }

    def test_start(self):
        self.evpn_driver.start()
        # Assert connections were started
        self.mock_ovs_idl().start.assert_called_once_with(
            CONF.ovsdb_connection)
        self.mock_sbdb().start.assert_called_once_with()

    @mock.patch.object(linux_net, 'ensure_arp_ndp_enabled_for_bridge')
    def test_sync(self, mock_ensure_ndp):
        self.mock_ovs_idl.get_ovn_bridge_mappings.return_value = [
            'net0:bridge0', 'net1:bridge1']
        port0 = fakes.create_object({
            'name': 'fake-port0',
            'type': constants.OVN_CHASSISREDIRECT_VIF_PORT_TYPE})
        port1 = fakes.create_object({
            'name': 'fake-port1',
            'type': constants.OVN_VIRTUAL_VIF_PORT_TYPE})
        self.sb_idl.get_ports_on_chassis.return_value = [
            port0, port1]

        mock_expose_ip = mock.patch.object(
            self.evpn_driver, '_expose_ip').start()
        mock_remove_extra_exposed_ips = mock.patch.object(
            self.evpn_driver, '_remove_extra_exposed_ips').start()
        mock_remove_extra_routes = mock.patch.object(
            self.evpn_driver, '_remove_extra_routes').start()
        mock_remove_extra_ovs_flows = mock.patch.object(
            self.evpn_driver, '_remove_extra_ovs_flows').start()
        mock_remove_extra_vrfs = mock.patch.object(
            self.evpn_driver, '_remove_extra_vrfs').start()

        self.evpn_driver.sync()

        expected_calls = [mock.call('bridge0', 1), mock.call('bridge1', 2)]
        mock_ensure_ndp.assert_has_calls(expected_calls)
        mock_expose_ip.assert_called_once_with(port0, cr_lrp=True)
        mock_remove_extra_exposed_ips.assert_called_once_with()
        mock_remove_extra_routes.assert_called_once_with()
        mock_remove_extra_ovs_flows.assert_called_once_with()
        mock_remove_extra_vrfs.assert_called_once_with()

    def test__ensure_network_exposed(self):
        self.sb_idl.get_evpn_info_from_port_name.return_value = 'fake-info'
        self.sb_idl.get_port_datapath.return_value = 'fake-dp'
        mock_expose_subnet = mock.patch.object(
            self.evpn_driver, '_expose_subnet').start()
        mock_get_bridge = mock.patch.object(
            self.evpn_driver, '_get_bridge_for_datapath').start()
        mock_get_bridge.return_value = (self.bridge, self.vlan_tag)
        gateway = {}
        gateway['ips'] = ['10.10.10.1/32']
        gateway['provider_datapath'] = 'fake-prov-dp'
        lrp = fakes.create_object({
            'name': 'fake-lrp',
            'logical_port': self.cr_lrp,
            'mac': ['{} {} {}'.format(self.mac, self.ipv4, self.ipv6)],
            'options': {'peer': 'fake-peer'},
            'datapath': 'fake-dp'})

        self.evpn_driver._ensure_network_exposed(lrp, gateway)

        mock_expose_subnet.assert_called_once_with(
            self.ipv4, ['10.10.10.1'],
            {'ips': ['10.10.10.1/32'], 'provider_datapath': 'fake-prov-dp'},
            self.bridge, self.vlan_tag, 'fake-dp')

    def test__get_bridge_for_datapath(self):
        self.sb_idl.get_network_name_and_tag.return_value = (
            'fake-network', [self.vlan_tag])
        ret = self.evpn_driver._get_bridge_for_datapath('fake-dp')
        self.assertEqual((self.bridge, self.vlan_tag), ret)

    def test__get_bridge_for_datapath_no_tag(self):
        self.sb_idl.get_network_name_and_tag.return_value = (
            'fake-network', None)
        ret = self.evpn_driver._get_bridge_for_datapath('fake-dp')
        self.assertEqual((self.bridge, None), ret)

    def test__get_bridge_for_datapath_no_network_name(self):
        self.sb_idl.get_network_name_and_tag.return_value = (None, None)
        ret = self.evpn_driver._get_bridge_for_datapath('fake-dp')
        self.assertEqual((None, None), ret)

    @mock.patch.object(linux_net, 'add_ip_nei')
    @mock.patch.object(frr, 'vrf_reconfigure')
    def _test_expose_ip(
            self, mock_vrf_reconfigure, mock_add_ip_nei, cr_lrp=False):
        mock_get_bridge = mock.patch.object(
            self.evpn_driver, '_get_bridge_for_datapath').start()
        mock_get_bridge.return_value = (self.bridge, self.vlan_tag)
        mock_ensure_evpn = mock.patch.object(
            self.evpn_driver, '_ensure_evpn_devices').start()
        mock_ensure_evpn.return_value = self.evpn_device
        mock_connect_evpn = mock.patch.object(
            self.evpn_driver, '_connect_evpn_to_ovn').start()
        mock_ensure_net_exposed = mock.patch.object(
            self.evpn_driver, '_ensure_network_exposed').start()
        row = fakes.create_object({
            'name': 'fake-row',
            'logical_port': self.cr_lrp,
            'mac': ['{} {} {}'.format(self.mac, self.ipv4, self.ipv6)],
            'datapath': 'fake-dp'})
        self.sb_idl.get_fip_associated.return_value = (
            self.fip, 'fake-dp')
        lrp0 = fakes.create_object({'chassis': 'fake-chassis', 'options': {}})
        lrp1 = fakes.create_object({'chassis': '', 'options': {}})
        self.sb_idl.get_lrp_ports_for_router.return_value = [lrp0, lrp1]

        if not cr_lrp:
            self.sb_idl.get_port_if_local_chassis.return_value = row
            self.sb_idl.get_evpn_info.return_value = self.evpn_info
        else:
            self.sb_idl.get_evpn_info_from_port_name.return_value = (
                self.evpn_info)

        self.evpn_driver.expose_ip(row, cr_lrp=cr_lrp)

        # Assertions
        mock_connect_evpn.assert_called_once_with(
            'fake-vrf-name', 'fake-veth-vrf', 'fake-veth-ovs',
            [self.ipv4, self.ipv6], self.bridge, self.vni,
            'fake-vlan-name', self.vlan_tag)
        mock_ensure_evpn.assert_called_once_with(
            self.bridge, self.vni, self.vlan_tag)
        mock_ensure_net_exposed.assert_called_once_with(
            lrp1,
            {'router_datapath': 'fake-dp', 'provider_datapath': 'fake-dp',
             'ips': [self.ipv4, self.ipv6], 'mac': self.mac, 'vni': self.vni,
             'bgp_as': 'fake-bgp-as', 'lo': 'fake-lo-name',
             'bridge': self.bridge, 'vxlan': 'fake-vxlan-name',
             'vrf': 'fake-vrf-name', 'veth_vrf': 'fake-veth-vrf',
             'veth_ovs': 'fake-veth-ovs', 'vlan': 'fake-vlan-name'})
        mock_vrf_reconfigure.assert_called_once_with(
            self.evpn_info, action='add-vrf')
        expected_calls = [mock.call(self.ipv4, self.mac, 'fake-vlan-name'),
                          mock.call(self.ipv6, self.mac, 'fake-vlan-name')]
        mock_add_ip_nei.assert_has_calls(expected_calls)

    def test_expose_ip(self):
        self._test_expose_ip(cr_lrp=False)

    def test_expose_ip_cr_lrp(self):
        self._test_expose_ip(cr_lrp=True)

    @mock.patch.object(ovs, 'remove_evpn_router_ovs_flows')
    @mock.patch.object(frr, 'vrf_reconfigure')
    def _test_withdraw_ip(
            self, mock_vrf_reconfigure, mock_remove_evpn_flows, cr_lrp=True,
            ret_vlan_tag=True):
        mock_remove_evpn = mock.patch.object(
            self.evpn_driver, '_remove_evpn_devices').start()
        mock_disconnect_epvn = mock.patch.object(
            self.evpn_driver, '_disconnect_evpn_from_ovn').start()
        mock_get_bridge = mock.patch.object(
            self.evpn_driver, '_get_bridge_for_datapath').start()
        vlan_tag = self.vlan_tag if ret_vlan_tag else None
        mock_get_bridge.return_value = (self.bridge, vlan_tag)
        row = fakes.create_object({
            'name': 'fake-row',
            'logical_port': self.cr_lrp})

        self.evpn_driver.withdraw_ip(row, cr_lrp=cr_lrp)

        mock_remove_evpn_flows.assert_called_once_with(
            self.bridge, constants.OVS_VRF_RULE_COOKIE, self.mac)
        mock_vrf_reconfigure.assert_called_once_with(
            {'vni': self.vni, 'bgp_as': 'fake-bgp-as'}, action='del-vrf')

        kwargs = {}
        if ret_vlan_tag:
            kwargs.update({'vlan_tag': vlan_tag})
        mock_disconnect_epvn.assert_called_once_with(
            self.vni, self.bridge, [self.fip], **kwargs)

        mock_remove_evpn.assert_called_once_with(self.vni)

    def test_withdraw_ip(self):
        self._test_withdraw_ip()

    def test_withdraw_ip_no_vlan_tag(self):
        self._test_withdraw_ip(ret_vlan_tag=False)

    @mock.patch.object(linux_net, 'add_ips_to_dev')
    def test_expose_remote_ip(self, mock_add_ip_dev):
        self.sb_idl.is_provider_network.return_value = False
        self.sb_idl.get_evpn_info_from_port_name.return_value = self.evpn_info
        lrp = 'fake-lrp'
        self.sb_idl.get_lrps_for_datapath.return_value = [lrp]
        self.evpn_driver.ovn_local_lrps = {lrp: 'fake-lrp'}
        row = fakes.create_object({
            'name': 'fake-row', 'datapath': 'fake-dp'})

        ips = [self.ipv4, self.ipv6]
        self.evpn_driver.expose_remote_ip(ips, row)

        lo_name = constants.OVN_EVPN_LO_PREFIX + str(self.vni)
        mock_add_ip_dev.assert_called_once_with(
            lo_name, ips, clear_local_route_at_table=self.vni)

    @mock.patch.object(linux_net, 'add_ips_to_dev')
    def test_expose_remote_ip_is_provider_network(self, mock_add_ip_dev):
        self.sb_idl.is_provider_network.return_value = True
        row = fakes.create_object({
            'name': 'fake-row', 'datapath': 'fake-dp'})

        ips = [self.ipv4, self.ipv6]
        self.evpn_driver.expose_remote_ip(ips, row)

        mock_add_ip_dev.assert_not_called()

    @mock.patch.object(linux_net, 'add_ips_to_dev')
    def test_expose_remote_ip_not_local(self, mock_add_ip_dev):
        self.sb_idl.is_provider_network.return_value = False
        lrp = 'fake-lrp'
        self.sb_idl.get_lrps_for_datapath.return_value = [lrp]
        self.evpn_driver.ovn_local_lrps = {}
        row = fakes.create_object({
            'name': 'fake-row', 'datapath': 'fake-dp'})

        ips = [self.ipv4, self.ipv6]
        self.evpn_driver.expose_remote_ip(ips, row)

        mock_add_ip_dev.assert_not_called()

    @mock.patch.object(linux_net, 'del_ips_from_dev')
    def test_withdraw_remote_ip(self, mock_del_ip_dev):
        self.sb_idl.is_provider_network.return_value = False
        self.sb_idl.get_evpn_info_from_port_name.return_value = self.evpn_info
        lrp = 'fake-lrp'
        self.sb_idl.get_lrps_for_datapath.return_value = [lrp]
        self.evpn_driver.ovn_local_lrps = {lrp: 'fake-lrp'}
        row = fakes.create_object({
            'name': 'fake-row', 'datapath': 'fake-dp'})

        ips = [self.ipv4, self.ipv6]
        self.evpn_driver.withdraw_remote_ip(ips, row)

        lo_name = constants.OVN_EVPN_LO_PREFIX + str(self.vni)
        mock_del_ip_dev.assert_called_once_with(lo_name, ips)

    @mock.patch.object(linux_net, 'del_ips_from_dev')
    def test_withdraw_remote_ip_is_provider_network(self, mock_del_ip_dev):
        self.sb_idl.is_provider_network.return_value = True
        row = fakes.create_object({
            'name': 'fake-row', 'datapath': 'fake-dp'})

        ips = [self.ipv4, self.ipv6]
        self.evpn_driver.withdraw_remote_ip(ips, row)

        mock_del_ip_dev.assert_not_called()

    @mock.patch.object(linux_net, 'del_ips_from_dev')
    def test_withdraw_remote_ip_not_local(self, mock_del_ip_dev):
        self.sb_idl.is_provider_network.return_value = False
        lrp = 'fake-lrp'
        self.sb_idl.get_lrps_for_datapath.return_value = [lrp]
        self.evpn_driver.ovn_local_lrps = {}
        row = fakes.create_object({
            'name': 'fake-row', 'datapath': 'fake-dp'})

        ips = [self.ipv4, self.ipv6]
        self.evpn_driver.withdraw_remote_ip(ips, row)

        mock_del_ip_dev.assert_not_called()

    def test_expose_subnet(self):
        self.sb_idl.get_evpn_info.return_value = self.evpn_info
        self.sb_idl.get_ip_from_port_peer.return_value = self.ipv4
        self.sb_idl.get_port_datapath.return_value = 'fake-dp'
        self.sb_idl.is_router_gateway_on_chassis.return_value = self.cr_lrp
        mock_get_bridge = mock.patch.object(
            self.evpn_driver, '_get_bridge_for_datapath').start()
        mock_get_bridge.return_value = (self.bridge, self.vlan_tag)
        mock_expose_subnet = mock.patch.object(
            self.evpn_driver, '_expose_subnet').start()

        row = fakes.create_object({
            'name': 'fake-row',
            'datapath': 'fake-dp',
            'logical_port': self.cr_lrp})

        self.evpn_driver.expose_subnet(row)

        mock_expose_subnet.assert_called_once_with(
            self.ipv4, [self.fip],
            self.evpn_driver.ovn_local_cr_lrps[self.cr_lrp],
            self.bridge, self.vlan_tag, 'fake-dp')

    @mock.patch.object(linux_net, 'add_ips_to_dev')
    @mock.patch.object(ovs, 'ensure_evpn_ovs_flow')
    @mock.patch.object(linux_net, 'add_ip_route')
    @mock.patch.object(linux_net, 'get_ip_version')
    def _test__expose_subnet(
            self, mock_ip_version, mock_add_route, mock_ensure_evpn_flow,
            mock_add_ip_dev, use_ipv6=False):
        # IPv4 vs IPv6 mocks
        ip = self.ipv6 if use_ipv6 else self.ipv4
        mock_ip_version.return_value = (
            constants.IP_VERSION_6 if use_ipv6 else constants.IP_VERSION_4)
        cidr = '128' if use_ipv6 else '32'

        port0 = fakes.create_object({
            'name': 'fake-port0',
            'type': constants.OVN_VM_VIF_PORT_TYPE,
            'logical_port': self.cr_lrp,
            'chassis': 'fake-chassis',
            'mac': ['{} {}'.format(self.mac, ip)],
            'datapath': 'fake-dp'})
        port1 = fakes.create_object({
            'name': 'fake-port1',
            'chassis': 'fake-chassis',
            'type': 'unknown-type'})
        self.sb_idl.get_ports_on_datapath.return_value = [port0, port1]

        self.evpn_driver._expose_subnet(
            '{}/{}'.format(ip, cidr), [self.fip],
            self.evpn_driver.ovn_local_cr_lrps[self.cr_lrp], self.bridge,
            10, 'fake-dp')

        mock_add_route.assert_called_once_with(
            mock.ANY, ip, self.vni, 'fake-vlan',
            mask=cidr, via=self.fip)
        mock_ensure_evpn_flow.assert_called_once_with(
            self.bridge, constants.OVS_VRF_RULE_COOKIE, self.mac,
            'fake-vlan', 'fake-vlan', '{}/{}'.format(ip, cidr),
            strip_vlan=True)
        mock_add_ip_dev.assert_called_once_with(
            'fake-lo', [ip], clear_local_route_at_table=self.vni)

    def test__expose_subnet(self):
        self._test__expose_subnet()

    def test__expose_subnet_ipv6(self):
        self._test__expose_subnet(use_ipv6=True)

    @mock.patch.object(linux_net, 'delete_exposed_ips')
    @mock.patch.object(linux_net, 'get_exposed_ips_on_network')
    @mock.patch.object(ovs, 'remove_evpn_network_ovs_flow')
    @mock.patch.object(linux_net, 'del_ip_route')
    @mock.patch.object(linux_net, 'get_ip_version')
    def _test_withdraw_subnet(
            self, mock_ip_version, mock_del_route, mock_remove_evpn_flows,
            mock_get_ips, mock_del_ips, use_ipv6=False):
        # IPv4 vs IPv6 mocks
        ip = self.ipv6 if use_ipv6 else self.ipv4
        mock_ip_version.return_value = (
            constants.IP_VERSION_6 if use_ipv6 else constants.IP_VERSION_4)
        cidr = '128' if use_ipv6 else '32'

        self.evpn_driver.ovn_local_lrps = {
            'lrp-port': {'datapath': 'fake-dp',
                         'ip': '{}/{}'.format(ip, cidr)}}
        self.sb_idl.is_router_gateway_on_chassis.return_value = self.cr_lrp
        mock_get_bridge = mock.patch.object(
            self.evpn_driver, '_get_bridge_for_datapath').start()
        mock_get_bridge.return_value = (self.bridge, self.vlan_tag)
        net_ips = ['10.10.10.1', '2001:0db8:85a3:0000:0000:8a2e:0370:7334']
        mock_get_ips.return_value = net_ips

        row = fakes.create_object({
            'name': 'fake-row',
            'logical_port': 'port'})
        self.evpn_driver.withdraw_subnet(row)

        mock_del_route.assert_called_once_with(
            mock.ANY, ip, self.vni, 'fake-vlan',
            mask=cidr, via=self.fip)
        mock_remove_evpn_flows.assert_called_once_with(
            self.bridge, constants.OVS_VRF_RULE_COOKIE, self.mac,
            '{}/{}'.format(ip, cidr))
        mock_del_ips.assert_called_once_with(net_ips, 'fake-lo')

    def test_withdraw_subnet(self):
        self._test_withdraw_subnet()

    def test_withdraw_subnet_ipv6(self):
        self._test_withdraw_subnet(use_ipv6=True)

    @mock.patch.object(linux_net, 'ensure_veth')
    @mock.patch.object(linux_net, 'enable_proxy_ndp')
    @mock.patch.object(linux_net, 'set_device_status')
    @mock.patch.object(ovs, 'add_vlan_port_to_ovs_bridge')
    @mock.patch.object(linux_net, 'get_nic_ip')
    @mock.patch.object(linux_net, 'ensure_dummy_device')
    @mock.patch.object(linux_net, 'ensure_vxlan')
    @mock.patch.object(linux_net, 'set_master_for_device')
    @mock.patch.object(linux_net, 'ensure_bridge')
    @mock.patch.object(linux_net, 'ensure_vrf')
    def _test__ensure_evpn_devices(
            self, mock_ensure_vrf, mock_ensure_bridge, mock_set_master,
            mock_ensure_vxlan, mock_ensure_dummy, mock_get_nic_ip,
            mock_add_vlan, mock_set_status, mock_proxy_ndp,
            mock_ensure_veth, use_vlan=True):

        mock_get_nic_ip.return_value = [self.ipv4]

        dp_bridge = 'datapath-bridge'
        vlan_tag = self.vlan_tag if use_vlan else None
        self.evpn_driver._ensure_evpn_devices(dp_bridge, self.vni, vlan_tag)

        # Asserts
        vrf_name = constants.OVN_EVPN_VRF_PREFIX + str(self.vni)
        mock_ensure_vrf.assert_called_once_with(vrf_name, self.vni)

        bridge_name = constants.OVN_EVPN_BRIDGE_PREFIX + str(self.vni)
        mock_ensure_bridge.assert_called_once_with(bridge_name)

        vxlan_name = constants.OVN_EVPN_VXLAN_PREFIX + str(self.vni)
        mock_ensure_vxlan.assert_called_once_with(
            vxlan_name, self.vni, self.ipv4, CONF.evpn_udp_dstport)

        lo_name = constants.OVN_EVPN_LO_PREFIX + str(self.vni)
        mock_ensure_dummy.assert_called_once_with(lo_name)

        set_master_expected_calls = [
            mock.call(bridge_name, vrf_name),
            mock.call(vxlan_name, bridge_name),
            mock.call(lo_name, vrf_name)]

        if use_vlan:
            vlan_name = constants.OVN_EVPN_VLAN_PREFIX + str(self.vni)
            mock_add_vlan.assert_called_once_with(
                dp_bridge, vlan_name, self.vlan_tag)

            mock_set_status.assert_called_once_with(
                vlan_name, constants.LINK_UP)
            mock_proxy_ndp.assert_called_once_with(vlan_name)

            set_master_expected_calls.append(mock.call(vlan_name, vrf_name))
        else:
            veth_vrf = constants.OVN_EVPN_VETH_VRF_PREFIX + str(self.vni)
            veth_ovs = constants.OVN_EVPN_VETH_OVS_PREFIX + str(self.vni)
            mock_ensure_veth.assert_called_once_with(veth_vrf, veth_ovs)

            set_master_expected_calls.append(mock.call(veth_vrf, vrf_name))

        mock_set_master.assert_has_calls(set_master_expected_calls)

    def test__ensure_evpn_devices(self):
        self._test__ensure_evpn_devices()

    def test__ensure_evpn_devices_not_vlan(self):
        self._test__ensure_evpn_devices(use_vlan=False)

    @mock.patch.object(linux_net, 'delete_device')
    def test__remove_evpn_devices(self, mock_del_device):
        vrf_name = constants.OVN_EVPN_VRF_PREFIX + str(self.vni)
        bridge_name = constants.OVN_EVPN_BRIDGE_PREFIX + str(self.vni)
        vxlan_name = constants.OVN_EVPN_VXLAN_PREFIX + str(self.vni)
        lo_name = constants.OVN_EVPN_LO_PREFIX + str(self.vni)
        veth_name = constants.OVN_EVPN_VETH_VRF_PREFIX + str(self.vni)
        vlan_name = constants.OVN_EVPN_VLAN_PREFIX + str(self.vni)

        self.evpn_driver._remove_evpn_devices(self.vni)

        expected_calls = [mock.call(lo_name), mock.call(vrf_name),
                          mock.call(bridge_name), mock.call(vxlan_name),
                          mock.call(veth_name), mock.call(vlan_name)]
        mock_del_device.assert_has_calls(expected_calls)

    @mock.patch.object(linux_net, 'add_unreachable_route')
    @mock.patch.object(linux_net, 'add_ndp_proxy')
    @mock.patch.object(linux_net, 'get_ip_version')
    @mock.patch.object(linux_net, 'add_ip_route')
    @mock.patch.object(ovs, 'add_device_to_ovs_bridge')
    def _test__connect_evpn_to_ovn(
            self, mock_add_ovs_bridge, mock_add_route, mock_ip_version,
            mock_add_ndp_proxy, mock_add_unreachable_route, use_vlan=True):
        mock_ip_version.side_effect = (constants.IP_VERSION_4,
                                       constants.IP_VERSION_6)
        vrf = 'fake-vrf'
        veth_vrf = 'fake-veth-vrf'
        veth_ovs = 'fake-veth-ovs'
        ips = [self.ipv4, self.ipv6]
        dp_bridge = 'datapath-bridge'
        vlan = 'fake-vlan'
        vlan_tag = self.vlan_tag if use_vlan else None

        self.evpn_driver._connect_evpn_to_ovn(
            vrf, veth_vrf, veth_ovs, ips, dp_bridge, self.vni,
            vlan, vlan_tag)

        mock_add_unreachable_route.assert_called_once_with(vrf)

        if not use_vlan:
            mock_add_ndp_proxy.assert_called_once_with(self.ipv6, dp_bridge)
            mock_add_ovs_bridge.assert_called_once_with(veth_ovs, dp_bridge)
            add_route_expected_calls = [
                mock.call(mock.ANY, self.ipv4, self.vni, veth_vrf),
                mock.call(mock.ANY, self.ipv6, self.vni, veth_vrf)]
        else:
            mock_add_ndp_proxy.assert_called_once_with(self.ipv6, vlan)
            add_route_expected_calls = [
                mock.call(mock.ANY, self.ipv4, self.vni, vlan),
                mock.call(mock.ANY, self.ipv6, self.vni, vlan)]

        mock_add_route.assert_has_calls(add_route_expected_calls)

    def test__connect_evpn_to_ovn(self):
        self._test__connect_evpn_to_ovn()

    def test__connect_evpn_to_ovn_not_vlan(self):
        self._test__connect_evpn_to_ovn(use_vlan=False)

    @mock.patch.object(linux_net, 'del_ndp_proxy')
    @mock.patch.object(linux_net, 'delete_routes_from_table')
    @mock.patch.object(ovs, 'del_device_from_ovs_bridge')
    @mock.patch.object(linux_net, 'get_ip_version')
    def _test_disconnect_evpn_from_ovn(
            self, mock_ip_version, mock_del_device, mock_delete_routes,
            mock_del_ndp, use_vlan=True, clean_ndp=True):
        mock_ip_version.side_effect = (constants.IP_VERSION_4,
                                       constants.IP_VERSION_6)
        dp_bridge = 'datapath-bridge'
        ips = [self.ipv4, self.ipv6]
        vlan_tag = self.vlan_tag if use_vlan else None

        self.evpn_driver._disconnect_evpn_from_ovn(
            self.vni, dp_bridge, ips, vlan_tag=vlan_tag,
            cleanup_ndp_proxy=clean_ndp)

        # Assertions
        device = constants.OVN_EVPN_VETH_OVS_PREFIX + str(self.vni)
        if use_vlan:
            device = constants.OVN_EVPN_VLAN_PREFIX + str(self.vni)

        mock_delete_routes.assert_called_once_with(self.vni)

        mock_del_device.assert_called_once_with(device, dp_bridge)
        if clean_ndp:
            mock_del_ndp.assert_called_once_with(self.ipv6, dp_bridge)
        else:
            mock_del_ndp.assert_not_called()

    def test_disconnect_evpn_from_ovn(self):
        self._test_disconnect_evpn_from_ovn()

    def test_disconnect_evpn_from_ovn_dont_clean_ndp(self):
        self._test_disconnect_evpn_from_ovn(clean_ndp=False)

    def test_disconnect_evpn_from_ovn_not_vlan(self):
        self._test_disconnect_evpn_from_ovn(use_vlan=False)

    @mock.patch.object(ovs, 'del_device_from_ovs_bridge')
    @mock.patch.object(linux_net, 'delete_device')
    @mock.patch.object(linux_net, 'get_interfaces')
    def test__remove_extra_vrfs(
            self, mock_get_ifaces, mock_del_device, mock_del_device_bridge):
        # NOTE(lucasagomes): Remove cr_lrp1 to simplify the test
        self.evpn_driver.ovn_local_cr_lrps.pop(self.cr_lrp1, None)
        mock_get_ifaces.return_value = [
            '%siface' % type_ for type_ in (
                constants.OVN_EVPN_VRF_PREFIX,
                constants.OVN_EVPN_LO_PREFIX,
                constants.OVN_EVPN_BRIDGE_PREFIX,
                constants.OVN_EVPN_VXLAN_PREFIX,
                constants.OVN_EVPN_VETH_VRF_PREFIX,
                constants.OVN_EVPN_VLAN_PREFIX)]

        self.evpn_driver._remove_extra_vrfs()

        # Assertions
        expected_calls = [mock.call('vrf-iface'),
                          mock.call('lo-iface'),
                          mock.call('br-iface'),
                          mock.call('vxlan-iface'),
                          mock.call('veth-vrf-iface')]
        mock_del_device.assert_has_calls(expected_calls)

        expected_calls = [mock.call('veth-vrf-iface'),
                          mock.call('vlan-iface')]
        mock_del_device_bridge.assert_has_calls(expected_calls)

    @mock.patch.object(linux_net, 'get_interface_index')
    @mock.patch.object(linux_net, 'delete_ip_routes')
    @mock.patch.object(linux_net, 'get_routes_on_tables')
    def test__remove_extra_routes(
            self, mock_get_routes, mock_del_ip_routes, mock_index):
        mock_index.return_value = 'fake-oif'
        mock_table_ids = mock.patch.object(
            self.evpn_driver, '_get_table_ids').start()
        mock_table_ids.return_value = ['fake-table-id']
        route_to_del = {
            'oif': 'fake-oif0',
            'gateway': 'fake-gateway0',
            'dst': 'fake-dst0',
            'dst_len': 'fake-dst-len0',
            'table': 'fake-table0'}
        mock_get_routes.return_value = [
            self.evpn_driver._ovn_routing_tables_routes[
                'fake-vlan'][0]['route'],
            route_to_del]

        self.evpn_driver._remove_extra_routes()

        # Assert the route meant to be deleted was deleted
        mock_del_ip_routes.assert_called_once_with([route_to_del])

    @mock.patch.object(ovs, 'get_flow_info')
    @mock.patch.object(ovs, 'get_bridge_flows')
    @mock.patch.object(ovs, 'del_flow')
    def test_remove_extra_ovs_flows_mac(
            self, mock_del_flow, mock_get_flows, mock_flow_info):
        mock_flow_info.return_value = {'mac': 'aa:aa:aa:aa:aa:aa'}
        mock_get_flows.return_value = ['fake-flow0', 'fake-flow1']

        self.evpn_driver._remove_extra_ovs_flows()

        expected_calls = [mock.call('fake-flow0', self.bridge,
                                    constants.OVS_VRF_RULE_COOKIE),
                          mock.call('fake-flow1', self.bridge,
                                    constants.OVS_VRF_RULE_COOKIE)]
        mock_del_flow.assert_has_calls(expected_calls)

    @mock.patch.object(ovs, 'get_flow_info')
    @mock.patch.object(ovs, 'get_bridge_flows')
    @mock.patch.object(ovs, 'del_flow')
    def test_remove_extra_ovs_flows_port(
            self, mock_del_flow, mock_get_flows, mock_flow_info):
        mock_flow_info.return_value = {
            'mac': self.mac,
            'port': 'fake-port',
        }
        mock_get_flows.return_value = ['fake-flow0', 'fake-flow1']

        self.evpn_driver._remove_extra_ovs_flows()

        expected_calls = [mock.call('fake-flow0', self.bridge,
                                    constants.OVS_VRF_RULE_COOKIE),
                          mock.call('fake-flow1', self.bridge,
                                    constants.OVS_VRF_RULE_COOKIE)]
        mock_del_flow.assert_has_calls(expected_calls)

    @mock.patch.object(ovs, 'get_device_port_at_ovs')
    @mock.patch.object(ovs, 'get_flow_info')
    @mock.patch.object(ovs, 'get_bridge_flows')
    @mock.patch.object(ovs, 'del_flow')
    def test_remove_extra_ovs_flows_port_nw_src(
            self, mock_del_flow, mock_get_flows, mock_flow_info,
            mock_get_port_ovs):
        mock_get_port_ovs.return_value = 'fake-ovs-port'
        mock_flow_info.return_value = {
            'mac': self.mac,
            'port': 'fake-port',
            'nw_src': '10.10.1.88/32',
        }
        mock_get_flows.return_value = ['fake-flow0', 'fake-flow1']

        self.evpn_driver._remove_extra_ovs_flows()

        expected_calls = [mock.call('fake-flow0', self.bridge,
                                    constants.OVS_VRF_RULE_COOKIE),
                          mock.call('fake-flow1', self.bridge,
                                    constants.OVS_VRF_RULE_COOKIE)]
        mock_del_flow.assert_has_calls(expected_calls)

    @mock.patch.object(ovs, 'get_flow_info')
    @mock.patch.object(ovs, 'get_bridge_flows')
    @mock.patch.object(ovs, 'del_flow')
    def test_remove_extra_ovs_flows(
            self, mock_del_flow, mock_get_flows, mock_flow_info):
        mock_flow_info.return_value = {}
        mock_get_flows.return_value = ['fake-flow0', 'fake-flow1']

        self.evpn_driver._remove_extra_ovs_flows()

        expected_calls = [mock.call('fake-flow0', self.bridge,
                                    constants.OVS_VRF_RULE_COOKIE),
                          mock.call('fake-flow1', self.bridge,
                                    constants.OVS_VRF_RULE_COOKIE)]
        mock_del_flow.assert_has_calls(expected_calls)

    @mock.patch.object(linux_net, 'del_ips_from_dev')
    @mock.patch.object(linux_net, 'get_exposed_ips')
    def test__remove_extra_exposed_ips(self, mock_get_ips, mock_del_ips):
        self.evpn_driver._ovn_exposed_evpn_ips = {
            'fake-lo': [self.ipv4, self.ipv6]}
        another_ip = '10.10.1.76'
        mock_get_ips.return_value = [another_ip]

        self.evpn_driver._remove_extra_exposed_ips()

        mock_del_ips.assert_called_once_with('fake-lo', [another_ip])

    def test__get_table_ids(self):
        ret = self.evpn_driver._get_table_ids()
        self.assertEqual([self.vni, self.vni1], ret)

    def test_get_cr_lrp_mac_mapping(self):
        ret = self.evpn_driver._get_cr_lrp_mac_mapping()
        expected_ret = {
            self.mac: {
                'veth_ovs': 'fake-veth-ovs',
                'veth_vrf': 'fake-veth-vrf',
                'vlan': 'fake-vlan'},
            self.mac1: {
                'veth_ovs': 'fake-veth-ovs1',
                'veth_vrf': 'fake-veth-vrf1',
                'vlan': 'fake-vlan1'}
        }
        self.assertEqual(expected_ret, ret)

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

import copy
import ipaddress

from unittest import mock

from ovn_bgp_agent import constants
from ovn_bgp_agent import exceptions as agent_exc
from ovn_bgp_agent.tests import base as test_base
from ovn_bgp_agent.utils import linux_net


class IPRouteDict(dict):
    def get_attr(self, attr_name):
        for attr in self['attrs']:
            if attr[0] == attr_name:
                return attr[1]
        return


class TestLinuxNet(test_base.TestCase):

    def setUp(self):
        super(TestLinuxNet, self).setUp()
        # Mock pyroute2.NDB context manager object
        self.mock_ndb = mock.patch.object(linux_net.pyroute2, 'NDB').start()
        self.fake_ndb = self.mock_ndb().__enter__()

        # Mock pyroute2.IPRoute context manager object
        self.mock_ipr = mock.patch.object(linux_net.pyroute2,
                                          'IPRoute').start()
        self.fake_ipr = self.mock_ipr().__enter__()

        # Helper variables used accross many tests
        self.ip = '10.10.1.16'
        self.ipv6 = '2002::1234:abcd:ffff:c0a8:101'
        self.dev = 'ethfake'
        self.mac = 'aa:bb:cc:dd:ee:ff'
        self.bridge = 'br-fake'
        self.table_id = 100
        self.network = ipaddress.IPv4Network("10.10.1.0/24")
        self.network_v6 = ipaddress.IPv6Network("2002:0:0:1234:0:0:0:0/64")

    def test_get_ip_version_v4(self):
        self.assertEqual(4, linux_net.get_ip_version('%s/32' % self.ip))
        self.assertEqual(4, linux_net.get_ip_version(self.ip))

    def test_get_ip_version_v6(self):
        self.assertEqual(6, linux_net.get_ip_version('%s/64' % self.ipv6))
        self.assertEqual(6, linux_net.get_ip_version(self.ipv6))

    def test_get_interfaces(self):
        iface0 = IPRouteDict({'attrs': [('IFLA_IFNAME', 'ethfake0')]})
        iface1 = IPRouteDict({'attrs': [('IFLA_IFNAME', 'ethfake1')]})
        iface2 = IPRouteDict({'attrs': [('IFLA_IFNAME', 'ethfake2')]})
        self.fake_ipr.get_links.return_value = [iface0, iface1, iface2]

        ret = linux_net.get_interfaces(filter_out='ethfake1')
        self.assertEqual(['ethfake0', 'ethfake2'], ret)

    def test_get_interface_index(self):
        self.fake_ipr.link_lookup.return_value = [7]
        ret = linux_net.get_interface_index('fake-nic')
        self.assertEqual(7, ret)

    def test_get_interface_index_error(self):
        self.fake_ipr.link_lookup.return_value = ''
        self.assertRaises(agent_exc.NetworkInterfaceNotFound,
                          linux_net.get_interface_index, 'fake-nic')

    def test_get_interface_address(self):
        device_idx = 7
        self.fake_ipr.link_lookup.return_value = [device_idx]
        fake_link = mock.MagicMock()
        fake_link.get_attr.return_value = self.mac
        self.fake_ipr.get_links.return_value = [fake_link]

        ret = linux_net.get_interface_address('fake-nic')
        self.assertEqual(self.mac, ret)

    def test_get_interface_address_index_error(self):
        self.fake_ipr.link_lookup.return_value = ''
        self.assertRaises(agent_exc.NetworkInterfaceNotFound,
                          linux_net.get_interface_address, 'fake-nic')

    def test_get_nic_info(self):
        device_idx = 7
        nic_addr = IPRouteDict({'prefixlen': 32,
                                'attrs': [('IFA_ADDRESS', self.ip)]})
        self.fake_ipr.link_lookup.return_value = [device_idx]
        self.fake_ipr.get_addr.return_value = [nic_addr]
        fake_link = mock.MagicMock()
        fake_link.get_attr.return_value = self.mac
        self.fake_ipr.get_links.return_value = [fake_link]

        ret = linux_net.get_nic_info('fake-nic')
        self.assertEqual(('{}/32'.format(self.ip), self.mac), ret)

    def test_get_nic_info_index_error(self):
        self.fake_ipr.link_lookup.return_value = ''
        self.assertRaises(agent_exc.NetworkInterfaceNotFound,
                          linux_net.get_nic_info, 'fake-nic')

    @mock.patch('ovn_bgp_agent.privileged.linux_net.ensure_vrf')
    def test_ensure_vrf(self, mock_ensure_vrf):
        linux_net.ensure_vrf('fake-vrf', 10)
        mock_ensure_vrf.assert_called_once_with('fake-vrf', 10)

    @mock.patch('ovn_bgp_agent.privileged.linux_net.ensure_bridge')
    def test_ensure_bridge(self, mock_ensure_bridge):
        linux_net.ensure_bridge('fake-bridge')
        mock_ensure_bridge.assert_called_once_with('fake-bridge')

    @mock.patch('ovn_bgp_agent.privileged.linux_net.ensure_vxlan')
    def test_ensure_vxlan(self, mock_ensure_vxlan):
        linux_net.ensure_vxlan('fake-vxlan', 11, self.ip, 7)
        mock_ensure_vxlan.assert_called_once_with('fake-vxlan', 11, self.ip, 7)

    @mock.patch('ovn_bgp_agent.privileged.linux_net.ensure_veth')
    def test_ensure_veth(self, mock_ensure_veth):
        linux_net.ensure_veth('fake-veth', 'fake-veth-peer')
        mock_ensure_veth.assert_called_once_with('fake-veth', 'fake-veth-peer')

    @mock.patch('ovn_bgp_agent.privileged.linux_net.ensure_dummy_device')
    def test_ensure_dummy_device(self, mock_ensure_dummy_device):
        linux_net.ensure_dummy_device('fake-dev')
        mock_ensure_dummy_device.assert_called_once_with('fake-dev')

    @mock.patch.object(linux_net, 'ensure_dummy_device')
    @mock.patch.object(linux_net, 'set_master_for_device')
    def test_ensure_ovn_device(self, mock_master, mock_dummy):
        linux_net.ensure_ovn_device('ifname', 'fake-vrf')
        mock_dummy.assert_called_once_with('ifname')
        mock_master.assert_called_once_with('ifname', 'fake-vrf')

    @mock.patch('ovn_bgp_agent.privileged.linux_net.delete_device')
    def test_delete_device(self, mock_delete_device):
        linux_net.delete_device('fake-dev')
        mock_delete_device.assert_called_once_with('fake-dev')

    @mock.patch.object(linux_net, 'enable_proxy_arp')
    @mock.patch.object(linux_net, 'enable_proxy_ndp')
    @mock.patch('ovn_bgp_agent.privileged.linux_net.add_ip_to_dev')
    def test_ensure_arp_ndp_enabled_for_bridge(self, mock_add_ip_to_dev,
                                               mock_ndp, mock_arp):
        linux_net.ensure_arp_ndp_enabled_for_bridge('fake-bridge', 511)
        # NOTE(ltomasbo): hardoced starting ipv4 is 192.168.0.0, and ipv6 is
        # fd53:d91e:400:7f17::0
        ipv4 = '169.254.1.255'  # base + 511 offset
        ipv6 = 'fd53:d91e:400:7f17::1ff'  # base + 5122 offset (to hex)
        calls = [mock.call(ipv4, 'fake-bridge'),
                 mock.call(ipv6, 'fake-bridge')]
        mock_add_ip_to_dev.assert_has_calls(calls)
        mock_ndp.assert_called_once_with('fake-bridge')
        mock_arp.assert_called_once_with('fake-bridge')

    @mock.patch.object(linux_net, 'enable_proxy_arp')
    @mock.patch.object(linux_net, 'enable_proxy_ndp')
    @mock.patch('ovn_bgp_agent.privileged.linux_net.add_ip_to_dev')
    def test_ensure_arp_ndp_enabled_for_bridge_vlan(self, mock_add_ip_to_dev,
                                                    mock_ndp, mock_arp):
        linux_net.ensure_arp_ndp_enabled_for_bridge('fake-bridge', 511, 11)
        # NOTE(ltomasbo): hardoced starting ipv4 is 192.168.0.0, and ipv6 is
        # fd53:d91e:400:7f17::0
        ipv4 = '169.254.1.255'  # base + 511 offset
        ipv6 = 'fd53:d91e:400:7f17::1ff'  # base + 5122 offset (to hex)
        calls = [mock.call(ipv4, 'fake-bridge'),
                 mock.call(ipv6, 'fake-bridge')]
        mock_add_ip_to_dev.assert_has_calls(calls)
        mock_ndp.assert_called_once_with('fake-bridge')
        mock_arp.assert_called_once_with('fake-bridge')

    @mock.patch.object(linux_net, 'enable_proxy_arp')
    @mock.patch.object(linux_net, 'enable_proxy_ndp')
    @mock.patch(
        'ovn_bgp_agent.privileged.linux_net.ensure_vlan_device_for_network')
    def test_ensure_vlan_device_for_network(
            self, mock_ensure_vlan_device_for_network, mock_ndp, mock_arp):
        linux_net.ensure_vlan_device_for_network('fake-br', 10)
        expected_dev = 'fake-br/10'
        mock_ensure_vlan_device_for_network.assert_called_once_with(
            'fake-br', 10)
        mock_ndp.assert_called_once_with(expected_dev)
        mock_arp.assert_called_once_with(expected_dev)

    @mock.patch.object(linux_net, 'delete_device')
    def test_delete_vlan_device_for_network(self, mock_del):
        linux_net.delete_vlan_device_for_network('fake-br', 10)
        vlan_name = 'fake-br.10'
        mock_del.assert_called_once_with(vlan_name)

    @mock.patch('ovn_bgp_agent.privileged.linux_net.set_kernel_flag')
    def test_enable_proxy_ndp(self, mock_flag):
        linux_net.enable_proxy_ndp(self.dev)
        expected_flag = 'net.ipv6.conf.%s.proxy_ndp' % self.dev
        mock_flag.assert_called_once_with(expected_flag, 1)

    @mock.patch('ovn_bgp_agent.privileged.linux_net.set_kernel_flag')
    def test_enable_proxy_arp(self, mock_flag):
        linux_net.enable_proxy_arp(self.dev)
        expected_flag = 'net.ipv4.conf.%s.proxy_arp' % self.dev
        mock_flag.assert_called_once_with(expected_flag, 1)

    def test_get_exposed_ips(self):
        ip0 = IPRouteDict({'prefixlen': 32,
                           'attrs': [('IFA_ADDRESS', self.ip)]})
        ip1 = IPRouteDict({'prefixlen': 128,
                           'attrs': [('IFA_ADDRESS', self.ipv6)]})
        ip2 = IPRouteDict({'prefixlen': 24,
                           'attrs': [('IFA_ADDRESS', '10.10.1.18')]})
        ip3 = IPRouteDict(
            {'prefixlen': 64,
             'attrs': [('IFA_ADDRESS', '2001:0DB8:0000:000b::')]})
        self.fake_ipr.get_addr.return_value = [ip0, ip1, ip2, ip3]

        ips = linux_net.get_exposed_ips(self.dev)

        expected_ips = [self.ip, self.ipv6]
        self.assertEqual(expected_ips, ips)

    def test_get_nic_ip(self):
        ip0 = IPRouteDict({'attrs': [('IFA_ADDRESS', '10.10.1.16')]})
        ip1 = IPRouteDict({'attrs': [('IFA_ADDRESS', '10.10.1.17')]})
        self.fake_ipr.get_addr.return_value = [ip0, ip1]

        ips = linux_net.get_nic_ip(self.dev)

        expected_ips = ['10.10.1.16', '10.10.1.17']
        self.assertEqual(expected_ips, ips)

    def test_get_exposed_ips_on_network(self):
        ip0 = IPRouteDict({'prefixlen': 32,
                           'attrs': [('IFA_ADDRESS', self.ip)]})
        ip1 = IPRouteDict({'prefixlen': 128,
                           'attrs': [('IFA_ADDRESS', '10.10.1.17')]})
        ip2 = IPRouteDict({'prefixlen': 128,
                           'attrs': [('IFA_ADDRESS', self.ipv6)]})
        ip3 = IPRouteDict({
            'prefixlen': 128,
            'attrs': [('IFA_ADDRESS', '2001:db8:3333:4444:5555:6666:7777:8888')
                      ]})

        self.fake_ipr.get_addr.return_value = [ip0, ip1, ip2, ip3]

        network_ips = [ipaddress.ip_address(self.ip),
                       ipaddress.ip_address(self.ipv6)]
        ret = linux_net.get_exposed_ips_on_network(self.dev, network_ips)

        self.assertEqual([self.ip, self.ipv6], ret)

    def test_get_exposed_routes_on_network_v4(self):
        route0 = mock.MagicMock(
            dst=mock.Mock(),
            table=self.table_id,
            scope=1,
            proto=11,
            gateway=self.ip,
        )
        route1 = mock.MagicMock(
            dst=mock.Mock(),
            table=self.table_id,
            scope=1,
            proto=11,
            gateway=self.ipv6,
        )
        route2 = mock.MagicMock(
            dst=mock.Mock(),
            table=self.table_id,
            scope=1,
            proto=11,
            gateway=None,
        )

        self.fake_ndb.routes.dump.return_value = [route0, route1, route2]
        ret = linux_net.get_exposed_routes_on_network(
            [self.table_id], self.network
        )

        self.assertEqual([route0], ret)

    def test_get_exposed_routes_on_network_v6(self):
        route0 = mock.MagicMock(
            dst=mock.Mock(),
            table=self.table_id,
            scope=1,
            proto=11,
            gateway=self.ip,
        )
        route1 = mock.MagicMock(
            dst=mock.Mock(),
            table=self.table_id,
            scope=1,
            proto=11,
            gateway=self.ipv6,
        )
        route2 = mock.MagicMock(
            dst=mock.Mock(),
            table=self.table_id,
            scope=1,
            proto=11,
            gateway=None,
        )

        self.fake_ndb.routes.dump.return_value = [route0, route1, route2]
        ret = linux_net.get_exposed_routes_on_network(
            [self.table_id], self.network_v6
        )

        self.assertEqual([route1], ret)

    def test_get_ovn_ip_rules(self):
        rule0 = IPRouteDict({'dst_len': 128, 'family': 10,
                             'attrs': [('FRA_TABLE', 7),
                                       ('FRA_DST', 10)]})
        rule1 = IPRouteDict({'dst_len': 32, 'family': 2,
                             'attrs': [('FRA_TABLE', 7),
                                       ('FRA_DST', 11)]})
        rule2 = IPRouteDict({'dst_len': 24, 'family': 2,
                             'attrs': [('FRA_TABLE', 9),
                                       ('FRA_DST', 5)]})
        rule3 = IPRouteDict({'dst_len': 128, 'family': 10,
                             'attrs': [('FRA_TABLE', 10),
                                       ('FRA_DST', 6)]})
        self.fake_ipr.get_rules.side_effect = [[rule1, rule2], [rule0, rule3]]

        ret = linux_net.get_ovn_ip_rules([7, 10])
        expected_ret = {'10/128': {'table': 7, 'family': 10},
                        '11/32': {'table': 7, 'family': 2},
                        '6/128': {'table': 10, 'family': 10}}
        self.assertEqual(expected_ret, ret)

    @mock.patch('ovn_bgp_agent.privileged.linux_net.delete_exposed_ips')
    def test_delete_exposed_ips(self, mock_delete_exposed_ips):
        linux_net.delete_exposed_ips([self.ip], self.dev)
        mock_delete_exposed_ips.assert_called_once_with([self.ip], self.dev)

    @mock.patch('ovn_bgp_agent.privileged.linux_net.delete_ip_rules')
    def test_delete_ip_rules(self, mock_delete_ip_rules):
        ip_rules = {'10/128': {'table': 7, 'family': 'fake'},
                    '6/128': {'table': 10, 'family': 'fake'}}
        linux_net.delete_ip_rules(ip_rules)
        mock_delete_ip_rules.assert_called_once_with(ip_rules)

    @mock.patch.object(linux_net, 'get_interface_index')
    def _test_delete_bridge_ip_routes(self, mock_route_delete, mock_get_index,
                                      is_vlan=False, has_gateway=False):
        gateway = '1.1.1.1'
        oif = 11
        vlan = 30 if is_vlan else None
        mock_get_index.return_value = oif

        route = {'route': {'dst': self.ip,
                           'dst_len': 32,
                           'table': 20},
                 'vlan': vlan}
        if has_gateway:
            route['route']['gateway'] = gateway

        routing_tables = {self.bridge: 20}
        routing_tables_routes = {self.bridge: [route]}
        # extra_route0 matches with the route
        extra_route0 = IPRouteDict({
            'dst_len': 32, 'family': constants.AF_INET, 'table': 20,
            'attrs': [('RTA_DST', self.ip),
                      ('RTA_OIF', oif),
                      ('RTA_GATEWAY', gateway)]})
        # extra_route1 does not match with route and should be removed
        extra_route1 = IPRouteDict({
            'dst_len': 32, 'family': constants.AF_INET, 'table': 20,
            'attrs': [('RTA_DST', '10.10.1.17'),
                      ('RTA_OIF', oif),
                      ('RTA_GATEWAY', gateway)]})
        extra_routes = {self.bridge: [extra_route0, extra_route1]}

        linux_net.delete_bridge_ip_routes(
            routing_tables, routing_tables_routes, extra_routes)

        # Assert extra_route1 has been removed
        expected_route = {'dst': '10.10.1.17', 'dst_len': 32,
                          'family': constants.AF_INET, 'oif': oif,
                          'gateway': gateway, 'table': 20}

        mock_route_delete.assert_called_once_with(expected_route)

    @mock.patch('ovn_bgp_agent.privileged.linux_net.route_delete')
    def test_delete_bridge_ip_routes(self, mock_route_delete):
        self._test_delete_bridge_ip_routes(mock_route_delete)

    @mock.patch('ovn_bgp_agent.privileged.linux_net.route_delete')
    def test_delete_bridge_ip_routes_vlan(self, mock_route_delete):
        self._test_delete_bridge_ip_routes(mock_route_delete, is_vlan=True)

    @mock.patch('ovn_bgp_agent.privileged.linux_net.route_delete')
    def test_delete_bridge_ip_routes_gateway(self, mock_route_delete):
        self._test_delete_bridge_ip_routes(mock_route_delete, has_gateway=True)

    @mock.patch('ovn_bgp_agent.utils.linux_net.delete_ip_routes')
    def test_delete_routes_from_table(self, mock_delete_ip_routes):
        route0 = {'scope': 1, 'proto': 11}
        route1 = {'scope': 2, 'proto': 22}
        route2 = {'scope': 254, 'proto': 186}
        self.fake_ipr.get_routes.return_value = [
            route0, route1, route2]

        linux_net.delete_routes_from_table('fake-table')

        mock_delete_ip_routes.assert_called_once_with([route0, route1])

    def test_get_routes_on_tables(self):
        route0 = IPRouteDict({
            'proto': 10, 'table': 10,
            'attrs': [('RTA_DST', '10.10.10.10')]})
        # Route1 has proto 186, should be ignored
        route1 = IPRouteDict({
            'proto': 186, 'table': 11,
            'attrs': [('RTA_DST', '11.11.11.11')]})
        route2 = IPRouteDict({
            'proto': 12, 'table': 11,
            'attrs': [('RTA_DST', '12.12.12.12')]})
        # Route3 is in the list but dst is empty
        route3 = IPRouteDict({
            'proto': 10, 'table': 22,
            'attrs': [('RTA_DST', '')]})
        self.fake_ipr.get_routes.side_effect = [
            [route0], [route1, route2], [route3]]

        ret = linux_net.get_routes_on_tables([10, 11, 22])

        self.assertEqual([route0, route2], ret)

    @mock.patch('ovn_bgp_agent.privileged.linux_net.route_delete')
    def test_delete_ip_routes(self, mock_route_delete):
        route0 = dict(
            table=10, dst='10.10.10.10', proto=10, dst_len=128,
            oif='ethout', family='fake', gateway='1.1.1.1')
        route1 = dict(
            table=11, dst='11.11.11.11', proto=11, dst_len=64,
            oif='ethout', family='fake', gateway='2.2.2.2')
        routes = [route0, route1]

        linux_net.delete_ip_routes(routes)

        route0.pop('proto')
        route1.pop('proto')
        mock_route_delete.assert_has_calls(
            [mock.call(route0), mock.call(route1)])

    @mock.patch('ovn_bgp_agent.privileged.linux_net.add_ndp_proxy')
    def test_add_ndp_proxy(self, mock_ndp_proxy):
        linux_net.add_ndp_proxy(self.ip, self.dev, vlan=10)
        mock_ndp_proxy.assert_called_once_with(self.ip, self.dev, 10)

    @mock.patch('ovn_bgp_agent.privileged.linux_net.del_ndp_proxy')
    def test_del_ndp_proxy(self, mock_ndp_proxy):
        linux_net.del_ndp_proxy(self.ip, self.dev, vlan=10)
        mock_ndp_proxy.assert_called_once_with(self.ip, self.dev, 10)

    @mock.patch.object(linux_net, 'get_interface_index')
    @mock.patch('ovn_bgp_agent.privileged.linux_net.route_delete')
    @mock.patch('ovn_bgp_agent.privileged.linux_net.add_ip_to_dev')
    def test_add_ips_to_dev(self, mock_add_ip_to_dev, mock_route_delete,
                            mock_get_index):
        ips = [self.ip, self.ipv6]
        oif = 7
        mock_get_index.return_value = oif
        linux_net.add_ips_to_dev(
            self.dev, ips, clear_local_route_at_table=123)

        # Assert called for each ip
        calls = [mock.call(self.ip, self.dev),
                 mock.call(self.ipv6, self.dev)]
        mock_add_ip_to_dev.assert_has_calls(calls)

        r1 = {'table': 123, 'proto': 2, 'scope': 254, 'dst': self.ip,
              'oif': oif}
        r2 = {'table': 123, 'proto': 2, 'scope': 254, 'dst': self.ipv6,
              'oif': oif}
        calls = [mock.call(r1),
                 mock.call(r2)]
        mock_route_delete.assert_has_calls(calls)

    @mock.patch('ovn_bgp_agent.privileged.linux_net.del_ip_from_dev')
    def test_del_ips_from_dev(self, mock_del_ip_from_dev):
        ips = [self.ip, self.ipv6]
        linux_net.del_ips_from_dev(self.dev, ips)

        calls = [mock.call(self.ip, self.dev),
                 mock.call(self.ipv6, self.dev)]
        mock_del_ip_from_dev.assert_has_calls(calls)

    @mock.patch.object(linux_net, 'add_ip_nei')
    @mock.patch('ovn_bgp_agent.privileged.linux_net.rule_create')
    def test_add_ip_rule(self, mock_rule_create, mock_add_ip_nei):
        linux_net.add_ip_rule(
            self.ip, 7, dev=self.dev, lladdr=self.mac)

        expected_args = {'dst': self.ip, 'table': 7,
                         'dst_len': 32, 'family': constants.AF_INET}
        mock_rule_create.assert_called_once_with(expected_args)
        mock_add_ip_nei.assert_called_once_with(self.ip, self.mac, self.dev)

    @mock.patch.object(linux_net, 'add_ip_nei')
    @mock.patch('ovn_bgp_agent.privileged.linux_net.rule_create')
    def test_add_ip_rule_ipv6(self, mock_rule_create, mock_add_ip_nei):
        linux_net.add_ip_rule(self.ipv6, 7, dev=self.dev, lladdr=self.mac)

        expected_args = {'dst': self.ipv6,
                         'table': 7, 'dst_len': 128,
                         'family': constants.AF_INET6}
        mock_rule_create.assert_called_once_with(expected_args)
        mock_add_ip_nei.assert_called_once_with(self.ipv6, self.mac, self.dev)

    @mock.patch('ovn_bgp_agent.privileged.linux_net.rule_create')
    def test_add_ip_rule_invalid_ip(self, mock_rule_create):
        self.assertRaises(agent_exc.InvalidPortIP,
                          linux_net.add_ip_rule, '10.10.1.6/30/128', 7)
        mock_rule_create.assert_not_called()

    @mock.patch('ovn_bgp_agent.privileged.linux_net.add_ip_nei')
    def test_add_ip_nei(self, mock_add_ip_nei):
        linux_net.add_ip_nei(self.ip, self.mac, self.dev)
        mock_add_ip_nei.assert_called_once_with(self.ip, self.mac, self.dev)

    @mock.patch.object(linux_net, 'del_ip_nei')
    @mock.patch('ovn_bgp_agent.privileged.linux_net.rule_delete')
    def test_del_ip_rule(self, mock_rule_delete, mock_del_ip_nei):
        linux_net.del_ip_rule(self.ip, 7, dev=self.dev, lladdr=self.mac)

        expected_args = {'dst': self.ip, 'table': 7,
                         'dst_len': 32, 'family': constants.AF_INET}
        mock_rule_delete.assert_called_once_with(expected_args)
        mock_del_ip_nei.assert_called_once_with(self.ip, self.mac, self.dev)

    @mock.patch.object(linux_net, 'del_ip_nei')
    @mock.patch('ovn_bgp_agent.privileged.linux_net.rule_delete')
    def test_del_ip_rule_ipv6(self, mock_rule_delete, mock_del_ip_nei):
        linux_net.del_ip_rule(self.ipv6, 7, dev=self.dev, lladdr=self.mac)

        expected_args = {'dst': self.ipv6, 'table': 7,
                         'dst_len': 128, 'family': constants.AF_INET6}
        mock_rule_delete.assert_called_once_with(expected_args)
        mock_del_ip_nei.assert_called_once_with(self.ipv6, self.mac, self.dev)

    @mock.patch.object(linux_net, 'del_ip_nei')
    @mock.patch('ovn_bgp_agent.privileged.linux_net.rule_delete')
    def test_del_ip_rule_invalid_ip(self, mock_rule_delete, mock_del_ip_nei):
        self.assertRaises(agent_exc.InvalidPortIP,
                          linux_net.del_ip_rule, '10.10.1.6/30/128', 7)

        mock_rule_delete.assert_not_called()
        mock_del_ip_nei.assert_not_called()

    @mock.patch('ovn_bgp_agent.privileged.linux_net.del_ip_nei')
    def test_del_ip_nei(self, mock_del_ip_nei):
        linux_net.del_ip_nei(self.ip, self.mac, self.dev)
        mock_del_ip_nei.assert_called_once_with(self.ip, self.mac, self.dev)

    @mock.patch('ovn_bgp_agent.privileged.linux_net.add_unreachable_route')
    def test_add_unreachable_route(self, mock_add_route):
        linux_net.add_unreachable_route('fake-vrf')
        mock_add_route.assert_called_once_with('fake-vrf')

    @mock.patch('ovn_bgp_agent.privileged.linux_net.route_create')
    def test_add_ip_route(self, mock_route_create):
        routes = {}
        linux_net.add_ip_route(routes, self.ip, 7, self.dev)
        expected_routes = {
            self.dev: [{'route': {'dst': self.ip,
                                  'dst_len': 32,
                                  'oif': mock.ANY,
                                  'proto': 3,
                                  'scope': 253,
                                  'table': 7},
                        'vlan': None}]}
        self.assertEqual(expected_routes, routes)
        mock_route_create.assert_not_called()

    @mock.patch('ovn_bgp_agent.privileged.linux_net.route_create')
    def test_add_ip_route_ipv6(self, mock_route_create):
        routes = {}
        linux_net.add_ip_route(routes, self.ipv6, 7, self.dev)
        expected_routes = {
            self.dev: [{'route': {'dst': self.ipv6,
                                  'dst_len': 128,
                                  'family': constants.AF_INET6,
                                  'oif': mock.ANY,
                                  'proto': 3,
                                  'table': 7},
                        'vlan': None}]}
        self.assertEqual(expected_routes, routes)
        mock_route_create.assert_not_called()

    @mock.patch('ovn_bgp_agent.privileged.linux_net.route_create')
    def test_add_ip_route_via(self, mock_route_create):
        routes = {}
        linux_net.add_ip_route(routes, self.ip, 7, self.dev, via='1.1.1.1')
        expected_routes = {
            self.dev: [{'route': {'dst': self.ip,
                                  'dst_len': 32,
                                  'gateway': '1.1.1.1',
                                  'oif': mock.ANY,
                                  'proto': 3,
                                  'scope': 0,
                                  'table': 7},
                        'vlan': None}]}
        self.assertEqual(expected_routes, routes)
        mock_route_create.assert_not_called()

    @mock.patch('ovn_bgp_agent.privileged.linux_net.route_create')
    def test_add_ip_route_vlan(self, mock_route_create):
        routes = {}
        linux_net.add_ip_route(routes, self.ip, 7, self.dev, vlan=10)
        expected_routes = {
            self.dev: [{'route': {'dst': self.ip,
                                  'dst_len': 32,
                                  'oif': mock.ANY,
                                  'proto': 3,
                                  'scope': 253,
                                  'table': 7},
                        'vlan': 10}]}
        self.assertEqual(expected_routes, routes)
        mock_route_create.assert_not_called()

    @mock.patch.object(linux_net, 'get_interface_index')
    @mock.patch.object(linux_net, 'ensure_vlan_device_for_network')
    @mock.patch('ovn_bgp_agent.privileged.linux_net.route_create')
    def test_add_ip_route_vlan_keyerror(self, mock_route_create,
                                        mock_ensure_vlan_device,
                                        mock_get_index):
        routes = {}
        oif = '5'
        mock_get_index.side_effect = [agent_exc.NetworkInterfaceNotFound, oif]
        linux_net.add_ip_route(routes, self.ip, 7, self.dev, vlan=10)
        expected_routes = {
            self.dev: [{'route': {'dst': self.ip,
                                  'dst_len': 32,
                                  'oif': oif,
                                  'proto': 3,
                                  'scope': 253,
                                  'table': 7},
                        'vlan': 10}]}
        self.assertEqual(expected_routes, routes)
        mock_ensure_vlan_device.assert_called_once_with(self.dev, 10)
        mock_route_create.assert_not_called()

    @mock.patch('ovn_bgp_agent.privileged.linux_net.route_create')
    def test_add_ip_route_mask(self, mock_route_create):
        routes = {}
        linux_net.add_ip_route(routes, self.ip, 7, self.dev, mask=30)
        expected_routes = {
            self.dev: [{'route': {'dst': self.ip,
                                  'dst_len': 30,
                                  'oif': mock.ANY,
                                  'proto': 3,
                                  'scope': 253,
                                  'table': 7},
                        'vlan': None}]}
        self.assertEqual(expected_routes, routes)
        mock_route_create.assert_not_called()

    @mock.patch('ovn_bgp_agent.privileged.linux_net.route_create')
    def test_add_ip_route_no_route(self, mock_route_create):
        self.fake_ipr.route.return_value = ()
        routes = {}
        linux_net.add_ip_route(routes, self.ip, 7, self.dev)
        expected_routes = {
            self.dev: [{'route': {'dst': self.ip,
                                  'dst_len': 32,
                                  'oif': mock.ANY,
                                  'proto': 3,
                                  'scope': 253,
                                  'table': 7},
                        'vlan': None}]}
        self.assertEqual(expected_routes, routes)
        mock_route_create.assert_called_once_with(
            expected_routes[self.dev][0]['route'])

    @mock.patch('ovn_bgp_agent.privileged.linux_net.route_delete')
    def test_del_ip_route(self, mock_route_delete):
        routes = {
            self.dev: [{'route': {'dst': self.ip,
                                  'dst_len': 32,
                                  'oif': mock.ANY,
                                  'proto': 3,
                                  'scope': 253,
                                  'table': 7},
                        'vlan': None}]}
        route = copy.deepcopy(routes[self.dev][0]['route'])

        linux_net.del_ip_route(routes, self.ip, 7, self.dev)

        self.assertEqual({self.dev: []}, routes)
        mock_route_delete.assert_called_once_with(route)

    @mock.patch('ovn_bgp_agent.privileged.linux_net.route_delete')
    def test_del_ip_route_ipv6(self, mock_route_delete):
        routes = {
            self.dev: [{'route': {'dst': self.ipv6,
                                  'dst_len': 128,
                                  'family': constants.AF_INET6,
                                  'oif': mock.ANY,
                                  'proto': 3,
                                  'table': 7},
                        'vlan': None}]}
        route = copy.deepcopy(routes[self.dev][0]['route'])

        linux_net.del_ip_route(routes, self.ipv6, 7, self.dev)

        self.assertEqual({self.dev: []}, routes)
        mock_route_delete.assert_called_once_with(route)

    @mock.patch('ovn_bgp_agent.privileged.linux_net.route_delete')
    def test_del_ip_route_via(self, mock_route_delete):
        routes = {
            self.dev: [{'route': {'dst': self.ip,
                                  'dst_len': 32,
                                  'oif': mock.ANY,
                                  'gateway': '1.1.1.1',
                                  'proto': 3,
                                  'scope': 0,
                                  'table': 7},
                        'vlan': None}]}
        route = copy.deepcopy(routes[self.dev][0]['route'])

        linux_net.del_ip_route(routes, self.ip, 7, self.dev, via='1.1.1.1')

        self.assertEqual({self.dev: []}, routes)
        mock_route_delete.assert_called_once_with(route)

    @mock.patch('ovn_bgp_agent.privileged.linux_net.route_delete')
    def test_del_ip_route_vlan(self, mock_route_delete):
        routes = {
            self.dev: [{'route': {'dst': self.ip,
                                  'dst_len': 32,
                                  'oif': mock.ANY,
                                  'proto': 3,
                                  'scope': 253,
                                  'table': 7},
                        'vlan': 10}]}
        route = copy.deepcopy(routes[self.dev][0]['route'])

        linux_net.del_ip_route(routes, self.ip, 7, self.dev, vlan=10)

        self.assertEqual({self.dev: []}, routes)
        mock_route_delete.assert_called_once_with(route)

    @mock.patch('ovn_bgp_agent.privileged.linux_net.route_delete')
    def test_del_ip_route_mask(self, mock_route_delete):
        routes = {
            self.dev: [{'route': {'dst': self.ip,
                                  'dst_len': 30,
                                  'oif': mock.ANY,
                                  'proto': 3,
                                  'scope': 253,
                                  'table': 7},
                        'vlan': None}]}
        route = copy.deepcopy(routes[self.dev][0]['route'])

        linux_net.del_ip_route(routes, self.ip, 7, self.dev, mask=30)

        self.assertEqual({self.dev: []}, routes)
        mock_route_delete.assert_called_once_with(route)


class TestEnsureRoutingTableForBridge(test_base.TestCase):
    def setUp(self):
        super().setUp()
        self.ovn_routing_tables = {}
        self.bridge_name = "br-test"
        self.vrf_table = 4
        self.generated_number = 2

        self.testing_multiline_file_content = [
            "1 foo",
            "# commented line",
            "random garbage text",
            "3	another bridge",
            "2",
        ]

        self.m_ensure_rt_routes = mock.patch.object(
            linux_net, '_ensure_routing_table_routes').start()

        # The 'random' generator will always generate number 2 because the
        # range is 1-4 while 1 and 3 are used in the file and 4 is the vrf
        mock.patch.object(constants, 'ROUTING_TABLE_MIN', 1).start()
        mock.patch.object(constants, 'ROUTING_TABLE_MAX', 4).start()

    def _create_fake_file_content(self):
        return "\n".join(self.testing_multiline_file_content)

    def test_ensure_routing_table_for_bridge_table_missing(self):
        self._test_ensure_routing_table_for_bridge_table_missing()

    def _test_ensure_routing_table_for_bridge_table_missing(self):
        with mock.patch(
                'builtins.open',
                mock.mock_open(read_data=self._create_fake_file_content())):
            linux_net.ensure_routing_table_for_bridge(
                self.ovn_routing_tables, self.bridge_name, self.vrf_table)

        self.assertDictEqual(
            {self.bridge_name: self.generated_number}, self.ovn_routing_tables)

    def test_ensure_routing_table_for_bridge_table_present(self):
        present_bridge_value = 5
        self.testing_multiline_file_content.insert(
            2, "%d %s" % (present_bridge_value, self.bridge_name))

        with mock.patch(
                'builtins.open',
                mock.mock_open(read_data=self._create_fake_file_content())):
            linux_net.ensure_routing_table_for_bridge(
                self.ovn_routing_tables, self.bridge_name, self.vrf_table)

        self.assertDictEqual(
            {self.bridge_name: present_bridge_value}, self.ovn_routing_tables)

    def test_ensure_routing_table_for_bridge_table_vrf_not_generated(self):
        self.vrf_table = 2
        self.generated_number = 4
        self._test_ensure_routing_table_for_bridge_table_missing()

    def test_ensure_routing_table_for_bridge_tables_depleted(self):
        present_bridge_value = 2
        self.testing_multiline_file_content.insert(
            2, "%d %s" % (present_bridge_value, "foo"))

        with mock.patch(
                'builtins.open',
                mock.mock_open(read_data=self._create_fake_file_content())):
            self.assertRaises(
                SystemExit,
                linux_net.ensure_routing_table_for_bridge,
                self.ovn_routing_tables, self.bridge_name, self.vrf_table)

        self.assertDictEqual({}, self.ovn_routing_tables)

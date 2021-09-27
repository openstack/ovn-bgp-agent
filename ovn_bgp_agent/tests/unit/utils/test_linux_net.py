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
from socket import AF_INET
from socket import AF_INET6

import pyroute2
from unittest import mock

from ovn_bgp_agent import constants
from ovn_bgp_agent import exceptions as agent_exc
from ovn_bgp_agent.tests import base as test_base
from ovn_bgp_agent.utils import linux_net


class TestLinuxNet(test_base.TestCase):

    def setUp(self):
        super(TestLinuxNet, self).setUp()
        # Mock pyroute2.NDB context manager object
        self.mock_ndb = mock.patch.object(linux_net.pyroute2, 'NDB').start()
        self.fake_ndb = self.mock_ndb().__enter__()
        # Mock pyroute2.IPRoute context manager object
        self.mock_iproute = mock.patch.object(
            linux_net.pyroute2, 'IPRoute').start()
        self.fake_iproute = self.mock_iproute().__enter__()

        # Helper variables used accross many tests
        self.ip = '10.10.1.16'
        self.ipv6 = '2002::1234:abcd:ffff:c0a8:101'
        self.dev = 'ethfake'
        self.mac = 'aa:bb:cc:dd:ee:ff'
        self.bridge = 'br-fake'

    def test_get_ip_version_v4(self):
        self.assertEqual(4, linux_net.get_ip_version('%s/32' % self.ip))
        self.assertEqual(4, linux_net.get_ip_version(self.ip))

    def test_get_ip_version_v6(self):
        self.assertEqual(6, linux_net.get_ip_version('%s/64' % self.ipv6))
        self.assertEqual(6, linux_net.get_ip_version(self.ipv6))

    def test_get_interfaces(self):
        iface0 = mock.Mock(ifname='ethfake0')
        iface1 = mock.Mock(ifname='ethfake1')
        iface2 = mock.Mock(ifname='ethfake2')
        self.fake_ndb.interfaces = [iface0, iface1, iface2]

        ret = linux_net.get_interfaces(filter_out='ethfake1')
        self.assertEqual(['ethfake0', 'ethfake2'], ret)

    def test_get_interface_index(self):
        self.fake_ndb.interfaces = {'fake-nic': {'index': 7}}
        ret = linux_net.get_interface_index('fake-nic')
        self.assertEqual(7, ret)

    @mock.patch.object(linux_net, 'set_device_status')
    def test_ensure_vrf(self, mock_dev_status):
        linux_net.ensure_vrf('fake-vrf', 10)
        mock_dev_status.assert_called_once_with(
            'fake-vrf', constants.LINK_UP, ndb=self.fake_ndb)

    @mock.patch.object(linux_net, 'set_device_status')
    def test_ensure_vrf_keyerror(self, mock_dev_status):
        mock_dev_status.side_effect = KeyError('Typhoons')
        linux_net.ensure_vrf('fake-vrf', 10)
        self.fake_ndb.interfaces.create.assert_called_once_with(
            kind='vrf', ifname='fake-vrf', vrf_table=10)

    @mock.patch.object(linux_net, 'set_device_status')
    def test_ensure_bridge(self, mock_dev_status):
        linux_net.ensure_bridge('fake-bridge')
        mock_dev_status.assert_called_once_with(
            'fake-bridge', constants.LINK_UP, ndb=self.fake_ndb)

    @mock.patch.object(linux_net, 'set_device_status')
    def test_ensure_bridge_keyerror(self, mock_dev_status):
        mock_dev_status.side_effect = KeyError('Oblivion')
        linux_net.ensure_bridge('fake-bridge')
        self.fake_ndb.interfaces.create.assert_called_once_with(
            kind='bridge', ifname='fake-bridge', br_stp_state=0)

    @mock.patch.object(linux_net, 'set_device_status')
    def test_ensure_vxlan(self, mock_dev_status):
        linux_net.ensure_vxlan('fake-vxlan', 11, self.ip, 7)
        mock_dev_status.assert_called_once_with(
            'fake-vxlan', constants.LINK_UP, ndb=self.fake_ndb)

    @mock.patch.object(linux_net, 'set_device_status')
    def test_ensure_vxlan_keyerror(self, mock_dev_status):
        mock_dev_status.side_effect = KeyError('Who Needs Friends')
        linux_net.ensure_vxlan('fake-vxlan', 11, self.ip, 7)
        self.fake_ndb.interfaces.create.assert_called_once_with(
            kind='vxlan', ifname='fake-vxlan', vxlan_id=11, vxlan_port=7,
            vxlan_local=self.ip, vxlan_learning=False)

    @mock.patch.object(linux_net, 'set_device_status')
    def test_ensure_veth(self, mock_dev_status):
        linux_net.ensure_veth('fake-veth', 'fake-veth-peer')
        calls = [mock.call('fake-veth', constants.LINK_UP),
                 mock.call('fake-veth-peer', constants.LINK_UP)]
        mock_dev_status.assert_has_calls(calls)

    @mock.patch.object(linux_net, 'set_device_status')
    def test_ensure_veth_keyerror(self, mock_dev_status):
        mock_dev_status.side_effect = (KeyError('Million and One'), None)
        linux_net.ensure_veth('fake-veth', 'fake-veth-peer')

        self.fake_ndb.interfaces.create.assert_called_once_with(
            kind='veth', ifname='fake-veth', peer='fake-veth-peer')
        calls = [mock.call('fake-veth', constants.LINK_UP),
                 mock.call('fake-veth-peer', constants.LINK_UP)]
        mock_dev_status.assert_has_calls(calls)

    def test_set_master_for_device(self):
        dev = mock.MagicMock()
        self.fake_ndb.interfaces = {
            'fake-dev': dev, 'fake-master': {'index': 5}}
        linux_net.set_master_for_device('fake-dev', 'fake-master')

        dev.__enter__().set.assert_called_once_with('master', 5)

    def test_set_master_for_device_already_set(self):
        dev = mock.MagicMock()
        dev.get.return_value = 5

        self.fake_ndb.interfaces = {
            'fake-dev': dev, 'fake-master': {'index': 5}}
        linux_net.set_master_for_device('fake-dev', 'fake-master')
        # Both values were the same, assert set() is not called
        self.assertFalse(dev.__enter__().set.called)

    def test_set_device_status(self):
        state_dict = {'state': constants.LINK_DOWN}
        dev = mock.MagicMock()
        dev.__enter__.return_value = state_dict
        self.mock_ndb().interfaces = {'fake-dev': dev}

        linux_net.set_device_status('fake-dev', constants.LINK_UP)

        # Assert the method updates the state to "up"
        self.assertEqual(constants.LINK_UP, state_dict['state'])

    @mock.patch.object(linux_net, 'set_device_status')
    def test_ensure_dummy_device(self, mock_dev_status):
        linux_net.ensure_dummy_device('fake-dev')
        mock_dev_status.assert_called_once_with(
            'fake-dev', constants.LINK_UP, ndb=self.fake_ndb)

    @mock.patch.object(linux_net, 'set_device_status')
    def test_ensure_dummy_device_keyerror(self, mock_dev_status):
        mock_dev_status.side_effect = KeyError('All We Have Is Now')
        linux_net.ensure_dummy_device('fake-dev')
        self.fake_ndb.interfaces.create.assert_called_once_with(
            kind='dummy', ifname='fake-dev')

    @mock.patch.object(linux_net, 'ensure_dummy_device')
    @mock.patch.object(linux_net, 'set_master_for_device')
    def test_ensure_ovn_device(self, mock_master, mock_dummy):
        linux_net.ensure_ovn_device('ifname', 'fake-vrf')
        mock_dummy.assert_called_once_with('ifname')
        mock_master.assert_called_once_with('ifname', 'fake-vrf')

    def test_delete_device(self):
        dev = mock.Mock()
        iface_dict = {'fake-dev': dev}
        self.fake_ndb.interfaces = iface_dict

        linux_net.delete_device('fake-dev')
        dev.remove.assert_called_once_with()

    def test_ensure_routing_table_for_bridge(self):
        # TODO(lucasagomes): This method is massive and complex, perhaps
        #  break it into helper methods for both readibility and maintenance
        #  of it.
        pass

    @mock.patch.object(linux_net, 'enable_proxy_arp')
    @mock.patch.object(linux_net, 'enable_proxy_ndp')
    @mock.patch.object(linux_net, 'set_device_status')
    def test_ensure_vlan_device_for_network(
            self, mock_dev_status, mock_ndp, mock_arp):
        linux_net.ensure_vlan_device_for_network('fake-br', 10)
        vlan_name = 'fake-br.10'
        expected_dev = 'fake-br/10'
        mock_dev_status.assert_called_once_with(
            vlan_name, constants.LINK_UP, ndb=self.fake_ndb)
        mock_ndp.assert_called_once_with(expected_dev)
        mock_arp.assert_called_once_with(expected_dev)

    @mock.patch.object(linux_net, 'enable_proxy_arp')
    @mock.patch.object(linux_net, 'enable_proxy_ndp')
    @mock.patch.object(linux_net, 'set_device_status')
    def test_ensure_vlan_device_for_network_keyerror(
            self, mock_dev_status, mock_ndp, mock_arp):
        mock_dev_status.side_effect = KeyError('Boilermaker')
        linux_net.ensure_vlan_device_for_network('fake-br', 10)

        vlan_name = 'fake-br.10'
        expected_dev = 'fake-br/10'
        self.fake_ndb.interfaces.create.assert_called_once_with(
            kind='vlan', ifname=vlan_name, vlan_id=10, link=mock.ANY)
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
        ip0 = mock.Mock(address=self.ip, prefixlen=32)
        ip1 = mock.Mock(address=self.ipv6, prefixlen=128)
        ip2 = mock.Mock(address='10.10.1.18', prefixlen=24)
        ip3 = mock.Mock(address='2001:0DB8:0000:000b::', prefixlen=64)
        iface = mock.Mock()
        iface.ipaddr.summary.return_value = [ip0, ip1, ip2, ip3]
        self.fake_ndb.interfaces = {self.dev: iface}

        ips = linux_net.get_exposed_ips(self.dev)

        expected_ips = [self.ip, self.ipv6]
        self.assertEqual(expected_ips, ips)

    def test_get_nic_ip(self):
        ip0 = mock.Mock(address='10.10.1.16')
        ip1 = mock.Mock(address='10.10.1.17')
        iface = mock.Mock()
        iface.ipaddr.summary.return_value = [ip0, ip1]
        self.fake_ndb.interfaces = {self.dev: iface}

        ips = linux_net.get_nic_ip(self.dev)

        expected_ips = ['10.10.1.16', '10.10.1.17']
        self.assertEqual(expected_ips, ips)

    def test_get_nic_ip_prefixlen(self):
        ip = mock.Mock(address=self.ip, prefixlen=32)
        iface = mock.Mock()
        iface.ipaddr.summary.return_value.filter.return_value = [ip]
        self.fake_ndb.interfaces = {self.dev: iface}

        linux_net.get_nic_ip(self.dev, prefixlen_filter=32)
        iface.ipaddr.summary.return_value.filter.assert_called_once_with(
            prefixlen=32)

    def test_get_exposed_ips_on_network(self):
        ip0 = mock.Mock(address=self.ip, prefixlen=32)
        ip1 = mock.Mock(address='10.10.1.17', prefixlen=128)
        ip2 = mock.Mock(address=self.ipv6, prefixlen=128)
        ip3 = mock.Mock(
            address='2001:db8:3333:4444:5555:6666:7777:8888', prefixlen=128)
        iface = mock.Mock()
        iface.ipaddr.summary.return_value = [ip0, ip1, ip2, ip3]
        self.fake_ndb.interfaces = {self.dev: iface}

        network_ips = [ipaddress.ip_address(self.ip),
                       ipaddress.ip_address(self.ipv6)]
        ret = linux_net.get_exposed_ips_on_network(self.dev, network_ips)

        self.assertEqual([self.ip, self.ipv6], ret)

    def test_get_ovn_ip_rules(self):
        rule0 = mock.Mock(table=7, dst=10, dst_len=128, family='fake')
        rule1 = mock.Mock(table=7, dst=11, dst_len=32, family='fake')
        rule2 = mock.Mock(table=9, dst=5, dst_len=24, family='fake')
        rule3 = mock.Mock(table=10, dst=6, dst_len=128, family='fake')
        self.fake_ndb.rules.dump.return_value = [rule0, rule1, rule2, rule3]

        ret = linux_net.get_ovn_ip_rules([7, 10])
        expected_ret = {'10/128': {'table': 7, 'family': 'fake'},
                        '11/32': {'table': 7, 'family': 'fake'},
                        '6/128': {'table': 10, 'family': 'fake'}}
        self.assertEqual(expected_ret, ret)

    def test_delete_exposed_ips(self):
        ip0 = mock.Mock(address='10.10.1.16')
        ip1 = mock.Mock(address='2002::1234:abcd:ffff:c0a8:101')
        iface = mock.Mock()
        iface.ipaddr = {'10.10.1.16/32': ip0,
                        '2002::1234:abcd:ffff:c0a8:101/128': ip1}
        self.fake_ndb.interfaces = {self.dev: iface}

        ips = ['10.10.1.16', '2002::1234:abcd:ffff:c0a8:101', '10.10.1.17']
        linux_net.delete_exposed_ips(ips, self.dev)

        ip0.remove.assert_called_once_with()
        ip1.remove.assert_called_once_with()

    def test_delete_ip_rules(self):
        rule0 = mock.MagicMock()
        rule1 = mock.MagicMock()
        self.fake_ndb.rules.__getitem__.side_effect = (rule0, rule1)

        ip_rules = {'10/128': {'table': 7, 'family': 'fake'},
                    '6/128': {'table': 10, 'family': 'fake'}}
        linux_net.delete_ip_rules(ip_rules)

        # Assert remove() was called on rules
        rule0.__enter__().remove.assert_called_once_with()
        rule1.__enter__().remove.assert_called_once_with()

    def test_delete_ip_rules_exceptions(self):
        rule0 = mock.MagicMock()
        self.fake_ndb.rules.__getitem__.side_effect = (
            KeyError('Limbo'),
            pyroute2.netlink.exceptions.NetlinkError(123))

        ip_rules = {'10/128': {'table': 7, 'family': 'fake'},
                    '6/128': {'table': 10, 'family': 'fake'}}
        linux_net.delete_ip_rules(ip_rules)

        # Assert remove() was not called due to the exceptions
        self.assertFalse(rule0.__enter__().remove.called)

    def _test_delete_bridge_ip_routes(self, is_vlan=False, has_gateway=False):
        gateway = '1.1.1.1'
        oif = 11
        vlan = 30 if is_vlan else None
        vlan_dev = '%s.%s' % (self.bridge, vlan) if is_vlan else None
        self.fake_ndb.interfaces = {self.bridge: {'index': oif}}
        if is_vlan:
            self.fake_ndb.interfaces.update({vlan_dev: {'index': oif}})

        route = {'route': {'dst': self.ip,
                           'dst_len': 32,
                           'table': 20},
                 'vlan': vlan}
        if has_gateway:
            route['route']['gateway'] = gateway

        routing_tables = {self.bridge: 20}
        routing_tables_routes = {self.bridge: [route]}
        # extra_route0 matches with the route
        extra_route0 = {'dst': self.ip, 'dst_len': 32,
                        'family': AF_INET, 'oif': oif,
                        'gateway': gateway, 'table': 20}
        # extra_route1 does not match with route and should be removed
        extra_route1 = copy.deepcopy(extra_route0)
        extra_route1['dst'] = '10.10.1.17'
        extra_routes = {self.bridge: [extra_route0, extra_route1]}

        linux_net.delete_bridge_ip_routes(
            routing_tables, routing_tables_routes, extra_routes)

        # Assert extra_route1 has been removed
        self.fake_ndb.routes.__getitem__.assert_called_once_with(extra_route1)
        self.fake_ndb.routes.__getitem__().__enter__().\
            remove.assert_called_once_with()

    def test_delete_bridge_ip_routes(self):
        self._test_delete_bridge_ip_routes()

    def test_delete_bridge_ip_routes_vlan(self):
        self._test_delete_bridge_ip_routes(is_vlan=True)

    def test_delete_bridge_ip_routes_gateway(self):
        self._test_delete_bridge_ip_routes(has_gateway=True)

    def test_delete_routes_from_table(self):
        route0 = mock.MagicMock(scope=1, proto=11)
        route1 = mock.MagicMock(scope=2, proto=22)
        route2 = mock.MagicMock(scope=254, proto=186)
        self.fake_ndb.routes.dump().filter.return_value = [
            route0, route1, route2]

        self.fake_ndb.routes.__getitem__.side_effect = (
            route0, route1, KeyError('Mad Visions'))

        linux_net.delete_routes_from_table('fake-table')

        # Assert remove() was called on rules
        route0.__enter__().remove.assert_called_once_with()
        route1.__enter__().remove.assert_called_once_with()
        self.assertFalse(route2.__enter__().remove.called)

    def test_get_routes_on_tables(self):
        route0 = mock.MagicMock(table=10, dst='10.10.10.10', proto=10)
        # Route1 has proto 186, should be ignored
        route1 = mock.MagicMock(table=11, dst='11.11.11.11', proto=186)
        route2 = mock.MagicMock(table=11, dst='12.12.12.12', proto=12)
        # Route3 is not in the table list, should be ignored
        route3 = mock.MagicMock(table=99, dst='14.14.14.14', proto=14)
        # Route4 is in the list but dst is empty
        route4 = mock.MagicMock(table=22, dst='', proto=10)
        self.fake_ndb.routes.dump.return_value = [
            route0, route1, route2, route3, route4]

        ret = linux_net.get_routes_on_tables([10, 11, 22])

        self.assertEqual([route0, route2], ret)

    def test_delete_ip_routes(self):
        route0 = mock.MagicMock(
            table=10, dst='10.10.10.10', proto=10, dst_len=128,
            oif='ethout', family='fake', gateway='1.1.1.1')
        route1 = mock.MagicMock(
            table=11, dst='11.11.11.11', proto=11, dst_len=64,
            oif='ethout', family='fake', gateway='2.2.2.2')
        routes = [route0, route1]
        self.fake_ndb.routes.__getitem__.side_effect = routes

        linux_net.delete_ip_routes(routes)

        route0.__enter__().remove.assert_called_once_with()
        route1.__enter__().remove.assert_called_once_with()

    def test_delete_ip_routes_keyerror(self):
        route0 = mock.MagicMock(
            table=10, dst='10.10.10.10', proto=10, dst_len=128,
            oif='ethout', family='fake', gateway='1.1.1.1')
        route1 = mock.MagicMock(
            table=11, dst='11.11.11.11', proto=11, dst_len=64,
            oif='ethout', family='fake', gateway='2.2.2.2')
        routes = [route0, route1]
        self.fake_ndb.routes.__getitem__.side_effect = (
            KeyError('Either You Want It'))

        linux_net.delete_ip_routes(routes)

        # Assert remove() wasn't called due to KeyError
        self.assertFalse(route0.__enter__().remove.called)
        self.assertFalse(route1.__enter__().remove.called)

    @mock.patch('ovn_bgp_agent.privileged.linux_net.add_ndp_proxy')
    def test_add_ndp_proxy(self, mock_ndp_proxy):
        linux_net.add_ndp_proxy(self.ip, self.dev, vlan=10)
        mock_ndp_proxy.assert_called_once_with(self.ip, self.dev, 10)

    @mock.patch('ovn_bgp_agent.privileged.linux_net.del_ndp_proxy')
    def test_del_ndp_proxy(self, mock_ndp_proxy):
        linux_net.del_ndp_proxy(self.ip, self.dev, vlan=10)
        mock_ndp_proxy.assert_called_once_with(self.ip, self.dev, 10)

    def test_add_ips_to_dev(self):
        iface = mock.MagicMock(index=7)
        self.fake_ndb.interfaces = {self.dev: iface}
        # clear_local_route_at_table bits below
        route0 = mock.MagicMock()
        route1 = mock.MagicMock()
        self.fake_ndb.routes.__getitem__.side_effect = (route0, route1)

        ips = [self.ip, self.ipv6]
        linux_net.add_ips_to_dev(
            self.dev, ips, clear_local_route_at_table=123)

        # Assert add_ip() was called for each ip
        calls = [mock.call('%s/32' % self.ip),
                 mock.call('%s/128' % self.ipv6)]
        iface.__enter__().add_ip.assert_has_calls(calls)

        # Assert clear_local_route_at_table were invoked
        route0.__enter__().remove.assert_called_once_with()
        route1.__enter__().remove.assert_called_once_with()

    def test_del_ips_from_dev(self):
        iface = mock.MagicMock()
        self.fake_ndb.interfaces = {self.dev: iface}

        ips = [self.ip, self.ipv6]
        linux_net.del_ips_from_dev(self.dev, ips)

        calls = [mock.call('%s/32' % self.ip),
                 mock.call('%s/128' % self.ipv6)]
        iface.__enter__().del_ip.assert_has_calls(calls)

    @mock.patch.object(linux_net, 'add_ip_nei')
    def test_add_ip_rule(self, mock_add_ip_nei):
        linux_net.add_ip_rule(
            self.ip, 7, dev=self.dev, lladdr=self.mac)

        expected_args = {'dst': self.ip, 'table': 7, 'dst_len': 32}
        self.fake_ndb.rules.__getitem__.assert_called_once_with(expected_args)

        mock_add_ip_nei.assert_called_once_with(self.ip, self.mac, self.dev)

    @mock.patch.object(linux_net, 'add_ip_nei')
    def test_add_ip_rule_ipv6(self, mock_add_ip_nei):
        linux_net.add_ip_rule(self.ipv6, 7, dev=self.dev, lladdr=self.mac)

        expected_args = {'dst': self.ipv6,
                         'table': 7, 'dst_len': 128, 'family': AF_INET6}
        self.fake_ndb.rules.__getitem__.assert_called_once_with(expected_args)

        mock_add_ip_nei.assert_called_once_with(self.ipv6, self.mac, self.dev)

    def test_add_ip_rule_create(self):
        self.fake_ndb.rules.__getitem__.side_effect = KeyError('Hold On')

        linux_net.add_ip_rule(self.ip, 7)

        expected_args = {'dst': self.ip, 'table': 7, 'dst_len': 32}
        self.fake_ndb.rules.create.assert_called_once_with(expected_args)

    def test_add_ip_rule_invalid_ip(self):
        self.assertRaises(agent_exc.InvalidPortIP,
                          linux_net.add_ip_rule, '10.10.1.6/30/128', 7)
        self.assertFalse(self.fake_ndb.rules.create.called)

    def test_add_ip_nei(self):
        linux_net.add_ip_nei(self.ip, self.mac, self.dev)

        self.fake_iproute.link_lookup.assert_called_once_with(ifname=self.dev)
        self.fake_iproute.neigh.assert_called_once_with(
            'set', dst=self.ip, lladdr=self.mac,
            ifindex=mock.ANY, state=mock.ANY)

    def test_add_ip_nei_ipv6(self):
        linux_net.add_ip_nei(self.ipv6, self.mac, self.dev)

        self.fake_iproute.link_lookup.assert_called_once_with(ifname=self.dev)
        self.fake_iproute.neigh.assert_called_once_with(
            'set', dst=self.ipv6, family=AF_INET6,
            lladdr=self.mac, ifindex=mock.ANY, state=mock.ANY)

    @mock.patch.object(linux_net, 'del_ip_nei')
    def test_del_ip_rule(self, mock_del_ip_nei):
        rule = mock.MagicMock()
        self.fake_ndb.rules.__getitem__.return_value = rule

        linux_net.del_ip_rule(self.ip, 7, dev=self.dev, lladdr=self.mac)

        expected_args = {'dst': self.ip, 'table': 7, 'dst_len': 32}
        self.fake_ndb.rules.__getitem__.assert_called_once_with(expected_args)
        rule.remove.assert_called_once_with()
        mock_del_ip_nei.assert_called_once_with(self.ip, self.mac, self.dev)

    @mock.patch.object(linux_net, 'del_ip_nei')
    def test_del_ip_rule_ipv6(self, mock_del_ip_nei):
        rule = mock.MagicMock()
        self.fake_ndb.rules.__getitem__.return_value = rule

        linux_net.del_ip_rule(self.ipv6, 7, dev=self.dev, lladdr=self.mac)

        expected_args = {'dst': self.ipv6, 'table': 7,
                         'dst_len': 128, 'family': AF_INET6}
        self.fake_ndb.rules.__getitem__.assert_called_once_with(expected_args)
        rule.remove.assert_called_once_with()
        mock_del_ip_nei.assert_called_once_with(self.ipv6, self.mac, self.dev)

    @mock.patch.object(linux_net, 'del_ip_nei')
    def test_del_ip_rule_invalid_ip(self, mock_del_ip_nei):
        rule = mock.MagicMock()
        self.fake_ndb.rules.__getitem__.return_value = rule

        self.assertIsNone(linux_net.del_ip_rule('10.10.1.6/30/128', 7))
        self.assertFalse(self.fake_ndb.rules.remove.called)
        self.assertFalse(rule.remove.called)

    def test_del_ip_nei(self):
        linux_net.del_ip_nei(self.ip, self.mac, self.dev)

        self.fake_iproute.link_lookup.assert_called_once_with(ifname=self.dev)
        self.fake_iproute.neigh.assert_called_once_with(
            'del', dst=self.ip, lladdr=self.mac,
            ifindex=mock.ANY, state=mock.ANY)

    def test_del_ip_nei_ipv6(self):
        linux_net.del_ip_nei(self.ipv6, self.mac, self.dev)

        self.fake_iproute.link_lookup.assert_called_once_with(ifname=self.dev)
        self.fake_iproute.neigh.assert_called_once_with(
            'del', dst=self.ipv6, family=AF_INET6,
            lladdr=self.mac, ifindex=mock.ANY, state=mock.ANY)

    @mock.patch('ovn_bgp_agent.privileged.linux_net.add_unreachable_route')
    def test_add_unreachable_route(self, mock_add_route):
        linux_net.add_unreachable_route('fake-vrf')
        mock_add_route.assert_called_once_with('fake-vrf')

    def test_add_ip_route(self):
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
        self.assertFalse(self.fake_ndb.routes.create.called)

    def test_add_ip_route_ipv6(self):
        routes = {}
        linux_net.add_ip_route(routes, self.ipv6, 7, self.dev)
        expected_routes = {
            self.dev: [{'route': {'dst': self.ipv6,
                                  'dst_len': 128,
                                  'family': AF_INET6,
                                  'oif': mock.ANY,
                                  'proto': 3,
                                  'table': 7},
                        'vlan': None}]}
        self.assertEqual(expected_routes, routes)
        self.assertFalse(self.fake_ndb.routes.create.called)

    def test_add_ip_route_via(self):
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
        self.assertFalse(self.fake_ndb.routes.create.called)

    def test_add_ip_route_vlan(self):
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
        self.assertFalse(self.fake_ndb.routes.create.called)

    def test_add_ip_route_mask(self):
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
        self.assertFalse(self.fake_ndb.routes.create.called)

    def test_add_ip_route_keyerror(self):
        self.fake_ndb.routes.__getitem__.side_effect = KeyError('Nite Expo')
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
        self.fake_ndb.routes.create.assert_called_once_with(
            expected_routes[self.dev][0]['route'])

    def test_del_ip_route(self):
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

        self.fake_ndb.routes.__getitem__.assert_called_once_with(route)
        self.fake_ndb.routes.__getitem__().__enter__().\
            remove.assert_called_once_with()
        self.assertEqual({self.dev: []}, routes)

    def test_del_ip_route_ipv6(self):
        routes = {
            self.dev: [{'route': {'dst': self.ipv6,
                                  'dst_len': 128,
                                  'family': AF_INET6,
                                  'oif': mock.ANY,
                                  'proto': 3,
                                  'scope': 253,
                                  'table': 7},
                        'vlan': None}]}
        route = copy.deepcopy(routes[self.dev][0]['route'])

        linux_net.del_ip_route(routes, self.ipv6, 7, self.dev)

        self.fake_ndb.routes.__getitem__.assert_called_once_with(route)
        self.fake_ndb.routes.__getitem__().__enter__().\
            remove.assert_called_once_with()
        self.assertEqual({self.dev: []}, routes)

    def test_del_ip_route_via(self):
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

        self.fake_ndb.routes.__getitem__.assert_called_once_with(route)
        self.fake_ndb.routes.__getitem__().__enter__().\
            remove.assert_called_once_with()
        self.assertEqual({self.dev: []}, routes)

    def test_del_ip_route_vlan(self):
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

        self.fake_ndb.routes.__getitem__.assert_called_once_with(route)
        self.fake_ndb.routes.__getitem__().__enter__().\
            remove.assert_called_once_with()
        self.assertEqual({self.dev: []}, routes)

    def test_del_ip_route_mask(self):
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

        self.fake_ndb.routes.__getitem__.assert_called_once_with(route)
        self.fake_ndb.routes.__getitem__().__enter__().\
            remove.assert_called_once_with()
        self.assertEqual({self.dev: []}, routes)

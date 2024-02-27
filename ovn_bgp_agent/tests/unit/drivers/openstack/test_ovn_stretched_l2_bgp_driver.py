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
from ovn_bgp_agent.drivers.openstack import ovn_stretched_l2_bgp_driver
from ovn_bgp_agent.drivers.openstack.utils import driver_utils
from ovn_bgp_agent.drivers.openstack.utils import frr
from ovn_bgp_agent.drivers.openstack.utils import ovn
from ovn_bgp_agent.drivers.openstack.utils import ovs
from ovn_bgp_agent import exceptions as agent_exc
from ovn_bgp_agent.tests import base as test_base
from ovn_bgp_agent.tests.unit import fakes
from ovn_bgp_agent.utils import linux_net

import ipaddress

CONF = cfg.CONF


class TestHashedRoute(test_base.TestCase):
    def setUp(self):
        super(TestHashedRoute, self).setUp()
        self.table = set()
        self.route = ovn_stretched_l2_bgp_driver.HashedRoute(
            "192.168.0.0", 24, "192.168.1.1")
        self.invalid_route = ovn_stretched_l2_bgp_driver.HashedRoute(
            "192.168.0.0", 24, "192.168.1.2")
        self.table.add(self.route)

    def test_lookup(self):
        self.assertTrue(self.route in self.table)
        self.assertFalse(self.invalid_route in self.table)

    def test_delete(self):
        self.table.remove(self.route)
        self.assertEqual(0, len(self.table))


class TestOVNBGPStretchedL2Driver(test_base.TestCase):
    def setUp(self):
        super(TestOVNBGPStretchedL2Driver, self).setUp()
        CONF.set_override(
            "address_scopes",
            "11111111-1111-1111-1111-11111111,22222222-2222-2222-2222-22222222",  # NOQA E501
        )
        self.bgp_driver = ovn_stretched_l2_bgp_driver.OVNBGPStretchedL2Driver()
        self.bgp_driver._post_fork_event = mock.Mock()
        self.bgp_driver.sb_idl = mock.Mock()
        self.sb_idl = self.bgp_driver.sb_idl
        self.bgp_driver.chassis = "fake-chassis"
        # self.bgp_driver.ovn_routing_tables = {self.bridge: 'fake-table'}
        # self.bgp_driver.ovn_bridge_mappings = {'fake-network': self.bridge}

        self.mock_sbdb = mock.patch.object(ovn, "OvnSbIdl").start()
        self.mock_ovs_idl = mock.patch.object(ovs, "OvsIdl").start()
        self.ipv4 = "192.168.1.17"
        self.ipv6 = "2002::1234:abcd:ffff:c0a8:101"
        self.fip = "172.24.4.33"
        self.mac = "aa:bb:cc:dd:ee:ff"
        self.bgp_driver.ovs_idl = self.mock_ovs_idl

        self.test_route_ipv4 = ovn_stretched_l2_bgp_driver.HashedRoute(
            network="192.168.1.0",
            prefix_len=24,
            dst="10.0.0.1",
        )

        self.test_route_ipv6 = ovn_stretched_l2_bgp_driver.HashedRoute(
            network="fdcc:8cf2:d40c:2::",
            prefix_len=64,
            dst="fd51:f4b3:872:eda::1",
        )

        self.addr_scopev4 = "11111111-1111-1111-1111-11111111"
        self.addr_scopev6 = "22222222-2222-2222-2222-22222222"
        self.addr_scope = {
            constants.IP_VERSION_4: self.addr_scopev4,
            constants.IP_VERSION_6: self.addr_scopev6,
        }

        self.addr_scope_external_ids = {
            "neutron:subnet_pool_addr_scope4": self.addr_scopev4,
            "neutron:subnet_pool_addr_scope6": self.addr_scopev6,
        }

        self.cr_lrp0 = mock.Mock()
        self.cr_lrp0.mac = [
            "ff:ff:ff:ff:ff:00 10.0.0.1/24 fd51:f4b3:872:eda::1/64"
        ]
        self.cr_lrp0.datapath = "fake-router-dp"
        self.cr_lrp0.type = constants.OVN_CHASSISREDIRECT_VIF_PORT_TYPE
        self.cr_lrp0.logical_port = "cr-lrp-fake-port"

        self.lp0 = mock.Mock()
        self.lp0.external_ids = self.addr_scope_external_ids

        self.router_port = fakes.create_object(
            {
                "name": "fake-router-port",
                "mac": [
                    "ff:ff:ff:ff:ff:01 192.168.1.1/24 fdcc:8cf2:d40c:2::1/64"
                ],
                "logical_port": "lrp-fake-logical-port",
            }
        )

        self.fake_patch_port = fakes.create_object(
            {
                "name": "fake-patch-port",
                "mac": [
                    "ff:ff:ff:ff:ff:01 192.168.1.1/24 fdcc:8cf2:d40c:2::1/64"
                ],
                "external_ids": self.addr_scope_external_ids,
                "logical_port": "fake-port",
            }
        )

        # Mock pyroute2.NDB context manager object
        self.mock_ndb = mock.patch.object(linux_net.pyroute2, "NDB").start()
        self.fake_ndb = self.mock_ndb().__enter__()

    @mock.patch.object(linux_net, "ensure_vrf")
    @mock.patch.object(linux_net, "ensure_ovn_device")
    @mock.patch.object(linux_net, "delete_routes_from_table")
    @mock.patch.object(frr, "vrf_leak")
    def test_start(self, mock_vrf, mock_delete_routes, mock_ensure_ovn_device,
                   *args):
        CONF.set_override("clear_vrf_routes_on_startup", True)

        mock_redistribute = mock.patch.object(
            frr, "set_default_redistribute"
        ).start()

        self.bgp_driver.start()

        mock_redistribute.assert_called_with(['kernel'])
        mock_vrf.assert_called_once_with(
            CONF.bgp_vrf,
            CONF.bgp_AS,
            CONF.bgp_router_id,
            template=frr.LEAK_VRF_TEMPLATE,
        )
        # Assert connections were started
        self.mock_ovs_idl().start.assert_called_once_with(
            CONF.ovsdb_connection
        )
        self.mock_sbdb().start.assert_called_once_with()
        mock_delete_routes.assert_called_once_with(CONF.bgp_vrf_table_id)
        mock_ensure_ovn_device.assert_called_once_with(
            CONF.bgp_nic, CONF.bgp_vrf)

    @mock.patch.object(linux_net, "ensure_vrf")
    @mock.patch.object(linux_net, "ensure_ovn_device")
    @mock.patch.object(linux_net, "delete_routes_from_table")
    @mock.patch.object(frr, "vrf_leak")
    def test_start_clear_routes(
        self, mock_vrf, mock_delete_routes, mock_ensure_ovn_device, *args):
        CONF.set_override("clear_vrf_routes_on_startup", False)

        mock_redistribute = mock.patch.object(
            frr, "set_default_redistribute"
        ).start()

        self.bgp_driver.start()

        mock_redistribute.assert_called_with(['kernel'])
        mock_vrf.assert_called_once_with(
            CONF.bgp_vrf,
            CONF.bgp_AS,
            CONF.bgp_router_id,
            template=frr.LEAK_VRF_TEMPLATE,
        )
        # Assert connections were started
        self.mock_ovs_idl().start.assert_called_once_with(
            CONF.ovsdb_connection
        )
        self.mock_sbdb().start.assert_called_once_with()
        mock_delete_routes.assert_not_called()
        mock_ensure_ovn_device.assert_called_once_with(
            CONF.bgp_nic, CONF.bgp_vrf)

    @mock.patch.object(linux_net, "add_ip_route")
    def test__add_route(self, mock_add_route):
        for test_route in [self.test_route_ipv4, self.test_route_ipv6]:
            self.bgp_driver._add_route(
                test_route.network,
                test_route.prefix_len,
                test_route.dst,
            )

            mock_add_route.assert_called_with(
                mock.ANY,
                test_route.network,
                CONF.bgp_vrf_table_id,
                CONF.bgp_nic,
                vlan=None,
                mask=test_route.prefix_len,
                via=test_route.dst,
            )

            self.assertTrue(test_route in self.bgp_driver.vrf_routes)

    @mock.patch.object(linux_net, "del_ip_route")
    def test__del_route(self, mock_del_route):
        self.bgp_driver.vrf_routes.add(self.test_route_ipv4)
        self.bgp_driver.vrf_routes.add(self.test_route_ipv6)
        for test_route in [self.test_route_ipv4, self.test_route_ipv6]:
            self.bgp_driver._del_route(
                test_route.network,
                test_route.prefix_len,
                test_route.dst,
            )

            mock_del_route.assert_called_with(
                mock.ANY,
                test_route.network,
                CONF.bgp_vrf_table_id,
                CONF.bgp_nic,
                vlan=None,
                mask=test_route.prefix_len,
                via=test_route.dst,
            )

            self.assertTrue(test_route not in self.bgp_driver.vrf_routes)

    def test__address_scope_allowed(self):
        test_scope2 = {
            constants.IP_VERSION_4: self.addr_scopev4,
            constants.IP_VERSION_6: "33333333-3333-3333-3333-33333333",
        }

        self.assertTrue(
            self.bgp_driver._address_scope_allowed(
                self.addr_scope,
                test_scope2,
                constants.IP_VERSION_4,
            )
        )

        self.assertFalse(
            self.bgp_driver._address_scope_allowed(
                self.addr_scope,
                test_scope2,
                constants.IP_VERSION_6,
            )
        )

    def test__address_scope_not_allowed_scope(self):
        test_scope1 = {
            constants.IP_VERSION_4: "33333333-3333-3333-3333-33333333",
            constants.IP_VERSION_6: "33333333-3333-3333-3333-33333333",
        }

        test_scope2 = {
            constants.IP_VERSION_4: "33333333-3333-3333-3333-33333333",
            constants.IP_VERSION_6: "33333333-3333-3333-3333-33333333",
        }

        self.assertFalse(
            self.bgp_driver._address_scope_allowed(
                test_scope1,
                test_scope2,
                constants.IP_VERSION_4,
            )
        )

        self.assertFalse(
            self.bgp_driver._address_scope_allowed(
                test_scope1,
                test_scope2,
                constants.IP_VERSION_6,
            )
        )

    def test__address_scope_allowed_no_scope(self):
        self.bgp_driver.allowed_address_scopes = set()
        test_scope2 = {
            constants.IP_VERSION_4: None,
            constants.IP_VERSION_6: None,
        }

        self.assertTrue(
            self.bgp_driver._address_scope_allowed(
                self.addr_scope,
                test_scope2,
                constants.IP_VERSION_4,
            )
        )

        self.assertTrue(
            self.bgp_driver._address_scope_allowed(
                self.addr_scope,
                test_scope2,
                constants.IP_VERSION_6,
            )
        )

    def test__address_scope_allowed_no_match(self):
        test_scope2 = {
            constants.IP_VERSION_4: None,
            constants.IP_VERSION_6: "44444444-4444-4444-4444-44444444",
        }

        self.assertFalse(
            self.bgp_driver._address_scope_allowed(
                self.addr_scope,
                test_scope2,
                constants.IP_VERSION_4,
            )
        )

        self.assertFalse(
            self.bgp_driver._address_scope_allowed(
                self.addr_scope,
                test_scope2,
                constants.IP_VERSION_6,
            )
        )

    def test_expose_subnet(self):
        mock__ensure_network_exposed = mock.patch.object(
            self.bgp_driver, "_ensure_network_exposed"
        ).start()
        self.sb_idl.is_router_gateway_on_any_chassis.return_value = (
            self.cr_lrp0
        )
        row = mock.Mock()
        row.datapath = "fake-dp"

        self.bgp_driver.expose_subnet(None, row)

        self.sb_idl.is_router_gateway_on_any_chassis.assert_called_once_with(
            row.datapath
        )

        mock__ensure_network_exposed.assert_called_once_with(
            row, self.cr_lrp0.logical_port
        )

    def test_expose_subnet_no_gateway_port(self):
        mock__ensure_network_exposed = mock.patch.object(
            self.bgp_driver, "_ensure_network_exposed"
        ).start()
        self.sb_idl.is_router_gateway_on_any_chassis.return_value = None
        row = mock.Mock()
        row.datapath = "fake-dp"

        self.bgp_driver.expose_subnet(None, row)

        self.sb_idl.is_router_gateway_on_any_chassis.assert_called_once_with(
            row.datapath
        )

        mock__ensure_network_exposed.assert_not_called()

    def test_expose_subnet_no_datapath(self):
        mock__ensure_network_exposed = mock.patch.object(
            self.bgp_driver, "_ensure_network_exposed"
        ).start()
        row = mock.Mock()
        row.datapath = "fake-dp"
        self.sb_idl.is_router_gateway_on_any_chassis.side_effect = (
            agent_exc.DatapathNotFound(datapath=row.datapath))

        self.bgp_driver.expose_subnet(None, row)

        self.sb_idl.is_router_gateway_on_any_chassis.assert_called_once_with(
            row.datapath
        )

        mock__ensure_network_exposed.assert_not_called()

    def test_update_subnet(self):
        mock__update_network = mock.patch.object(
            self.bgp_driver, "_update_network"
        ).start()
        self.sb_idl.is_router_gateway_on_any_chassis.return_value = (
            self.cr_lrp0
        )
        old = mock.Mock()
        old.mac = ["ff:ff:ff:ff:ff:01 1.1.1.1/24 2.2.2.2/24"]

        row = mock.Mock()
        row.datapath = "fake-dp"
        row.mac = ["ff:ff:ff:ff:ff:01 2.2.2.2/24 3.3.3.3/24"]

        self.bgp_driver.update_subnet(old, row)

        self.sb_idl.is_router_gateway_on_any_chassis.assert_called_once_with(
            row.datapath
        )

        mock__update_network.assert_called_once_with(
            row, self.cr_lrp0.logical_port, ["3.3.3.3/24"], ["1.1.1.1/24"]
        )

    def test_update_subnet_no_datapath(self):
        mock__update_network = mock.patch.object(
            self.bgp_driver, "_update_network"
        ).start()
        self.sb_idl.is_router_gateway_on_any_chassis.return_value = (
            self.cr_lrp0
        )
        old = mock.Mock()
        old.mac = ["ff:ff:ff:ff:ff:01 1.1.1.1/24 2.2.2.2/24"]

        row = mock.Mock()
        row.datapath = "fake-dp"
        row.mac = ["ff:ff:ff:ff:ff:01 2.2.2.2/24 3.3.3.3/24"]

        self.sb_idl.is_router_gateway_on_any_chassis.side_effect = (
            agent_exc.DatapathNotFound(datapath=row.datapath))

        self.bgp_driver.update_subnet(old, row)

        self.sb_idl.is_router_gateway_on_any_chassis.assert_called_once_with(
            row.datapath
        )

        mock__update_network.assert_not_called()

    @mock.patch.object(linux_net, "get_exposed_routes_on_network")
    @mock.patch.object(linux_net, "del_ip_route")
    @mock.patch.object(linux_net, "add_ip_route")
    def test__update_network(
        self,
        mock_add_ip_route,
        mock_del_ip_route,
        mock_get_exposed_routes_on_network,
    ):
        gateway = {}
        gateway["ips"] = [
            ipaddress.ip_interface(ip)
            for ip in ["10.0.0.10/26", "fd51:f4b3:872:eda::10/64"]
        ]
        gateway["address_scopes"] = self.addr_scope
        gateway["lrp_ports"] = set()
        self.bgp_driver.ovn_local_cr_lrps = {"gateway_port": gateway}

        self.router_lrp = mock.Mock()
        self.router_lrp.mac = [
            "ff:ff:ff:ff:ff:01 192.168.1.1/24 fdcc:8cf2:d40c:2::1/64"
        ]

        add_ips = ["192.168.1.1/24", "fdcc:8cf2:d40c:2::1/64"]
        delete_ips = ["192.168.0.1/24"]

        mock_get_exposed_routes_on_network.side_effect = (
            ["route-v4"],
            ["route-v6"],
        )

        self.sb_idl.get_port_by_name.return_value = self.fake_patch_port

        self.bgp_driver._update_network(
            self.router_port, "gateway_port", add_ips, delete_ips
        )

        self.sb_idl.get_port_by_name.assert_called_once_with(
            "fake-logical-port"
        )

        expected_calls = [
            mock.call(
                mock.ANY,
                "10.0.0.0",
                CONF.bgp_vrf_table_id,
                CONF.bgp_nic,
                vlan=None,
                mask=26,
                via=None,
            ),
            mock.call(
                mock.ANY,
                "192.168.1.0",
                CONF.bgp_vrf_table_id,
                CONF.bgp_nic,
                vlan=None,
                mask=24,
                via="10.0.0.10",
            ),
            mock.call(
                mock.ANY,
                "fd51:f4b3:872:eda::",
                CONF.bgp_vrf_table_id,
                CONF.bgp_nic,
                vlan=None,
                mask=64,
                via=None,
            ),
            mock.call(
                mock.ANY,
                "fdcc:8cf2:d40c:2::",
                CONF.bgp_vrf_table_id,
                CONF.bgp_nic,
                vlan=None,
                mask=64,
                via="fd51:f4b3:872:eda::10",
            ),
        ]

        mock_add_ip_route.assert_has_calls(expected_calls)
        mock_del_ip_route.assert_called_once_with(
            mock.ANY,
            "192.168.0.0",
            CONF.bgp_vrf_table_id,
            CONF.bgp_nic,
            vlan=None,
            mask=24,
            via="10.0.0.10",
        )

        self.assertDictEqual(
            self.bgp_driver.propagated_lrp_ports,
            {
                self.router_port.logical_port: {
                    "cr_lrp": "gateway_port",
                    "subnets": {
                        "fdcc:8cf2:d40c:2::/64",
                        "192.168.1.0/24"
                    }
                }
            }
        )

    @mock.patch.object(linux_net, "get_exposed_routes_on_network")
    @mock.patch.object(linux_net, "del_ip_route")
    @mock.patch.object(linux_net, "add_ip_route")
    def test__update_network_no_gateway(
        self,
        mock_add_ip_route,
        mock_del_ip_route,
        mock_get_exposed_routes_on_network,
    ):
        self.bgp_driver.ovn_local_cr_lrps = {}

        self.router_lrp = mock.Mock()
        self.router_lrp.mac = [
            "ff:ff:ff:ff:ff:01 192.168.1.1/24 fdcc:8cf2:d40c:2::1/64"
        ]

        add_ips = ["192.168.1.1/24", "fdcc:8cf2:d40c:2::1/64"]
        delete_ips = ["192.168.0.1/24"]

        self.bgp_driver._update_network(
            self.router_port, "gateway_port", add_ips, delete_ips
        )

        mock_get_exposed_routes_on_network.assert_not_called()
        mock_del_ip_route.assert_not_called()
        mock_add_ip_route.assert_not_called()
        self.sb_idl.get_port_by_name.assert_not_called()

    @mock.patch.object(linux_net, "get_exposed_routes_on_network")
    @mock.patch.object(linux_net, "del_ip_route")
    @mock.patch.object(linux_net, "add_ip_route")
    def test__update_network_no_mac(
        self,
        mock_add_ip_route,
        mock_del_ip_route,
        mock_get_exposed_routes_on_network,
    ):
        gateway = {}
        gateway["ips"] = [
            ipaddress.ip_interface(ip)
            for ip in ["10.0.0.10/26", "fd51:f4b3:872:eda::10/64"]
        ]
        gateway["address_scopes"] = self.addr_scope
        self.bgp_driver.ovn_local_cr_lrps = {"gateway_port": gateway}

        self.router_port.mac = []

        add_ips = ["192.168.1.1/24", "fdcc:8cf2:d40c:2::1/64"]
        delete_ips = ["192.168.0.1/24"]

        self.bgp_driver._update_network(
            self.router_port, "gateway_port", add_ips, delete_ips
        )

        mock_get_exposed_routes_on_network.assert_not_called()
        mock_del_ip_route.assert_not_called()
        mock_add_ip_route.assert_not_called()
        self.sb_idl.get_port_by_name.assert_not_called()

    def test_withdraw_subnet(self):
        mock__withdraw_subnet = mock.patch.object(
            self.bgp_driver, "_withdraw_subnet"
        ).start()

        row = mock.Mock()
        row.datapath = "fake-dp"
        row.logical_port = "fake-lport"
        port_info = {
            "cr_lrp": self.cr_lrp0.logical_port,
            "subnets": {
                "fdcc:8cf2:d40c:2::/64",
                "192.168.1.0/24"
            }
        }

        self.bgp_driver.propagated_lrp_ports = {
            row.logical_port: port_info,
            "another_lrp_port": {}
        }
        self.bgp_driver.ovn_local_cr_lrps = {
            self.cr_lrp0.logical_port: {
                "lrp_ports": {row.logical_port, "another_lrp_port"}
            }
        }

        self.bgp_driver.withdraw_subnet(None, row)

        mock__withdraw_subnet.assert_called_once_with(
            port_info, self.cr_lrp0.logical_port
        )
        self.assertDictEqual(
            self.bgp_driver.propagated_lrp_ports,
            {
                "another_lrp_port": {}
            }
        )
        self.assertDictEqual(
            self.bgp_driver.ovn_local_cr_lrps,
            {
                self.cr_lrp0.logical_port: {
                    "lrp_ports": {"another_lrp_port"}
                }
            }
        )

    @mock.patch.object(linux_net, "add_ip_route")
    def test__ensure_network_exposed(self, mock_add_ip_route):
        gateway = {}
        gateway["ips"] = [
            ipaddress.ip_interface(ip)
            for ip in ["10.0.0.10/26", "fd51:f4b3:872:eda::10/64"]
        ]
        gateway["address_scopes"] = self.addr_scope
        gateway["lrp_ports"] = set()
        self.bgp_driver.ovn_local_cr_lrps = {"gateway_port": gateway}

        self.router_lrp = mock.Mock()
        self.router_lrp.mac = [
            "ff:ff:ff:ff:ff:01 192.168.1.1/24 fdcc:8cf2:d40c:2::1/64"
        ]

        self.sb_idl.get_port_by_name.return_value = self.fake_patch_port

        self.bgp_driver._ensure_network_exposed(
            self.router_port, "gateway_port"
        )

        self.sb_idl.get_port_by_name.assert_called_once_with(
            "fake-logical-port"
        )

        expected_calls = [
            mock.call(
                mock.ANY,
                "10.0.0.0",
                CONF.bgp_vrf_table_id,
                CONF.bgp_nic,
                vlan=None,
                mask=26,
                via=None,
            ),
            mock.call(
                mock.ANY,
                "192.168.1.0",
                CONF.bgp_vrf_table_id,
                CONF.bgp_nic,
                vlan=None,
                mask=24,
                via="10.0.0.10",
            ),
            mock.call(
                mock.ANY,
                "fd51:f4b3:872:eda::",
                CONF.bgp_vrf_table_id,
                CONF.bgp_nic,
                vlan=None,
                mask=64,
                via=None,
            ),
            mock.call(
                mock.ANY,
                "fdcc:8cf2:d40c:2::",
                CONF.bgp_vrf_table_id,
                CONF.bgp_nic,
                vlan=None,
                mask=64,
                via="fd51:f4b3:872:eda::10",
            ),
        ]

        mock_add_ip_route.assert_has_calls(expected_calls)
        self.assertDictEqual(
            self.bgp_driver.ovn_local_cr_lrps,
            {
                'gateway_port': {
                    'address_scopes': {
                        4: '11111111-1111-1111-1111-11111111',
                        6: '22222222-2222-2222-2222-22222222'},
                    'ips': [
                        ipaddress.IPv4Interface('10.0.0.10/26'),
                        ipaddress.IPv6Interface('fd51:f4b3:872:eda::10/64')],
                    'lrp_ports': {'lrp-fake-logical-port'}
                }
            }
        )
        self.assertDictEqual(
            self.bgp_driver.propagated_lrp_ports,
            {
                "lrp-fake-logical-port": {
                    'cr_lrp': 'gateway_port',
                    'subnets': {'192.168.1.0/24', 'fdcc:8cf2:d40c:2::/64'}
                }
            }
        )

    @mock.patch.object(linux_net, "add_ip_route")
    def test__ensure_network_exposed_invalid_addr_scopes(
        self,
        mock_add_ip_route
    ):
        gateway = {}
        gateway["ips"] = [
            ipaddress.ip_interface(ip)
            for ip in ["10.0.0.10/26", "fd51:f4b3:872:eda::10/64"]
        ]

        # Both of them are valid but none of them matches to the correct
        # IP version
        gateway["address_scopes"] = {
            constants.IP_VERSION_4: self.addr_scopev6,
            constants.IP_VERSION_6: self.addr_scopev4,
        }
        gateway["lrp_ports"] = set()
        self.bgp_driver.ovn_local_cr_lrps = {"gateway_port": gateway}

        self.router_lrp = mock.Mock()
        self.router_lrp.mac = [
            "ff:ff:ff:ff:ff:01 192.168.1.1/24 fdcc:8cf2:d40c:2::1/64"
        ]

        self.sb_idl.get_port_by_name.return_value = self.fake_patch_port

        self.bgp_driver._ensure_network_exposed(
            self.router_port, "gateway_port"
        )

        self.sb_idl.get_port_by_name.assert_called_once_with(
            "fake-logical-port"
        )
        mock_add_ip_route.assert_not_called()
        self.assertDictEqual(
            self.bgp_driver.ovn_local_cr_lrps,
            {
                'gateway_port': {
                    'address_scopes': {
                        4: '22222222-2222-2222-2222-22222222',
                        6: '11111111-1111-1111-1111-11111111'},
                    'ips': [
                        ipaddress.IPv4Interface('10.0.0.10/26'),
                        ipaddress.IPv6Interface('fd51:f4b3:872:eda::10/64')],
                    'lrp_ports': set()
                }
            }
        )
        self.assertDictEqual(
            self.bgp_driver.propagated_lrp_ports,
            {}
        )

    @mock.patch.object(linux_net, "add_ip_route")
    def test__ensure_network_exposed_no_gateway(self, mock_add_ip_route):
        self.bgp_driver.ovn_local_cr_lrps = {}

        self.bgp_driver._ensure_network_exposed(
            self.router_port, "gateway_port"
        )

        self.sb_idl.get_port_by_name.assert_not_called()
        mock_add_ip_route.assert_not_called()
        self.assertDictEqual(
            self.bgp_driver.propagated_lrp_ports,
            {}
        )

    @mock.patch.object(linux_net, "add_ip_route")
    def test__ensure_network_exposed_duplicate_ip(self, mock_add_ip_route):
        gateway = {}
        gateway["ips"] = [
            ipaddress.ip_interface(ip)
            for ip in ["192.168.1.1/24", "fd51:f4b3:872:eda::10/64"]
        ]
        gateway["address_scopes"] = self.addr_scope
        self.bgp_driver.ovn_local_cr_lrps = {"gateway_port": gateway}

        self.bgp_driver._ensure_network_exposed(
            self.router_port, "gateway_port"
        )

        self.sb_idl.get_port_by_name.assert_not_called()
        mock_add_ip_route.assert_not_called()
        self.assertDictEqual(
            self.bgp_driver.propagated_lrp_ports,
            {}
        )

    @mock.patch.object(driver_utils, "get_addr_scopes")
    @mock.patch.object(linux_net, "add_ip_route")
    def test__ensure_network_exposed_port_not_existing(self,
                                                       mock_add_ip_route,
                                                       mock_addr_scopes):
        gateway = {}
        gateway["ips"] = [
            ipaddress.ip_interface(ip)
            for ip in ["10.0.0.10/26", "fd51:f4b3:872:eda::10/64"]
        ]
        gateway["address_scopes"] = self.addr_scope
        self.bgp_driver.ovn_local_cr_lrps = {"gateway_port": gateway}

        self.sb_idl.get_port_by_name.return_value = []
        self.bgp_driver._ensure_network_exposed(
            self.router_port, "gateway_port"
        )
        mock_addr_scopes.assert_not_called()
        mock_add_ip_route.assert_not_called()
        self.assertDictEqual(
            self.bgp_driver.propagated_lrp_ports,
            {}
        )

    @mock.patch.object(linux_net, "add_ip_route")
    def test__ensure_network_exposed_port_addr_scope_no_match(
        self,
        mock_add_ip_route
    ):
        gateway = {}
        gateway["ips"] = [
            ipaddress.ip_interface(ip)
            for ip in ["10.0.0.10/26", "fd51:f4b3:872:eda::10/64"]
        ]
        gateway["address_scopes"] = {
            constants.IP_VERSION_4: "address_scope_v4",
            constants.IP_VERSION_6: "address_scope_v6",
        }
        self.bgp_driver.ovn_local_cr_lrps = {"gateway_port": gateway}

        self.sb_idl.get_port_by_name.return_value = self.fake_patch_port
        self.bgp_driver._ensure_network_exposed(
            self.router_port, "gateway_port"
        )

        self.sb_idl.get_port_by_name.assert_called_once_with(
            "fake-logical-port"
        )
        mock_add_ip_route.assert_not_called()
        self.assertDictEqual(
            self.bgp_driver.propagated_lrp_ports,
            {}
        )

    @mock.patch.object(linux_net, "get_exposed_routes_on_network")
    @mock.patch.object(linux_net, "del_ip_route")
    def test__withdraw_subnet(
        self, mock_del_ip_route, mock_get_exposed_routes_on_network
    ):
        gateway = {}
        gateway["ips"] = [
            ipaddress.ip_interface(ip)
            for ip in ["10.0.0.10/26", "fd51:f4b3:872:eda::10/64"]
        ]
        gateway["address_scopes"] = self.addr_scope
        gateway["lrp_ports"] = {""}
        self.bgp_driver.ovn_local_cr_lrps = {"gateway_port": gateway}
        port_info = {
            "cr_lrp": self.cr_lrp0.logical_port,
            "subnets": {
                "fdcc:8cf2:d40c:2::/64",
                "192.168.1.0/24"
            }
        }

        mock_get_exposed_routes_on_network.side_effect = (["route-v4"], [])

        self.bgp_driver._withdraw_subnet(port_info, "gateway_port")

        expected_calls = [
            mock.call(
                mock.ANY,
                "192.168.1.0",
                CONF.bgp_vrf_table_id,
                CONF.bgp_nic,
                vlan=None,
                mask=24,
                via="10.0.0.10",
            ),
            mock.call(
                mock.ANY,
                "fdcc:8cf2:d40c:2::",
                CONF.bgp_vrf_table_id,
                CONF.bgp_nic,
                vlan=None,
                mask=64,
                via="fd51:f4b3:872:eda::10",
            ),
            mock.call(
                mock.ANY,
                "fd51:f4b3:872:eda::",
                CONF.bgp_vrf_table_id,
                CONF.bgp_nic,
                vlan=None,
                mask=64,
                via=None,
            ),
        ]

        mock_del_ip_route.assert_has_calls(expected_calls)

    @mock.patch.object(linux_net, "get_exposed_routes_on_network")
    @mock.patch.object(linux_net, "del_ip_route")
    def test__withdraw_subnet_no_gateway(
        self, mock_del_ip_route, mock_get_exposed_routes_on_network
    ):
        self.bgp_driver.ovn_local_cr_lrps = {}
        self.bgp_driver._withdraw_subnet(self.router_port, "gateway_port")
        mock_del_ip_route.assert_not_called()
        mock_get_exposed_routes_on_network.assert_not_called()

    @mock.patch.object(linux_net, "delete_ip_routes")
    @mock.patch.object(linux_net, "get_routes_on_tables")
    def test_sync(self, mock_get_routes_on_tables, mock_delete_ip_routes):
        def create_route(dst, dst_len, gateway):
            m = mock.Mock([])
            m.dst = dst
            m.dst_len = dst_len
            m.gateway = gateway
            return m

        def create_hashed_route(dst, dst_len, gateway):
            return ovn_stretched_l2_bgp_driver.HashedRoute(
                network=dst,
                prefix_len=dst_len,
                dst=gateway,
            )

        mock__expose_cr_lrp = mock.patch.object(
            self.bgp_driver, "_expose_cr_lrp"
        ).start()

        vrf_routes = [
            create_hashed_route(dst, dst_len, gateway)
            for (dst, dst_len, gateway) in [
                ("192.168.1.0", 24, "10.0.0.1"),
                ("10.0.0.0", 24, None),
                ("fdcc:8cf2:d40c:2::", 64, "fd51:f4b3:872:eda::1"),
                ("fd51:f4b3:872:eda::", 64, None),
            ]
        ]

        # really hacky way to get the routes into self.bgp_driver.vrf_routes
        mock__expose_cr_lrp.side_effect = (
            lambda _, __: self.bgp_driver.vrf_routes.update(vrf_routes)
        )

        self.sb_idl.get_cr_lrp_ports.return_value = [self.cr_lrp0]

        delete_route = create_route("192.168.0.0", 24, "10.0.0.1")
        routes = [
            create_route(dst, dst_len, gateway)
            for (dst, dst_len, gateway) in [
                ("192.168.1.0", 24, "10.0.0.1"),
                ("10.0.0.0", 24, None),
                ("fdcc:8cf2:d40c:2::", 64, "fd51:f4b3:872:eda::1"),
                ("fd51:f4b3:872:eda::", 64, None),
            ]
        ]
        routes.append(delete_route)

        mock_get_routes_on_tables.return_value = routes

        self.bgp_driver.sync()

        mock_get_routes_on_tables.assert_called_once_with(
            [CONF.bgp_vrf_table_id]
        )
        mock_delete_ip_routes.assert_called_once_with([delete_route])
        mock__expose_cr_lrp.assert_called_once_with(
            ["10.0.0.1/24", "fd51:f4b3:872:eda::1/64"], self.cr_lrp0
        )

    def test_withdraw_ip(self):
        mock__withdraw_cr_lrp = mock.patch.object(
            self.bgp_driver, "_withdraw_cr_lrp"
        ).start()

        self.bgp_driver.withdraw_ip(None, self.cr_lrp0)

        mock__withdraw_cr_lrp.assert_called_once_with(None, self.cr_lrp0)

    def test__withdraw_cr_lrp(self):
        mock__withdraw_subnet = mock.patch.object(
            self.bgp_driver, "_withdraw_subnet"
        ).start()

        gateway = {}
        gateway["ips"] = [
            ipaddress.ip_interface(ip)
            for ip in ["10.0.0.10/26", "fd51:f4b3:872:eda::10/64"]
        ]
        gateway["address_scopes"] = self.addr_scope
        self.bgp_driver.ovn_local_cr_lrps = {
            self.cr_lrp0.logical_port: gateway
        }
        gateway["lrp_ports"] = {
            "lrp-lrp_port0",
            "lrp-lrp_port1",
            "lrp-lrp_port2",
        }

        lrp_port0 = {
            "cr_lrp": self.cr_lrp0.logical_port,
            "subnets": {
                "fdcc:8cf2:d40c:1::/64",
                "192.168.0.0/24"}
        }
        lrp_port1 = {
            "cr_lrp": self.cr_lrp0.logical_port,
            "subnets": {
                "fdcc:8cf2:d40c:2::/64",
                "192.168.1.0/24"}
        }

        self.bgp_driver.propagated_lrp_ports = {
            "lrp-lrp_port0": lrp_port0,
            "lrp-lrp_port1": lrp_port1,
        }
        self.bgp_driver.ovn_local_cr_lrps = {
            self.cr_lrp0.logical_port: gateway
        }

        self.bgp_driver._withdraw_cr_lrp(None, self.cr_lrp0)
        mock__withdraw_subnet.assert_has_calls(
            [
                mock.call(lrp_port0, self.cr_lrp0.logical_port),
                mock.call(lrp_port1, self.cr_lrp0.logical_port),
            ],
            any_order=True
        )
        self.assertDictEqual(
            self.bgp_driver.ovn_local_cr_lrps,
            {}
        )
        self.assertDictEqual(
            self.bgp_driver.propagated_lrp_ports,
            {}
        )

    def test__withdraw_cr_lrp_invalid_addr_scope(self):
        mock__withdraw_subnet = mock.patch.object(
            self.bgp_driver, "_withdraw_subnet"
        ).start()

        gateway = {
            "address_scopes": {
                constants.IP_VERSION_4: '',
                constants.IP_VERSION_6: '',
            }
        }
        gateway["lrp_ports"] = {
            "lrp-lrp_port0",
            "lrp-lrp_port1",
            "lrp-lrp_port2",
        }
        self.bgp_driver.propagated_lrp_ports = {
            "lrp-lrp_port0": {},
            "lrp-lrp_port1": {},
            "lrp-lrp_port2": {},
        }
        self.bgp_driver.ovn_local_cr_lrps = {
            self.cr_lrp0.logical_port: gateway
        }

        self.bgp_driver._withdraw_cr_lrp(None, self.cr_lrp0)

        self.sb_idl.get_lrp_ports_for_router.assert_not_called()
        mock__withdraw_subnet.assert_not_called()

    def test_expose_ip(self):
        mock__expose_cr_lrp = mock.patch.object(
            self.bgp_driver, "_expose_cr_lrp"
        ).start()

        ips = ["10.0.0.1/24", "fd51:f4b3:872:eda::1/64"]

        self.bgp_driver.expose_ip(ips, self.cr_lrp0)

        mock__expose_cr_lrp.assert_called_once_with(ips, self.cr_lrp0)

    def test_expose_ip_invalid_type(self):
        mock__expose_cr_lrp = mock.patch.object(
            self.bgp_driver, "_expose_cr_lrp"
        ).start()

        patch_port = mock.Mock()
        patch_port.type = constants.OVN_PATCH_VIF_PORT_TYPE

        self.bgp_driver.expose_ip([], patch_port)

        mock__expose_cr_lrp.assert_not_called()

    def test__expose_cr_lrp(self):
        mock__ensure_network_exposed = mock.patch.object(
            self.bgp_driver, "_ensure_network_exposed"
        ).start()

        lrp_port0 = fakes.create_object(
            {
                "name": "fake-port-lrp0",
                "type": constants.OVN_PATCH_VIF_PORT_TYPE,
                "chassis": "fake-chassis1",
                "external_ids": {},
                "logical_port": "lrp-lrp_port0",
                "options": {
                    "chassis-redirect-port": self.cr_lrp0.logical_port,
                },
            }
        )

        lrp_port1 = fakes.create_object(
            {
                "name": "fake-port-lrp1",
                "type": constants.OVN_PATCH_VIF_PORT_TYPE,
                "mac": ["aa:bb:cc:dd:ee:ee 192.168.1.12 192.168.1.13"],
                "logical_port": "lrp-lrp_port1",
                "chassis": "fake-chassis1",
                "external_ids": {},
                "options": {},
            }
        )

        lrp_port2 = fakes.create_object(
            {
                "name": "fake-port-lrp2",
                "type": constants.OVN_PATCH_VIF_PORT_TYPE,
                "mac": [],
                "logical_port": "lrp-lrp_port2",
                "chassis": "fake-chassis1",
                "external_ids": {},
                "options": {},
            }
        )

        lrp_port3 = fakes.create_object(
            {
                "name": "fake-port-lrp3",
                "type": constants.OVN_PATCH_VIF_PORT_TYPE,
                "mac": [],
                "logical_port": "lrp-lrp_port3",
                "chassis": "",
                "up": [False],
                "external_ids": {},
                "options": {},
            }
        )

        lrp_port4 = fakes.create_object(
            {
                "name": "fake-port-lrp4",
                "type": constants.OVN_PATCH_VIF_PORT_TYPE,
                "mac": [],
                "logical_port": "lrp-lrp_port4",
                "chassis": "",
                "up": [False],
                "options": {},
            }
        )

        lrp_port5 = fakes.create_object(
            {
                "name": "fake-port-lrp5",
                "type": constants.OVN_PATCH_VIF_PORT_TYPE,
                "mac": [],
                "logical_port": "lrp-lrp_port5",
                "chassis": "",
                "up": [False],
                "options": {
                    "chassis-redirect-port": self.cr_lrp0.logical_port,
                },
            }
        )

        self.sb_idl.get_lrp_ports_for_router.return_value = [
            lrp_port0,
            lrp_port1,
            lrp_port2,
            lrp_port3,
            lrp_port4,
            lrp_port5,
        ]

        self.sb_idl.get_port_by_name.return_value = self.fake_patch_port

        ips = ["10.0.0.1/24", "fd51:f4b3:872:eda::1/64"]

        self.bgp_driver._expose_cr_lrp(ips, self.cr_lrp0)

        mock__ensure_network_exposed.assert_has_calls(
            [
                mock.call(lrp_port3, self.cr_lrp0.logical_port),
                mock.call(lrp_port4, self.cr_lrp0.logical_port),
            ]
        )

        self.sb_idl.get_port_by_name.assert_called_once_with("fake-port")

        self.assertEqual(
            {
                self.cr_lrp0.logical_port: {
                    "ips": [ipaddress.ip_interface(ip) for ip in ips],
                    "address_scopes": self.addr_scope,
                    "lrp_ports": set()
                }
            },
            self.bgp_driver.ovn_local_cr_lrps)

    def test__expose_cr_lrp_no_port(self):
        mock__ensure_network_exposed = mock.patch.object(
            self.bgp_driver, "_ensure_network_exposed"
        ).start()

        self.sb_idl.get_port_by_name.return_value = []

        ips = ["10.0.0.1/24", "fd51:f4b3:872:eda::1/64"]

        self.bgp_driver._expose_cr_lrp(ips, self.cr_lrp0)

        mock__ensure_network_exposed.assert_not_called()
        self.sb_idl.get_port_by_name.assert_called_once_with("fake-port")

    @mock.patch.object(driver_utils, "get_addr_scopes")
    def test__expose_cr_lrp_no_addr_scope(self, mock_addr_scopes):
        mock__ensure_network_exposed = mock.patch.object(
            self.bgp_driver, "_ensure_network_exposed"
        ).start()

        self.sb_idl.get_port_by_name.return_value = self.fake_patch_port

        mock_addr_scopes.return_value = {
            constants.IP_VERSION_4: "address_scope_v4",
            constants.IP_VERSION_6: "address_scope_v6",
        }

        self.bgp_driver._expose_cr_lrp([], self.cr_lrp0)

        self.sb_idl.get_port_by_name.assert_called_once_with("fake-port")
        mock_addr_scopes.assert_called_once_with(self.fake_patch_port)
        self.sb_idl.get_lrp_ports_for_router.assert_not_called()
        mock__ensure_network_exposed.assert_not_called()

    def test_expose_remote_ip(self):
        self.assertRaises(
            NotImplementedError,
            self.bgp_driver.expose_remote_ip,
            "1.2.3.4/24")

    def test_withdraw_remote_ip(self):
        self.assertRaises(
            NotImplementedError,
            self.bgp_driver.withdraw_remote_ip,
            "1.2.3.4/24")

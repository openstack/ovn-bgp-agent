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

from oslo_config import cfg
from ovs.stream import Stream
from ovsdbapp.backend.ovs_idl import connection
from ovsdbapp.backend.ovs_idl import idlutils

from ovn_bgp_agent import constants
from ovn_bgp_agent.drivers.openstack.utils import ovn as ovn_utils
from ovn_bgp_agent import exceptions
from ovn_bgp_agent.tests import base as test_base
from ovn_bgp_agent.tests.unit import fakes

CONF = cfg.CONF


class TestOvsdbNbOvnIdl(test_base.TestCase):

    def setUp(self):
        super(TestOvsdbNbOvnIdl, self).setUp()
        self.nb_idl = ovn_utils.OvsdbNbOvnIdl(mock.Mock())

        # Monkey-patch parent class methods
        self.nb_idl.db_find_rows = mock.Mock()
        self.nb_idl.db_list_rows = mock.Mock()
        self.nb_idl.lookup = mock.Mock()

    def test_get_network_vlan_tags(self):
        tag = [123]
        lsp = fakes.create_object({'name': 'port-0',
                                   'tag': tag})
        self.nb_idl.db_find_rows.return_value.execute.return_value = [
            lsp]
        ret = self.nb_idl.get_network_vlan_tags()

        self.assertEqual(tag, ret)
        self.nb_idl.db_find_rows.assert_called_once_with(
            'Logical_Switch_Port',
            ('type', '=', constants.OVN_LOCALNET_VIF_PORT_TYPE))

    def test_get_network_vlan_tag_by_network_name(self):
        network_name = 'net0'
        tag = [123]
        lsp = fakes.create_object({'name': 'port-0',
                                   'options': {'network_name': network_name},
                                   'tag': tag})
        self.nb_idl.db_find_rows.return_value.execute.return_value = [
            lsp]
        ret = self.nb_idl.get_network_vlan_tag_by_network_name(network_name)

        self.assertEqual(tag, ret)
        self.nb_idl.db_find_rows.assert_called_once_with(
            'Logical_Switch_Port',
            ('type', '=', constants.OVN_LOCALNET_VIF_PORT_TYPE))

    def test_ls_has_virtual_ports(self):
        ls_name = 'logical_switch'
        port = fakes.create_object(
            {'type': constants.OVN_VIRTUAL_VIF_PORT_TYPE})
        ls = fakes.create_object({'ports': [port]})
        self.nb_idl.lookup.return_value = ls
        ret = self.nb_idl.ls_has_virtual_ports(ls_name)

        self.assertEqual(True, ret)
        self.nb_idl.lookup.assert_called_once_with('Logical_Switch', ls_name)

    def test_ls_has_virtual_ports_not_found(self):
        ls_name = 'logical_switch'
        port = fakes.create_object({'type': constants.OVN_VM_VIF_PORT_TYPE})
        ls = fakes.create_object({'ports': [port]})
        self.nb_idl.lookup.return_value = ls
        ret = self.nb_idl.ls_has_virtual_ports(ls_name)

        self.assertEqual(False, ret)
        self.nb_idl.lookup.assert_called_once_with('Logical_Switch', ls_name)

    def test_get_nat_by_logical_port(self):
        logical_port = 'logical_port'
        nat_info = ['nat_info']
        self.nb_idl.db_find_rows.return_value.execute.return_value = nat_info
        ret = self.nb_idl.get_nat_by_logical_port(logical_port)

        self.assertEqual('nat_info', ret)
        self.nb_idl.db_find_rows.assert_called_once_with(
            'NAT',
            ('logical_port', '=', logical_port))

    def test_get_active_lsp_on_chassis_options(self):
        chassis = 'local_chassis'
        row1 = fakes.create_object({
            'options': {'requested-chassis': chassis},
            'external_ids': {}})
        row2 = fakes.create_object({
            'options': {'requested-chassis': 'other_chassis'},
            'external_ids': {}})
        self.nb_idl.db_find_rows.return_value.execute.return_value = [
            row1, row2]
        ret = self.nb_idl.get_active_lsp_on_chassis(chassis)

        self.assertEqual([row1], ret)
        self.nb_idl.db_find_rows.assert_called_once_with(
            'Logical_Switch_Port',
            ('up', '=', True))

    def test_get_active_lsp_on_chassis_external_ids(self):
        chassis = 'local_chassis'
        row1 = fakes.create_object({
            'options': {},
            'external_ids': {'neutron:host_id': chassis}})
        row2 = fakes.create_object({
            'options': {},
            'external_ids': {'neutron:host_id': 'other_chassis'}})
        self.nb_idl.db_find_rows.return_value.execute.return_value = [
            row1, row2]
        ret = self.nb_idl.get_active_lsp_on_chassis(chassis)

        self.assertEqual([row1], ret)
        self.nb_idl.db_find_rows.assert_called_once_with(
            'Logical_Switch_Port',
            ('up', '=', True))

    def test_get_active_cr_lrp_on_chassis(self):
        chassis = 'local_chassis'
        row1 = fakes.create_object({
            'status': {'hosting-chassis': 'local_chassis'}})
        row2 = fakes.create_object({
            'status': {'hosting-chassis': 'other_chassis'}})
        row3 = fakes.create_object({})
        self.nb_idl.db_list_rows.return_value.execute.return_value = [
            row1, row2, row3]

        ret = self.nb_idl.get_active_cr_lrp_on_chassis(chassis)

        self.assertEqual([row1], ret)
        self.nb_idl.db_list_rows.assert_called_once_with(
            'Logical_Router_Port')

    def test_get_active_local_lrps(self):
        local_gateway_ports = ['router1']
        row1 = fakes.create_object({
            'external_ids': {
                constants.OVN_DEVICE_OWNER_EXT_ID_KEY:
                    constants.OVN_ROUTER_INTERFACE,
                constants.OVN_DEVICE_ID_EXT_ID_KEY: 'router1'
            }})
        row2 = fakes.create_object({
            'external_ids': {
                constants.OVN_DEVICE_OWNER_EXT_ID_KEY:
                    constants.OVN_ROUTER_INTERFACE,
                constants.OVN_DEVICE_ID_EXT_ID_KEY: 'other_router'
            }})

        self.nb_idl.db_find_rows.return_value.execute.return_value = [
            row1, row2]
        ret = self.nb_idl.get_active_local_lrps(local_gateway_ports)

        self.assertEqual([row1], ret)
        self.nb_idl.db_find_rows.assert_called_once_with(
            'Logical_Switch_Port',
            ('up', '=', True), ('type', '=', constants.OVN_ROUTER_PORT_TYPE),
            ('external_ids', '=', {constants.OVN_DEVICE_OWNER_EXT_ID_KEY:
                                   constants.OVN_ROUTER_INTERFACE}))

    def test_get_active_lsp(self):
        row1 = fakes.create_object({
            'type': constants.OVN_VM_VIF_PORT_TYPE,
            'external_ids': {constants.OVN_LS_NAME_EXT_ID_KEY: 'net1'}})
        row2 = fakes.create_object({
            'type': constants.OVN_VIRTUAL_VIF_PORT_TYPE,
            'external_ids': {constants.OVN_LS_NAME_EXT_ID_KEY: 'net1'}})
        self.nb_idl.db_find_rows.return_value.execute.side_effect = [
            [row1], [row2]]

        ret = self.nb_idl.get_active_lsp('net1')

        self.assertEqual([row1, row2], ret)
        expected_calls = [
            mock.call('Logical_Switch_Port', ('up', '=', True),
                      ('type', '=', constants.OVN_VM_VIF_PORT_TYPE),
                      ('external_ids', '=',
                       {constants.OVN_LS_NAME_EXT_ID_KEY: 'net1'})),
            mock.call().execute(check_error=True),
            mock.call('Logical_Switch_Port', ('up', '=', True),
                      ('type', '=', constants.OVN_VIRTUAL_VIF_PORT_TYPE),
                      ('external_ids', '=',
                       {constants.OVN_LS_NAME_EXT_ID_KEY: 'net1'})),
            mock.call().execute(check_error=True)]

        self.nb_idl.db_find_rows.assert_has_calls(expected_calls)

    def test_get_active_local_lbs(self):
        local_gateway_ports = ['router1']
        lb1 = fakes.create_object({
            'vips': {'vip': 'member1,member2'},
            'external_ids': {
                constants.OVN_LB_LR_REF_EXT_ID_KEY: "neutron-router1"}})
        lb2 = fakes.create_object({
            'vips': {'vip': 'member1,member2'},
            'external_ids': {
                constants.OVN_LB_LR_REF_EXT_ID_KEY: "neutron-router2"}})
        self.nb_idl.db_find_rows.return_value.execute.return_value = [lb1, lb2]

        ret = self.nb_idl.get_active_local_lbs(local_gateway_ports)

        self.assertEqual([lb1], ret)
        self.nb_idl.db_find_rows.assert_called_once_with(
            'Load_Balancer', ('vips', '!=', {}))

        self.nb_idl.db_find_rows.reset_mock()

        lb3 = fakes.create_object({
            'vips': {'fip': 'member1'},
            'external_ids': {
                constants.OVN_LR_NAME_EXT_ID_KEY: "neutron-router1"}})
        self.nb_idl.db_find_rows.return_value.execute.return_value = [
            lb1, lb2, lb3]
        ret = self.nb_idl.get_active_local_lbs(local_gateway_ports)
        self.assertEqual([lb1, lb3], ret)
        self.nb_idl.db_find_rows.assert_called_once_with(
            'Load_Balancer', ('vips', '!=', {}))


class TestOvsdbSbOvnIdl(test_base.TestCase):

    def setUp(self):
        super(TestOvsdbSbOvnIdl, self).setUp()
        self.sb_idl = ovn_utils.OvsdbSbOvnIdl(mock.Mock())

        # Monkey-patch parent class methods
        self.sb_idl.db_find_rows = mock.Mock()
        self.sb_idl.db_list_rows = mock.Mock()

    def test_get_port_by_name(self):
        fake_p_info = 'fake-port-info'
        port = 'fake-port'
        self.sb_idl.db_find_rows.return_value.execute.return_value = [
            fake_p_info]
        ret = self.sb_idl.get_port_by_name(port)

        self.assertEqual(fake_p_info, ret)
        self.sb_idl.db_find_rows.assert_called_once_with(
            'Port_Binding', ('logical_port', '=', port))

    def test_get_port_by_name_empty(self):
        port = 'fake-port'
        self.sb_idl.db_find_rows.return_value.execute.return_value = []
        ret = self.sb_idl.get_port_by_name(port)

        self.assertEqual([], ret)
        self.sb_idl.db_find_rows.assert_called_once_with(
            'Port_Binding', ('logical_port', '=', port))

    def test_get_ports_on_datapath(self):
        dp = 'fake-datapath'
        self.sb_idl.db_find_rows.return_value.execute.return_value = [
            'fake-port']
        ret = self.sb_idl.get_ports_on_datapath(dp)

        self.assertEqual(['fake-port'], ret)
        self.sb_idl.db_find_rows.assert_called_once_with(
            'Port_Binding', ('datapath', '=', dp))

    def test_get_ports_on_datapath_port_type(self):
        dp = 'fake-datapath'
        p_type = 'fake-type'
        self.sb_idl.db_find_rows.return_value.execute.return_value = [
            'fake-port']
        ret = self.sb_idl.get_ports_on_datapath(dp, port_type=p_type)

        self.assertEqual(['fake-port'], ret)
        self.sb_idl.db_find_rows.assert_called_once_with(
            'Port_Binding', ('datapath', '=', dp), ('type', '=', p_type))

    def test_get_ports_by_type(self):
        fake_p_info = 'fake-port-info'
        port_type = 'fake-type'
        self.sb_idl.db_find_rows.return_value.execute.return_value = [
            fake_p_info]
        ret = self.sb_idl.get_ports_by_type(port_type)

        self.assertEqual([fake_p_info], ret)
        self.sb_idl.db_find_rows.assert_called_once_with(
            'Port_Binding', ('type', '=', port_type))

    def test_is_provider_network(self):
        dp = 'fake-datapath'
        self.sb_idl.db_find_rows.return_value.execute.return_value = ['fake']
        self.assertTrue(self.sb_idl.is_provider_network(dp))
        self.sb_idl.db_find_rows.assert_called_once_with(
            'Port_Binding', ('datapath', '=', dp),
            ('type', '=', constants.OVN_LOCALNET_VIF_PORT_TYPE))

    def test_is_provider_network_false(self):
        dp = 'fake-datapath'
        self.sb_idl.db_find_rows.return_value.execute.return_value = []
        self.assertFalse(self.sb_idl.is_provider_network(dp))
        self.sb_idl.db_find_rows.assert_called_once_with(
            'Port_Binding', ('datapath', '=', dp),
            ('type', '=', constants.OVN_LOCALNET_VIF_PORT_TYPE))

    def test_get_fip_associated(self):
        port = '1ad5f7e1-fcca-4791-bf50-120c4c73e602'
        datapath = '3e2dc454-6970-4419-9132-b3593d19cdfa'
        fip = '172.24.200.7'
        row = fakes.create_object({
            'datapath': datapath,
            'nat_addresses': ['aa:bb:cc:dd:ee:ff {} is_chassis_resident('
                              '"cr-lrp-{}")'.format(fip, port)]})
        self.sb_idl.db_find_rows.return_value.execute.return_value = [row]
        fip_addr, fip_dp = self.sb_idl.get_fip_associated(port)

        self.assertEqual(fip, fip_addr)
        self.assertEqual(datapath, fip_dp)
        self.sb_idl.db_find_rows.assert_called_once_with(
            'Port_Binding', ('type', '=', constants.OVN_PATCH_VIF_PORT_TYPE))

    def test_get_fip_associated_not_found(self):
        self.sb_idl.db_find_rows.return_value.execute.return_value = []
        fip_addr, fip_dp = self.sb_idl.get_fip_associated('fake-port')

        self.assertIsNone(fip_addr)
        self.assertIsNone(fip_dp)
        self.sb_idl.db_find_rows.assert_called_once_with(
            'Port_Binding', ('type', '=', constants.OVN_PATCH_VIF_PORT_TYPE))

    def _test_is_port_on_chassis(self, should_match=True):
        chassis_name = 'fake-chassis'
        with mock.patch.object(self.sb_idl, 'get_port_by_name') as mock_p:
            ch = fakes.create_object({'name': chassis_name})
            mock_p.return_value = fakes.create_object(
                {'type': constants.OVN_VM_VIF_PORT_TYPE,
                 'chassis': [ch]})
            if should_match:
                self.assertTrue(self.sb_idl.is_port_on_chassis(
                    'fake-port', chassis_name))
            else:
                self.assertFalse(self.sb_idl.is_port_on_chassis(
                    'fake-port', 'wrong-chassis'))

    def test_is_port_on_chassis(self):
        self._test_is_port_on_chassis()

    def test_is_port_on_chassis_no_match_on_chassis(self):
        self._test_is_port_on_chassis(should_match=False)

    def test_is_port_on_chassis_port_not_found(self):
        with mock.patch.object(self.sb_idl, 'get_port_by_name') as mock_p:
            mock_p.return_value = []
            self.assertFalse(self.sb_idl.is_port_on_chassis(
                'fake-port', 'fake-chassis'))

    def test_is_port_without_chassis(self):
        chassis_name = 'fake-chassis'
        with mock.patch.object(self.sb_idl, 'get_port_by_name') as mock_p:
            ch = fakes.create_object({'name': chassis_name})
            mock_p.return_value = fakes.create_object(
                {'type': constants.OVN_VM_VIF_PORT_TYPE,
                 'chassis': [ch]})
            self.assertFalse(self.sb_idl.is_port_without_chassis('fake-port'))

    def test_is_port_without_chassis_no_chassis(self):
        with mock.patch.object(self.sb_idl, 'get_port_by_name') as mock_p:
            mock_p.return_value = fakes.create_object(
                {'type': constants.OVN_VM_VIF_PORT_TYPE,
                 'chassis': []})
            self.assertTrue(self.sb_idl.is_port_without_chassis('fake-port'))

    def _test_is_port_deleted(self, port_exist=True):
        ret_value = mock.Mock() if port_exist else []
        with mock.patch.object(self.sb_idl, 'get_port_by_name') as mock_p:
            mock_p.return_value = ret_value
            if port_exist:
                # Should return False as the port is not deleted
                self.assertFalse(self.sb_idl.is_port_deleted('fake-port'))
            else:
                self.assertTrue(self.sb_idl.is_port_deleted('fake-port'))

    def test_is_port_deleted(self):
        self._test_is_port_deleted()

    def test_is_port_deleted_false(self):
        self._test_is_port_deleted(port_exist=False)

    def test_get_ports_on_chassis(self):
        ch0 = fakes.create_object({'name': 'chassis-0'})
        ch1 = fakes.create_object({'name': 'chassis-1'})
        port0 = fakes.create_object({'name': 'port-0', 'chassis': [ch0]})
        port1 = fakes.create_object({'name': 'port-1', 'chassis': [ch1]})
        port2 = fakes.create_object({'name': 'port-2', 'chassis': [ch0]})
        self.sb_idl.db_list_rows.return_value.execute.return_value = [
            port0, port1, port2]

        ret = self.sb_idl.get_ports_on_chassis('chassis-0')
        self.assertIn(port0, ret)
        self.assertIn(port2, ret)
        # Port-1 is bound to chassis-1
        self.assertNotIn(port1, ret)

    def _test_get_provider_datapath_from_cr_lrp(self, port, found_port=True):
        ret_value = (fakes.create_object({'datapath': 'dp1'})
                     if found_port else None)
        with mock.patch.object(self.sb_idl, 'get_port_by_name') as mock_p:
            mock_p.return_value = ret_value
            if found_port:
                self.assertEqual(
                    self.sb_idl.get_provider_datapath_from_cr_lrp(port),
                    'dp1')
            else:
                self.assertIsNone(
                    self.sb_idl.get_provider_datapath_from_cr_lrp(port))
            if port.startswith('cr-lrp'):
                mock_p.assert_called_once_with(port.split("cr-lrp-")[1])
            else:
                mock_p.assert_not_called()

    def test_get_provider_datapath_from_cr_lrp(self):
        port = 'cr-lrp-port'
        self._test_get_provider_datapath_from_cr_lrp(port)

    def test_get_provider_datapath_from_cr_lrp_no_cr_lrp(self):
        port = 'port'
        self._test_get_provider_datapath_from_cr_lrp(port, found_port=False)

    def test_get_provider_datapath_from_cr_lrp_no_port(self):
        port = 'cr-lrp-port'
        self._test_get_provider_datapath_from_cr_lrp(port, found_port=False)

    def test_get_datapath_from_port_peer(self):
        with mock.patch.object(self.sb_idl, 'get_port_datapath') as m_dp:
            port0 = fakes.create_object({'name': 'port-0',
                                         'options': {'peer': 'port-peer'}})
            self.sb_idl.get_datapath_from_port_peer(port0)
            m_dp.assert_called_once_with('port-peer')

    def _test_get_network_name_and_tag(self, network_in_bridge_map=True):
        tag = 1001
        network = 'public' if network_in_bridge_map else 'spongebob'
        with mock.patch.object(self.sb_idl, 'get_ports_on_datapath') as m_dp:
            row = fakes.create_object({
                'options': {'network_name': network},
                'tag': tag})
            m_dp.return_value = [row, ]
            net_name, net_tag = self.sb_idl.get_network_name_and_tag(
                'fake-dp', 'br-ex:public'.format(network))

            if network_in_bridge_map:
                self.assertEqual(network, net_name)
                self.assertEqual(tag, net_tag)
            else:
                self.assertIsNone(net_name)
                self.assertIsNone(net_tag)

    def test_get_network_name_and_tag(self):
        self._test_get_network_name_and_tag()

    def test_get_network_name_and_tag_not_in_bridge_mappings(self):
        self._test_get_network_name_and_tag(network_in_bridge_map=False)

    def test_get_netweork_vlan_tags(self):
        tag = [1001]
        row = fakes.create_object({'tag': tag})
        self.sb_idl.db_find_rows.return_value.execute.return_value = [row, ]

        ret = self.sb_idl.get_network_vlan_tags()
        self.assertEqual(tag, ret)

    def _test_get_network_vlan_tag_by_network_name(self, match=True):
        network = 'public' if match else 'spongebob'
        tag = [1001]
        row = fakes.create_object({
            'options': {'network_name': 'public'},
            'tag': tag})
        self.sb_idl.db_find_rows.return_value.execute.return_value = [row, ]

        ret = self.sb_idl.get_network_vlan_tag_by_network_name(network)
        if match:
            self.assertEqual(tag, ret)
        else:
            self.assertEqual([], ret)

    def test_get_network_vlan_tag_by_network_name(self):
        self._test_get_network_vlan_tag_by_network_name()

    def test_get_network_vlan_tag_by_network_name_no_match(self):
        self._test_get_network_vlan_tag_by_network_name(match=False)

    def _test_is_router_gateway_on_chassis(self, match=True):
        chassis = 'chassis-0' if match else 'spongebob'
        port = '39c38ce6-f0ea-484e-a57c-aec0d4e961a5'
        with mock.patch.object(self.sb_idl, 'get_ports_on_datapath') as m_dp:
            ch = fakes.create_object({'name': 'chassis-0'})
            row = fakes.create_object({'logical_port': port, 'chassis': [ch]})
            m_dp.return_value = [row, ]
            ret = self.sb_idl.is_router_gateway_on_chassis('fake-dp', chassis)

            if match:
                self.assertEqual(port, ret)
            else:
                self.assertIsNone(ret)

    def test_is_router_gateway_on_chassis(self):
        self._test_is_router_gateway_on_chassis()

    def test_is_router_gateway_on_chassis_not_on_chassis(self):
        self._test_is_router_gateway_on_chassis(match=False)

    def _test_is_router_gateway_on_any_chassis(self, match=True):
        if match:
            ch = fakes.create_object({'name': 'chassis-0'})
        else:
            ch = fakes.create_object({'name': ''})
        port = '39c38ce6-f0ea-484e-a57c-aec0d4e961a5'
        with mock.patch.object(self.sb_idl, 'get_ports_on_datapath') as m_dp:
            row = fakes.create_object({'logical_port': port, 'chassis': [ch]})
            m_dp.return_value = [row, ]
            ret = self.sb_idl.is_router_gateway_on_any_chassis('fake-dp')

            if match:
                self.assertEqual(row, ret)
            else:
                self.assertIsNone(ret)

    def test_is_router_gateway_on_any_chassis(self):
        self._test_is_router_gateway_on_any_chassis()

    def test_is_router_gateway_on_chassis_not_on_any_chassis(self):
        self._test_is_router_gateway_on_any_chassis(match=False)

    def _test_get_lrps_for_datapath(self, has_options=True):
        peer = '75c793bd-d865-48f3-8f05-68ba4239d14e'
        with mock.patch.object(self.sb_idl, 'get_ports_on_datapath') as m_dp:
            options = {}
            if has_options:
                options.update({'peer': peer})
            row = fakes.create_object({'options': options})
            m_dp.return_value = [row, ]
            ret = self.sb_idl.get_lrps_for_datapath('fake-dp')

            if has_options:
                self.assertEqual([peer], ret)
            else:
                self.assertEqual([], ret)

    def test_get_lrps_for_datapath(self):
        self._test_get_lrps_for_datapath()

    def test_get_lrps_for_datapath_no_options(self):
        self._test_get_lrps_for_datapath(has_options=False)

    def test_get_lrp_ports_for_router(self):
        with mock.patch.object(self.sb_idl, 'get_ports_on_datapath') as m_dp:
            datapath = 'router-dp'
            self.sb_idl.get_lrp_ports_for_router(datapath)
            m_dp.assert_called_once_with(datapath,
                                         constants.OVN_PATCH_VIF_PORT_TYPE)

    def test_get_lrp_ports_on_provider(self):
        port = '39c38ce6-f0ea-484e-a57c-aec0d4e961a5'
        with mock.patch.object(self.sb_idl, 'get_ports_by_type') as m_pt:
            ch = fakes.create_object({'name': 'chassis-0'})
            row = fakes.create_object({'logical_port': port, 'chassis': [ch],
                                       'datapath': 'fake-dp'})
            m_pt.return_value = [row, ]

            with mock.patch.object(self.sb_idl, 'is_provider_network') as m_pn:
                self.sb_idl.get_lrp_ports_on_provider()
                m_pt.assert_called_once_with(constants.OVN_PATCH_VIF_PORT_TYPE)
                m_pn.assert_called_once_with(row.datapath)

    def test_get_lrp_ports_on_provider_starts_with_lrp(self):
        port = 'lrp-39c38ce6-f0ea-484e-a57c-aec0d4e961a5'
        with mock.patch.object(self.sb_idl, 'get_ports_by_type') as m_pt:
            ch = fakes.create_object({'name': 'chassis-0'})
            row = fakes.create_object({'logical_port': port, 'chassis': [ch]})
            m_pt.return_value = [row, ]

            with mock.patch.object(self.sb_idl, 'is_provider_network') as m_pn:
                self.sb_idl.get_lrp_ports_on_provider()
                m_pt.assert_called_once_with(constants.OVN_PATCH_VIF_PORT_TYPE)
                m_pn.assert_not_called()

    def _test_get_port_datapath(self, port_found=True):
        dp = '3fce2c5f-7801-469b-894e-05561e3bda15'
        with mock.patch.object(self.sb_idl, 'get_port_by_name') as mock_p:
            port_info = None
            if port_found:
                port_info = fakes.create_object({'datapath': dp})
            mock_p.return_value = port_info
            ret = self.sb_idl.get_port_datapath('fake-port')

            if port_found:
                self.assertEqual(dp, ret)
            else:
                self.assertIsNone(ret)

    def test_get_port_datapath(self):
        self._test_get_port_datapath()

    def test_get_port_datapath_port_not_found(self):
        self._test_get_port_datapath(port_found=False)

    def test_get_ip_from_port_peer(self):
        ip = '172.24.200.7'
        port = fakes.create_object({'options': {'peer': 'fake-peer'}})
        with mock.patch.object(self.sb_idl, 'get_port_by_name') as mock_p:
            port_peer = fakes.create_object({
                'mac': ['aa:bb:cc:dd:ee:ff 172.24.200.7']})
            mock_p.return_value = port_peer
            ret = self.sb_idl.get_ip_from_port_peer(port)

            self.assertEqual(ip, ret)

    def test_get_ip_from_port_peer_port_not_found(self):
        port = fakes.create_object({'options': {'peer': 'fake-peer'}})
        with mock.patch.object(self.sb_idl, 'get_port_by_name') as mock_p:
            mock_p.return_value = []

            self.assertRaises(exceptions.PortNotFound,
                              self.sb_idl.get_ip_from_port_peer, port)

    def _test_get_evpn_info_from_port_name(self, crlrp=False, lrp=False):
        port = '48dc4289-a1b9-4505-b513-4eff0c460c29'
        if crlrp:
            port_name = constants.OVN_CRLRP_PORT_NAME_PREFIX + port
        elif lrp:
            port_name = constants.OVN_LRP_PORT_NAME_PREFIX + port
        else:
            port_name = port

        expected_return = 'spongebob'
        with mock.patch.object(self.sb_idl, 'get_port_by_name') as mock_p:
            with mock.patch.object(self.sb_idl, 'get_evpn_info') as mock_evpn:
                mock_evpn.return_value = expected_return
                ret = self.sb_idl.get_evpn_info_from_port_name(port_name)

                mock_p.assert_called_once_with(port)
                self.assertEqual(expected_return, ret)

    def test_get_evpn_info_from_port_name(self):
        self._test_get_evpn_info_from_port_name()

    def test_get_evpn_info_from_port_name_crlrp(self):
        self._test_get_evpn_info_from_port_name(crlrp=True)

    def test_get_evpn_info_from_port_name_lrp(self):
        self._test_get_evpn_info_from_port_name(lrp=True)

    def _test_get_evpn_info(self, value_error=False):
        vni = 'invalid-vni' if value_error else '1001'
        port = fakes.create_object({
            'logical_port': 'fake-port',
            'external_ids': {constants.OVN_EVPN_VNI_EXT_ID_KEY: vni,
                             constants.OVN_EVPN_AS_EXT_ID_KEY: '123'}})
        ret = self.sb_idl.get_evpn_info(port)

        expected_return = {}
        if not value_error:
            expected_return.update({'vni': 1001, 'bgp_as': 123})

        self.assertEqual(expected_return, ret)

    def test_get_evpn_info(self):
        self._test_get_evpn_info()

    def test_get_evpn_info_value_error(self):
        self._test_get_evpn_info(value_error=True)

    def test_get_evpn_info_key_error(self):
        port = fakes.create_object({'logical_port': 'fake-port',
                                    'external_ids': {}})
        ret = self.sb_idl.get_evpn_info(port)
        self.assertEqual({}, ret)

    def _test_get_port_if_local_chassis(self, wrong_chassis=False):
        chassis = 'wrong-chassis' if wrong_chassis else 'chassis-0'
        with mock.patch.object(self.sb_idl, 'get_port_by_name') as mock_p:
            ch = fakes.create_object({'name': 'chassis-0'})
            port = fakes.create_object({'chassis': [ch]})
            mock_p.return_value = port
            ret = self.sb_idl.get_port_if_local_chassis('fake-port', chassis)

            if wrong_chassis:
                self.assertIsNone(ret)
            else:
                self.assertEqual(port, ret)

    def test_get_port_if_local_chassis(self):
        self._test_get_port_if_local_chassis()

    def test_get_port_if_local_chassis_wrong_chassis(self):
        self._test_get_port_if_local_chassis(wrong_chassis=True)

    def test_get_virtual_ports_on_datapath_by_chassis(self):
        with mock.patch.object(self.sb_idl, 'get_ports_on_datapath') as mock_p:
            ch1 = fakes.create_object({'name': 'chassis-1'})
            ch2 = fakes.create_object({'name': 'chassis-2'})
            port1 = fakes.create_object({'chassis': [ch1]})
            port2 = fakes.create_object({'chassis': [ch2]})
            mock_p.return_value = [port1, port2]
            ret = self.sb_idl.get_virtual_ports_on_datapath_by_chassis(
                'fake-datapath', 'chassis-1')

            self.assertEqual([port1], ret)

    def test_get_ovn_lb(self):
        fake_lb_info = 'fake-lbinfo'
        lb = 'fake-lb'
        self.sb_idl.db_find_rows.return_value.execute.return_value = [
            fake_lb_info]
        ret = self.sb_idl.get_ovn_lb(lb)

        self.assertEqual(fake_lb_info, ret)
        self.sb_idl.db_find_rows.assert_called_once_with(
            'Load_Balancer', ('name', '=', lb))

    def test_get_ovn_lb_empty(self):
        lb = 'fake-port'
        self.sb_idl.db_find_rows.return_value.execute.return_value = []
        ret = self.sb_idl.get_ovn_lb(lb)

        self.assertEqual([], ret)
        self.sb_idl.db_find_rows.assert_called_once_with(
            'Load_Balancer', ('name', '=', lb))

    def test_get_provider_ovn_lbs_on_cr_lrp(self):
        lb1_name = 'ovn-lb-vip-fake-lb1'
        lb2_name = 'ovn-lb-vip-fake-lb2'
        provider_dp = 'fake-provider-dp'
        router_dp = ['fake-router-dp']
        router_lrp = 'fake-router-lrp'
        dp1 = fakes.create_object({'datapaths': ['fake-subnet-dp']})
        lb1 = fakes.create_object({'datapath_group': [dp1],
                                   'name': 'fake-lb1'})
        port0 = fakes.create_object({
            'logical_port': 'fake-port-0',
            'external_ids': {constants.OVN_CIDRS_EXT_ID_KEY: '10.0.0.15/24',
                             constants.OVN_PORT_NAME_EXT_ID_KEY: lb1_name}})
        port1 = fakes.create_object({
            'logical_port': 'fake-port-1',
            'external_ids': {constants.OVN_CIDRS_EXT_ID_KEY: '10.0.0.16/24'}})
        port2 = fakes.create_object({
            'logical_port': 'fake-port-0',
            'external_ids': {constants.OVN_CIDRS_EXT_ID_KEY: '10.0.0.17/24',
                             constants.OVN_PORT_NAME_EXT_ID_KEY: lb2_name}})

        self.sb_idl.db_find_rows.return_value.execute.return_value = [
            port0, port1, port2]

        mock_lb = mock.patch.object(self.sb_idl, 'get_ovn_lb').start()
        mock_lb.side_effect = (lb1, [])

        mock_lrp = mock.patch.object(self.sb_idl,
                                     'get_lrps_for_datapath').start()
        mock_lrp.return_value = [router_lrp]

        mock_get_port_dp = mock.patch.object(self.sb_idl,
                                             'get_port_datapath').start()
        mock_get_port_dp.return_value = router_dp

        ret = self.sb_idl.get_provider_ovn_lbs_on_cr_lrp(provider_dp,
                                                         router_dp)
        expected_return = {'fake-lb1': '10.0.0.15'}
        self.assertEqual(expected_return, ret)

    def test_get_ovn_vip_port(self):
        lb_name = 'ovn-lb-vip-fake-lb'
        lb1 = fakes.create_object(
            {'external_ids': {
                constants.OVN_PORT_NAME_EXT_ID_KEY: 'different-name'}})
        lb2 = fakes.create_object(
            {'external_ids': {constants.OVN_PORT_NAME_EXT_ID_KEY: lb_name}})

        self.sb_idl.db_find_rows.return_value.execute.return_value = [
            lb1, lb2]
        ret = self.sb_idl.get_ovn_vip_port('fake-lb')

        self.assertEqual(lb2, ret)


class TestOvnNbIdl(test_base.TestCase):

    def setUp(self):
        super(TestOvnNbIdl, self).setUp()
        mock.patch.object(idlutils, 'get_schema_helper').start()
        mock.patch.object(ovn_utils.OvnIdl, '__init__').start()
        self.nb_idl = ovn_utils.OvnNbIdl('tcp:127.0.0.1:6640')

    @mock.patch.object(Stream, 'ssl_set_ca_cert_file')
    @mock.patch.object(Stream, 'ssl_set_certificate_file')
    @mock.patch.object(Stream, 'ssl_set_private_key_file')
    def test__check_and_set_ssl_files(
            self, mock_ssl_priv_key, mock_ssl_cert, mock_ssl_ca_cert):
        CONF.set_override('ovn_nb_private_key', 'fake-priv-key', group='ovn')
        CONF.set_override('ovn_nb_certificate', 'fake-cert', group='ovn')
        CONF.set_override('ovn_nb_ca_cert', 'fake-ca-cert', group='ovn')

        self.nb_idl._check_and_set_ssl_files('fake-schema')

        mock_ssl_priv_key.assert_called_once_with('fake-priv-key')
        mock_ssl_cert.assert_called_once_with('fake-cert')
        mock_ssl_ca_cert.assert_called_once_with('fake-ca-cert')

    @mock.patch.object(connection, 'Connection')
    def test_start(self, mock_conn):
        notify_handler = mock.Mock()
        self.nb_idl.notify_handler = notify_handler
        self.nb_idl._events = ['fake-event0', 'fake-event1']

        self.nb_idl.start()

        mock_conn.assert_called_once_with(self.nb_idl, timeout=180)
        notify_handler.watch_events.assert_called_once_with(
            ['fake-event0', 'fake-event1'])


class TestOvnSbIdl(test_base.TestCase):

    def setUp(self):
        super(TestOvnSbIdl, self).setUp()
        mock.patch.object(idlutils, 'get_schema_helper').start()
        mock.patch.object(ovn_utils.OvnIdl, '__init__').start()
        self.sb_idl = ovn_utils.OvnSbIdl('tcp:127.0.0.1:6640')

    @mock.patch.object(Stream, 'ssl_set_ca_cert_file')
    @mock.patch.object(Stream, 'ssl_set_certificate_file')
    @mock.patch.object(Stream, 'ssl_set_private_key_file')
    def test__check_and_set_ssl_files(
            self, mock_ssl_priv_key, mock_ssl_cert, mock_ssl_ca_cert):
        CONF.set_override('ovn_sb_private_key', 'fake-priv-key', group='ovn')
        CONF.set_override('ovn_sb_certificate', 'fake-cert', group='ovn')
        CONF.set_override('ovn_sb_ca_cert', 'fake-ca-cert', group='ovn')

        self.sb_idl._check_and_set_ssl_files('fake-schema')

        mock_ssl_priv_key.assert_called_once_with('fake-priv-key')
        mock_ssl_cert.assert_called_once_with('fake-cert')
        mock_ssl_ca_cert.assert_called_once_with('fake-ca-cert')

    @mock.patch.object(connection, 'Connection')
    def test_start(self, mock_conn):
        notify_handler = mock.Mock()
        self.sb_idl.notify_handler = notify_handler
        self.sb_idl._events = ['fake-event0', 'fake-event1']

        self.sb_idl.start()

        mock_conn.assert_called_once_with(self.sb_idl, timeout=180)
        notify_handler.watch_events.assert_called_once_with(
            ['fake-event0', 'fake-event1'])

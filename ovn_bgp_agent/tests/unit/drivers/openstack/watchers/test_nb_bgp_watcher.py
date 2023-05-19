
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

from ovn_bgp_agent import constants
from ovn_bgp_agent.drivers.openstack.watchers import nb_bgp_watcher
from ovn_bgp_agent.tests import base as test_base
from ovn_bgp_agent.tests import utils


class TestLogicalSwitchPortProviderCreateEvent(test_base.TestCase):

    def setUp(self):
        super(TestLogicalSwitchPortProviderCreateEvent, self).setUp()
        self.chassis = 'fake-chassis'
        self.agent = mock.Mock(chassis=self.chassis)
        self.event = nb_bgp_watcher.LogicalSwitchPortProviderCreateEvent(
            self.agent)

    def test_match_fn(self):
        row = utils.create_row(type=constants.OVN_VM_VIF_PORT_TYPE,
                               addresses=['mac 192.168.0.1'],
                               options={'requested-chassis': self.chassis},
                               up=[True])
        old = utils.create_row(options={}, up=[True])
        self.assertTrue(self.event.match_fn(mock.Mock(), row, old))

    def test_match_fn_port_up(self):
        row = utils.create_row(type=constants.OVN_VM_VIF_PORT_TYPE,
                               addresses=['mac 192.168.0.1'],
                               options={'requested-chassis': self.chassis},
                               up=[True])
        old = utils.create_row(type=constants.OVN_VM_VIF_PORT_TYPE,
                               addresses=['mac 192.168.0.1'],
                               options={'requested-chassis': self.chassis},
                               up=[False])
        self.assertTrue(self.event.match_fn(mock.Mock(), row, old))

    def test_match_fn_external_id(self):
        row = utils.create_row(type=constants.OVN_VM_VIF_PORT_TYPE,
                               addresses=['mac 192.168.0.1'],
                               external_ids={'neutron:host_id': self.chassis},
                               up=[True])
        old = utils.create_row(external_ids={}, up=[True])
        self.assertTrue(self.event.match_fn(mock.Mock(), row, old))

    def test_match_fn_exception(self):
        row = utils.create_row(type=constants.OVN_VM_VIF_PORT_TYPE,
                               up=[False])
        self.assertFalse(self.event.match_fn(mock.Mock(), row, mock.Mock()))

    def test_match_fn_not_up(self):
        row = utils.create_row(type=constants.OVN_VM_VIF_PORT_TYPE,
                               addresses=['mac 192.168.0.1'],
                               options={'requested-chassis': self.chassis},
                               up=[False])
        self.assertFalse(self.event.match_fn(mock.Mock(), row, mock.Mock()))

    def test_match_fn_invalid_address(self):
        row = utils.create_row(type=constants.OVN_VM_VIF_PORT_TYPE,
                               addresses=['mac '],
                               options={'requested-chassis': self.chassis},
                               up=[True])
        self.assertFalse(self.event.match_fn(mock.Mock(), row, mock.Mock()))

    def test_match_fn_wrong_chassis(self):
        row = utils.create_row(type=constants.OVN_VM_VIF_PORT_TYPE,
                               addresses=['mac 192.168.0.1'],
                               options={'requested-chassis': 'fake_chassis'},
                               up=[True])
        old = utils.create_row(options={}, up=[True])
        self.assertFalse(self.event.match_fn(mock.Mock(), row, old))

    def test_run(self):
        row = utils.create_row(type=constants.OVN_VM_VIF_PORT_TYPE,
                               addresses=['mac 192.168.0.1'],
                               options={'requested-chassis': self.chassis},
                               up=[True])
        self.event.run(mock.Mock(), row, mock.Mock())
        self.agent.expose_ip.assert_called_once_with(['192.168.0.1'], row)

    def test_run_wrong_type(self):
        row = utils.create_row(
            type=constants.OVN_CHASSISREDIRECT_VIF_PORT_TYPE,
            addresses=['mac 192.168.0.1'],
            options={'requested-chassis': self.chassis},
            up=[True])
        self.event.run(mock.Mock(), row, mock.Mock())
        self.agent.expose_ip.assert_not_called()


class TestLogicalSwitchPortProviderDeleteEvent(test_base.TestCase):

    def setUp(self):
        super(TestLogicalSwitchPortProviderDeleteEvent, self).setUp()
        self.chassis = 'fake-chassis'
        self.agent = mock.Mock(chassis=self.chassis)
        self.event = nb_bgp_watcher.LogicalSwitchPortProviderDeleteEvent(
            self.agent)

    def test_match_fn_delete(self):
        event = self.event.ROW_DELETE
        row = utils.create_row(type=constants.OVN_VM_VIF_PORT_TYPE,
                               addresses=['mac 192.168.0.1'],
                               options={'requested-chassis': self.chassis},
                               up=[True])
        self.assertTrue(self.event.match_fn(event, row, mock.Mock()))

    def test_match_fn_update(self):
        event = self.event.ROW_UPDATE
        row = utils.create_row(type=constants.OVN_VM_VIF_PORT_TYPE,
                               addresses=['mac 192.168.0.1'],
                               options={'requested-chassis': self.chassis},
                               up=[False])
        old = utils.create_row(options={'requested-chassis': self.chassis},
                               up=[True])
        self.assertTrue(self.event.match_fn(event, row, old))

    def test_match_fn_update_chassis(self):
        event = self.event.ROW_UPDATE
        row = utils.create_row(type=constants.OVN_VM_VIF_PORT_TYPE,
                               addresses=['mac 192.168.0.1'],
                               external_ids={'neutron:host_id': 'chassis2'},
                               up=[True])
        old = utils.create_row(external_ids={'neutron:host_id': self.chassis},
                               up=[True])
        self.assertTrue(self.event.match_fn(event, row, old))

    def test_match_fn_exception(self):
        row = utils.create_row(type=constants.OVN_VM_VIF_PORT_TYPE,
                               up=[False])
        self.assertFalse(self.event.match_fn(mock.Mock(), row, mock.Mock()))

    def test_match_fn_not_up(self):
        row = utils.create_row(type=constants.OVN_VM_VIF_PORT_TYPE,
                               addresses=['mac 192.168.0.1'],
                               options={'requested-chassis': self.chassis},
                               up=[False])
        old = utils.create_row(options={'requested-chassis': self.chassis},
                               up=[False])
        self.assertFalse(self.event.match_fn(mock.Mock(), row, old))

    def test_match_fn_invalid_address(self):
        row = utils.create_row(type=constants.OVN_VM_VIF_PORT_TYPE,
                               addresses=['mac '],
                               options={'requested-chassis': self.chassis},
                               up=[True])
        self.assertFalse(self.event.match_fn(mock.Mock(), row, mock.Mock()))

    def test_match_fn_wrong_chassis(self):
        row = utils.create_row(type=constants.OVN_VM_VIF_PORT_TYPE,
                               addresses=['mac 192.168.0.1'],
                               options={'requested-chassis': self.chassis},
                               up=[True])
        old = utils.create_row(options={'requested-chassis': 'other_chassis'})
        self.assertFalse(self.event.match_fn(mock.Mock(), row, old))

    def test_run(self):
        row = utils.create_row(type=constants.OVN_VM_VIF_PORT_TYPE,
                               addresses=['mac 192.168.0.1'],
                               options={'requested-chassis': self.chassis},
                               up=[True])
        self.event.run(mock.Mock(), row, mock.Mock())
        self.agent.withdraw_ip.assert_called_once_with(['192.168.0.1'], row)

    def test_run_wrong_type(self):
        row = utils.create_row(
            type=constants.OVN_CHASSISREDIRECT_VIF_PORT_TYPE,
            addresses=['mac 192.168.0.1'],
            options={'requested-chassis': self.chassis},
            up=[True])
        self.event.run(mock.Mock(), row, mock.Mock())
        self.agent.withdraw_ip.assert_not_called()


class TestLogicalSwitchPortFIPCreateEvent(test_base.TestCase):

    def setUp(self):
        super(TestLogicalSwitchPortFIPCreateEvent, self).setUp()
        self.chassis = 'fake-chassis'
        self.agent = mock.Mock(chassis=self.chassis)
        self.event = nb_bgp_watcher.LogicalSwitchPortFIPCreateEvent(
            self.agent)

    def test_match_fn_chassis_change(self):
        row = utils.create_row(type=constants.OVN_VM_VIF_PORT_TYPE,
                               addresses=['mac 192.168.0.1'],
                               options={'requested-chassis': self.chassis},
                               external_ids={
                                   constants.OVN_FIP_EXT_ID_KEY: 'fip-ip'},
                               up=[True])
        old = utils.create_row(options={}, up=[True])
        self.assertTrue(self.event.match_fn(mock.Mock(), row, old))

    def test_match_fn_chassis_change_external_ids(self):
        row = utils.create_row(
            type=constants.OVN_VM_VIF_PORT_TYPE,
            addresses=['mac 192.168.0.1'],
            external_ids={
                constants.OVN_HOST_ID_EXT_ID_KEY: self.chassis,
                constants.OVN_FIP_EXT_ID_KEY: 'fip-ip'},
            up=[True])
        old = utils.create_row(external_ids={}, up=[True])
        self.assertTrue(self.event.match_fn(mock.Mock(), row, old))

    def test_match_fn_status_change(self):
        row = utils.create_row(type=constants.OVN_VM_VIF_PORT_TYPE,
                               addresses=['mac 192.168.0.1'],
                               options={'requested-chassis': self.chassis},
                               external_ids={
                                   constants.OVN_FIP_EXT_ID_KEY: 'fip-ip'},
                               up=[True])
        old = utils.create_row(options={'requested-chassis': self.chassis},
                               external_ids={
                                   constants.OVN_FIP_EXT_ID_KEY: 'fip-ip'},
                               up=[False])
        self.assertTrue(self.event.match_fn(mock.Mock(), row, old))

    def test_match_fn_fip_addition(self):
        row = utils.create_row(type=constants.OVN_VM_VIF_PORT_TYPE,
                               addresses=['mac 192.168.0.1'],
                               options={'requested-chassis': self.chassis},
                               external_ids={
                                   constants.OVN_FIP_EXT_ID_KEY: 'fip-ip'},
                               up=[True])
        old = utils.create_row(options={'requested-chassis': self.chassis},
                               external_ids={},
                               up=[True])
        self.assertTrue(self.event.match_fn(mock.Mock(), row, old))

    def test_match_fn_no_fip(self):
        row = utils.create_row(type=constants.OVN_VM_VIF_PORT_TYPE,
                               addresses=['mac 192.168.0.1'],
                               options={'requested-chassis': self.chassis},
                               external_ids={},
                               up=[True])
        self.assertFalse(self.event.match_fn(mock.Mock(), row, mock.Mock()))

    def test_match_fn_wrong_chassis(self):
        row = utils.create_row(type=constants.OVN_VM_VIF_PORT_TYPE,
                               addresses=['mac 192.168.0.1'],
                               options={'requested-chassis': 'wrong_chassis'},
                               external_ids={
                                   constants.OVN_FIP_EXT_ID_KEY: 'fip-ip'},
                               up=[True])
        self.assertFalse(self.event.match_fn(mock.Mock(), row, mock.Mock()))

    def test_match_fn_port_down(self):
        row = utils.create_row(type=constants.OVN_VM_VIF_PORT_TYPE,
                               addresses=['mac 192.168.0.1'],
                               options={'requested-chassis': self.chassis},
                               external_ids={
                                   constants.OVN_FIP_EXT_ID_KEY: 'fip-ip'},
                               up=[False])
        self.assertFalse(self.event.match_fn(mock.Mock(), row, mock.Mock()))

    def test_match_fn_wrong_address(self):
        row = utils.create_row(type=constants.OVN_VM_VIF_PORT_TYPE,
                               addresses=['mac '],
                               options={'requested-chassis': self.chassis},
                               external_ids={
                                   constants.OVN_FIP_EXT_ID_KEY: 'fip-ip'},
                               up=[True])
        self.assertFalse(self.event.match_fn(mock.Mock(), row, mock.Mock()))

    def test_match_fn_exception(self):
        row = utils.create_row(type=constants.OVN_VM_VIF_PORT_TYPE,
                               addresses=['mac 192.168.0.1'],
                               options={'requested-chassis': self.chassis},
                               up=[False])
        self.assertFalse(self.event.match_fn(mock.Mock(), row, mock.Mock()))

    def test_run(self):
        external_ip = '10.0.0.10'
        ls_name = 'neutron-net-id'
        self.agent.get_port_external_ip_and_ls.return_value = (external_ip,
                                                               ls_name)
        row = utils.create_row(type=constants.OVN_VM_VIF_PORT_TYPE,
                               name='net-id')
        self.event.run(mock.Mock(), row, mock.Mock())
        self.agent.expose_fip.assert_called_once_with(external_ip, ls_name,
                                                      row)

    def test_run_no_external_ip(self):
        external_ip = None
        ls_name = 'logical_switch'
        self.agent.get_port_external_ip_and_ls.return_value = (external_ip,
                                                               ls_name)
        row = utils.create_row(type=constants.OVN_VM_VIF_PORT_TYPE,
                               name='net-id')
        self.event.run(mock.Mock(), row, mock.Mock())
        self.agent.expose_fip.assert_not_called()

    def test_run_wrong_type(self):
        row = utils.create_row(
            type=constants.OVN_CHASSISREDIRECT_VIF_PORT_TYPE)
        self.event.run(mock.Mock(), row, mock.Mock())
        self.agent.expose_fip.assert_not_called()


class TestLogicalSwitchPortFIPDeleteEvent(test_base.TestCase):

    def setUp(self):
        super(TestLogicalSwitchPortFIPDeleteEvent, self).setUp()
        self.chassis = 'fake-chassis'
        self.agent = mock.Mock(chassis=self.chassis)
        self.event = nb_bgp_watcher.LogicalSwitchPortFIPDeleteEvent(
            self.agent)

    def test_match_fn_delete(self):
        event = self.event.ROW_DELETE
        row = utils.create_row(type=constants.OVN_VM_VIF_PORT_TYPE,
                               addresses=['mac 192.168.0.1'],
                               options={'requested-chassis': self.chassis},
                               external_ids={
                                   constants.OVN_FIP_EXT_ID_KEY: 'fip-ip'},
                               up=[True])
        self.assertTrue(self.event.match_fn(event, row, mock.Mock()))

    def test_match_fn_update(self):
        event = self.event.ROW_UPDATE
        row = utils.create_row(type=constants.OVN_VM_VIF_PORT_TYPE,
                               addresses=['mac 192.168.0.1'],
                               options={'requested-chassis': self.chassis},
                               external_ids={
                                   constants.OVN_FIP_EXT_ID_KEY: 'fip-ip'},
                               up=[False])
        old = utils.create_row(up=[True])
        self.assertTrue(self.event.match_fn(event, row, old))

    def test_match_fn_update_external_id(self):
        event = self.event.ROW_UPDATE
        row = utils.create_row(
            type=constants.OVN_VM_VIF_PORT_TYPE,
            addresses=['mac 192.168.0.1'],
            external_ids={
                constants.OVN_HOST_ID_EXT_ID_KEY: 'other-chassis',
                constants.OVN_FIP_EXT_ID_KEY: 'fip-ip'},
            up=[True])
        old = utils.create_row(external_ids={
            constants.OVN_HOST_ID_EXT_ID_KEY: self.chassis,
            constants.OVN_FIP_EXT_ID_KEY: 'fip-ip'})
        self.assertTrue(self.event.match_fn(event, row, old))

    def test_match_fn_update_external_id_remove_fip(self):
        event = self.event.ROW_UPDATE
        row = utils.create_row(
            type=constants.OVN_VM_VIF_PORT_TYPE,
            addresses=['mac 192.168.0.1'],
            external_ids={
                constants.OVN_HOST_ID_EXT_ID_KEY: self.chassis},
            up=[True])
        old = utils.create_row(external_ids={
            constants.OVN_HOST_ID_EXT_ID_KEY: self.chassis,
            constants.OVN_FIP_EXT_ID_KEY: 'fip-ip'})
        self.assertTrue(self.event.match_fn(event, row, old))

    def test_match_fn_update_external_id_no_fip(self):
        event = self.event.ROW_UPDATE
        row = utils.create_row(
            type=constants.OVN_VM_VIF_PORT_TYPE,
            addresses=['mac 192.168.0.1'],
            external_ids={
                constants.OVN_HOST_ID_EXT_ID_KEY: self.chassis},
            up=[True])
        old = utils.create_row(external_ids={
            constants.OVN_HOST_ID_EXT_ID_KEY: self.chassis})
        self.assertFalse(self.event.match_fn(event, row, old))

    def test_match_fn_exception(self):
        row = utils.create_row(type=constants.OVN_VM_VIF_PORT_TYPE,
                               addresses=['mac 192.168.0.1'],
                               up=[False])
        self.assertFalse(self.event.match_fn(mock.Mock(), row, mock.Mock()))

    def test_match_fn_not_up(self):
        row = utils.create_row(type=constants.OVN_VM_VIF_PORT_TYPE,
                               addresses=['mac 192.168.0.1'],
                               options={'requested-chassis': self.chassis},
                               external_ids={
                                   constants.OVN_FIP_EXT_ID_KEY: 'fip-ip'},
                               up=[False])
        old = utils.create_row(options={'requested-chassis': self.chassis},
                               up=[False])
        self.assertFalse(self.event.match_fn(mock.Mock(), row, old))

    def test_match_fn_invalid_address(self):
        row = utils.create_row(type=constants.OVN_VM_VIF_PORT_TYPE,
                               addresses=['mac '],
                               options={'requested-chassis': self.chassis},
                               up=[True])
        self.assertFalse(self.event.match_fn(mock.Mock(), row, mock.Mock()))

    def test_match_fn_wrong_chassis(self):
        row = utils.create_row(type=constants.OVN_VM_VIF_PORT_TYPE,
                               addresses=['mac 192.168.0.1'],
                               options={'requested-chassis': self.chassis},
                               external_ids={
                                   constants.OVN_FIP_EXT_ID_KEY: 'fip-ip'},
                               up=[True])
        old = utils.create_row(options={'requested-chassis': 'other_chassis'})
        self.assertFalse(self.event.match_fn(mock.Mock(), row, old))

    def test_match_fn_chassis_update(self):
        row = utils.create_row(type=constants.OVN_VM_VIF_PORT_TYPE,
                               addresses=['mac 192.168.0.1'],
                               options={'requested-chassis': 'other_chassis'},
                               external_ids={
                                   constants.OVN_FIP_EXT_ID_KEY: 'fip-ip'},
                               up=[True])
        old = utils.create_row(options={'requested-chassis': self.chassis})
        self.assertTrue(self.event.match_fn(mock.Mock(), row, old))

    def test_match_fn_fip_update(self):
        row = utils.create_row(type=constants.OVN_VM_VIF_PORT_TYPE,
                               addresses=['mac 192.168.0.1'],
                               options={'requested-chassis': self.chassis},
                               external_ids={
                                   constants.OVN_FIP_EXT_ID_KEY: 'new-fip-ip'},
                               up=[True])
        old = utils.create_row(
            external_ids={constants.OVN_FIP_EXT_ID_KEY: 'fip-ip'})
        self.assertTrue(self.event.match_fn(mock.Mock(), row, old))

    def test_run(self):
        row = utils.create_row(type=constants.OVN_VM_VIF_PORT_TYPE,
                               external_ids={
                                   constants.OVN_FIP_EXT_ID_KEY: 'fip-ip'},
                               up=[True])
        self.event.run(mock.Mock(), row, mock.Mock())
        self.agent.withdraw_fip.assert_called_once_with('fip-ip', row)

    def test_run_no_fip(self):
        row = utils.create_row(type=constants.OVN_VM_VIF_PORT_TYPE,
                               external_ids={})
        old = utils.create_row(type=constants.OVN_VM_VIF_PORT_TYPE,
                               external_ids={})
        self.event.run(mock.Mock(), row, old)
        self.agent.withdraw_fip.assert_not_called()

    def test_run_wrong_type(self):
        row = utils.create_row(
            type=constants.OVN_CHASSISREDIRECT_VIF_PORT_TYPE)
        self.event.run(mock.Mock(), row, mock.Mock())
        self.agent.withdraw_fip.assert_not_called()


class TestLocalnetCreateDeleteEvent(test_base.TestCase):

    def setUp(self):
        super(TestLocalnetCreateDeleteEvent, self).setUp()
        self.agent = mock.Mock()
        self.event = nb_bgp_watcher.LocalnetCreateDeleteEvent(
            self.agent)

    def test_match_fn(self):
        row = utils.create_row(type=constants.OVN_LOCALNET_VIF_PORT_TYPE)
        self.assertTrue(self.event.match_fn(None, row, None))

        row = utils.create_row(type=constants.OVN_VM_VIF_PORT_TYPE)
        self.assertFalse(self.event.match_fn(None, row, None))

    def test_run(self):
        row = utils.create_row(type=constants.OVN_LOCALNET_VIF_PORT_TYPE)
        self.event.run(None, row, None)
        self.agent.sync.assert_called_once()

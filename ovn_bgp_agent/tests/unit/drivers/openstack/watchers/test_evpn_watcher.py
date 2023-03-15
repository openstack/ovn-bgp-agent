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

from ovn_bgp_agent import constants
from ovn_bgp_agent.drivers.openstack.watchers import evpn_watcher
from ovn_bgp_agent.tests import base as test_base
from ovn_bgp_agent.tests import utils


class TestPortBindingChassisCreatedEvent(test_base.TestCase):

    def setUp(self):
        super(TestPortBindingChassisCreatedEvent, self).setUp()
        self.chassis = '935f91fa-b8f8-47b9-8b1b-3a7a90ef7c26'
        self.agent = mock.Mock(chassis=self.chassis)
        self.event = evpn_watcher.PortBindingChassisCreatedEvent(self.agent)

    def test_match_fn(self):
        ch = utils.create_row(name=self.chassis)
        row = utils.create_row(
            type=constants.OVN_CHASSISREDIRECT_VIF_PORT_TYPE,
            chassis=[ch], mac=['aa:bb:cc:dd:ee:ff 10.10.1.16'])
        old = utils.create_row(chassis=[])
        self.assertTrue(self.event.match_fn(mock.Mock(), row, old))

    def test_match_fn_not_single_or_dual_stack(self):
        ch = utils.create_row(name=self.chassis)
        row = utils.create_row(
            type=constants.OVN_CHASSISREDIRECT_VIF_PORT_TYPE,
            chassis=[ch], mac=['aa:bb:cc:dd:ee:ff'])
        old = utils.create_row(chassis=[])
        self.assertFalse(self.event.match_fn(mock.Mock(), row, old))

    def test_match_fn_old_chassis_set(self):
        ch = utils.create_row(name=self.chassis)
        row = utils.create_row(
            type=constants.OVN_CHASSISREDIRECT_VIF_PORT_TYPE,
            chassis=[ch], mac=['aa:bb:cc:dd:ee:ff 10.10.1.16'])
        old = utils.create_row(chassis=self.chassis)
        self.assertFalse(self.event.match_fn(mock.Mock(), row, old))

    def test_match_fn_index_error(self):
        row = utils.create_row(
            type=constants.OVN_CHASSISREDIRECT_VIF_PORT_TYPE,
            chassis=[], mac=['aa:bb:cc:dd:ee:ff 10.10.1.16'])
        old = utils.create_row(chassis=[])
        self.assertFalse(self.event.match_fn(mock.Mock(), row, old))

    def test_match_fn_wrong_type(self):
        ch = utils.create_row(name=self.chassis)
        row = utils.create_row(type='farofa', chassis=[ch],
                               mac=['aa:bb:cc:dd:ee:ff 10.10.1.16'])
        old = utils.create_row(chassis=[])
        self.assertFalse(self.event.match_fn(mock.Mock(), row, old))

    def test_run(self):
        row = utils.create_row(
            type=constants.OVN_CHASSISREDIRECT_VIF_PORT_TYPE)
        self.event.run(mock.Mock(), row, mock.Mock())
        self.agent.expose_ip.assert_called_once_with(row, cr_lrp=True)

    def test_run_dual_stack(self):
        row = utils.create_row(
            type=constants.OVN_CHASSISREDIRECT_VIF_PORT_TYPE)
        self.event.run(mock.Mock(), row, mock.Mock())
        self.agent.expose_ip.assert_called_once_with(row, cr_lrp=True)

    def test_run_wrong_type(self):
        row = utils.create_row(type='farofa')
        self.event.run(mock.Mock(), row, mock.Mock())
        self.agent.expose_ip.assert_not_called()


class TestPortBindingChassisDeletedEvent(test_base.TestCase):

    def setUp(self):
        super(TestPortBindingChassisDeletedEvent, self).setUp()
        self.chassis = '935f91fa-b8f8-47b9-8b1b-3a7a90ef7c26'
        self.agent = mock.Mock(chassis=self.chassis)
        self.event = evpn_watcher.PortBindingChassisDeletedEvent(self.agent)

    def test_match_fn(self):
        ch = utils.create_row(name=self.chassis)
        row = utils.create_row(
            type=constants.OVN_CHASSISREDIRECT_VIF_PORT_TYPE,
            chassis=[ch], mac=['aa:bb:cc:dd:ee:ff 10.10.1.16'])
        old = utils.create_row(chassis=[])
        self.assertTrue(self.event.match_fn(mock.Mock(), row, old))

    def test_match_fn_not_single_or_dual_stack(self):
        ch = utils.create_row(name=self.chassis)
        row = utils.create_row(
            type=constants.OVN_CHASSISREDIRECT_VIF_PORT_TYPE,
            chassis=[ch], mac=['aa:bb:cc:dd:ee:ff'])
        old = utils.create_row(chassis=[])
        self.assertFalse(self.event.match_fn(mock.Mock(), row, old))

    def test_match_fn_update(self):
        event = self.event.ROW_UPDATE
        ch = utils.create_row(name=self.chassis)
        row = utils.create_row(
            type=constants.OVN_CHASSISREDIRECT_VIF_PORT_TYPE,
            chassis=[], mac=['aa:bb:cc:dd:ee:ff 10.10.1.16'])
        old = utils.create_row(chassis=[ch])
        self.assertTrue(self.event.match_fn(event, row, old))

    def test_match_fn_update_old_chassis_set(self):
        event = self.event.ROW_UPDATE
        ch = utils.create_row(name=self.chassis)
        row = utils.create_row(
            type=constants.OVN_CHASSISREDIRECT_VIF_PORT_TYPE,
            chassis=[ch], mac=['aa:bb:cc:dd:ee:ff 10.10.1.16'])
        old = utils.create_row(chassis=self.chassis)
        self.assertFalse(self.event.match_fn(event, row, old))

    def test_match_fn_index_error(self):
        row = utils.create_row(
            type=constants.OVN_CHASSISREDIRECT_VIF_PORT_TYPE,
            chassis=[], mac=['aa:bb:cc:dd:ee:ff 10.10.1.16'])
        old = utils.create_row(chassis=[])
        self.assertFalse(self.event.match_fn(mock.Mock(), row, old))

    def test_match_fn_wrong_type(self):
        row = utils.create_row(
            type='farofa',
            chassis=[], mac=['aa:bb:cc:dd:ee:ff 10.10.1.16'])
        old = utils.create_row(chassis=[])
        self.assertFalse(self.event.match_fn(mock.Mock(), row, old))

    def test_run(self):
        row = utils.create_row(
            type=constants.OVN_CHASSISREDIRECT_VIF_PORT_TYPE)
        self.event.run(mock.Mock(), row, mock.Mock())
        self.agent.withdraw_ip.assert_called_once_with(row, cr_lrp=True)

    def test_run_wrong_type(self):
        row = utils.create_row(type='farofa')
        self.event.run(mock.Mock(), row, mock.Mock())
        self.agent.withdraw_ip.assert_not_called()


class TestSubnetRouterAttachedEvent(test_base.TestCase):

    def setUp(self):
        super(TestSubnetRouterAttachedEvent, self).setUp()
        self.chassis = '935f91fa-b8f8-47b9-8b1b-3a7a90ef7c26'
        self.agent = mock.Mock(chassis=self.chassis)
        self.event = evpn_watcher.SubnetRouterAttachedEvent(self.agent)

    def test_match_fn(self):
        ext_ids = {constants.OVN_EVPN_VNI_EXT_ID_KEY: 'fake-vni-id',
                   constants.OVN_EVPN_AS_EXT_ID_KEY: 'fake-as-id'}
        row = utils.create_row(
            chassis=[], logical_port='fake-lrp', external_ids=ext_ids)
        self.assertTrue(self.event.match_fn(mock.Mock(), row, mock.Mock()))

    def test_match_fn_chassis_set(self):
        ch = utils.create_row(name=self.chassis)
        ext_ids = {constants.OVN_EVPN_VNI_EXT_ID_KEY: 'fake-vni-id',
                   constants.OVN_EVPN_AS_EXT_ID_KEY: 'fake-as-id'}
        row = utils.create_row(
            chassis=[ch], logical_port='fake-lrp', external_ids=ext_ids)
        self.assertFalse(self.event.match_fn(mock.Mock(), row, mock.Mock()))

    def test_match_fn_lrp(self):
        ext_ids = {constants.OVN_EVPN_VNI_EXT_ID_KEY: 'fake-vni-id',
                   constants.OVN_EVPN_AS_EXT_ID_KEY: 'fake-as-id'}
        row = utils.create_row(
            chassis=[], logical_port='lrp-fake', external_ids=ext_ids)
        self.assertFalse(self.event.match_fn(mock.Mock(), row, mock.Mock()))

    def test_match_fn_missing_ext_ids(self):
        row = utils.create_row(
            chassis=[], logical_port='fake-lrp', external_ids={})
        self.assertFalse(self.event.match_fn(mock.Mock(), row, mock.Mock()))

    def test_match_fn_update(self):
        event = self.event.ROW_UPDATE
        ext_ids = {constants.OVN_EVPN_VNI_EXT_ID_KEY: 'fake-vni-id',
                   constants.OVN_EVPN_AS_EXT_ID_KEY: 'fake-as-id'}
        row = utils.create_row(
            chassis=[], logical_port='fake-lrp', external_ids=ext_ids)
        old = utils.create_row(external_ids={})
        self.assertTrue(self.event.match_fn(event, row, old))

    def test_match_fn_update_chassis_set(self):
        event = self.event.ROW_UPDATE
        ch = utils.create_row(name=self.chassis)
        ext_ids = {constants.OVN_EVPN_VNI_EXT_ID_KEY: 'fake-vni-id',
                   constants.OVN_EVPN_AS_EXT_ID_KEY: 'fake-as-id'}
        row = utils.create_row(
            chassis=[ch], logical_port='fake-lrp', external_ids=ext_ids)
        old = utils.create_row(external_ids={})
        self.assertFalse(self.event.match_fn(event, row, old))

    def test_match_fn_update_lrp(self):
        event = self.event.ROW_UPDATE
        ext_ids = {constants.OVN_EVPN_VNI_EXT_ID_KEY: 'fake-vni-id',
                   constants.OVN_EVPN_AS_EXT_ID_KEY: 'fake-as-id'}
        row = utils.create_row(
            chassis=[], logical_port='lrp-fake', external_ids=ext_ids)
        old = utils.create_row(external_ids={})
        self.assertFalse(self.event.match_fn(event, row, old))

    def test_match_fn_update_missing_ext_ids(self):
        event = self.event.ROW_UPDATE
        row = utils.create_row(
            chassis=[], logical_port='fake-lrp', external_ids={})
        old = utils.create_row(external_ids={})
        self.assertFalse(self.event.match_fn(event, row, old))

    def test_match_fn_update_old_ext_ids(self):
        event = self.event.ROW_UPDATE
        ext_ids = {constants.OVN_EVPN_VNI_EXT_ID_KEY: 'fake-vni-id',
                   constants.OVN_EVPN_AS_EXT_ID_KEY: 'fake-as-id'}
        row = utils.create_row(
            chassis=[], logical_port='fake-lrp', external_ids=ext_ids)
        old = utils.create_row(external_ids=ext_ids)
        self.assertFalse(self.event.match_fn(event, row, old))

    def test_run(self):
        row = utils.create_row(
            type=constants.OVN_PATCH_VIF_PORT_TYPE, nat_addresses=[])
        self.event.run(mock.Mock(), row, mock.Mock())
        self.agent.expose_subnet.assert_called_once_with(row)

    def test_run_nat_addresses(self):
        row = utils.create_row(
            type=constants.OVN_PATCH_VIF_PORT_TYPE,
            nat_addresses=['10.10.1.16'])
        self.event.run(mock.Mock(), row, mock.Mock())
        self.agent.expose_ip.assert_called_once_with(row)

    def test_run_wrong_type(self):
        row = utils.create_row(type='farofa')
        self.event.run(mock.Mock(), row, mock.Mock())
        self.agent.expose_ip.assert_not_called()
        self.agent.expose_subnet.assert_not_called()


class TestSubnetRouterDetachedEvent(test_base.TestCase):

    def setUp(self):
        super(TestSubnetRouterDetachedEvent, self).setUp()
        self.chassis = '935f91fa-b8f8-47b9-8b1b-3a7a90ef7c26'
        self.agent = mock.Mock(chassis=self.chassis)
        self.event = evpn_watcher.SubnetRouterDetachedEvent(self.agent)

    def test_match_fn(self):
        ext_ids = {constants.OVN_EVPN_VNI_EXT_ID_KEY: 'fake-vni-id',
                   constants.OVN_EVPN_AS_EXT_ID_KEY: 'fake-as-id'}
        row = utils.create_row(
            chassis=[], logical_port='fake-lrp', external_ids=ext_ids)
        self.assertTrue(self.event.match_fn(mock.Mock(), row, mock.Mock()))

    def test_match_fn_chassis_set(self):
        ch = utils.create_row(name=self.chassis)
        ext_ids = {constants.OVN_EVPN_VNI_EXT_ID_KEY: 'fake-vni-id',
                   constants.OVN_EVPN_AS_EXT_ID_KEY: 'fake-as-id'}
        row = utils.create_row(
            chassis=[ch], logical_port='fake-lrp', external_ids=ext_ids)
        self.assertFalse(self.event.match_fn(mock.Mock(), row, mock.Mock()))

    def test_match_fn_lrp(self):
        ext_ids = {constants.OVN_EVPN_VNI_EXT_ID_KEY: 'fake-vni-id',
                   constants.OVN_EVPN_AS_EXT_ID_KEY: 'fake-as-id'}
        row = utils.create_row(
            chassis=[], logical_port='lrp-fake', external_ids=ext_ids)
        self.assertFalse(self.event.match_fn(mock.Mock(), row, mock.Mock()))

    def test_match_fn_missing_ext_ids(self):
        row = utils.create_row(
            chassis=[], logical_port='fake-lrp', external_ids={})
        self.assertFalse(self.event.match_fn(mock.Mock(), row, mock.Mock()))

    def test_match_fn_update(self):
        event = self.event.ROW_UPDATE
        ext_ids = {constants.OVN_EVPN_VNI_EXT_ID_KEY: 'fake-vni-id',
                   constants.OVN_EVPN_AS_EXT_ID_KEY: 'fake-as-id'}
        row = utils.create_row(
            chassis=[], logical_port='fake-lrp', external_ids={})
        old = utils.create_row(external_ids=ext_ids)
        self.assertTrue(self.event.match_fn(event, row, old))

    def test_match_fn_update_chassis_set(self):
        event = self.event.ROW_UPDATE
        ch = utils.create_row(name=self.chassis)
        ext_ids = {constants.OVN_EVPN_VNI_EXT_ID_KEY: 'fake-vni-id',
                   constants.OVN_EVPN_AS_EXT_ID_KEY: 'fake-as-id'}
        row = utils.create_row(
            chassis=[ch], logical_port='fake-lrp', external_ids={})
        old = utils.create_row(external_ids=ext_ids)
        self.assertFalse(self.event.match_fn(event, row, old))

    def test_match_fn_update_lrp(self):
        event = self.event.ROW_UPDATE
        ext_ids = {constants.OVN_EVPN_VNI_EXT_ID_KEY: 'fake-vni-id',
                   constants.OVN_EVPN_AS_EXT_ID_KEY: 'fake-as-id'}
        row = utils.create_row(
            chassis=[], logical_port='lrp-fake', external_ids={})
        old = utils.create_row(external_ids=ext_ids)
        self.assertFalse(self.event.match_fn(event, row, old))

    def test_match_fn_update_missing_ext_ids(self):
        event = self.event.ROW_UPDATE
        row = utils.create_row(
            chassis=[], logical_port='fake-lrp', external_ids={})
        old = utils.create_row(external_ids={})
        self.assertFalse(self.event.match_fn(event, row, old))

    def test_match_fn_update_row_ext_ids(self):
        event = self.event.ROW_UPDATE
        ext_ids = {constants.OVN_EVPN_VNI_EXT_ID_KEY: 'fake-vni-id',
                   constants.OVN_EVPN_AS_EXT_ID_KEY: 'fake-as-id'}
        row = utils.create_row(
            chassis=[], logical_port='fake-lrp', external_ids=ext_ids)
        old = utils.create_row(external_ids=ext_ids)
        self.assertFalse(self.event.match_fn(event, row, old))

    def test_run(self):
        row = utils.create_row(
            type=constants.OVN_PATCH_VIF_PORT_TYPE, nat_addresses=[])
        self.event.run(mock.Mock(), row, mock.Mock())
        self.agent.withdraw_subnet.assert_called_once_with(row)

    def test_run_nat_addresses(self):
        row = utils.create_row(
            type=constants.OVN_PATCH_VIF_PORT_TYPE,
            nat_addresses=['10.10.1.16'])
        self.event.run(mock.Mock(), row, mock.Mock())
        self.agent.withdraw_ip.assert_called_once_with(row)

    def test_run_wrong_type(self):
        row = utils.create_row(type='farofa')
        self.event.run(mock.Mock(), row, mock.Mock())
        self.agent.withdraw_ip.assert_not_called()
        self.agent.withdraw_subnet.assert_not_called()


class TestTenantPortCreatedEvent(test_base.TestCase):

    def setUp(self):
        super(TestTenantPortCreatedEvent, self).setUp()
        self.chassis = '935f91fa-b8f8-47b9-8b1b-3a7a90ef7c26'
        self.agent = mock.Mock(chassis=self.chassis)
        self.agent.ovn_local_lrps = ['172.24.100.111']
        self.event = evpn_watcher.TenantPortCreatedEvent(self.agent)

    def test_match_fn(self):
        ch = utils.create_row(name=self.chassis)
        row = utils.create_row(mac=['aa:bb:cc:dd:ee:ff 10.10.1.16'],
                               chassis=[ch])
        old = utils.create_row(chassis=[])
        self.assertTrue(self.event.match_fn(mock.Mock(), row, old))

    def test_match_fn_not_single_or_dual_stack(self):
        ch = utils.create_row(name=self.chassis)
        row = utils.create_row(mac=['aa:bb:cc:dd:ee:ff'],
                               chassis=[ch])
        self.assertFalse(self.event.match_fn(mock.Mock(), row, mock.Mock()))

    def test_match_fn_old_chassis_set(self):
        ch = utils.create_row(name=self.chassis)
        row = utils.create_row(mac=['aa:bb:cc:dd:ee:ff 10.10.1.16'],
                               chassis=[ch])
        old = utils.create_row(chassis=[ch])
        self.assertFalse(self.event.match_fn(mock.Mock(), row, old))

    def test_match_fn_empty_ovn_local_lrps(self):
        ch = utils.create_row(name=self.chassis)
        self.agent.ovn_local_lrps = []
        row = utils.create_row(mac=['aa:bb:cc:dd:ee:ff 10.10.1.16'],
                               chassis=[ch])
        old = utils.create_row(chassis=[])
        self.assertFalse(self.event.match_fn(mock.Mock(), row, old))

    def test_match_fn_index_error(self):
        row = utils.create_row(mac=[])
        self.assertFalse(self.event.match_fn(mock.Mock(), row, mock.Mock()))

    def test_run(self):
        row = utils.create_row(type=constants.OVN_VM_VIF_PORT_TYPE,
                               mac=['aa:bb:cc:dd:ee:ff 10.10.1.16'])
        self.event.run(mock.Mock(), row, mock.Mock())
        self.agent.expose_remote_ip.assert_called_once_with(
            ['10.10.1.16'], row)

    def test_run_dual_stack(self):
        row = utils.create_row(
            type=constants.OVN_VM_VIF_PORT_TYPE,
            mac=['aa:bb:cc:dd:ee:ff 10.10.1.16 2002::1234:abcd:ffff:c0a8:101'])
        self.event.run(mock.Mock(), row, mock.Mock())
        self.agent.expose_remote_ip.assert_called_once_with(
            ['10.10.1.16', '2002::1234:abcd:ffff:c0a8:101'], row)

    def test_run_wrong_type(self):
        row = utils.create_row(type='brigadeiro')
        self.event.run(mock.Mock(), row, mock.Mock())
        self.agent.expose_remote_ip.assert_not_called()


class TestTenantPortDeletedEvent(test_base.TestCase):

    def setUp(self):
        super(TestTenantPortDeletedEvent, self).setUp()
        self.chassis = '935f91fa-b8f8-47b9-8b1b-3a7a90ef7c26'
        self.agent = mock.Mock(chassis=self.chassis)
        self.agent.ovn_local_lrps = ['172.24.100.111']
        self.event = evpn_watcher.TenantPortDeletedEvent(self.agent)

    def test_match_fn(self):
        ch = utils.create_row(name=self.chassis)
        row = utils.create_row(mac=['aa:bb:cc:dd:ee:ff 10.10.1.16'],
                               chassis=[ch])
        self.assertTrue(self.event.match_fn(mock.Mock(), row, mock.Mock()))

    def test_match_fn_not_single_or_dual_stack(self):
        ch = utils.create_row(name=self.chassis)
        row = utils.create_row(mac=['aa:bb:cc:dd:ee:ff'],
                               chassis=[ch])
        self.assertFalse(self.event.match_fn(mock.Mock(), row, mock.Mock()))

    def test_match_fn_empty_ovn_local_lrps(self):
        ch = utils.create_row(name=self.chassis)
        self.agent.ovn_local_lrps = []
        row = utils.create_row(mac=['aa:bb:cc:dd:ee:ff 10.10.1.16'],
                               chassis=[ch])
        self.assertFalse(self.event.match_fn(mock.Mock(), row, mock.Mock()))

    def test_match_fn_update_old_chassis_set(self):
        event = self.event.ROW_UPDATE
        ch = utils.create_row(name=self.chassis)
        row = utils.create_row(mac=['aa:bb:cc:dd:ee:ff 10.10.1.16'],
                               chassis=[ch])
        old = utils.create_row(chassis=[ch])
        self.assertFalse(self.event.match_fn(event, row, old))

    def test_match_fn_update_empty_ovn_local_lrps(self):
        event = self.event.ROW_UPDATE
        ch = utils.create_row(name=self.chassis)
        self.agent.ovn_local_lrps = []
        row = utils.create_row(mac=['aa:bb:cc:dd:ee:ff 10.10.1.16'],
                               chassis=[ch])
        old = utils.create_row(chassis=[])
        self.assertFalse(self.event.match_fn(event, row, old))

    def test_match_fn_index_error(self):
        row = utils.create_row(mac=[])
        self.assertFalse(self.event.match_fn(mock.Mock(), row, mock.Mock()))

    def test_run(self):
        row = utils.create_row(type=constants.OVN_VM_VIF_PORT_TYPE,
                               mac=['aa:bb:cc:dd:ee:ff 10.10.1.16'])
        self.event.run(mock.Mock(), row, mock.Mock())
        self.agent.withdraw_remote_ip.assert_called_once_with(
            ['10.10.1.16'], row)

    def test_run_dual_stack(self):
        row = utils.create_row(
            type=constants.OVN_VM_VIF_PORT_TYPE,
            mac=['aa:bb:cc:dd:ee:ff 10.10.1.16 2002::1234:abcd:ffff:c0a8:101'])
        self.event.run(mock.Mock(), row, mock.Mock())
        self.agent.withdraw_remote_ip.assert_called_once_with(
            ['10.10.1.16', '2002::1234:abcd:ffff:c0a8:101'], row)

    def test_run_wrong_type(self):
        row = utils.create_row(type='brigadeiro')
        self.event.run(mock.Mock(), row, mock.Mock())
        self.agent.withdraw_remote_ip.assert_not_called()


class TestLocalnetCreateDeleteEvent(test_base.TestCase):

    def setUp(self):
        super(TestLocalnetCreateDeleteEvent, self).setUp()
        self.agent = mock.Mock()
        self.event = evpn_watcher.LocalnetCreateDeleteEvent(self.agent)

    def test_match_fn(self):
        row = utils.create_row(type=constants.OVN_LOCALNET_VIF_PORT_TYPE)
        self.assertTrue(self.event.match_fn(mock.Mock(), row, mock.Mock()))

    def test_match_fn_not_match(self):
        row = utils.create_row(type=constants.OVN_VM_VIF_PORT_TYPE)
        self.assertFalse(self.event.match_fn(mock.Mock(), row, mock.Mock()))

    def test_run(self):
        self.event.run(mock.Mock(), mock.Mock(), mock.Mock())
        self.agent.sync.assert_called_once()


class TestChassisCreateEvent(test_base.TestCase):
    _event = evpn_watcher.ChassisCreateEvent

    def setUp(self):
        super(TestChassisCreateEvent, self).setUp()
        self.chassis = '935f91fa-b8f8-47b9-8b1b-3a7a90ef7c26'
        self.agent = mock.Mock(chassis=self.chassis)
        self.event = self._event(self.agent)

    def test_run(self):
        self.assertTrue(self.event.first_time)
        self.event.run(mock.Mock(), mock.Mock(), mock.Mock())

        self.assertFalse(self.event.first_time)
        self.agent.sync.assert_not_called()

    def test_run_not_first_time(self):
        self.event.first_time = False
        self.event.run(mock.Mock(), mock.Mock(), mock.Mock())
        self.agent.sync.assert_called_once_with()


class TestChassisPrivateCreateEvent(TestChassisCreateEvent):
    _event = evpn_watcher.ChassisPrivateCreateEvent

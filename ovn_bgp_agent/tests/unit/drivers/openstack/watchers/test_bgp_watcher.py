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
from ovn_bgp_agent.drivers.openstack.watchers import bgp_watcher
from ovn_bgp_agent.tests import base as test_base
from ovn_bgp_agent.tests import utils

CONF = cfg.CONF


class TestPortBindingChassisCreatedEvent(test_base.TestCase):

    def setUp(self):
        super(TestPortBindingChassisCreatedEvent, self).setUp()
        self.chassis = '935f91fa-b8f8-47b9-8b1b-3a7a90ef7c26'
        self.agent = mock.Mock(chassis=self.chassis)
        self.event = bgp_watcher.PortBindingChassisCreatedEvent(self.agent)

    def test_match_fn(self):
        ch = utils.create_row(name=self.chassis)
        row = utils.create_row(chassis=[ch],
                               mac=['aa:bb:cc:dd:ee:ff 10.10.1.16'],
                               up=[True])
        old = utils.create_row(chassis=[])
        self.assertTrue(self.event.match_fn(mock.Mock(), row, old))

    def test_match_fn_not_single_or_dual_stack(self):
        ch = utils.create_row(name=self.chassis)
        row = utils.create_row(chassis=[ch],
                               mac=['aa:bb:cc:dd:ee:ff'])
        old = utils.create_row(chassis=[])
        self.assertFalse(self.event.match_fn(mock.Mock(), row, old))

    def test_match_fn_old_chassis_set(self):
        ch = utils.create_row(name=self.chassis)
        row = utils.create_row(chassis=[ch],
                               mac=['aa:bb:cc:dd:ee:ff 10.10.1.16'],
                               up=[True])
        old = utils.create_row(chassis=[ch])
        self.assertFalse(self.event.match_fn(mock.Mock(), row, old))

    def test_match_fn_no_old_chassis(self):
        ch = utils.create_row(name=self.chassis)
        row = utils.create_row(chassis=[ch],
                               mac=['aa:bb:cc:dd:ee:ff 10.10.1.16'],
                               up=[True])
        old = utils.create_row(chassis=[])
        self.assertTrue(self.event.match_fn(mock.Mock(), row, old))

    def test_match_fn_different_old_chassis(self):
        ch = utils.create_row(name=self.chassis)
        ch_old = utils.create_row(name='old-chassis')
        row = utils.create_row(chassis=[ch],
                               mac=['aa:bb:cc:dd:ee:ff 10.10.1.16'],
                               up=[True])
        old = utils.create_row(chassis=[ch_old])
        self.assertTrue(self.event.match_fn(mock.Mock(), row, old))

    def test_match_fn_no_up(self):
        ch = utils.create_row(name=self.chassis)
        row = utils.create_row(chassis=[ch],
                               mac=['aa:bb:cc:dd:ee:ff 10.10.1.16'],
                               up=[False])
        self.assertFalse(self.event.match_fn(mock.Mock(), row, mock.Mock))

    def test_match_fn_no_old_up(self):
        ch = utils.create_row(name=self.chassis)
        row = utils.create_row(chassis=[ch],
                               mac=['aa:bb:cc:dd:ee:ff 10.10.1.16'],
                               up=[True])
        old = utils.create_row(chassis=[ch],
                               up=[False])
        self.assertTrue(self.event.match_fn(mock.Mock(), row, old))

    def test_match_fn_index_error(self):
        row = utils.create_row(chassis=[],
                               mac=['aa:bb:cc:dd:ee:ff 10.10.1.16'])
        old = utils.create_row(chassis=[])
        self.assertFalse(self.event.match_fn(mock.Mock(), row, old))

    def test_run(self):
        row = utils.create_row(type=constants.OVN_VIF_PORT_TYPES[0],
                               mac=['aa:bb:cc:dd:ee:ff 10.10.1.16'])
        self.event.run(mock.Mock(), row, mock.Mock())
        self.agent.expose_ip.assert_called_once_with(['10.10.1.16'], row)

    def test_run_dual_stack(self):
        row = utils.create_row(
            type=constants.OVN_VIF_PORT_TYPES[0],
            mac=['aa:bb:cc:dd:ee:ff 10.10.1.16 2002::1234:abcd:ffff:c0a8:101'])
        self.event.run(mock.Mock(), row, mock.Mock())
        self.agent.expose_ip.assert_called_once_with(
            ['10.10.1.16', '2002::1234:abcd:ffff:c0a8:101'], row)

    def test_run_wrong_type(self):
        row = utils.create_row(type='farofa',
                               mac=['aa:bb:cc:dd:ee:ff 10.10.1.16'])
        self.event.run(mock.Mock(), row, mock.Mock())
        self.agent.expose_ip.assert_not_called()


class TestPortBindingChassisDeletedEvent(test_base.TestCase):

    def setUp(self):
        super(TestPortBindingChassisDeletedEvent, self).setUp()
        self.chassis = '935f91fa-b8f8-47b9-8b1b-3a7a90ef7c26'
        self.agent = mock.Mock(chassis=self.chassis)
        self.event = bgp_watcher.PortBindingChassisDeletedEvent(self.agent)

    def test_match_fn(self):
        event = self.event.ROW_DELETE
        ch = utils.create_row(name=self.chassis)
        row = utils.create_row(chassis=[ch],
                               mac=['aa:bb:cc:dd:ee:ff 10.10.1.16'])
        old = utils.create_row(chassis=[])
        self.assertTrue(self.event.match_fn(event, row, old))

    def test_match_fn_not_single_or_dual_stack(self):
        ch = utils.create_row(name=self.chassis)
        row = utils.create_row(chassis=[ch],
                               mac=['aa:bb:cc:dd:ee:ff'])
        old = utils.create_row(chassis=[])
        self.assertFalse(self.event.match_fn(mock.Mock(), row, old))

    def test_match_fn_update(self):
        event = self.event.ROW_UPDATE
        ch = utils.create_row(name=self.chassis)
        row = utils.create_row(chassis=[],
                               mac=['aa:bb:cc:dd:ee:ff 10.10.1.16'])
        old = utils.create_row(chassis=[ch])
        self.assertTrue(self.event.match_fn(event, row, old))

    def test_match_fn_update_old_chassis_set_up_false(self):
        event = self.event.ROW_UPDATE
        ch = utils.create_row(name=self.chassis)
        row = utils.create_row(chassis=[ch],
                               mac=['aa:bb:cc:dd:ee:ff 10.10.1.16'],
                               up=[True])
        old = utils.create_row(chassis=[ch],
                               up=[False])
        self.assertFalse(self.event.match_fn(event, row, old))

    def test_match_fn_update_old_chassis_set_up_true(self):
        event = self.event.ROW_UPDATE
        ch = utils.create_row(name=self.chassis)
        row = utils.create_row(chassis=[ch],
                               mac=['aa:bb:cc:dd:ee:ff 10.10.1.16'],
                               up=[False])
        old = utils.create_row(chassis=[ch],
                               up=[True])
        self.assertTrue(self.event.match_fn(event, row, old))

    def test_match_fn_update_different_chassis_set_up_false(self):
        event = self.event.ROW_UPDATE
        ch = utils.create_row(name='other-chassis')
        row = utils.create_row(chassis=[ch],
                               mac=['aa:bb:cc:dd:ee:ff 10.10.1.16'],
                               up=[False])
        old = utils.create_row(up=[True])
        self.assertFalse(self.event.match_fn(event, row, old))

    def test_match_fn_update_no_chassis(self):
        event = self.event.ROW_UPDATE
        ch = utils.create_row(name=self.chassis)
        row = utils.create_row(chassis=[],
                               mac=['aa:bb:cc:dd:ee:ff 10.10.1.16'])
        old = utils.create_row(chassis=[ch])
        self.assertTrue(self.event.match_fn(event, row, old))

    def test_match_fn_update_different_chassis(self):
        event = self.event.ROW_UPDATE
        ch = utils.create_row(name=self.chassis)
        ch_new = utils.create_row(name='new-chassis')
        row = utils.create_row(chassis=[ch_new],
                               mac=['aa:bb:cc:dd:ee:ff 10.10.1.16'])
        old = utils.create_row(chassis=[ch])
        self.assertTrue(self.event.match_fn(event, row, old))

    def test_match_fn_index_error(self):
        row = utils.create_row(chassis=[],
                               mac=['aa:bb:cc:dd:ee:ff 10.10.1.16'])
        old = utils.create_row(chassis=[])
        self.assertFalse(self.event.match_fn(mock.Mock(), row, old))

    def test_run(self):
        row = utils.create_row(type=constants.OVN_VIF_PORT_TYPES[0],
                               mac=['aa:bb:cc:dd:ee:ff 10.10.1.16'])
        self.event.run(mock.Mock(), row, mock.Mock())
        self.agent.withdraw_ip.assert_called_once_with(['10.10.1.16'], row)

    def test_run_dual_stack(self):
        row = utils.create_row(
            type=constants.OVN_VIF_PORT_TYPES[0],
            mac=['aa:bb:cc:dd:ee:ff 10.10.1.16 2002::1234:abcd:ffff:c0a8:101'])
        self.event.run(mock.Mock(), row, mock.Mock())
        self.agent.withdraw_ip.assert_called_once_with(
            ['10.10.1.16', '2002::1234:abcd:ffff:c0a8:101'], row)

    def test_run_wrong_type(self):
        row = utils.create_row(type='farofa',
                               mac=['aa:bb:cc:dd:ee:ff 10.10.1.16'])
        self.event.run(mock.Mock(), row, mock.Mock())
        self.agent.withdraw_ip.assert_not_called()


class TestFIPSetEvent(test_base.TestCase):

    def setUp(self):
        super(TestFIPSetEvent, self).setUp()
        self.chassis = '935f91fa-b8f8-47b9-8b1b-3a7a90ef7c26'
        self.agent = mock.Mock(chassis=self.chassis)
        self.event = bgp_watcher.FIPSetEvent(self.agent)

    def test_match_fn(self):
        row = utils.create_row(chassis=[], nat_addresses=['10.10.1.16'],
                               logical_port='fake-lp')
        old = utils.create_row(nat_addresses=['10.10.1.17'])
        self.assertTrue(self.event.match_fn(mock.Mock(), row, old))

    def test_match_fn_same_nat_addresses(self):
        row = utils.create_row(chassis=[], nat_addresses=['10.10.1.16'],
                               logical_port='fake-lp')
        old = utils.create_row(nat_addresses=['10.10.1.16'])
        self.assertFalse(self.event.match_fn(mock.Mock(), row, old))

    def test_match_fn_chassis_set(self):
        ch = utils.create_row(name=self.chassis)
        row = utils.create_row(chassis=[ch], nat_addresses=['10.10.1.16'],
                               logical_port='fake-lp')
        old = utils.create_row(nat_addresses=['10.10.1.17'])
        self.assertFalse(self.event.match_fn(mock.Mock(), row, old))

    def test_match_fn_lrp(self):
        row = utils.create_row(chassis=[], nat_addresses=['10.10.1.16'],
                               logical_port='lrp-fake')
        old = utils.create_row(nat_addresses=['10.10.1.17'])
        self.assertFalse(self.event.match_fn(mock.Mock(), row, old))

    def test_match_fn_attribute_errir(self):
        row = utils.create_row()
        old = utils.create_row(nat_addresses=['10.10.1.17'])
        self.assertFalse(self.event.match_fn(mock.Mock(), row, old))

    def test_run(self):
        row = utils.create_row(
            type=constants.OVN_PATCH_VIF_PORT_TYPE,
            nat_addresses=[
                'aa:aa:aa:aa:aa:aa 10.10.1.16 10.10.1.17 '
                'is_chassis_resident(\\"cr-lrp-aaaaaaaa-aaaa-aaaa-'
                'aaaa-aaaaaaaaaaaa\\")'])
        old = utils.create_row(
            nat_addresses=[
                'aa:aa:aa:aa:aa:aa 10.10.1.16 10.10.1.18 '
                'is_chassis_resident(\\"cr-lrp-bbbbbbbb-bbbb-bbbb-'
                'bbbb-bbbbbbbbbbbb\\")'])
        self.event.run(mock.Mock(), row, old)
        self.agent.expose_ip.assert_called_once_with(
            ['10.10.1.16', '10.10.1.17'], row,
            associated_port='cr-lrp-aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa\\')

    def test_run_same_port(self):
        row = utils.create_row(
            type=constants.OVN_PATCH_VIF_PORT_TYPE,
            nat_addresses=[
                'aa:aa:aa:aa:aa:aa 10.10.1.16 10.10.1.17 '
                'is_chassis_resident(\\"cr-lrp-aaaaaaaa-aaaa-aaaa-'
                'aaaa-aaaaaaaaaaaa\\")'])
        old = utils.create_row(
            nat_addresses=[
                'aa:aa:aa:aa:aa:aa 10.10.1.16 10.10.1.18 '
                'is_chassis_resident(\\"cr-lrp-aaaaaaaa-aaaa-aaaa-'
                'aaaa-aaaaaaaaaaaa\\")'])
        self.event.run(mock.Mock(), row, old)
        self.agent.expose_ip.assert_called_once_with(
            ['10.10.1.17'], row,
            associated_port='cr-lrp-aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa\\')

    def test_run_empty_old_nat_addresses(self):
        row = utils.create_row(
            type=constants.OVN_PATCH_VIF_PORT_TYPE,
            nat_addresses=[
                'aa:aa:aa:aa:aa:aa 10.10.1.16 10.10.1.17 '
                'is_chassis_resident(\\"cr-lrp-aaaaaaaa-aaaa-aaaa-'
                'aaaa-aaaaaaaaaaaa\\")'])
        old = utils.create_row(nat_addresses=[])
        self.event.run(mock.Mock(), row, old)
        self.agent.expose_ip.assert_called_once_with(
            ['10.10.1.16', '10.10.1.17'], row,
            associated_port='cr-lrp-aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa\\')

    def test_run_wrong_type(self):
        row = utils.create_row(
            type='feijoada',
            nat_addresses=[
                'aa:aa:aa:aa:aa:aa 10.10.1.16 10.10.1.17 '
                'is_chassis_resident(\\"cr-lrp-aaaaaaaa-aaaa-aaaa-'
                'aaaa-aaaaaaaaaaaa\\")'])
        self.event.run(mock.Mock(), row, mock.Mock())
        self.agent.expose_ip.assert_not_called()


class TestFIPUnsetEvent(test_base.TestCase):

    def setUp(self):
        super(TestFIPUnsetEvent, self).setUp()
        self.chassis = '935f91fa-b8f8-47b9-8b1b-3a7a90ef7c26'
        self.agent = mock.Mock(chassis=self.chassis)
        self.event = bgp_watcher.FIPUnsetEvent(self.agent)

    def test_match_fn(self):
        row = utils.create_row(chassis=[], nat_addresses=['10.10.1.16'],
                               logical_port='fake-lp')
        old = utils.create_row(nat_addresses=['10.10.1.17'])
        self.assertTrue(self.event.match_fn(mock.Mock(), row, old))

    def test_match_fn_same_nat_addresses(self):
        row = utils.create_row(chassis=[], nat_addresses=['10.10.1.16'],
                               logical_port='fake-lp')
        old = utils.create_row(nat_addresses=['10.10.1.16'])
        self.assertFalse(self.event.match_fn(mock.Mock(), row, old))

    def test_match_fn_chassis_set(self):
        ch = utils.create_row(name=self.chassis)
        row = utils.create_row(chassis=[ch], nat_addresses=['10.10.1.16'],
                               logical_port='fake-lp')
        old = utils.create_row(nat_addresses=['10.10.1.17'])
        self.assertFalse(self.event.match_fn(mock.Mock(), row, old))

    def test_match_fn_lrp(self):
        row = utils.create_row(chassis=[], nat_addresses=['10.10.1.16'],
                               logical_port='lrp-fake')
        old = utils.create_row(nat_addresses=['10.10.1.17'])
        self.assertFalse(self.event.match_fn(mock.Mock(), row, old))

    def test_match_fn_attribute_errir(self):
        row = utils.create_row()
        old = utils.create_row(nat_addresses=['10.10.1.17'])
        self.assertFalse(self.event.match_fn(mock.Mock(), row, old))

    def test_run(self):
        row = utils.create_row(
            type=constants.OVN_PATCH_VIF_PORT_TYPE,
            nat_addresses=[
                'aa:aa:aa:aa:aa:aa 10.10.1.16 10.10.1.17 '
                'is_chassis_resident(\\"cr-lrp-aaaaaaaa-aaaa-aaaa-'
                'aaaa-aaaaaaaaaaaa\\")'])
        old = utils.create_row(
            nat_addresses=[
                'aa:aa:aa:aa:aa:aa 10.10.1.16 10.10.1.18 '
                'is_chassis_resident(\\"cr-lrp-bbbbbbbb-bbbb-bbbb-'
                'bbbb-bbbbbbbbbbbb\\")'])
        self.event.run(mock.Mock(), row, old)
        self.agent.withdraw_ip.assert_called_once_with(
            ['10.10.1.16', '10.10.1.18'], row,
            associated_port='cr-lrp-bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb\\')

    def test_run_same_port(self):
        row = utils.create_row(
            type=constants.OVN_PATCH_VIF_PORT_TYPE,
            nat_addresses=[
                'aa:aa:aa:aa:aa:aa 10.10.1.16 10.10.1.17 '
                'is_chassis_resident(\\"cr-lrp-aaaaaaaa-aaaa-aaaa-'
                'aaaa-aaaaaaaaaaaa\\")'])
        old = utils.create_row(
            nat_addresses=[
                'aa:aa:aa:aa:aa:aa 10.10.1.16 10.10.1.18 '
                'is_chassis_resident(\\"cr-lrp-aaaaaaaa-aaaa-aaaa-'
                'aaaa-aaaaaaaaaaaa\\")'])
        self.event.run(mock.Mock(), row, old)
        self.agent.withdraw_ip.assert_called_once_with(
            ['10.10.1.18'], row,
            associated_port='cr-lrp-aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa\\')

    def test_run_empty_row_nat_addresses(self):
        row = utils.create_row(
            type=constants.OVN_PATCH_VIF_PORT_TYPE,
            nat_addresses=[])
        old = utils.create_row(
            nat_addresses=[
                'aa:aa:aa:aa:aa:aa 10.10.1.16 10.10.1.17 '
                'is_chassis_resident(\\"cr-lrp-aaaaaaaa-aaaa-aaaa-'
                'aaaa-aaaaaaaaaaaa\\")'])
        self.event.run(mock.Mock(), row, old)
        self.agent.withdraw_ip.assert_called_once_with(
            ['10.10.1.16', '10.10.1.17'], row,
            associated_port='cr-lrp-aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa\\')

    def test_run_wrong_type(self):
        row = utils.create_row(
            type='feijoada',
            nat_addresses=[
                'aa:aa:aa:aa:aa:aa 10.10.1.16 10.10.1.17 '
                'is_chassis_resident(\\"cr-lrp-aaaaaaaa-aaaa-aaaa-'
                'aaaa-aaaaaaaaaaaa\\")'])
        self.event.run(mock.Mock(), row, mock.Mock())
        self.agent.withdraw_ip.assert_not_called()


class TestSubnetRouterAttachedEvent(test_base.TestCase):

    def setUp(self):
        super(TestSubnetRouterAttachedEvent, self).setUp()
        self.chassis = '935f91fa-b8f8-47b9-8b1b-3a7a90ef7c26'
        self.agent = mock.Mock(chassis=self.chassis)
        self.event = bgp_watcher.SubnetRouterAttachedEvent(self.agent)

    def test_match_fn(self):
        row = utils.create_row(chassis=[], logical_port='lrp-fake',
                               mac=['aa:bb:cc:dd:ee:ff 10.10.1.16'],
                               options={})
        self.assertTrue(self.event.match_fn(mock.Mock(), row, mock.Mock()))

    def test_match_fn_not_single_or_dual_stack(self):
        row = utils.create_row(chassis=[], logical_port='lrp-fake',
                               mac=['aa:bb:cc:dd:ee:ff'],
                               options={})
        self.assertFalse(self.event.match_fn(mock.Mock(), row, mock.Mock()))

    def test_match_fn_not_lrp(self):
        row = utils.create_row(chassis=[], logical_port='fake-lp',
                               mac=['aa:bb:cc:dd:ee:ff 10.10.1.16'],
                               options={})
        self.assertFalse(self.event.match_fn(mock.Mock(), row, mock.Mock()))

    def test_match_fn_chassis_redirect(self):
        row = utils.create_row(chassis=[], logical_port='lrp-fake',
                               mac=['aa:bb:cc:dd:ee:ff 10.10.1.16'],
                               options={'chassis-redirect-port': True})
        self.assertFalse(self.event.match_fn(mock.Mock(), row, mock.Mock()))

    def test_match_fn_chassis_set(self):
        row = utils.create_row(chassis=[mock.Mock()], logical_port='lrp-fake',
                               mac=['aa:bb:cc:dd:ee:ff 10.10.1.16'],
                               options={})
        self.assertFalse(self.event.match_fn(mock.Mock(), row, mock.Mock()))

    def test_match_fn_index_error(self):
        row = utils.create_row(chassis=[], logical_port='lrp-fake',
                               mac=[], options={})
        self.assertFalse(self.event.match_fn(mock.Mock(), row, mock.Mock()))

    def test_run(self):
        row = utils.create_row(type=constants.OVN_PATCH_VIF_PORT_TYPE,
                               mac=['aa:bb:cc:dd:ee:ff 10.10.1.16'])
        self.event.run(mock.Mock(), row, mock.Mock())
        self.agent.expose_subnet.assert_called_once_with('10.10.1.16', row)

    def test_run_wrong_type(self):
        row = utils.create_row(type='coxinha',
                               mac=['aa:bb:cc:dd:ee:ff 10.10.1.16'])
        self.event.run(mock.Mock(), row, mock.Mock())
        self.agent.expose_subnet.assert_not_called()


class TestSubnetRouterUpdateEvent(test_base.TestCase):

    def setUp(self):
        super(TestSubnetRouterUpdateEvent, self).setUp()
        self.chassis = '935f91fa-b8f8-47b9-8b1b-3a7a90ef7c26'
        self.agent = mock.Mock(chassis=self.chassis)
        self.event = bgp_watcher.SubnetRouterUpdateEvent(self.agent)

    def test_match_fn(self):
        row = utils.create_row(chassis=[], logical_port='lrp-fake',
                               mac=['aa:bb:cc:dd:ee:ff 10.10.1.16'],
                               options={})
        self.assertTrue(self.event.match_fn(mock.Mock(), row, mock.Mock()))

    def test_match_fn_not_single_or_dual_stack(self):
        row = utils.create_row(chassis=[], logical_port='lrp-fake',
                               mac=['aa:bb:cc:dd:ee:ff'],
                               options={})
        old = utils.create_row(chassis=[], logical_port='lrp-fake',
                               mac=['aa:bb:cc:dd:ee:ff'],
                               options={})
        self.assertFalse(self.event.match_fn(mock.Mock(), row, old))

    def test_match_fn_not_lrp(self):
        row = utils.create_row(chassis=[], logical_port='fake-lp',
                               mac=['aa:bb:cc:dd:ee:ff 10.10.1.16'],
                               options={})
        self.assertFalse(self.event.match_fn(mock.Mock(), row, mock.Mock()))

    def test_match_fn_chassis_redirect(self):
        row = utils.create_row(chassis=[], logical_port='lrp-fake',
                               mac=['aa:bb:cc:dd:ee:ff 10.10.1.16'],
                               options={'chassis-redirect-port': True})
        self.assertFalse(self.event.match_fn(mock.Mock(), row, mock.Mock()))

    def test_match_fn_chassis_set(self):
        row = utils.create_row(chassis=[mock.Mock()], logical_port='lrp-fake',
                               mac=['aa:bb:cc:dd:ee:ff 10.10.1.16'],
                               options={})
        self.assertFalse(self.event.match_fn(mock.Mock(), row, mock.Mock()))

    def test_match_fn_mac_not_changed(self):
        row = utils.create_row(chassis=[], logical_port='lrp-fake',
                               mac=['aa:bb:cc:dd:ee:ff 10.10.1.16'],
                               options={})
        old = utils.create_row(chassis=[], logical_port='lrp-fake',
                               mac=['aa:bb:cc:dd:ee:ff 10.10.1.16'],
                               options={})
        self.assertFalse(self.event.match_fn(mock.Mock(), row, old))

    def test_match_fn_mac_changed(self):
        row = utils.create_row(chassis=[], logical_port='lrp-fake',
                               mac=['aa:bb:cc:dd:ee:ff 10.10.1.16'],
                               options={})
        old = utils.create_row(chassis=[], logical_port='lrp-fake',
                               mac=['aa:bb:cc:dd:ee:ff 10.10.1.16 10.10.1.17'],
                               options={})
        self.assertTrue(self.event.match_fn(mock.Mock(), row, old))

    def test_match_fn_index_error(self):
        row = utils.create_row(chassis=[], logical_port='lrp-fake',
                               mac=[], options={})
        self.assertFalse(self.event.match_fn(mock.Mock(), row, mock.Mock()))

    def test_run(self):
        row = utils.create_row(type=constants.OVN_PATCH_VIF_PORT_TYPE,
                               mac=['aa:bb:cc:dd:ee:ff 10.10.1.16'])
        old = utils.create_row(type=constants.OVN_PATCH_VIF_PORT_TYPE,
                               mac=['aa:bb:cc:dd:ee:ff'])
        self.event.run(mock.Mock(), row, old)
        self.agent.update_subnet.assert_called_once_with(old, row)

    def test_run_wrong_type(self):
        row = utils.create_row(type='coxinha',
                               mac=['aa:bb:cc:dd:ee:ff 10.10.1.16'])
        old = utils.create_row(type='coxinha',
                               mac=['aa:bb:cc:dd:ee:ff'])
        self.event.run(mock.Mock(), row, old)
        self.agent.update_subnet.assert_not_called()


class TestSubnetRouterDetachedEvent(test_base.TestCase):

    def setUp(self):
        super(TestSubnetRouterDetachedEvent, self).setUp()
        self.chassis = '935f91fa-b8f8-47b9-8b1b-3a7a90ef7c26'
        self.agent = mock.Mock(chassis=self.chassis)
        self.event = bgp_watcher.SubnetRouterDetachedEvent(self.agent)

    def test_match_fn(self):
        row = utils.create_row(chassis=[], logical_port='lrp-fake',
                               mac=['aa:bb:cc:dd:ee:ff 10.10.1.16'],
                               options={})
        self.assertTrue(self.event.match_fn(mock.Mock(), row, mock.Mock()))

    def test_match_fn_not_single_or_dual_stack(self):
        row = utils.create_row(chassis=[], logical_port='lrp-fake',
                               mac=['aa:bb:cc:dd:ee:ff'],
                               options={})
        self.assertFalse(self.event.match_fn(mock.Mock(), row, mock.Mock()))

    def test_match_fn_not_lrp(self):
        row = utils.create_row(chassis=[], logical_port='fake-lp',
                               mac=['aa:bb:cc:dd:ee:ff 10.10.1.16'],
                               options={})
        self.assertFalse(self.event.match_fn(mock.Mock(), row, mock.Mock()))

    def test_match_fn_chassis_redirect(self):
        row = utils.create_row(chassis=[], logical_port='lrp-fake',
                               mac=['aa:bb:cc:dd:ee:ff 10.10.1.16'],
                               options={'chassis-redirect-port': True})
        self.assertFalse(self.event.match_fn(mock.Mock(), row, mock.Mock()))

    def test_match_fn_chassis_set(self):
        row = utils.create_row(chassis=[mock.Mock()], logical_port='lrp-fake',
                               mac=['aa:bb:cc:dd:ee:ff 10.10.1.16'],
                               options={})
        self.assertFalse(self.event.match_fn(mock.Mock(), row, mock.Mock()))

    def test_match_fn_index_error(self):
        row = utils.create_row(chassis=[], logical_port='lrp-fake',
                               mac=[], options={})
        self.assertFalse(self.event.match_fn(mock.Mock(), row, mock.Mock()))

    def test_run(self):
        row = utils.create_row(type=constants.OVN_PATCH_VIF_PORT_TYPE,
                               mac=['aa:bb:cc:dd:ee:ff 10.10.1.16'])
        self.event.run(mock.Mock(), row, mock.Mock())
        self.agent.withdraw_subnet.assert_called_once_with('10.10.1.16', row)

    def test_run_wrong_type(self):
        row = utils.create_row(type='coxinha',
                               mac=['aa:bb:cc:dd:ee:ff 10.10.1.16'])
        self.event.run(mock.Mock(), row, mock.Mock())
        self.agent.withdraw_subnet.assert_not_called()


class TestTenantPortCreatedEvent(test_base.TestCase):

    def setUp(self):
        super(TestTenantPortCreatedEvent, self).setUp()
        self.chassis = '935f91fa-b8f8-47b9-8b1b-3a7a90ef7c26'
        self.agent = mock.Mock(chassis=self.chassis)
        self.agent.ovn_local_lrps = ['172.24.100.111']
        self.event = bgp_watcher.TenantPortCreatedEvent(self.agent)

    def test_match_fn(self):
        row = utils.create_row(chassis=[mock.Mock()],
                               mac=['aa:bb:cc:dd:ee:ff 10.10.1.16'])
        old = utils.create_row(chassis=[])
        self.assertTrue(self.event.match_fn(mock.Mock(), row, old))

    def test_match_fn_unknown_mac(self):
        event = self.event.ROW_UPDATE
        row = utils.create_row(chassis=[mock.Mock()],
                               mac=['unknown'],
                               external_ids={
                                   'neutron:cidrs': '10.10.1.16/24'})
        old = utils.create_row(chassis=[],
                               mac=['unknown'],
                               external_ids={
                                   'neutron:cidrs': '10.10.1.16/24'})
        self.assertTrue(self.event.match_fn(event, row, old))

    def test_match_fn_unknown_mac_no_cidr(self):
        event = self.event.ROW_UPDATE
        row = utils.create_row(chassis=[mock.Mock()],
                               mac=['unknown'],
                               external_ids={})
        old = utils.create_row(chassis=[],
                               mac=['unknown'],
                               external_ids={})
        self.assertFalse(self.event.match_fn(event, row, old))

    def test_match_fn_no_chassis(self):
        row = utils.create_row(mac=['aa:bb:cc:dd:ee:ff 10.10.1.16'])
        old = utils.create_row(chassis=[])
        self.assertFalse(self.event.match_fn(mock.Mock(), row, old))

    def test_match_fn_not_single_or_dual_stack(self):
        row = utils.create_row(mac=['aa:bb:cc:dd:ee:ff'])
        self.assertFalse(self.event.match_fn(mock.Mock(), row, mock.Mock()))

    def test_match_fn_old_chassis_set(self):
        row = utils.create_row(chassis=[mock.Mock()],
                               mac=['aa:bb:cc:dd:ee:ff 10.10.1.16'])
        old = utils.create_row(chassis=[mock.Mock()])
        self.assertFalse(self.event.match_fn(mock.Mock(), row, old))

    def test_match_fn_empty_ovn_local_lrps(self):
        self.agent.ovn_local_lrps = []
        row = utils.create_row(chassis=[mock.Mock()],
                               mac=['aa:bb:cc:dd:ee:ff 10.10.1.16'])
        old = utils.create_row(chassis=[])
        self.assertFalse(self.event.match_fn(mock.Mock(), row, old))

    def test_match_fn_index_error(self):
        row = utils.create_row(chassis=[mock.Mock()], mac=[])
        self.assertFalse(self.event.match_fn(mock.Mock(), row, mock.Mock()))

    def test_run(self):
        row = utils.create_row(type=constants.OVN_VM_VIF_PORT_TYPE,
                               mac=['aa:bb:cc:dd:ee:ff 10.10.1.16'])
        self.event.run(mock.Mock(), row, mock.Mock())
        self.agent.expose_remote_ip.assert_called_once_with(
            ['10.10.1.16'], row)

    def test_run_unknown_mac(self):
        row = utils.create_row(type=constants.OVN_VM_VIF_PORT_TYPE,
                               mac=['unknown'],
                               external_ids={
                                   'neutron:cidrs': '10.10.1.16/24'})
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
        self.event = bgp_watcher.TenantPortDeletedEvent(self.agent)

    def test_match_fn(self):
        event = self.event.ROW_UPDATE
        row = utils.create_row(chassis=[],
                               mac=['aa:bb:cc:dd:ee:ff 10.10.1.16'])
        old = utils.create_row(chassis=[mock.Mock()],
                               mac=['aa:bb:cc:dd:ee:ff 10.10.1.16'])
        self.assertTrue(self.event.match_fn(event, row, old))

    def test_match_fn_unknown_mac(self):
        event = self.event.ROW_UPDATE
        row = utils.create_row(chassis=[],
                               mac=['unknown'],
                               external_ids={
                                   'neutron:cidrs': '192.168.1.10/24'})
        old = utils.create_row(chassis=[mock.Mock()],
                               mac=['unknown'],
                               external_ids={
                                   'neutron:cidrs': '192.168.1.10/24'})
        self.assertTrue(self.event.match_fn(event, row, old))

    def test_match_fn_unknown_mac_no_cidr(self):
        event = self.event.ROW_UPDATE
        row = utils.create_row(chassis=[],
                               mac=['unknown'],
                               external_ids={})
        old = utils.create_row(chassis=[mock.Mock()],
                               mac=['unknown'],
                               external_ids={})
        self.assertFalse(self.event.match_fn(event, row, old))

    def test_match_fn_delete(self):
        event = self.event.ROW_DELETE
        row = utils.create_row(chassis=[],
                               mac=['aa:bb:cc:dd:ee:ff 10.10.1.16'])
        self.assertTrue(self.event.match_fn(event, row, mock.Mock()))

    def test_match_fn_not_single_or_dual_stack(self):
        row = utils.create_row(mac=['aa:bb:cc:dd:ee:ff'])
        self.assertFalse(self.event.match_fn(mock.Mock(), row, mock.Mock()))

    def test_match_fn_empty_ovn_local_lrps(self):
        row = utils.create_row(chassis=[],
                               mac=['aa:bb:cc:dd:ee:ff 10.10.1.16'])
        old = utils.create_row(chassis=[mock.Mock()],
                               mac=['aa:bb:cc:dd:ee:ff 10.10.1.16'])
        self.agent.ovn_local_lrps = []
        self.assertFalse(self.event.match_fn(mock.Mock(), row, old))

    def test_match_fn_index_error(self):
        row = utils.create_row(mac=[])
        self.assertFalse(self.event.match_fn(mock.Mock(), row, mock.Mock()))

    def test_run(self):
        event = self.event.ROW_UPDATE
        row = utils.create_row(type=constants.OVN_VM_VIF_PORT_TYPE,
                               mac=['aa:bb:cc:dd:ee:ff 10.10.1.16'],
                               chassis=[mock.Mock()])
        self.event.run(event, row, mock.Mock())
        self.agent.withdraw_remote_ip.assert_called_once_with(
            ['10.10.1.16'], row, mock.ANY)

    def test_run_unknown_mac(self):
        row = utils.create_row(type=constants.OVN_VM_VIF_PORT_TYPE,
                               chassis=[mock.Mock()],
                               mac=['unknown'],
                               external_ids={
                                   'neutron:cidrs': '10.10.1.16/24'})
        self.event.run(mock.Mock(), row, mock.Mock())
        self.agent.withdraw_remote_ip.assert_called_once_with(
            ['10.10.1.16'], row, mock.ANY)

    def test_run_dual_stack(self):
        row = utils.create_row(
            type=constants.OVN_VM_VIF_PORT_TYPE,
            mac=['aa:bb:cc:dd:ee:ff 10.10.1.16 2002::1234:abcd:ffff:c0a8:101'],
            chassis=[mock.Mock()])
        self.event.run(mock.Mock(), row, mock.Mock())
        self.agent.withdraw_remote_ip.assert_called_once_with(
            ['10.10.1.16', '2002::1234:abcd:ffff:c0a8:101'], row, mock.ANY)

    def test_run_wrong_type(self):
        row = utils.create_row(type='brigadeiro')
        self.event.run(mock.Mock(), row, mock.Mock())
        self.agent.withdraw_remote_ip.assert_not_called()

    def test_run_delete(self):
        event = self.event.ROW_DELETE
        row = utils.create_row(type=constants.OVN_VM_VIF_PORT_TYPE,
                               mac=['aa:bb:cc:dd:ee:ff 10.10.1.16'],
                               chassis=[mock.Mock()])
        self.event.run(event, row, [])
        self.agent.withdraw_remote_ip.assert_called_once_with(
            ['10.10.1.16'], row, mock.ANY)


class OVNLBVIPPortEvent(test_base.TestCase):

    def setUp(self):
        super(OVNLBVIPPortEvent, self).setUp()
        self.chassis = '935f91fa-b8f8-47b9-8b1b-3a7a90ef7c26'
        self.agent = mock.Mock(chassis=self.chassis)
        self.agent.ovn_local_cr_lrps = {'fake-cr-lrp-port': {}}
        self.event = bgp_watcher.OVNLBVIPPortEvent(self.agent)

    def test_match_fn(self):
        row = utils.create_row(chassis=[], mac=[], up=[False])
        self.assertTrue(self.event.match_fn(mock.Mock(), row, mock.Mock()))

    def test_match_fn_chassis(self):
        row = utils.create_row(chassis=[mock.Mock()], mac=[], up=[False])
        self.assertFalse(self.event.match_fn(mock.Mock(), row, mock.Mock()))

    def test_match_fn_mac(self):
        row = utils.create_row(chassis=[],
                               mac=['aa:bb:cc:dd:ee:ff 10.10.1.16'],
                               up=['False'])
        self.assertFalse(self.event.match_fn(mock.Mock(), row, mock.Mock()))

    def test_match_fn_up(self):
        row = utils.create_row(chassis=[], mac=[], up=[True])
        self.assertFalse(self.event.match_fn(mock.Mock(), row, mock.Mock()))

    def test_match_fn_empty_ovn_local_cr_lrps(self):
        self.agent.ovn_local_cr_lrps = []
        row = utils.create_row(chassis=[], mac=[], up=[False])
        self.assertFalse(self.event.match_fn(mock.Mock(), row, mock.Mock()))

    def test_match_fn_attribute_error(self):
        row = utils.create_row(mac=[])
        self.assertFalse(self.event.match_fn(mock.Mock(), row, mock.Mock()))

    def test_run(self):
        event = self.event.ROW_CREATE
        row = utils.create_row(
            type=constants.OVN_VM_VIF_PORT_TYPE, mac=[], chassis=[],
            up=[False], external_ids={
                constants.OVN_CIDRS_EXT_ID_KEY: "10.10.1.16/24"})
        self.event.run(event, row, mock.Mock())
        self.agent.expose_ovn_lb.assert_called_once_with(
            '10.10.1.16', row)

    def test_run_delete(self):
        event = self.event.ROW_DELETE
        row = utils.create_row(
            type=constants.OVN_VM_VIF_PORT_TYPE, mac=[], chassis=[],
            up=[False], external_ids={
                constants.OVN_CIDRS_EXT_ID_KEY: "10.10.1.16/24"})
        self.event.run(event, row, mock.Mock())
        self.agent.withdraw_ovn_lb.assert_called_once_with(
            '10.10.1.16', row)

    def test_run_no_external_id(self):
        row = utils.create_row(
            type=constants.OVN_VM_VIF_PORT_TYPE, mac=[], chassis=[],
            up=[False], external_ids={})
        self.event.run(mock.Mock(), row, mock.Mock())
        self.agent.expose_ovn_lb.assert_not_called()
        self.agent.withdraw_ovn_lb.assert_not_called()

    def test_run_wrong_type(self):
        row = utils.create_row(
            type=constants.OVN_VIRTUAL_VIF_PORT_TYPE, mac=[], chassis=[],
            up=[False], external_ids={
                constants.OVN_CIDRS_EXT_ID_KEY: "10.10.1.16/24"})
        self.event.run(mock.Mock(), row, mock.Mock())
        self.agent.expose_ovn_lb.assert_not_called()
        self.agent.withdraw_ovn_lb.assert_not_called()


class TestOVNLBMemberCreateEvent(test_base.TestCase):

    def setUp(self):
        super(TestOVNLBMemberCreateEvent, self).setUp()
        self.chassis = '935f91fa-b8f8-47b9-8b1b-3a7a90ef7c26'
        self.agent = mock.Mock(chassis=self.chassis)
        self.agent.ovn_local_cr_lrps = {
            'cr-lrp1': {'provider_datapath': 'dp1',
                        'subnets_datapath': {'lrp1': 's_dp1'},
                        'ovn_lbs': 'ovn-lb1'}}
        self.event = bgp_watcher.OVNLBMemberCreateEvent(self.agent)

    def test_match_fn(self):
        self.assertTrue(self.event.match_fn(mock.Mock(), mock.Mock(),
                                            mock.Mock()))

    def test_match_fn_no_cr_lrp(self):
        self.agent.ovn_local_cr_lrps = {}
        self.assertFalse(self.event.match_fn(mock.Mock(), mock.Mock(),
                                             mock.Mock()))

    def test_run(self):
        dpg1 = utils.create_row(_uuid='fake_dp_group',
                                datapaths=['s_dp1'])
        row = utils.create_row(name='ovn-lb1',
                               datapath_group=[dpg1],
                               vips={'172.24.100.66:80': '10.0.0.5:8080'})
        vip_port = utils.create_row(
            datapath='dp1',
            logical_port='ovn-lb-port-1',
            external_ids={constants.OVN_CIDRS_EXT_ID_KEY: '172.24.100.66/26'})
        self.agent.sb_idl.get_ovn_vip_port.return_value = vip_port
        self.agent.sb_idl.get_lrps_for_datapath.return_value = ['fake-lrp']
        self.agent.sb_idl.get_port_datapath.return_value = 'r_dp'
        self.event.run(self.event.ROW_CREATE, row, mock.Mock())
        self.agent.expose_ovn_lb_on_provider.assert_called_once_with(
            '172.24.100.66', row.name, 'cr-lrp1')
        self.agent.withdraw_ovn_lb_on_provider.assert_not_called()

    def test_run_no_subnets_datapath(self):
        CONF.set_override('expose_tenant_networks', False)
        self.addCleanup(CONF.clear_override, 'expose_tenant_networks')
        dpg1 = utils.create_row(_uuid='fake_dp_group',
                                datapaths=['s_dp1'])
        row = utils.create_row(name='ovn-lb1',
                               ls_datapath_group=[dpg1],
                               vips={'172.24.100.66:80': '10.0.0.5:8080'})
        self.agent.ovn_local_cr_lrps = {
            'cr-lrp1': {'provider_datapath': 'dp1',
                        'router_datapath': 'r_dp',
                        'subnets_datapath': {},
                        'ovn_lbs': 'ovn-lb1'}}
        vip_port = utils.create_row(
            datapath='dp1',
            logical_port='ovn-lb-port-1',
            external_ids={constants.OVN_CIDRS_EXT_ID_KEY: '172.24.100.66/26'})
        self.agent.sb_idl.get_ovn_vip_port.return_value = vip_port
        self.agent.sb_idl.get_lrps_for_datapath.return_value = ['fake-lrp']
        self.agent.sb_idl.get_port_datapath.return_value = 'r_dp'
        self.event.run(self.event.ROW_CREATE, row, mock.Mock())
        self.agent.expose_ovn_lb_on_provider.assert_called_once_with(
            '172.24.100.66', row.name, 'cr-lrp1')
        self.agent.withdraw_ovn_lb_on_provider.assert_not_called()

    def test_run_no_vip_port(self):
        dpg1 = utils.create_row(_uuid='fake_dp_group',
                                datapaths=['s_dp1'])
        row = utils.create_row(name='ovn-lb1',
                               lr_datapath_group=[dpg1],
                               vips={'172.24.100.66:80': '10.0.0.5:8080'})
        self.agent.sb_idl.get_ovn_vip_port.return_value = []
        self.event.run(self.event.ROW_CREATE, row, mock.Mock())
        self.agent.expose_ovn_lb_on_provider.assert_not_called()
        self.agent.withdraw_ovn_lb_on_provider.assert_not_called()

    def test_run_different_provider(self):
        dpg1 = utils.create_row(_uuid='fake_dp_group',
                                datapaths=['s_dp1'])
        row = utils.create_row(name='ovn-lb1',
                               datapath_group=[dpg1],
                               vips={'172.24.100.66:80': '10.0.0.5:8080'})
        vip_port = utils.create_row(
            datapath='dp2',
            logical_port='ovn-lb-port-1',
            external_ids={constants.OVN_CIDRS_EXT_ID_KEY: '172.24.100.66/26'})
        self.agent.sb_idl.get_lrps_for_datapath.return_value = ['fake-lrp']
        self.agent.sb_idl.get_port_datapath.return_value = 'dp2'
        self.agent.sb_idl.get_ovn_vip_port.return_value = vip_port
        self.event.run(self.event.ROW_CREATE, row, mock.Mock())
        self.agent.expose_ovn_lb_on_provider.assert_not_called()
        self.agent.withdraw_ovn_lb_on_provider.assert_not_called()

    def test_run_no_cr_lrp_match(self):
        dpg1 = utils.create_row(_uuid='fake_dp_group',
                                datapaths=['s_dp2'])
        row = utils.create_row(name='ovn-lb1',
                               ls_datapath_group=[dpg1],
                               vips={'172.24.100.66:80': '10.0.0.5:8080'})
        vip_port = utils.create_row(
            datapath='dp1',
            logical_port='ovn-lb-port-1',
            external_ids={constants.OVN_CIDRS_EXT_ID_KEY: '172.24.100.66/26'})
        self.agent.sb_idl.get_lrps_for_datapath.return_value = ['fake-lrp']
        self.agent.sb_idl.get_port_datapath.return_value = 'r_dp'
        self.agent.sb_idl.get_ovn_vip_port.return_value = vip_port
        self.event.run(self.event.ROW_CREATE, row, mock.Mock())
        self.agent.expose_ovn_lb_on_provider.assert_not_called()
        self.agent.withdraw_ovn_lb_on_provider.assert_not_called()

    def test_run_no_vip(self):
        dpg1 = utils.create_row(_uuid='fake_dp_group',
                                datapaths=['s_dp1'])
        row = utils.create_row(name='ovn-lb1',
                               lr_datapath_group=[dpg1],
                               vips={'172.24.100.66:80': '10.0.0.5:8080'})
        vip_port = utils.create_row(
            datapath='dp1',
            logical_port='port-1',
            external_ids={})
        self.agent.sb_idl.get_lrps_for_datapath.return_value = ['fake-lrp']
        self.agent.sb_idl.get_port_datapath.return_value = 'r_dp'
        self.agent.sb_idl.get_ovn_vip_port.return_value = vip_port
        self.event.run(self.event.ROW_CREATE, row, mock.Mock())
        self.agent.expose_ovn_lb_on_provider.assert_not_called()
        self.agent.withdraw_ovn_lb_on_provider.assert_not_called()


class TestOVNLBMemberDeleteEvent(test_base.TestCase):

    def setUp(self):
        super(TestOVNLBMemberDeleteEvent, self).setUp()
        self.chassis = '935f91fa-b8f8-47b9-8b1b-3a7a90ef7c26'
        self.agent = mock.Mock(chassis=self.chassis)
        self.agent.provider_ovn_lbs = {
            'ovn-lb1': {'ips': ['fake-ip'], 'gateway_port': 'cr-lrp1'}}
        self.event = bgp_watcher.OVNLBMemberDeleteEvent(self.agent)

    def test_match_fn(self):
        row = utils.create_row(name='ovn-lb1')
        self.assertTrue(self.event.match_fn(mock.Mock(), row, mock.Mock()))

    def test_match_fn_no_lb(self):
        row = utils.create_row(name='ovn-lb2')
        self.agent.ovn_local_cr_lrps = {}
        self.assertFalse(self.event.match_fn(mock.Mock(), row, mock.Mock()))

    def test_run(self):
        dpg1 = utils.create_row(_uuid='fake_dp_group',
                                datapaths=['s_dp1'])
        row = utils.create_row(name='ovn-lb1',
                               datapath_group=[dpg1],
                               vips={'172.24.100.66:80': '10.0.0.5:8080'})
        vip_port = utils.create_row(
            datapath='dp1',
            logical_port='ovn-lb-port-1',
            external_ids={constants.OVN_CIDRS_EXT_ID_KEY: '172.24.100.66/26'})
        self.agent.sb_idl.get_lrps_for_datapath.return_value = ['fake-lrp']
        self.agent.sb_idl.get_port_datapath.return_value = 'r_dp'
        self.agent.sb_idl.get_ovn_vip_port.return_value = vip_port
        self.event.run(self.event.ROW_DELETE, row, mock.Mock())
        self.agent.withdraw_ovn_lb_on_provider.assert_called_once_with(
            row.name, 'cr-lrp1')
        self.agent.expose_ovn_lb_on_provider.assert_not_called()


class TestLocalnetCreateDeleteEvent(test_base.TestCase):

    def setUp(self):
        super(TestLocalnetCreateDeleteEvent, self).setUp()
        self.agent = mock.Mock()
        self.event = bgp_watcher.LocalnetCreateDeleteEvent(self.agent)

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
    _event = bgp_watcher.ChassisCreateEvent

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
    _event = bgp_watcher.ChassisPrivateCreateEvent

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
from ovn_bgp_agent.drivers.openstack.watchers import bgp_watcher
from ovn_bgp_agent.tests import base as test_base
from ovn_bgp_agent.tests import utils


class TestPortBindingChassisCreatedEvent(test_base.TestCase):

    def setUp(self):
        super(TestPortBindingChassisCreatedEvent, self).setUp()
        self.chassis = '935f91fa-b8f8-47b9-8b1b-3a7a90ef7c26'
        self.agent = mock.Mock(chassis=self.chassis)
        self.event = bgp_watcher.PortBindingChassisCreatedEvent(self.agent)

    def test_match_fn(self):
        ch = utils.create_row(name=self.chassis)
        row = utils.create_row(chassis=[ch],
                               mac=['aa:bb:cc:dd:ee:ff 10.10.1.16'])
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
                               mac=['aa:bb:cc:dd:ee:ff 10.10.1.16'])
        old = utils.create_row(chassis=self.chassis)
        self.assertFalse(self.event.match_fn(mock.Mock(), row, old))

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
        ch = utils.create_row(name=self.chassis)
        row = utils.create_row(chassis=[ch],
                               mac=['aa:bb:cc:dd:ee:ff 10.10.1.16'])
        old = utils.create_row(chassis=[])
        self.assertTrue(self.event.match_fn(mock.Mock(), row, old))

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

    def test_match_fn_update_old_chassis_set(self):
        event = self.event.ROW_UPDATE
        ch = utils.create_row(name=self.chassis)
        row = utils.create_row(chassis=[ch],
                               mac=['aa:bb:cc:dd:ee:ff 10.10.1.16'])
        old = utils.create_row(chassis=self.chassis)
        self.assertFalse(self.event.match_fn(event, row, old))

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
        row = utils.create_row(mac=['aa:bb:cc:dd:ee:ff 10.10.1.16'])
        old = utils.create_row(chassis=[])
        self.assertTrue(self.event.match_fn(mock.Mock(), row, old))

    def test_match_fn_not_single_or_dual_stack(self):
        row = utils.create_row(mac=['aa:bb:cc:dd:ee:ff'])
        self.assertFalse(self.event.match_fn(mock.Mock(), row, mock.Mock()))

    def test_match_fn_old_chassis_set(self):
        row = utils.create_row(mac=['aa:bb:cc:dd:ee:ff 10.10.1.16'])
        old = utils.create_row(chassis=[mock.Mock()])
        self.assertFalse(self.event.match_fn(mock.Mock(), row, old))

    def test_match_fn_empty_ovn_local_lrps(self):
        self.agent.ovn_local_lrps = []
        row = utils.create_row(mac=['aa:bb:cc:dd:ee:ff 10.10.1.16'])
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
        self.event = bgp_watcher.TenantPortDeletedEvent(self.agent)

    def test_match_fn(self):
        row = utils.create_row(mac=['aa:bb:cc:dd:ee:ff 10.10.1.16'])
        self.assertTrue(self.event.match_fn(mock.Mock(), row, mock.Mock()))

    def test_match_fn_not_single_or_dual_stack(self):
        row = utils.create_row(mac=['aa:bb:cc:dd:ee:ff'])
        self.assertFalse(self.event.match_fn(mock.Mock(), row, mock.Mock()))

    def test_match_fn_empty_ovn_local_lrps(self):
        self.agent.ovn_local_lrps = []
        row = utils.create_row(mac=['aa:bb:cc:dd:ee:ff 10.10.1.16'])
        self.assertFalse(self.event.match_fn(mock.Mock(), row, mock.Mock()))

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


class TestOVNLBMemberUpdateEvent(test_base.TestCase):

    def setUp(self):
        super(TestOVNLBMemberUpdateEvent, self).setUp()
        self.chassis = '935f91fa-b8f8-47b9-8b1b-3a7a90ef7c26'
        self.agent = mock.Mock(chassis=self.chassis)
        self.agent.ovn_local_cr_lrps = {
            'cr-lrp1': {'provider_datapath': 'dp1',
                        'subnets_datapath': {'lrp1': 's_dp1'}}}
        self.event = bgp_watcher.OVNLBMemberUpdateEvent(self.agent)

    def test_match_fn(self):
        row = utils.create_row(datapaths=['dp1', 'dp2'])
        old = utils.create_row(datapaths=['dp1'])
        self.assertTrue(self.event.match_fn(mock.Mock(), row, old))

    def test_match_fn_no_dp_change(self):
        row = utils.create_row(datapaths=['dp1'])
        old = utils.create_row(datapaths=['dp1'])
        self.assertFalse(self.event.match_fn(mock.Mock(), row, old))

    def test_match_fn_removed_dp(self):
        row = utils.create_row(datapaths=['dp1'])
        old = utils.create_row(datapaths=[])
        self.assertTrue(self.event.match_fn(mock.Mock(), row, old))

    def test_match_fn_no_cr_lrp(self):
        self.agent.ovn_local_cr_lrps = {}
        row = utils.create_row(datapaths=['dp1'])
        old = utils.create_row(datapaths=['dp1', 'dp2'])
        self.assertFalse(self.event.match_fn(mock.Mock(), row, old))

    def test_run(self):
        row = utils.create_row(name='ovn-lb1',
                               datapaths=['dp1', 's_dp1'],
                               vips={'172.24.100.66:80': '10.0.0.5:8080'})
        old = utils.create_row(name='ovn-lb1',
                               datapaths=['dp1'],
                               vips={'172.24.100.66:80': '10.0.0.5:8080'})
        self.event.run(mock.Mock(), row, old)
        self.agent.expose_ovn_lb_on_provider.assert_called_once_with(
            'ovn-lb1', '172.24.100.66', 'dp1', 'cr-lrp1')
        self.agent.withdraw_ovn_lb_on_provider.assert_not_called()

    def test_run_no_provider_dp(self):
        row = utils.create_row(name='ovn-lb1',
                               datapaths=['s_dp2'])
        self.event.run(mock.Mock(), row, mock.Mock())
        self.agent.expose_ovn_lb_on_provider.assert_not_called()
        self.agent.withdraw_ovn_lb_on_provider.assert_not_called()

    def test_run_removed_dp(self):
        row = utils.create_row(name='ovn-lb1',
                               datapaths=['dp1'])
        old = utils.create_row(name='ovn-lb1',
                               datapaths=['dp1', 's_dp1'],
                               vips={'172.24.100.66:80': '10.0.0.5:8080'})
        self.event.run(mock.Mock(), row, old)
        self.agent.expose_ovn_lb_on_provider.assert_not_called()
        self.agent.withdraw_ovn_lb_on_provider.assert_called_once_with(
            'ovn-lb1', 'dp1', 'cr-lrp1')

    def test_run_no_match_subnets_dp(self):
        row = utils.create_row(name='ovn-lb1',
                               datapaths=['dp1', 's_dp2'],
                               vips={'172.24.100.66:80': '10.0.0.5:8080'})
        old = utils.create_row(name='ovn-lb1',
                               datapaths=['dp1'],
                               vips={'172.24.100.66:80': '10.0.0.5:8080'})
        self.event.run(mock.Mock(), row, old)
        self.agent.expose_ovn_lb_on_provider.assert_not_called()
        self.agent.withdraw_ovn_lb_on_provider.assert_not_called()

    def test_run_no_member(self):
        row = utils.create_row(name='ovn-lb1',
                               datapaths=['dp1'])
        old = utils.create_row(name='ovn-lb1',
                               datapaths=['dp1'])
        self.event.run(mock.Mock(), row, old)
        self.agent.expose_ovn_lb_on_provider.assert_not_called()
        self.agent.withdraw_ovn_lb_on_provider.assert_not_called()

    def test_run_member_removal(self):
        row = utils.create_row(name='ovn-lb1',
                               datapaths=['dp1', 's_dp1'])
        old = utils.create_row(name='ovn-lb1',
                               datapaths=['dp1', 's_dp1', 's_dp2'])
        self.event.run(mock.Mock(), row, old)
        self.agent.expose_ovn_lb_on_provider.assert_not_called()
        self.agent.withdraw_ovn_lb_on_provider.assert_not_called()


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

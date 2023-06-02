# Copyright 2021 Red Hat, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from oslo_concurrency import lockutils
from oslo_log import log as logging

from ovn_bgp_agent import constants
from ovn_bgp_agent.drivers.openstack.watchers import base_watcher


LOG = logging.getLogger(__name__)

_SYNC_STATE_LOCK = lockutils.ReaderWriterLock()


class PortBindingChassisCreatedEvent(base_watcher.PortBindingChassisEvent):
    def __init__(self, bgp_agent):
        events = (self.ROW_UPDATE,)
        super(PortBindingChassisCreatedEvent, self).__init__(
            bgp_agent, events)

    def match_fn(self, event, row, old):
        try:
            if row.type != constants.OVN_CHASSISREDIRECT_VIF_PORT_TYPE:
                return False
            # single and dual-stack format
            if not self._check_ip_associated(row.mac[0]):
                return False
            return (row.chassis[0].name == self.agent.chassis and
                    not old.chassis)
        except (IndexError, AttributeError):
            return False

    def _run(self, event, row, old):
        if row.type != constants.OVN_CHASSISREDIRECT_VIF_PORT_TYPE:
            return
        with _SYNC_STATE_LOCK.read_lock():
            self.agent.expose_ip(row, cr_lrp=True)


class PortBindingChassisDeletedEvent(base_watcher.PortBindingChassisEvent):
    def __init__(self, bgp_agent):
        events = (self.ROW_UPDATE, self.ROW_DELETE,)
        super(PortBindingChassisDeletedEvent, self).__init__(
            bgp_agent, events)

    def match_fn(self, event, row, old):
        try:
            if row.type != constants.OVN_CHASSISREDIRECT_VIF_PORT_TYPE:
                return False
            # single and dual-stack format
            if not self._check_ip_associated(row.mac[0]):
                return False
            if event == self.ROW_UPDATE:
                return (old.chassis[0].name == self.agent.chassis and
                        not row.chassis)
            else:
                return row.chassis[0].name == self.agent.chassis
        except (IndexError, AttributeError):
            return False

    def _run(self, event, row, old):
        if row.type != constants.OVN_CHASSISREDIRECT_VIF_PORT_TYPE:
            return
        with _SYNC_STATE_LOCK.read_lock():
            self.agent.withdraw_ip(row, cr_lrp=True)


class SubnetRouterAttachedEvent(base_watcher.PortBindingChassisEvent):
    def __init__(self, bgp_agent):
        events = (self.ROW_UPDATE, self.ROW_CREATE,)
        super(SubnetRouterAttachedEvent, self).__init__(
            bgp_agent, events)

    def match_fn(self, event, row, old):
        try:
            if event == self.ROW_UPDATE:
                return (not row.chassis and
                        not row.logical_port.startswith('lrp-') and
                        row.external_ids[constants.OVN_EVPN_VNI_EXT_ID_KEY] and
                        row.external_ids[constants.OVN_EVPN_AS_EXT_ID_KEY] and
                        (not old.external_ids.get(
                            constants.OVN_EVPN_VNI_EXT_ID_KEY) or
                         not old.external_ids.get(
                             constants.constants.OVN_EVPN_AS_EXT_ID_KEY)))
            else:
                return (not row.chassis and
                        not row.logical_port.startswith('lrp-') and
                        row.external_ids[constants.OVN_EVPN_VNI_EXT_ID_KEY] and
                        row.external_ids[constants.OVN_EVPN_AS_EXT_ID_KEY])
        except (IndexError, AttributeError, KeyError):
            return False

    def _run(self, event, row, old):
        if row.type != constants.OVN_PATCH_VIF_PORT_TYPE:
            return
        with _SYNC_STATE_LOCK.read_lock():
            if row.nat_addresses:
                self.agent.expose_ip(row)
            else:
                self.agent.expose_subnet(row)


class SubnetRouterDetachedEvent(base_watcher.PortBindingChassisEvent):
    def __init__(self, bgp_agent):
        events = (self.ROW_UPDATE, self.ROW_DELETE,)
        super(SubnetRouterDetachedEvent, self).__init__(
            bgp_agent, events)

    def match_fn(self, event, row, old):
        try:
            if event == self.ROW_UPDATE:
                return (not row.chassis and
                        not row.logical_port.startswith('lrp-') and
                        old.external_ids[constants.OVN_EVPN_VNI_EXT_ID_KEY] and
                        old.external_ids[constants.OVN_EVPN_AS_EXT_ID_KEY] and
                        (not row.external_ids.get(
                            constants.OVN_EVPN_VNI_EXT_ID_KEY) or
                         not row.external_ids.get(
                             constants.OVN_EVPN_AS_EXT_ID_KEY)))
            else:
                return (not row.chassis and
                        not row.logical_port.startswith('lrp-') and
                        row.external_ids[constants.OVN_EVPN_VNI_EXT_ID_KEY] and
                        row.external_ids[constants.OVN_EVPN_AS_EXT_ID_KEY])
        except (IndexError, AttributeError, KeyError):
            return False

    def _run(self, event, row, old):
        if row.type != constants.OVN_PATCH_VIF_PORT_TYPE:
            return
        with _SYNC_STATE_LOCK.read_lock():
            if row.nat_addresses:
                self.agent.withdraw_ip(row)
            else:
                self.agent.withdraw_subnet(row)


class TenantPortCreatedEvent(base_watcher.PortBindingChassisEvent):
    def __init__(self, bgp_agent):
        events = (self.ROW_UPDATE,)
        super(TenantPortCreatedEvent, self).__init__(
            bgp_agent, events)

    def match_fn(self, event, row, old):
        try:
            # single and dual-stack format
            if not self._check_ip_associated(row.mac[0]):
                return False
            return (not old.chassis and row.chassis and
                    self.agent.ovn_local_lrps != [])
        except (IndexError, AttributeError):
            return False

    def _run(self, event, row, old):
        if row.type not in (constants.OVN_VM_VIF_PORT_TYPE,
                            constants.OVN_VIRTUAL_VIF_PORT_TYPE):
            return
        with _SYNC_STATE_LOCK.read_lock():
            ips = row.mac[0].split(' ')[1:]
            self.agent.expose_remote_ip(ips, row)


class TenantPortDeletedEvent(base_watcher.PortBindingChassisEvent):
    def __init__(self, bgp_agent):
        events = (self.ROW_DELETE, self.ROW_UPDATE,)
        super(TenantPortDeletedEvent, self).__init__(
            bgp_agent, events)

    def match_fn(self, event, row, old):
        try:
            # single and dual-stack format
            if not self._check_ip_associated(row.mac[0]):
                return False
            if event == self.ROW_UPDATE:
                return (old.chassis and not row.chassis and
                        self.agent.ovn_local_lrps != [])
            else:
                return (self.agent.ovn_local_lrps != [])
        except (IndexError, AttributeError):
            return False

    def _run(self, event, row, old):
        if row.type not in (constants.OVN_VM_VIF_PORT_TYPE,
                            constants.OVN_VIRTUAL_VIF_PORT_TYPE):
            return
        with _SYNC_STATE_LOCK.read_lock():
            ips = row.mac[0].split(' ')[1:]
            self.agent.withdraw_remote_ip(ips, row)


class LocalnetCreateDeleteEvent(base_watcher.PortBindingChassisEvent):
    def __init__(self, bgp_agent):
        events = (self.ROW_CREATE, self.ROW_DELETE,)
        super(LocalnetCreateDeleteEvent, self).__init__(
            bgp_agent, events)

    def match_fn(self, event, row, old):
        return row.type == constants.OVN_LOCALNET_VIF_PORT_TYPE

    def _run(self, event, row, old):
        with _SYNC_STATE_LOCK.read_lock():
            self.agent.sync()


class ChassisCreateEventBase(base_watcher.Event):
    table = None

    def __init__(self, bgp_agent):
        self.agent = bgp_agent
        self.first_time = True
        events = (self.ROW_CREATE,)
        super(ChassisCreateEventBase, self).__init__(
            events, self.table, (('name', '=', self.agent.chassis),))
        self.event_name = self.__class__.__name__

    def _run(self, event, row, old):
        if self.first_time:
            self.first_time = False
        else:
            LOG.info("Connection to OVSDB established, doing a full sync")
            self.agent.sync()


class ChassisCreateEvent(ChassisCreateEventBase):
    table = 'Chassis'


class ChassisPrivateCreateEvent(ChassisCreateEventBase):
    table = 'Chassis_Private'

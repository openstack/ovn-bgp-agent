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
from ovsdbapp.backend.ovs_idl import event as row_event

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
            # single and dual-stack format
            if not self._check_single_dual_stack_format(row.mac[0]):
                return False
            return (row.chassis[0].name == self.agent.chassis and
                    not old.chassis)
        except (IndexError, AttributeError):
            return False

    def run(self, event, row, old):
        if row.type not in constants.OVN_VIF_PORT_TYPES:
            return
        with _SYNC_STATE_LOCK.read_lock():
            ips = [row.mac[0].split(' ')[1]]
            # for dual-stack
            if len(row.mac[0].split(' ')) == 3:
                ips.append(row.mac[0].split(' ')[2])
            self.agent.expose_ip(ips, row)


class PortBindingChassisDeletedEvent(base_watcher.PortBindingChassisEvent):
    def __init__(self, bgp_agent):
        events = (self.ROW_UPDATE, self.ROW_DELETE,)
        super(PortBindingChassisDeletedEvent, self).__init__(
            bgp_agent, events)

    def match_fn(self, event, row, old):
        try:
            # single and dual-stack format
            if not self._check_single_dual_stack_format(row.mac[0]):
                return False
            if event == self.ROW_UPDATE:
                return (old.chassis[0].name == self.agent.chassis and
                        not row.chassis)
            else:
                return row.chassis[0].name == self.agent.chassis
        except (IndexError, AttributeError):
            return False

    def run(self, event, row, old):
        if row.type not in constants.OVN_VIF_PORT_TYPES:
            return
        with _SYNC_STATE_LOCK.read_lock():
            ips = [row.mac[0].split(' ')[1]]
            # for dual-stack
            if len(row.mac[0].split(' ')) == 3:
                ips.append(row.mac[0].split(' ')[2])
            self.agent.withdraw_ip(ips, row)


class FIPSetEvent(base_watcher.PortBindingChassisEvent):
    def __init__(self, bgp_agent):
        events = (self.ROW_UPDATE,)
        super(FIPSetEvent, self).__init__(
            bgp_agent, events)

    def match_fn(self, event, row, old):
        try:
            return (not row.chassis and
                    row.nat_addresses != old.nat_addresses and
                    not row.logical_port.startswith('lrp-'))
        except (AttributeError):
            return False

    def run(self, event, row, old):
        if row.type != constants.OVN_PATCH_VIF_PORT_TYPE:
            return
        with _SYNC_STATE_LOCK.read_lock():
            # NOTE(ltomasbo): nat_addresses has the same format, where
            # different IPs can be present:
            # ["fa:16:3e:77:7f:9c 172.24.100.229 172.24.100.112
            #  is_chassis_resident(\"
            #      cr-lrp-add962d2-21ab-4733-b6ef-35538eff25a8\")"]
            old_cr_lrps = {}
            for nat in old.nat_addresses:
                ips = nat.split(" ")[1:-1]
                port = nat.split(" ")[-1].split("\"")[1]
                old_cr_lrps.setdefault(port, set()).update(ips)
            for nat in row.nat_addresses:
                ips = nat.split(" ")[1:-1]
                port = nat.split(" ")[-1].split("\"")[1]
                ips_to_expose = [ip for ip in ips
                                 if ip not in old_cr_lrps.get(port, set())]
                self.agent.expose_ip(ips_to_expose, row, associated_port=port)


class FIPUnsetEvent(base_watcher.PortBindingChassisEvent):
    def __init__(self, bgp_agent):
        events = (self.ROW_UPDATE,)
        super(FIPUnsetEvent, self).__init__(
            bgp_agent, events)

    def match_fn(self, event, row, old):
        try:
            return (not row.chassis and
                    row.nat_addresses != old.nat_addresses and
                    not row.logical_port.startswith('lrp-'))
        except (AttributeError):
            return False

    def run(self, event, row, old):
        if row.type != constants.OVN_PATCH_VIF_PORT_TYPE:
            return
        with _SYNC_STATE_LOCK.read_lock():
            # NOTE(ltomasbo): nat_addresses has the same format, where
            # different IPs can be present:
            # ["fa:16:3e:77:7f:9c 172.24.100.229 172.24.100.112
            #  is_chassis_resident(\"
            #      cr-lrp-add962d2-21ab-4733-b6ef-35538eff25a8\")"]
            current_cr_lrps = {}
            for nat in row.nat_addresses:
                ips = nat.split(" ")[1:-1]
                port = nat.split(" ")[-1].split("\"")[1]
                current_cr_lrps.setdefault(port, set()).update(ips)
            for nat in old.nat_addresses:
                ips = nat.split(" ")[1:-1]
                port = nat.split(" ")[-1].split("\"")[1]
                ips_to_withdraw = [ip for ip in ips
                                   if ip not in current_cr_lrps.get(port,
                                                                    set())]
                self.agent.withdraw_ip(ips_to_withdraw, row,
                                       associated_port=port)


class SubnetRouterAttachedEvent(base_watcher.PortBindingChassisEvent):
    def __init__(self, bgp_agent):
        events = (self.ROW_CREATE,)
        super(SubnetRouterAttachedEvent, self).__init__(
            bgp_agent, events)

    def match_fn(self, event, row, old):
        try:
            # single and dual-stack format
            if not self._check_single_dual_stack_format(row.mac[0]):
                return False
            return (not row.chassis and row.logical_port.startswith('lrp-'))
        except (IndexError, AttributeError):
            return False

    def run(self, event, row, old):
        if row.type != constants.OVN_PATCH_VIF_PORT_TYPE:
            return
        with _SYNC_STATE_LOCK.read_lock():
            ip_address = row.mac[0].split(' ')[1]
            self.agent.expose_subnet(ip_address, row)


class SubnetRouterDetachedEvent(base_watcher.PortBindingChassisEvent):
    def __init__(self, bgp_agent):
        events = (self.ROW_DELETE,)
        super(SubnetRouterDetachedEvent, self).__init__(
            bgp_agent, events)

    def match_fn(self, event, row, old):
        try:
            # single and dual-stack format
            if not self._check_single_dual_stack_format(row.mac[0]):
                return False
            return (not row.chassis and row.logical_port.startswith('lrp-'))
        except (IndexError, AttributeError):
            return False

    def run(self, event, row, old):
        if row.type != constants.OVN_PATCH_VIF_PORT_TYPE:
            return
        with _SYNC_STATE_LOCK.read_lock():
            ip_address = row.mac[0].split(' ')[1]
            self.agent.withdraw_subnet(ip_address, row)


class TenantPortCreatedEvent(base_watcher.PortBindingChassisEvent):
    def __init__(self, bgp_agent):
        events = (self.ROW_UPDATE,)
        super(TenantPortCreatedEvent, self).__init__(
            bgp_agent, events)

    def match_fn(self, event, row, old):
        try:
            # single and dual-stack format
            if not self._check_single_dual_stack_format(row.mac[0]):
                return False
            return (not old.chassis and
                    self.agent.ovn_local_lrps != [])
        except (IndexError, AttributeError):
            return False

    def run(self, event, row, old):
        if row.type not in (constants.OVN_VM_VIF_PORT_TYPE,
                            constants.OVN_VIRTUAL_VIF_PORT_TYPE):
            return
        with _SYNC_STATE_LOCK.read_lock():
            ips = [row.mac[0].split(' ')[1]]
            # for dual-stack
            if len(row.mac[0].split(' ')) == 3:
                ips.append(row.mac[0].split(' ')[2])
            self.agent.expose_remote_ip(ips, row)


class TenantPortDeletedEvent(base_watcher.PortBindingChassisEvent):
    def __init__(self, bgp_agent):
        events = (self.ROW_DELETE,)
        super(TenantPortDeletedEvent, self).__init__(
            bgp_agent, events)

    def match_fn(self, event, row, old):
        try:
            # single and dual-stack format
            if not self._check_single_dual_stack_format(row.mac[0]):
                return False
            return (self.agent.ovn_local_lrps != [])
        except (IndexError, AttributeError):
            return False

    def run(self, event, row, old):
        if row.type not in (constants.OVN_VM_VIF_PORT_TYPE,
                            constants.OVN_VIRTUAL_VIF_PORT_TYPE):
            return
        with _SYNC_STATE_LOCK.read_lock():
            ips = [row.mac[0].split(' ')[1]]
            # for dual-stack
            if len(row.mac[0].split(' ')) == 3:
                ips.append(row.mac[0].split(' ')[2])
            self.agent.withdraw_remote_ip(ips, row)


class ChassisCreateEventBase(row_event.RowEvent):
    table = None

    def __init__(self, bgp_agent):
        self.agent = bgp_agent
        self.first_time = True
        events = (self.ROW_CREATE,)
        super(ChassisCreateEventBase, self).__init__(
            events, self.table, (('name', '=', self.agent.chassis),))
        self.event_name = self.__class__.__name__

    def run(self, event, row, old):
        if self.first_time:
            self.first_time = False
        else:
            LOG.info("Connection to OVSDB established, doing a full sync")
            self.agent.sync()


class ChassisCreateEvent(ChassisCreateEventBase):
    table = 'Chassis'


class ChassisPrivateCreateEvent(ChassisCreateEventBase):
    table = 'Chassis_Private'

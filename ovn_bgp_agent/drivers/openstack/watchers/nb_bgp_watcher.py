# Copyright 2023 Red Hat, Inc.
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


class LogicalSwitchPortProviderCreateEvent(base_watcher.LSPChassisEvent):
    def __init__(self, bgp_agent):
        events = (self.ROW_UPDATE,)
        super(LogicalSwitchPortProviderCreateEvent, self).__init__(
            bgp_agent, events)

    def match_fn(self, event, row, old):
        try:
            # single and dual-stack format
            if not self._check_ip_associated(row.addresses[0]):
                return False

            current_chassis = row.options.get(constants.OVN_REQUESTED_CHASSIS)
            if current_chassis != self.agent.chassis:
                return False
            if not row.up:
                return False
            old_chassis = old.options.get(constants.OVN_REQUESTED_CHASSIS)
            if (not old_chassis or current_chassis != old_chassis or
                    not old.up):
                return True
        except (IndexError, AttributeError):
            return False

    def run(self, event, row, old):
        if row.type not in [constants.OVN_VM_VIF_PORT_TYPE,
                            constants.OVN_VIRTUAL_VIF_PORT_TYPE]:
            return
        with _SYNC_STATE_LOCK.read_lock():
            ips = row.addresses[0].split(' ')[1:]
            self.agent.expose_ip(ips, row)


class LogicalSwitchPortProviderDeleteEvent(base_watcher.LSPChassisEvent):
    def __init__(self, bgp_agent):
        events = (self.ROW_UPDATE, self.ROW_DELETE,)
        super(LogicalSwitchPortProviderDeleteEvent, self).__init__(
            bgp_agent, events)

    def match_fn(self, event, row, old):
        try:
            # single and dual-stack format
            if not self._check_ip_associated(row.addresses[0]):
                return False

            current_chassis = row.options.get(constants.OVN_REQUESTED_CHASSIS)
            if event == self.ROW_DELETE:
                return current_chassis == self.agent.chassis

            # ROW_UPDATE EVENT
            if hasattr(old, 'options'):
                # check chassis change
                old_chassis = old.options.get(constants.OVN_REQUESTED_CHASSIS)
                if old_chassis != self.agent.chassis:
                    return False
                if not current_chassis or current_chassis != old_chassis:
                    return True

            if hasattr(old, 'up'):
                if not old.up:
                    return False
                if not row.up:
                    return True
        except (IndexError, AttributeError):
            return False

    def run(self, event, row, old):
        if row.type not in [constants.OVN_VM_VIF_PORT_TYPE,
                            constants.OVN_VIRTUAL_VIF_PORT_TYPE]:
            return
        with _SYNC_STATE_LOCK.read_lock():
            ips = row.addresses[0].split(' ')[1:]
            self.agent.withdraw_ip(ips, row)


class LogicalSwitchPortFIPCreateEvent(base_watcher.LSPChassisEvent):
    def __init__(self, bgp_agent):
        events = (self.ROW_UPDATE,)
        super(LogicalSwitchPortFIPCreateEvent, self).__init__(
            bgp_agent, events)

    def match_fn(self, event, row, old):
        try:
            # single and dual-stack format
            if not self._check_ip_associated(row.addresses[0]):
                return False

            current_chassis = row.options.get(constants.OVN_REQUESTED_CHASSIS)
            current_port_fip = row.external_ids.get(
                constants.OVN_FIP_EXT_ID_KEY)
            if (current_chassis != self.agent.chassis or not row.up or
                    not current_port_fip):
                return False

            if hasattr(old, 'options'):
                # check chassis change
                old_chassis = old.options.get(constants.OVN_REQUESTED_CHASSIS)
                if not old_chassis or current_chassis != old_chassis:
                    return True
            if hasattr(old, 'external_ids'):
                # check fips addition
                old_port_fip = old.external_ids.get(
                    constants.OVN_FIP_EXT_ID_KEY)
                if not old_port_fip or current_port_fip != old_port_fip:
                    return True
            if hasattr(old, 'up'):
                # check port status change
                if not old.up:
                    return True
        except (IndexError, AttributeError):
            return False
        return False

    def run(self, event, row, old):
        if row.type not in [constants.OVN_VM_VIF_PORT_TYPE,
                            constants.OVN_VIRTUAL_VIF_PORT_TYPE]:
            return
        external_ip, ls_name = self.agent.get_port_external_ip_and_ls(row.name)
        if not external_ip or not ls_name:
            return

        with _SYNC_STATE_LOCK.read_lock():
            self.agent.expose_fip(external_ip, ls_name, row)


class LogicalSwitchPortFIPDeleteEvent(base_watcher.LSPChassisEvent):
    def __init__(self, bgp_agent):
        events = (self.ROW_UPDATE, self.ROW_DELETE,)
        super(LogicalSwitchPortFIPDeleteEvent, self).__init__(
            bgp_agent, events)

    def match_fn(self, event, row, old):
        try:
            # single and dual-stack format
            if not self._check_ip_associated(row.addresses[0]):
                return False

            current_chassis = row.options.get(constants.OVN_REQUESTED_CHASSIS)
            current_port_fip = row.external_ids.get(
                constants.OVN_FIP_EXT_ID_KEY)
            if event == self.ROW_DELETE:
                if (current_chassis == self.agent.chassis and row.up and
                        current_port_fip):
                    return True
                return False

            if hasattr(old, 'options'):
                # check chassis change
                old_chassis = old.options.get(constants.OVN_REQUESTED_CHASSIS)
                if (not old_chassis or old_chassis != self.agent.chassis):
                    return False
                if current_chassis != old_chassis and current_port_fip:
                    return True
            # There was no change in chassis, so only progress if the
            # chassis matches
            if current_chassis != self.agent.chassis:
                return False
            if hasattr(old, 'external_ids'):
                # check fips deletion
                old_port_fip = old.external_ids.get(
                    constants.OVN_FIP_EXT_ID_KEY)
                if not old_port_fip:
                    return False
                if old_port_fip != current_port_fip:
                    return True
            if hasattr(old, 'up'):
                # check port status change
                if not old.up:
                    return False
                if not row.up and current_port_fip:
                    return True
        except (IndexError, AttributeError):
            return False
        return False

    def run(self, event, row, old):
        if row.type not in [constants.OVN_VM_VIF_PORT_TYPE,
                            constants.OVN_VIRTUAL_VIF_PORT_TYPE]:
            return
        fip = row.external_ids.get(constants.OVN_FIP_EXT_ID_KEY)
        if not fip:
            fip = old.external_ids.get(constants.OVN_FIP_EXT_ID_KEY)
        if not fip:
            return
        with _SYNC_STATE_LOCK.read_lock():
            self.agent.withdraw_fip(fip, row)


class LocalnetCreateDeleteEvent(base_watcher.LSPChassisEvent):
    def __init__(self, bgp_agent):
        events = (self.ROW_CREATE, self.ROW_DELETE,)
        super(LocalnetCreateDeleteEvent, self).__init__(
            bgp_agent, events)

    def match_fn(self, event, row, old):
        if row.type == constants.OVN_LOCALNET_VIF_PORT_TYPE:
            return True
        return False

    def run(self, event, row, old):
        with _SYNC_STATE_LOCK.read_lock():
            self.agent.sync()

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

from oslo_log import log as logging
from ovsdbapp.backend.ovs_idl import event as row_event

from ovn_bgp_agent import constants


LOG = logging.getLogger(__name__)


class Event(row_event.RowEvent):
    def run(self, *args, **kwargs):
        try:
            self._run(*args, **kwargs)
        except Exception:
            LOG.exception("Unexpected exception while running the event "
                          "action")


class PortBindingChassisEvent(Event):
    def __init__(self, bgp_agent, events):
        self.agent = bgp_agent
        table = 'Port_Binding'
        super(PortBindingChassisEvent, self).__init__(
            events, table, None)
        self.event_name = self.__class__.__name__

    def _check_ip_associated(self, mac):
        return len(mac.strip().split(' ')) > 1


class OVNLBEvent(Event):
    def __init__(self, bgp_agent, events):
        self.agent = bgp_agent
        table = 'Load_Balancer'
        super(OVNLBEvent, self).__init__(
            events, table, None)
        self.event_name = self.__class__.__name__

    def _get_router(self, row):
        try:
            return row.external_ids[
                constants.OVN_LB_LR_REF_EXT_ID_KEY].replace('neutron-', "", 1)
        except (AttributeError, KeyError):
            return

    def _get_vip_fip(self, row):
        try:
            return row.external_ids[constants.OVN_LB_VIP_FIP_EXT_ID_KEY]
        except (AttributeError, KeyError):
            return


class LSPChassisEvent(Event):
    def __init__(self, bgp_agent, events):
        self.agent = bgp_agent
        table = 'Logical_Switch_Port'
        super(LSPChassisEvent, self).__init__(
            events, table, None)
        self.event_name = self.__class__.__name__

    def _check_ip_associated(self, mac):
        return len(mac.strip().split(' ')) > 1

    def _get_chassis(self, row):
        if (hasattr(row, 'external_ids') and
                row.external_ids.get(constants.OVN_HOST_ID_EXT_ID_KEY)):
            return (row.external_ids[constants.OVN_HOST_ID_EXT_ID_KEY],
                    constants.OVN_CHASSIS_AT_EXT_IDS)
        elif (hasattr(row, 'options') and
                row.options.get(constants.OVN_REQUESTED_CHASSIS)):
            return (row.options[constants.OVN_REQUESTED_CHASSIS],
                    constants.OVN_CHASSIS_AT_OPTIONS)
        return None, None

    def _get_network(self, row):
        try:
            return row.external_ids[constants.OVN_LS_NAME_EXT_ID_KEY]
        except (AttributeError, KeyError):
            return


class LRPChassisEvent(Event):
    def __init__(self, bgp_agent, events):
        self.agent = bgp_agent
        table = 'Logical_Router_Port'
        super(LRPChassisEvent, self).__init__(
            events, table, None)
        self.event_name = self.__class__.__name__

    def _get_network(self, row):
        try:
            return row.external_ids[constants.OVN_LS_NAME_EXT_ID_KEY]
        except (AttributeError, KeyError):
            return

    def _get_ips_info(self, row):
        return {
            'mac': row.mac,
            'cidrs': row.networks,
            'type': constants.OVN_CR_LRP_PORT_TYPE,
            'logical_switch': self._get_network(row),
            'router': row.external_ids.get(constants.OVN_LR_NAME_EXT_ID_KEY),
        }

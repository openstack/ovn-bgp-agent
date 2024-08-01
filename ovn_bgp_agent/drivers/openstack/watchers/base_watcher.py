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
from ovn_bgp_agent.drivers.openstack.utils import common as common_utils
from ovn_bgp_agent.drivers.openstack.utils import driver_utils


LOG = logging.getLogger(__name__)


class Event(row_event.RowEvent):
    def __init__(self, agent, events, table, condition=None):
        self.agent = agent
        super().__init__(events, table, condition)

    def run(self, *args, **kwargs):
        try:
            self._run(*args, **kwargs)
        except Exception:
            LOG.exception("Unexpected exception while running the event "
                          "action")


class PortBindingChassisEvent(Event):
    def __init__(self, bgp_agent, events):
        table = 'Port_Binding'
        super().__init__(bgp_agent, events, table)
        self.event_name = self.__class__.__name__


class OVNLBEvent(Event):
    def __init__(self, bgp_agent, events):
        table = 'Load_Balancer'
        super().__init__(bgp_agent, events, table)
        self.event_name = self.__class__.__name__

    def _get_ip_from_vips(self, row):
        return [driver_utils.remove_port_from_ip(ipport)
                for ipport in getattr(row, 'vips', {}).keys()]

    def _get_diff_ip_from_vips(self, new, old):
        """Returns a list of IPs that are present in 'new' but not in 'old'

        Note: As LB VIP contains a port (e.g., '192.168.1.1:80'), the port part
        is removed before comparison.
        """
        return list(set(self._get_ip_from_vips(new)) -
                    set(self._get_ip_from_vips(old)))

    def _is_vip_or_fip(self, row, ip, key):
        try:
            return ip == row.external_ids.get(key)
        except AttributeError:
            pass

    def _is_vip(self, row, ip):
        return self._is_vip_or_fip(row, ip, constants.OVN_LB_VIP_IP_EXT_ID_KEY)

    def _is_fip(self, row, ip):
        return self._is_vip_or_fip(row,
                                   ip,
                                   constants.OVN_LB_VIP_FIP_EXT_ID_KEY)


class LogicalSwitchChassisEvent(Event):
    def __init__(self, bgp_agent, events):
        table = 'Logical_Switch'
        super().__init__(bgp_agent, events, table)
        self.event_name = self.__class__.__name__


class LSPChassisEvent(Event):
    def __init__(self, bgp_agent, events):
        table = 'Logical_Switch_Port'
        super().__init__(bgp_agent, events, table)
        self.event_name = self.__class__.__name__

    def _get_chassis(self, row, default_type=constants.OVN_VM_VIF_PORT_TYPE):
        return driver_utils.get_port_chassis(row, self.agent.chassis,
                                             default_port_type=default_type)

    def _has_additional_binding(self, row):
        if (hasattr(row, 'options') and
                row.options.get(constants.OVN_REQUESTED_CHASSIS)):

            # requested-chassis can be a comma separated list, so if there
            # is a comma in the string, there is an additional binding.
            return ',' in row.options[constants.OVN_REQUESTED_CHASSIS]

        return False

    def _get_ips_info(self, row):
        return {
            'mac': row.addresses[0].strip().split(' ')[0],
            'cidrs': row.external_ids.get(constants.OVN_CIDRS_EXT_ID_KEY,
                                          "").split(),
            'type': row.type,
            'logical_switch': common_utils.get_from_external_ids(
                row, constants.OVN_LS_NAME_EXT_ID_KEY),
        }

    def _get_port_fip(self, row):
        return getattr(row, 'external_ids', {}).get(
            constants.OVN_FIP_EXT_ID_KEY)


class LRPChassisEvent(Event):
    def __init__(self, bgp_agent, events):
        table = 'Logical_Router_Port'
        super().__init__(bgp_agent, events, table)
        self.event_name = self.__class__.__name__

    def _get_ips_info(self, row):
        return {
            'mac': row.mac,
            'cidrs': row.networks,
            'type': constants.OVN_CR_LRP_PORT_TYPE,
            'logical_switch': common_utils.get_from_external_ids(
                row, constants.OVN_LS_NAME_EXT_ID_KEY),
            'router': row.external_ids.get(constants.OVN_LR_NAME_EXT_ID_KEY),
        }


class ChassisCreateEventBase(Event):
    table = None

    def __init__(self, bgp_agent):
        self.first_time = True
        events = (self.ROW_CREATE,)
        super().__init__(
            bgp_agent, events, self.table,
            (('name', '=', bgp_agent.chassis),))
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

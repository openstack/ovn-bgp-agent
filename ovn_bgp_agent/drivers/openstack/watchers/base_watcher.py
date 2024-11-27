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
from ovn_bgp_agent.drivers.openstack.utils import driver_utils
from ovn_bgp_agent.drivers.openstack.utils import nat as nat_utils


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


class LRPChassisEvent(Event):
    def __init__(self, bgp_agent, events):
        table = 'Logical_Router_Port'
        super().__init__(bgp_agent, events, table)
        self.event_name = self.__class__.__name__


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


class DnatSnatBaseEvent(Event):
    events = None

    def __init__(self, bgp_agent):
        table = 'NAT'
        super().__init__(
            bgp_agent,
            self.__class__.events,
            table,
            (('type', '=', 'dnat_and_snat'),))


class FipOnCRLRPBaseEvent(DnatSnatBaseEvent):
    """Base class for NAT event.

    It matches if the associated LSP is either virtual port or a normal port
    and if the gateway chassis port is on this chassis.
    """
    def match_fn(self, event, row, old):
        try:
            lsp_uuid = row.logical_port[0]
        except IndexError:
            LOG.warning("NAT entry %s has no associated logical port",
                        row.uuid)
            return False
        lsp = self.agent.nb_idl.lsp_get(
            lsp_uuid).execute(check_error=True)
        if not lsp:
            LOG.warning("Switch Port %s cannot be found" % lsp_uuid)
            return False

        if lsp.type not in [constants.OVN_VM_VIF_PORT_TYPE,
                            constants.OVN_VIRTUAL_VIF_PORT_TYPE]:
            return False

        if constants.OVN_FIP_NET_EXT_ID_KEY not in row.external_ids:
            LOG.error("NAT entry %(nat)s does not have %(fip_net)s set in "
                      "external_ids", {
                          'nat': row.uuid,
                          'fip_net': constants.OVN_FIP_NET_EXT_ID_KEY})
            return False

        gw_chassis = nat_utils.get_chassis_hosting_crlrp(row)

        return self.agent.chassis_id == gw_chassis

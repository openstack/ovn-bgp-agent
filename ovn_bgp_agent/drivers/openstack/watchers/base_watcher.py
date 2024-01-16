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

    def _get_router(self, row, key=constants.OVN_LB_LR_REF_EXT_ID_KEY):
        try:
            return row.external_ids[key].replace('neutron-', "", 1)
        except (AttributeError, KeyError):
            return

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


class LSPChassisEvent(Event):
    def __init__(self, bgp_agent, events):
        self.agent = bgp_agent
        table = 'Logical_Switch_Port'
        super(LSPChassisEvent, self).__init__(
            events, table, None)
        self.event_name = self.__class__.__name__

    def _check_ip_associated(self, mac):
        return len(mac.strip().split(' ')) > 1

    def _get_chassis(self, row, default_type=constants.OVN_VM_VIF_PORT_TYPE):
        # row.options['requested-chassis'] superseeds the id in external_ids.
        # Since it is not used for virtual ports by ovn, this option will be
        # ignored for virtual ports.

        # since 'old' rows could be used, it will not hold the type information
        # if that is the case, please supply a default in the arguments.
        row_type = getattr(row, 'type', default_type)
        if (row_type not in [constants.OVN_VIRTUAL_VIF_PORT_TYPE] and
                hasattr(row, 'options') and
                row.options.get(constants.OVN_REQUESTED_CHASSIS)):

            # requested-chassis can be a comma separated list,
            # so lets only return our chassis if it is a list, to be able to
            # do a == equal comparison
            req_chassis = row.options[constants.OVN_REQUESTED_CHASSIS]
            if self.agent.chassis in req_chassis.split(','):
                req_chassis = self.agent.chassis

            return (req_chassis, constants.OVN_CHASSIS_AT_OPTIONS)
        elif (hasattr(row, 'external_ids') and
                row.external_ids.get(constants.OVN_HOST_ID_EXT_ID_KEY)):
            return (row.external_ids[constants.OVN_HOST_ID_EXT_ID_KEY],
                    constants.OVN_CHASSIS_AT_EXT_IDS)
        return None, None

    def _has_additional_binding(self, row):
        if (hasattr(row, 'options') and
                row.options.get(constants.OVN_REQUESTED_CHASSIS)):

            # requested-chassis can be a comma separated list, so if there
            # is a comma in the string, there is an additional binding.
            return ',' in row.options[constants.OVN_REQUESTED_CHASSIS]

        return False

    def _get_network(self, row):
        try:
            return row.external_ids[constants.OVN_LS_NAME_EXT_ID_KEY]
        except (AttributeError, KeyError):
            return

    def _get_ips_info(self, row):
        return {
            'mac': row.addresses[0].strip().split(' ')[0],
            'cidrs': row.external_ids.get(constants.OVN_CIDRS_EXT_ID_KEY,
                                          "").split(),
            'type': row.type,
            'logical_switch': self._get_network(row),
        }

    def _get_port_fip(self, row):
        return getattr(row, 'external_ids', {}).get(
            constants.OVN_FIP_EXT_ID_KEY)


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

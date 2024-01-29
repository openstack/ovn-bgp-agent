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
from ovn_bgp_agent.drivers.openstack.utils import driver_utils
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

            current_chassis, chassis_location = self._get_chassis(row)
            if current_chassis != self.agent.chassis:
                return False
            if not bool(row.up[0]):
                return False

            if hasattr(old, 'up'):
                if not bool(old.up[0]):
                    return True

            # NOTE(ltomasbo): This can be updated/removed once neutron has
            # chassis information on external ids
            if chassis_location == constants.OVN_CHASSIS_AT_OPTIONS:
                if hasattr(old, 'options'):
                    old_chassis, _ = self._get_chassis(old)
                    if not old_chassis or current_chassis != old_chassis:
                        return True
            else:
                if hasattr(old, 'external_ids'):
                    old_chassis, _ = self._get_chassis(old)
                    if not old_chassis or current_chassis != old_chassis:
                        return True
        except (IndexError, AttributeError):
            return False
        return False

    def _run(self, event, row, old):
        if row.type not in [constants.OVN_VM_VIF_PORT_TYPE,
                            constants.OVN_VIRTUAL_VIF_PORT_TYPE]:
            return
        with _SYNC_STATE_LOCK.read_lock():
            ips = row.addresses[0].split(' ')[1:]
            mac = row.addresses[0].strip().split(' ')[0]
            ips_info = {
                'mac': mac,
                'cidrs': row.external_ids.get(constants.OVN_CIDRS_EXT_ID_KEY,
                                              "").split(),
                'type': row.type,
                'logical_switch': self._get_network(row)
            }
            self.agent.expose_ip(ips, ips_info)


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

            current_chassis, chassis_location = self._get_chassis(row)
            if event == self.ROW_DELETE:
                return (current_chassis == self.agent.chassis and
                        bool(row.up[0]))

            # ROW_UPDATE EVENT
            if hasattr(old, 'up'):
                if not bool(old.up[0]):
                    return False
                # Assumes chassis and status are not changed at the same time
                if (not bool(row.up[0]) and
                        current_chassis == self.agent.chassis):
                    return True
            else:
                # If there is no change on the status, and it was already down
                # there is no need to remove it again
                if not bool(row.up[0]):
                    return False

            # NOTE(ltomasbo): This can be updated/removed once neutron has
            # chassis information on external ids
            if chassis_location == constants.OVN_CHASSIS_AT_OPTIONS:
                if hasattr(old, 'options'):
                    # check chassis change
                    old_chassis, _ = self._get_chassis(old)
                    if old_chassis != self.agent.chassis:
                        return False
                    if not current_chassis or current_chassis != old_chassis:
                        return True
            else:
                if hasattr(old, 'external_ids'):
                    # check chassis change
                    old_chassis, _ = self._get_chassis(old)
                    if old_chassis != self.agent.chassis:
                        return False
                    if not current_chassis or current_chassis != old_chassis:
                        return True
        except (IndexError, AttributeError):
            return False
        return False

    def _run(self, event, row, old):
        if row.type not in [constants.OVN_VM_VIF_PORT_TYPE,
                            constants.OVN_VIRTUAL_VIF_PORT_TYPE]:
            return
        with _SYNC_STATE_LOCK.read_lock():
            ips = row.addresses[0].split(' ')[1:]
            mac = row.addresses[0].strip().split(' ')[0]
            ips_info = {
                'mac': mac,
                'cidrs': row.external_ids.get(constants.OVN_CIDRS_EXT_ID_KEY,
                                              "").split(),
                'type': row.type,
                'logical_switch': row.external_ids.get(
                    constants.OVN_LS_NAME_EXT_ID_KEY)
            }
            self.agent.withdraw_ip(ips, ips_info)


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

            current_chassis, chassis_location = self._get_chassis(row)
            current_port_fip = row.external_ids.get(
                constants.OVN_FIP_EXT_ID_KEY)
            if (current_chassis != self.agent.chassis or not bool(row.up[0]) or
                    not current_port_fip):
                return False

            if hasattr(old, 'up'):
                # check port status change
                if not bool(old.up[0]):
                    return True

            # NOTE(ltomasbo): This can be updated/removed once neutron has
            # chassis information on external ids
            if chassis_location == constants.OVN_CHASSIS_AT_OPTIONS:
                if hasattr(old, 'options'):
                    old_chassis, _ = self._get_chassis(old)
                    if not old_chassis or current_chassis != old_chassis:
                        return True
                if hasattr(old, 'external_ids'):
                    # check fips addition
                    old_port_fip = old.external_ids.get(
                        constants.OVN_FIP_EXT_ID_KEY)
                    if not old_port_fip or current_port_fip != old_port_fip:
                        return True
            else:  # by default expect the chassis information at external-ids
                if hasattr(old, 'external_ids'):
                    # note the whole extenal-ids are included, even if only
                    # one field inside it is updated
                    old_chassis, _ = self._get_chassis(old)
                    old_port_fip = old.external_ids.get(
                        constants.OVN_FIP_EXT_ID_KEY)
                    if (current_chassis != old_chassis or
                            current_port_fip != old_port_fip):
                        return True
        except (IndexError, AttributeError):
            return False
        return False

    def _run(self, event, row, old):
        if row.type not in [constants.OVN_VM_VIF_PORT_TYPE,
                            constants.OVN_VIRTUAL_VIF_PORT_TYPE]:
            return
        external_ip, external_mac, ls_name = (
            self.agent.get_port_external_ip_and_ls(row.name))
        if not external_ip or not ls_name:
            return

        with _SYNC_STATE_LOCK.read_lock():
            self.agent.expose_fip(external_ip, external_mac, ls_name, row)


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

            current_chassis, chassis_location = self._get_chassis(row)
            current_port_fip = row.external_ids.get(
                constants.OVN_FIP_EXT_ID_KEY)
            if event == self.ROW_DELETE:
                if (current_chassis == self.agent.chassis and
                        bool(row.up[0]) and current_port_fip):
                    return True
                return False

            if hasattr(old, 'up'):
                # check port status change
                if not bool(old.up[0]):
                    return False
                # Assumes chassis and status are not changed at the same time
                if (not bool(row.up[0]) and current_port_fip and
                        current_chassis == self.agent.chassis):
                    return True

            # NOTE(ltomasbo): This can be updated/removed once neutron has
            # chassis information on external ids
            if chassis_location == constants.OVN_CHASSIS_AT_OPTIONS:
                if hasattr(old, 'options'):
                    # check chassis change
                    old_chassis, _ = self._get_chassis(old)
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
            else:  # by default expect the chassis information at external-ids
                if hasattr(old, 'external_ids'):
                    # check chassis change
                    old_chassis, _ = self._get_chassis(old)
                    if (not old_chassis or old_chassis != self.agent.chassis):
                        return False
                    if current_chassis != old_chassis and current_port_fip:
                        return True
                    # check fips deletion
                    old_port_fip = old.external_ids.get(
                        constants.OVN_FIP_EXT_ID_KEY)
                    if not old_port_fip:
                        return False
                    if old_port_fip != current_port_fip:
                        return True
        except (IndexError, AttributeError):
            return False
        return False

    def _run(self, event, row, old):
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

    def _run(self, event, row, old):
        with _SYNC_STATE_LOCK.read_lock():
            self.agent.sync()


class ChassisRedirectCreateEvent(base_watcher.LRPChassisEvent):
    def __init__(self, bgp_agent):
        events = (self.ROW_UPDATE,)
        super(ChassisRedirectCreateEvent, self).__init__(
            bgp_agent, events)

    def match_fn(self, event, row, old):
        try:
            if not row.networks:
                return False

            # check if hosting-chassis is being added
            hosting_chassis = row.status.get(constants.OVN_STATUS_CHASSIS)
            if hosting_chassis != self.agent.chassis_id:
                # No chassis set or different one
                return False

            if hasattr(old, 'status'):
                # status has changed
                old_hosting_chassis = old.status.get(
                    constants.OVN_STATUS_CHASSIS)
                if old_hosting_chassis != hosting_chassis:
                    return True
        except (IndexError, AttributeError):
            return False
        return False

    def _run(self, event, row, old):
        with _SYNC_STATE_LOCK.read_lock():
            ips_info = self._get_ips_info(row)
            ips = [net.split("/")[0] for net in row.networks]
            self.agent.expose_ip(ips, ips_info)


class ChassisRedirectDeleteEvent(base_watcher.LRPChassisEvent):
    def __init__(self, bgp_agent):
        events = (self.ROW_UPDATE, self.ROW_DELETE,)
        super(ChassisRedirectDeleteEvent, self).__init__(
            bgp_agent, events)

    def match_fn(self, event, row, old):
        try:
            if not row.networks:
                return

            if event == self.ROW_DELETE:
                return (row.status.get(constants.OVN_STATUS_CHASSIS) ==
                        self.agent.chassis_id)
            # ROW UPDATE EVENT
            if hasattr(old, 'status'):
                # status has changed
                hosting_chassis = row.status.get(constants.OVN_STATUS_CHASSIS)
                old_hosting_chassis = old.status.get(
                    constants.OVN_STATUS_CHASSIS)
                if (hosting_chassis != old_hosting_chassis and
                        old_hosting_chassis == self.agent.chassis_id):
                    return True
        except (IndexError, AttributeError):
            return False
        return False

    def _run(self, event, row, old):
        with _SYNC_STATE_LOCK.read_lock():
            ips_info = self._get_ips_info(row)
            ips = [net.split("/")[0] for net in row.networks]
            self.agent.withdraw_ip(ips, ips_info)


class LogicalSwitchPortSubnetAttachEvent(base_watcher.LSPChassisEvent):
    def __init__(self, bgp_agent):
        events = (self.ROW_UPDATE,)
        super(LogicalSwitchPortSubnetAttachEvent, self).__init__(
            bgp_agent, events)

    def match_fn(self, event, row, old):
        try:
            if row.type != constants.OVN_ROUTER_PORT_TYPE:
                return False
            # skip route_gateway port events
            row_device_owner = row.external_ids.get(
                constants.OVN_DEVICE_OWNER_EXT_ID_KEY)
            if row_device_owner != constants.OVN_ROUTER_INTERFACE:
                return False

            if not bool(row.up[0]):
                return False

            associated_router = row.external_ids.get(
                constants.OVN_DEVICE_ID_EXT_ID_KEY)

            if associated_router not in self.agent.ovn_local_cr_lrps:
                return False

            if hasattr(old, 'up') and not bool(old.up[0]):
                return True

            if hasattr(old, 'external_ids'):
                previous_associated_router = old.external_ids.get(
                    constants.OVN_DEVICE_ID_EXT_ID_KEY)
                if (associated_router != previous_associated_router and
                        previous_associated_router not in
                        self.agent.ovn_local_cr_lrps):
                    return True
        except (IndexError, AttributeError):
            return False
        return False

    def _run(self, event, row, old):
        with _SYNC_STATE_LOCK.read_lock():
            ips = row.external_ids.get(constants.OVN_CIDRS_EXT_ID_KEY,
                                       "").split()
            subnet_info = {
                'associated_router': row.external_ids.get(
                    constants.OVN_DEVICE_ID_EXT_ID_KEY),
                'network': self._get_network(row),
                'address_scopes': driver_utils.get_addr_scopes(row)}
            self.agent.expose_subnet(ips, subnet_info)


class LogicalSwitchPortSubnetDetachEvent(base_watcher.LSPChassisEvent):
    def __init__(self, bgp_agent):
        events = (self.ROW_UPDATE, self.ROW_DELETE,)
        super(LogicalSwitchPortSubnetDetachEvent, self).__init__(
            bgp_agent, events)

    def match_fn(self, event, row, old):
        try:
            if row.type != constants.OVN_ROUTER_PORT_TYPE:
                return False
            # skip route_gateway port events
            row_device_owner = row.external_ids.get(
                constants.OVN_DEVICE_OWNER_EXT_ID_KEY)
            if row_device_owner != constants.OVN_ROUTER_INTERFACE:
                return False

            associated_router = row.external_ids.get(
                constants.OVN_DEVICE_ID_EXT_ID_KEY)

            if event == self.ROW_DELETE:
                if not bool(row.up[0]):
                    return False
                if associated_router in self.agent.ovn_local_cr_lrps:
                    return True
                return False

            # ROW UPDATE
            # We need to withdraw the subnet in the next cases:
            # 1. same/local associated router and status moves from up to down
            # 2. status changes to down and also associated router changes to a
            #    non local one
            # 3. status is up (same) but associated router changes to a non
            #    local one
            if hasattr(old, 'up'):
                if not bool(old.up[0]):
                    return False
                if hasattr(old, 'external_ids'):
                    previous_associated_router = old.external_ids.get(
                        constants.OVN_DEVICE_ID_EXT_ID_KEY)
                    if previous_associated_router in (
                            self.agent.ovn_local_cr_lrps):
                        return True
                else:
                    if associated_router in self.agent.ovn_local_cr_lrps:
                        return True
            else:
                # no change in status
                if not bool(row.up[0]):
                    # it was not exposed
                    return False
                if hasattr(old, 'external_ids'):
                    previous_associated_router = old.external_ids.get(
                        constants.OVN_DEVICE_ID_EXT_ID_KEY)
                    if (previous_associated_router and
                            associated_router != previous_associated_router and
                            previous_associated_router in
                            self.agent.ovn_local_cr_lrps):
                        return True
        except (IndexError, AttributeError):
            return False
        return False

    def _run(self, event, row, old):
        with _SYNC_STATE_LOCK.read_lock():
            ips = row.external_ids.get(constants.OVN_CIDRS_EXT_ID_KEY,
                                       "").split()
            if event == self.ROW_DELETE:
                subnet_info = {
                    'associated_router': row.external_ids.get(
                        constants.OVN_DEVICE_ID_EXT_ID_KEY),
                    'network': self._get_network(row),
                    'address_scopes': driver_utils.get_addr_scopes(row)}
            else:
                associated_router = row.external_ids.get(
                    constants.OVN_DEVICE_ID_EXT_ID_KEY)
                if hasattr(old, 'external_ids'):
                    previous_associated_router = old.external_ids.get(
                        constants.OVN_DEVICE_ID_EXT_ID_KEY)
                    if previous_associated_router != associated_router:
                        associated_router = previous_associated_router
                subnet_info = {
                    'associated_router': associated_router,
                    'network': self._get_network(row),
                    'address_scopes': driver_utils.get_addr_scopes(row)}
            self.agent.withdraw_subnet(ips, subnet_info)


class LogicalSwitchPortTenantCreateEvent(base_watcher.LSPChassisEvent):
    def __init__(self, bgp_agent):
        events = (self.ROW_UPDATE,)
        super(LogicalSwitchPortTenantCreateEvent, self).__init__(
            bgp_agent, events)

    def match_fn(self, event, row, old):
        try:
            # single and dual-stack format
            if not self._check_ip_associated(row.addresses[0]):
                return False

            if not bool(row.up[0]):
                return False

            current_network = self._get_network(row)
            if current_network not in self.agent.ovn_local_lrps:
                return False

            if hasattr(old, 'up'):
                if not bool(old.up[0]):
                    return True

            if hasattr(old, 'external_ids'):
                old_network = self._get_network(old)
                if old_network != current_network:
                    return True
        except (IndexError, AttributeError):
            return False
        return False

    def _run(self, event, row, old):
        if row.type not in [constants.OVN_VM_VIF_PORT_TYPE,
                            constants.OVN_VIRTUAL_VIF_PORT_TYPE]:
            return
        with _SYNC_STATE_LOCK.read_lock():
            ips = row.addresses[0].split(' ')[1:]
            mac = row.addresses[0].strip().split(' ')[0]
            ips_info = {
                'mac': mac,
                'cidrs': row.external_ids.get(constants.OVN_CIDRS_EXT_ID_KEY,
                                              "").split(),
                'type': row.type,
                'logical_switch': self._get_network(row)
            }
            self.agent.expose_remote_ip(ips, ips_info)


class LogicalSwitchPortTenantDeleteEvent(base_watcher.LSPChassisEvent):
    def __init__(self, bgp_agent):
        events = (self.ROW_UPDATE, self.ROW_DELETE,)
        super(LogicalSwitchPortTenantDeleteEvent, self).__init__(
            bgp_agent, events)

    def match_fn(self, event, row, old):
        try:
            # single and dual-stack format
            if not self._check_ip_associated(row.addresses[0]):
                return False

            current_network = self._get_network(row)
            # Assuming the current_network cannot be changed at once
            if current_network not in self.agent.ovn_local_lrps:
                return False

            if event == self.ROW_DELETE:
                return bool(row.up[0])

            # ROW UPDATE EVENT
            if hasattr(old, 'up'):
                return bool(old.up[0])
        except (IndexError, AttributeError):
            return False
        return False

    def _run(self, event, row, old):
        if row.type not in [constants.OVN_VM_VIF_PORT_TYPE,
                            constants.OVN_VIRTUAL_VIF_PORT_TYPE]:
            return
        with _SYNC_STATE_LOCK.read_lock():
            ips = row.addresses[0].split(' ')[1:]
            mac = row.addresses[0].strip().split(' ')[0]
            ips_info = {
                'mac': mac,
                'cidrs': row.external_ids.get(constants.OVN_CIDRS_EXT_ID_KEY,
                                              "").split(),
                'type': row.type,
                'logical_switch': self._get_network(row)
            }
            self.agent.withdraw_remote_ip(ips, ips_info)


class OVNLBCreateEvent(base_watcher.OVNLBEvent):
    def __init__(self, bgp_agent):
        events = (self.ROW_UPDATE,)
        super(OVNLBCreateEvent, self).__init__(
            bgp_agent, events)

    def match_fn(self, event, row, old):
        # The ovn lb balancers are exposed through the cr-lrp, so if the
        # local agent does not have the matching router there is no need
        # to process the event
        try:
            if not row.vips:
                return False
            lb_router = self._get_router(row)
            if lb_router not in self.agent.ovn_local_cr_lrps.keys():
                return False

            # Only expose if there is a modification in the VIPS
            # And only expose if it is the first item on VIPs
            if hasattr(old, 'vips'):
                if not old.vips and row.vips:
                    return True

            if hasattr(old, 'external_ids'):
                # Check if the lb_router was added
                old_lb_router = self._get_router(old)
                if lb_router != old_lb_router:
                    return True
                # Also check if there is a vip_fip addition to expose the FIP
                vip_fip = self._get_vip_fip(row)
                if not vip_fip:
                    return False
                old_vip_fip = self._get_vip_fip(old)
                if vip_fip != old_vip_fip:
                    return True
        except (IndexError, AttributeError):
            return False
        return False

    def _run(self, event, row, old):
        vip_fip = self._get_vip_fip(row)
        old_vip_fip = self._get_vip_fip(old)
        with _SYNC_STATE_LOCK.read_lock():
            if hasattr(old, 'external_ids') and vip_fip != old_vip_fip:
                self.agent.expose_ovn_lb_fip(row)
            else:
                self.agent.expose_ovn_lb_vip(row)


class OVNLBDeleteEvent(base_watcher.OVNLBEvent):
    def __init__(self, bgp_agent):
        events = (self.ROW_DELETE, self.ROW_UPDATE)
        super(OVNLBDeleteEvent, self).__init__(
            bgp_agent, events)

    def match_fn(self, event, row, old):
        # The ovn lb balancers are exposed through the cr-lrp, so if the
        # local agent does not have the matching router there is no need
        # to process the event
        try:
            if event == self.ROW_DELETE:
                if not row.vips:
                    return False
                lb_router = self._get_router(row)
                if lb_router in self.agent.ovn_local_cr_lrps.keys():
                    return True
                return False

            # ROW UPDATE EVENT
            lb_router = self._get_router(row)
            old_external_ids = False
            if hasattr(old, 'external_ids'):
                old_external_ids = True
                old_lb_router = self._get_router(old)
                if not old_lb_router:
                    return False
                if old_lb_router not in self.agent.ovn_local_cr_lrps.keys():
                    return False
                if old_lb_router != lb_router:
                    # Router should not be removed, but if that is the case we
                    # should remove the loadbalancer
                    return True
                # Also check if the vip_fip is removed to withdraw the FIP
                vip_fip = self._get_vip_fip(row)
                old_vip_fip = self._get_vip_fip(old)
                if old_vip_fip and old_vip_fip != vip_fip:
                    return True

            # Withdraw IP if VIPs is removed
            if hasattr(old, 'vips'):
                if old.vips and not row.vips:
                    if old_external_ids:
                        old_lb_router = self._get_router(old)
                        return (old_lb_router in
                                self.agent.ovn_local_cr_lrps.keys())
                    else:
                        return (lb_router in
                                self.agent.ovn_local_cr_lrps.keys())
        except (IndexError, AttributeError):
            return False
        return False

    def _run(self, event, row, old):
        vip_fip = self._get_vip_fip(row)
        old_vip_fip = self._get_vip_fip(old)
        with _SYNC_STATE_LOCK.read_lock():
            if event == self.ROW_DELETE:
                self.agent.withdraw_ovn_lb_vip(row)
                if vip_fip:
                    self.agent.withdraw_ovn_lb_fip(row)
            else:
                if not vip_fip and vip_fip != old_vip_fip:
                    self.agent.withdraw_ovn_lb_fip(old)

                if hasattr(old, 'vips'):
                    self.agent.withdraw_ovn_lb_vip(row)

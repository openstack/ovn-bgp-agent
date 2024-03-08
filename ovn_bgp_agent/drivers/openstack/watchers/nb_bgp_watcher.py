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
        '''Match port updates to see if we should expose this lsp

        If the event matches the following criteria, we should
        totally ignore this event, since it is not meant for this host.

        1. this host does not own this lsp
        2. the lsp is not up
        3. the logical switch is not exposed with agent, which means it
           is not a provider network

        When the event still has not been rejected, then the only thing to
        do is to check if the ips for this lsp have not been exported yet.
        '''
        if row.type not in [constants.OVN_VM_VIF_PORT_TYPE,
                            constants.OVN_VIRTUAL_VIF_PORT_TYPE]:
            return
        try:
            # single and dual-stack format
            if not self._check_ip_associated(row.addresses[0]):
                return False

            current_chassis, _ = self._get_chassis(row)
            logical_switch = self._get_network(row)

            if logical_switch in self.agent.ovn_local_lrps:
                # This is a tenant network, routed through lrp, handled by
                # event LogicalSwitchPortTenantCreateEvent
                return False

            # Check for rejection criteria
            if (current_chassis != self.agent.chassis or
                    not bool(row.up[0]) or
                    not self.agent.is_ls_provider(logical_switch)):
                return False

            # At this point, the port is bound on this host, it is up and
            # the logical switch is exposable by the agent.
            # Only create the ips if not already exposed.
            ips = row.addresses[0].split(' ')[1:]
            return not self.agent.is_ip_exposed(logical_switch, ips)

        except (IndexError, AttributeError):
            return False

    def _run(self, event, row, old):
        with _SYNC_STATE_LOCK.read_lock():
            ips = row.addresses[0].split(' ')[1:]
            ips_info = self._get_ips_info(row)
            self.agent.expose_ip(ips, ips_info)


class LogicalSwitchPortProviderDeleteEvent(base_watcher.LSPChassisEvent):
    def __init__(self, bgp_agent):
        events = (self.ROW_UPDATE, self.ROW_DELETE,)
        super(LogicalSwitchPortProviderDeleteEvent, self).__init__(
            bgp_agent, events)

    def match_fn(self, event, row, old):
        '''Match port deletes or port downs or migrations

        1. [DELETE] Port has been deleted, and we're hosting it
        2. [UPDATE] Port went down, withdraw if we announced it
        3. [UPDATE] Port has been migrated away and we're hosting it
        '''
        if row.type not in [constants.OVN_VM_VIF_PORT_TYPE,
                            constants.OVN_VIRTUAL_VIF_PORT_TYPE]:
            return
        try:
            # single and dual-stack format
            if not self._check_ip_associated(row.addresses[0]):
                return False

            ips = row.addresses[0].split(' ')[1:]
            logical_switch = self._get_network(row)

            if logical_switch in self.agent.ovn_local_lrps:
                # This is a tenant network, routed through lrp, handled by
                # event LogicalSwitchPortTenantDeleteEvent
                return False

            # Do nothing if we do not expose the current port
            if not self.agent.is_ip_exposed(logical_switch, ips):
                return False

            # Delete event, always execute (since we expose it)
            if event == self.ROW_DELETE:
                return True

            current_chassis, _ = self._get_chassis(row)
            # Delete the port from current chassis, if
            # 1. port went down (while only attached here)
            if (hasattr(old, 'up') and bool(old.up[0]) and   # port was up
                    not bool(row.up[0]) and                  # is now down
                    not self._has_additional_binding(row)):  # and bound here
                return True

            # 2. port no longer bound here
            return current_chassis != self.agent.chassis

        except (IndexError, AttributeError):
            return False

    def _run(self, event, row, old):
        with _SYNC_STATE_LOCK.read_lock():
            ips = row.addresses[0].split(' ')[1:]
            ips_info = self._get_ips_info(row)
            self.agent.withdraw_ip(ips, ips_info)


class LogicalSwitchPortFIPCreateEvent(base_watcher.LSPChassisEvent):
    '''Floating IP create events based on the LogicalSwitchPort

    The LSP has information about the host is should be exposed to, which
    adds a bit of complexity in the event match, but saves a lot of queries
    to the OVN NB DB.

    Should trigger on:
    - floating ip was attached to a lsp (external_ids.neutron:port_fip
                                         appeared with information)
    - port with floating ip attached was set to up (old.up = false and
                                                    row.up = true)

    During a migration of a lsp, the following events happen (chronologically):
    1. options.requested_chassis is updated (now a comma separated list)
       we also get external_ids, but only revision_number is updated.
    2. update with only external_ids update (with only a revnum update)
    3. port is set down (by ovn-controller on source host)
    4. update with only external_ids update (with only a revnum update)
    5. external_ids update (neutron:host_id is removed)
    6. options.requested_chassis is updated (with only dest host)
       and external_ids update which now includes neutron:host_id again
    7. port is set up (by ovn-controller on dest host)
    8 and 9 are only a revnum update in the external_ids

    So for migration flow we are only interested in event 7.
    Otherwise the floating ip would be added upon event 2, deleted with
        event 3 and re-added with event 7.
    '''
    def __init__(self, bgp_agent):
        events = (self.ROW_UPDATE,)
        super(LogicalSwitchPortFIPCreateEvent, self).__init__(
            bgp_agent, events)

    def match_fn(self, event, row, old):
        if row.type not in [constants.OVN_VM_VIF_PORT_TYPE,
                            constants.OVN_VIRTUAL_VIF_PORT_TYPE]:
            return
        try:
            # single and dual-stack format
            if not self._check_ip_associated(row.addresses[0]):
                return False

            current_chassis, _ = self._get_chassis(row)
            current_port_fip = row.external_ids.get(
                constants.OVN_FIP_EXT_ID_KEY)
            if (current_chassis != self.agent.chassis or
                    not bool(row.up[0]) or not current_port_fip):
                # Port is not bound on this host, is down or does not have a
                # floating ip attached.
                return False

            if hasattr(old, 'up') and not bool(old.up[0]):
                # Port changed up, which happens when the port is picked up
                # on this host by the ovn-controller during migrations
                return True

            old_port_fip = getattr(old, 'external_ids', {}).get(
                constants.OVN_FIP_EXT_ID_KEY)
            if old_port_fip == current_port_fip:
                # Only if the floating ip has changed (for example from empty
                # to something else) we need to process this update.
                # If nothing else changed in the external_ids, we do not care
                # as it would just cause unnecessary events during migrations.
                # (see the docstring of this class)
                return False

            # Check if the current port_fip has not been exposed yet
            return not self.agent.is_ip_exposed(self._get_network(row),
                                                current_port_fip)

        except (IndexError, AttributeError):
            return False

    def _run(self, event, row, old):
        external_ip, external_mac, ls_name = (
            self.agent.get_port_external_ip_and_ls(row.name))
        if not external_ip or not ls_name:
            return

        with _SYNC_STATE_LOCK.read_lock():
            self.agent.expose_fip(external_ip, external_mac, ls_name, row)


class LogicalSwitchPortFIPDeleteEvent(base_watcher.LSPChassisEvent):
    '''Floating IP delete events based on the LogicalSwitchPort

    The LSP has information about the host is should be exposed to, which
    adds a bit of complexity in the event match, but saves a lot of queries
    to the OVN NB DB.

    Should trigger on:
    - lsp deleted and bound on this host
    - floating ip removed from a lsp (external_ids.neutron:port_fip
                                      disappeared with information)
    - port with floating ip attached was set to down (old.up = true and
                                                      row.up = false)
    - current floating ip is not the same as old floating ip
    '''
    def __init__(self, bgp_agent):
        events = (self.ROW_UPDATE, self.ROW_DELETE,)
        super(LogicalSwitchPortFIPDeleteEvent, self).__init__(
            bgp_agent, events)

    def match_fn(self, event, row, old):
        '''Match port deletes or port downs or migrations or fip changes

        1. [DELETE] Port has been deleted, and we're hosting it
        2. [UPDATE] Port went down, withdraw if we announced it
        3. [UPDATE] Floating IP has been disassociated (or re-associated
                    with another floating ip)
        4. [UPDATE] Port has been migrated away and we're hosting it
        '''
        if row.type not in [constants.OVN_VM_VIF_PORT_TYPE,
                            constants.OVN_VIRTUAL_VIF_PORT_TYPE]:
            return
        try:
            # single and dual-stack format
            if not self._check_ip_associated(row.addresses[0]):
                return False

            current_port_fip = self._get_port_fip(row)
            old_port_fip = self._get_port_fip(old)
            if not current_port_fip and not old_port_fip:
                # This port is not a floating ip update
                return False

            logical_switch = self._get_network(row)
            is_exposed = self.agent.is_ip_exposed(logical_switch,
                                                  old_port_fip or
                                                  current_port_fip)
            if not is_exposed:
                # already deleted or not exposed.
                return False

            # From here on we know we are exposing a FIP (either old or
            #                                             current)

            if event == self.ROW_DELETE:
                # Port is deleting
                return True

            if (hasattr(old, 'up') and bool(old.up[0]) and  # port was up
                    not bool(row.up[0])):                   # is now down
                return True

            if old_port_fip is not None and current_port_fip != old_port_fip:
                # fip has changed, we should remove the old one.
                return True

            # If we reach here, just check if host changed
            current_chassis, _ = self._get_chassis(row)
            return current_chassis != self.agent.chassis

        except (IndexError, AttributeError):
            return False

    def _run(self, event, row, old):
        # First check to remove the fip provided in old (since this might
        # have been updated)
        fip = self._get_port_fip(old)
        if not fip:
            # Remove the fip provided in the current row, probably a
            # disassociate of the fip (or a down or a move)
            fip = self._get_port_fip(row)
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

            # Expose if there is a modification in the VIPS, first new item (
            # that could happend with and non existing vips on old event or
            # empty one) or additional items because a bigger row.vips is
            # including old.vips
            if hasattr(old, 'vips'):
                if ((not old.vips and row.vips) or
                        (old.vips != row.vips and
                         set(old.vips.keys()).issubset(set(row.vips.keys())))):
                    return True

            if hasattr(old, 'external_ids'):
                # Check if the lb_router was added
                old_lb_router = self._get_router(old)
                if lb_router != old_lb_router:
                    return True
        except AttributeError:
            return False
        return False

    def _run(self, event, row, old):
        # vips field grows
        diff = self._get_diff_ip_from_vips(row, old)
        for ip in diff:
            with _SYNC_STATE_LOCK.read_lock():
                if self._is_vip(row, ip):
                    self.agent.expose_ovn_lb_vip(row)
                elif self._is_fip(row, ip):
                    self.agent.expose_ovn_lb_fip(row)

        # router set ext-gw
        # NOTE(froyo): Not needed to check/call to expose_ovn_lb_fip, since up
        # to this point this LB could not have been associated with a FIP
        # since the subnet did not have access to the public network
        if hasattr(old, 'external_ids'):
            with _SYNC_STATE_LOCK.read_lock():
                if self._get_router(old) != self._get_router(row):
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
            if hasattr(old, 'external_ids'):
                old_lb_router = self._get_router(old)
                if not old_lb_router:
                    return False
                if old_lb_router not in self.agent.ovn_local_cr_lrps.keys():
                    return False
                if old_lb_router != lb_router:
                    # Router should not be removed, but if that is the case we
                    # should remove the loadbalancer
                    return True

            # Whatever the change removing any field from vips should be manage
            if hasattr(old, 'vips'):
                if ((old.vips != row.vips and
                        set(row.vips.keys()).issubset(
                            set(old.vips.keys())))):
                    return True
        except AttributeError:
            return False
        return False

    def _run(self, event, row, old):
        # DELETE event need drop all
        if event == self.ROW_DELETE:
            diff = self._get_ip_from_vips(row)
            for ip in diff:
                with _SYNC_STATE_LOCK.read_lock():
                    if self._is_vip(row, ip):
                        self.agent.withdraw_ovn_lb_vip(row)
                    elif self._is_fip(row, ip):
                        self.agent.withdraw_ovn_lb_fip(row)
            return

        # UPDATE event
        # vips field decrease
        diff = self._get_diff_ip_from_vips(old, row)
        for ip in diff:
            with _SYNC_STATE_LOCK.read_lock():
                if self._is_vip(old, ip):
                    self.agent.withdraw_ovn_lb_vip(old)
                elif self._is_fip(old, ip):
                    self.agent.withdraw_ovn_lb_fip(old)

        # router unset ext-gw
        if hasattr(old, 'external_ids'):
            with _SYNC_STATE_LOCK.read_lock():
                if self._get_router(old) != self._get_router(row):
                    self.agent.withdraw_ovn_lb_vip(old)


class OVNPFBaseEvent(base_watcher.OVNLBEvent):

    event = None

    def __init__(self, bgp_agent):
        super(OVNPFBaseEvent, self).__init__(
            bgp_agent, (self.event,))

    def match_fn(self, event, row, old):
        # The ovn port forwarding are manage as OVN lb balancers and they are
        # exposed through the cr-lrp, so if the local agent does not have the
        # matching router there is no need to process the event
        if not driver_utils.check_name_prefix(row,
                                              constants.OVN_LB_PF_NAME_PREFIX):
            return False

        if not row.vips:
            return False
        lb_router = self._get_router(row, constants.OVN_LR_NAME_EXT_ID_KEY)
        return lb_router in self.agent.ovn_local_cr_lrps.keys()


class OVNPFCreateEvent(OVNPFBaseEvent):

    event = OVNPFBaseEvent.ROW_CREATE

    def _run(self, event, row, old):
        with _SYNC_STATE_LOCK.read_lock():
            self.agent.expose_ovn_pf_lb_fip(row)


class OVNPFDeleteEvent(OVNPFBaseEvent):

    event = OVNPFBaseEvent.ROW_DELETE

    def _run(self, event, row, old):
        with _SYNC_STATE_LOCK.read_lock():
            self.agent.withdraw_ovn_pf_lb_fip(row)

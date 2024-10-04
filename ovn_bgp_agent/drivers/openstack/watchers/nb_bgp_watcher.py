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
from ovn_bgp_agent.drivers.openstack import nb_exceptions
from ovn_bgp_agent.drivers.openstack.utils import common as common_utils
from ovn_bgp_agent.drivers.openstack.utils import driver_utils
from ovn_bgp_agent.drivers.openstack.utils import loadbalancer as lb_utils
from ovn_bgp_agent.drivers.openstack.utils import port as port_utils
from ovn_bgp_agent.drivers.openstack.utils import router as router_utils
from ovn_bgp_agent.drivers.openstack.watchers import base_watcher
from ovn_bgp_agent import exceptions


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
            if not port_utils.has_ip_address_defined(row.addresses[0]):
                return False

            current_chassis = self._get_chassis(row)
            logical_switch = common_utils.get_from_external_ids(
                row, constants.OVN_LS_NAME_EXT_ID_KEY)

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
            try:
                ips = port_utils.get_ips_from_lsp(row)
            except exceptions.IpAddressNotFound:
                return False

            return not self.agent.is_ip_exposed(logical_switch, ips)

        except (IndexError, AttributeError):
            return False

    def _run(self, event, row, old):
        with _SYNC_STATE_LOCK.read_lock():
            ips = port_utils.get_ips_from_lsp(row)
            ips_info = port_utils.make_lsp_dict(row)
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
            if not port_utils.has_ip_address_defined(row.addresses[0]):
                return False

            try:
                ips = port_utils.get_ips_from_lsp(row)
            except exceptions.IpAddressNotFound:
                return False

            logical_switch = common_utils.get_from_external_ids(
                row, constants.OVN_LS_NAME_EXT_ID_KEY)

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

            current_chassis = self._get_chassis(row)
            # Delete the port from current chassis, if
            # 1. port went down (while only attached here)
            if (hasattr(old, 'up') and bool(old.up[0]) and   # port was up
                    not bool(row.up[0]) and                  # is now down
                    not port_utils.has_additional_binding(row)):  # and bound
                return True

            # 2. port no longer bound here
            return current_chassis != self.agent.chassis

        except (IndexError, AttributeError):
            return False

    def _run(self, event, row, old):
        with _SYNC_STATE_LOCK.read_lock():
            ips = port_utils.get_ips_from_lsp(row)
            ips_info = port_utils.make_lsp_dict(row)
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

    For the live migration of a VIP (floating ip attached to virtual port),
    the following events happen:
    1. port is set down (by ovn-controller on source host)
    2. external_ids update (neutron:host_id is removed)
    3. port is set up (by ovn-controller on dest host)
    4. external_ids update (neutron:host_id is added)

    In this case we only need to catch event 4.
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
            if not port_utils.has_ip_address_defined(row.addresses[0]):
                return False

            current_chassis = self._get_chassis(row)
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
                # Only case we are interested in is if the chassis has changed
                # with this event.
                # (see the docstring of this class)
                old_chassis = self._get_chassis(old)
                return old_chassis != current_chassis

            # Check if the current port_fip has not been exposed yet
            return not self.agent.is_ip_exposed(
                common_utils.get_from_external_ids(
                    row, constants.OVN_LS_NAME_EXT_ID_KEY),
                current_port_fip)

        except (IndexError, AttributeError):
            return False

    def _run(self, event, row, old):
        try:
            external_ip, external_mac, ls_name = (
                self.agent.get_port_external_ip_and_ls(row.name))
        except nb_exceptions.NATNotFound as e:
            LOG.debug("Logical Switch Port %s does not have all data required"
                      " in its NAT entry: %s", row.name, e)
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
            if not port_utils.has_ip_address_defined(row.addresses[0]):
                return False

            current_port_fip = port_utils.get_fip(row)
            old_port_fip = port_utils.get_fip(old)
            if not current_port_fip and not old_port_fip:
                # This port is not a floating ip update
                return False

            logical_switch = common_utils.get_from_external_ids(
                row, constants.OVN_LS_NAME_EXT_ID_KEY)
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
            current_chassis = self._get_chassis(row)
            return current_chassis != self.agent.chassis

        except (IndexError, AttributeError):
            return False

    def _run(self, event, row, old):
        # First check to remove the fip provided in old (since this might
        # have been updated)
        fip = port_utils.get_fip(old)
        if not fip:
            # Remove the fip provided in the current row, probably a
            # disassociate of the fip (or a down or a move)
            fip = port_utils.get_fip(row)
        if not fip:
            return
        with _SYNC_STATE_LOCK.read_lock():
            self.agent.withdraw_fip(fip, row)


class LogicalSwitchUpdateEvent(base_watcher.LogicalSwitchChassisEvent):
    '''Event to trigger on logical switch vrf config updates'''
    def __init__(self, bgp_agent):
        events = (self.ROW_UPDATE, self.ROW_DELETE)
        super(LogicalSwitchUpdateEvent, self).__init__(
            bgp_agent, events)

    def match_fn(self, event, row, old):
        '''Match updates for vrf configuration

        Will trigger whenever external_ids[neutron_bgpvpn:vni] and
        external_ids[neutron_bgpvpn:type] have been set and either one has
        been updated
        '''

        settings = driver_utils.get_port_vrf_settings(row)
        if settings and event == self.ROW_DELETE:
            # Always run sync method if we are deleting this network (and it
            # had settings applied)
            return True

        old_settings = driver_utils.get_port_vrf_settings(old)
        if old_settings is None:
            # it was not provided in old, so do not process this update
            return False

        return settings != old_settings

    def _run(self, event, row, old):
        with _SYNC_STATE_LOCK.read_lock():
            # NOTE(mnederlof): For now it makes sense to run the sync method
            # as this is triggered with a configured interval anyway and it
            # will add/remove the triggered logical switch.
            # It might make sense in the future to optimize this behaviour.
            self.agent.sync()


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
            ips_info = port_utils.make_lrp_dict(row)
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
            ips_info = port_utils.make_lrp_dict(row)
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
                'network': common_utils.get_from_external_ids(
                    row, constants.OVN_LS_NAME_EXT_ID_KEY),
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
                    'network': common_utils.get_from_external_ids(
                        row, constants.OVN_LS_NAME_EXT_ID_KEY),
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
                    'network': common_utils.get_from_external_ids(
                        row, constants.OVN_LS_NAME_EXT_ID_KEY),
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
            try:
                port_utils.get_ips_from_lsp(row)
            except exceptions.IpAddressNotFound:
                return False

            if not bool(row.up[0]):
                return False

            current_network = common_utils.get_from_external_ids(
                row, constants.OVN_LS_NAME_EXT_ID_KEY)
            if current_network not in self.agent.ovn_local_lrps:
                return False

            if hasattr(old, 'up'):
                if not bool(old.up[0]):
                    return True

            if hasattr(old, 'external_ids'):
                old_network = common_utils.get_from_external_ids(
                    old, constants.OVN_LS_NAME_EXT_ID_KEY)
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
            ips = port_utils.get_ips_from_lsp(row)
            mac = port_utils.get_mac_from_lsp(row)
            ips_info = {
                'mac': mac,
                'cidrs': row.external_ids.get(constants.OVN_CIDRS_EXT_ID_KEY,
                                              "").split(),
                'type': row.type,
                'logical_switch': common_utils.get_from_external_ids(
                    row, constants.OVN_LS_NAME_EXT_ID_KEY),
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
            if not port_utils.has_ip_address_defined(row.addresses[0]):
                return False

            current_network = common_utils.get_from_external_ids(
                row, constants.OVN_LS_NAME_EXT_ID_KEY)
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
            # The address is present because of the
            # has_ip_address_defined() check in match_fn(), therefore
            # there is no need for the try-except block.
            ips = port_utils.get_ips_from_lsp(row)
            mac = port_utils.get_mac_from_lsp(row)
            ips_info = {
                'mac': mac,
                'cidrs': row.external_ids.get(constants.OVN_CIDRS_EXT_ID_KEY,
                                              "").split(),
                'type': row.type,
                'logical_switch': common_utils.get_from_external_ids(
                    row, constants.OVN_LS_NAME_EXT_ID_KEY),
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
            lb_router = router_utils.get_name_from_external_ids(row)
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
                old_lb_router = router_utils.get_name_from_external_ids(old)
                if lb_router != old_lb_router:
                    return True
        except AttributeError:
            return False
        return False

    def _run(self, event, row, old):
        # vips field grows
        diff = lb_utils.get_diff_ip_from_vips(row, old)
        for ip in diff:
            with _SYNC_STATE_LOCK.read_lock():
                if lb_utils.is_vip(row, ip):
                    self.agent.expose_ovn_lb_vip(row)
                elif lb_utils.is_fip(row, ip):
                    self.agent.expose_ovn_lb_fip(row)

        # router set ext-gw
        # NOTE(froyo): Not needed to check/call to expose_ovn_lb_fip, since up
        # to this point this LB could not have been associated with a FIP
        # since the subnet did not have access to the public network
        if hasattr(old, 'external_ids'):
            with _SYNC_STATE_LOCK.read_lock():
                if (router_utils.get_name_from_external_ids(old) !=
                        router_utils.get_name_from_external_ids(row)):
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
                lb_router = router_utils.get_name_from_external_ids(row)
                if lb_router in self.agent.ovn_local_cr_lrps.keys():
                    return True
                return False

            # ROW UPDATE EVENT
            lb_router = router_utils.get_name_from_external_ids(row)
            if hasattr(old, 'external_ids'):
                old_lb_router = router_utils.get_name_from_external_ids(old)
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
            diff = lb_utils.get_vips(row)
            for ip in diff:
                with _SYNC_STATE_LOCK.read_lock():
                    if lb_utils.is_vip(row, ip):
                        self.agent.withdraw_ovn_lb_vip(row)
                    elif lb_utils.is_fip(row, ip):
                        self.agent.withdraw_ovn_lb_fip(row)
            return

        # UPDATE event
        # vips field decrease
        diff = lb_utils.get_diff_ip_from_vips(old, row)
        for ip in diff:
            with _SYNC_STATE_LOCK.read_lock():
                if lb_utils.is_vip(old, ip):
                    self.agent.withdraw_ovn_lb_vip(old)
                elif lb_utils.is_fip(old, ip):
                    self.agent.withdraw_ovn_lb_fip(old)

        # router unset ext-gw
        if hasattr(old, 'external_ids'):
            with _SYNC_STATE_LOCK.read_lock():
                if (router_utils.get_name_from_external_ids(old) !=
                        router_utils.get_name_from_external_ids(row)):
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
        lb_router = router_utils.get_name_from_external_ids(
            row, constants.OVN_LR_NAME_EXT_ID_KEY)
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


class NATMACAddedEvent(base_watcher.DnatSnatBaseEvent):
    events = (base_watcher.DnatSnatBaseEvent.ROW_UPDATE,)

    def match_fn(self, event, row, old):
        try:
            lsp_id = row.logical_port[0]
        except IndexError:
            LOG.error("NAT entry %s has no logical port set.", row.uuid)
            return False

        lsp = self.agent.nb_idl.lsp_get(lsp_id).execute()

        if lsp is None:
            LOG.error("Logical Switch Port %(lsp)s for NAT entry %(nat)s "
                      "was not found in OVN NB DB.", {
                          'lsp': lsp_id,
                          'nat': row.uuid})
            return False

        if lsp.type != constants.OVN_VM_VIF_PORT_TYPE:
            return False

        try:
            if lsp.options['requested-chassis'] != self.agent.chassis:
                return False
        except KeyError:
            return False

        try:
            if old.external_mac and old.external_mac[0] == row.external_mac[0]:
                return False
        except (AttributeError, IndexError):
            return False

        # This is required to be able to expose the FIP, there is no point in
        # continuing if the external_id is not set
        if constants.OVN_FIP_NET_EXT_ID_KEY not in row.external_ids:
            LOG.error("NAT entry %(nat)s does not have %(fip_net)s set in "
                      "external_ids", {
                          'nat': row.uuid,
                          'fip_net': constants.OVN_FIP_NET_EXT_ID_KEY})
            return False

        if not row.external_ip:
            LOG.error("NAT entry %s does not have external_ip set", row.uuid)
            return False

        return True

    def run(self, event, row, old):
        lsp = self.agent.nb_idl.lsp_get(row.logical_port[0]).execute()
        # The key is present, it was checked in match_fn
        net_id = row.external_ids[constants.OVN_FIP_NET_EXT_ID_KEY]
        ls_name = "neutron-{}".format(net_id)
        with _SYNC_STATE_LOCK.read_lock():
            self.agent.expose_fip(
                row.external_ip, row.external_mac[0], ls_name, lsp)


class ExposeFIPOnCRLRP(base_watcher.FipOnCRLRPBaseEvent):
    """Expose floating IP on the gateway chassis hosting the gateway port.

    This event happens when NAT entry is created. It exposes the floating IP on
    the gateway chassis hosting the gateway router.
    """
    events = (base_watcher.DnatSnatBaseEvent.ROW_CREATE,)

    def run(self, event, row, old):
        with _SYNC_STATE_LOCK.read_lock():
            self.agent.nat_exposer.expose_fip_from_nat(row)


class WithdrawFIPOnCRLRP(base_watcher.FipOnCRLRPBaseEvent):
    """Withdraw floating IP from the gateway chassis hosting the gateway port.

    This event happens when NAT entry is deleted. It withdraws the floating IP
    from the gateway chassis hosting the gateway router.
    """
    events = (base_watcher.DnatSnatBaseEvent.ROW_DELETE,)

    def run(self, event, row, old):
        self.agent.nat_exposer.withdraw_fip_from_nat(row)


class CrLrpChassisChangeBaseEvent(base_watcher.LRPChassisEvent):
    """Base class for case when gateway port moves.

    It matches if the hosting-chassis in status column of the gateway port has
    changed.
    """
    def __init__(self, bgp_agent):
        super().__init__(bgp_agent, (self.ROW_UPDATE,))

    def match_fn(self, event, row, old):
        new_chassis = row.status.get(constants.OVN_STATUS_CHASSIS)
        try:
            old_chassis = old.status.get(constants.OVN_STATUS_CHASSIS)
        except AttributeError:
            return False

        # Match only if the port was moved
        return new_chassis != old_chassis


class CrLrpChassisChangeExposeEvent(CrLrpChassisChangeBaseEvent):
    """A LRP event to expose floating IPs on centralized node.

    Expose all floating IPs hosted by a router with this gateway port hosted on
    this chassis. It matches in case of gateway port changes its hosting
    chassis to this chassis.
    """
    def match_fn(self, event, row, old):
        if not super().match_fn(event, row, old):
            return False

        if constants.OVN_STATUS_CHASSIS not in row.status:
            return False

        if row.status[constants.OVN_STATUS_CHASSIS] != self.agent.chassis_id:
            return False

        return True

    def run(self, event, row, old):
        nats = self.agent.nb_idl.get_nats_by_lrp(row)
        with _SYNC_STATE_LOCK.read_lock():
            for nat in nats:
                self.agent.nat_exposer.expose_fip_from_nat(nat)


class CrLrpChassisChangeWithdrawEvent(CrLrpChassisChangeBaseEvent):
    """A LRP event to expose floating IPs on centralized node.

    Expose all floating IPs hosted by a router with this gateway port hosted on
    this chassis. It matches in case of gateway port changes its hosting
    chassis to this chassis.
    """
    def match_fn(self, event, row, old):
        if not super().match_fn(event, row, old):
            return False

        # if old does not have status, it would have failed in
        # super().match_fn()
        if constants.OVN_STATUS_CHASSIS not in old.status:
            return False

        if old.status[constants.OVN_STATUS_CHASSIS] != self.agent.chassis_id:
            return False

        return True

    def run(self, event, row, old):
        nats = self.agent.nb_idl.get_nats_by_lrp(row)
        with _SYNC_STATE_LOCK.read_lock():
            for nat in nats:
                self.agent.nat_exposer.withdraw_fip_from_nat(nat)


class DistributedFlagChangedEvent(base_watcher.Event):
    """Re-register events if Neutron changed the distributed flag.

    The event matches if distributed flag was switched in OVN. Then it
    re-registers the events to react on the right events and does a full
    re-sync to withdraw or expose IPs.
    """
    def __init__(self, bgp_agent):
        table = 'NB_Global'
        events = (self.ROW_UPDATE,)
        super().__init__(bgp_agent, events, table)
        self.event_name = self.__class__.__name__

    def match_fn(self, event, row, old):
        try:
            if (old.external_ids.get(constants.OVN_FIP_DISTRIBUTED) ==
                    row.external_ids[constants.OVN_FIP_DISTRIBUTED]):
                return False
        except KeyError:
            # Distributed flag was deleted, behave like distributed agent
            pass
        except AttributeError:
            return False

        return True

    def run(self, event, row, old):
        if row.external_ids.get(constants.OVN_FIP_DISTRIBUTED) == "True":
            self.agent.distributed = True
        elif row.external_ids.get(constants.OVN_FIP_DISTRIBUTED) == "False":
            self.agent.distributed = False
        else:
            # Default to True
            self.agent.distributed = True

        self.agent.sync()
        self.agent.frr_sync()

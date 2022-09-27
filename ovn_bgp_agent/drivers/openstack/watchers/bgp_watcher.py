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
from ovn_bgp_agent.drivers.openstack.utils import driver_utils
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
            return (not row.chassis and
                    row.logical_port.startswith('lrp-') and
                    "chassis-redirect-port" not in row.options.keys())
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
            return (not row.chassis and
                    row.logical_port.startswith('lrp-') and
                    "chassis-redirect-port" not in row.options.keys())
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
            return (not old.chassis and row.chassis and
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
        events = (self.ROW_UPDATE, self.ROW_DELETE,)
        super(TenantPortDeletedEvent, self).__init__(
            bgp_agent, events)

    def match_fn(self, event, row, old):
        try:
            # single and dual-stack format
            if not self._check_single_dual_stack_format(row.mac[0]):
                return False
            if event == self.ROW_UPDATE:
                return (old.chassis and not row.chassis and
                        self.agent.ovn_local_lrps != [])
            if event == self.ROW_DELETE:
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


class OVNLBTenantPortEvent(base_watcher.PortBindingChassisEvent):
    def __init__(self, bgp_agent):
        events = (self.ROW_CREATE, self.ROW_DELETE,)
        super(OVNLBTenantPortEvent, self).__init__(
            bgp_agent, events)

    def match_fn(self, event, row, old):
        try:
            # it should not have mac, no chassis, and status down
            if not row.mac and not row.chassis and not row.up[0]:
                if self.agent.ovn_local_lrps != []:
                    return True
            return False
        except (IndexError, AttributeError):
            return False

    def run(self, event, row, old):
        if row.type != constants.OVN_VM_VIF_PORT_TYPE:
            return

        with _SYNC_STATE_LOCK.read_lock():
            # This is depending on the external-id information added by
            # neutron, regarding the neutron:cidrs
            ext_n_cidr = row.external_ids.get(constants.OVN_CIDRS_EXT_ID_KEY)
            if not ext_n_cidr:
                return

            ovn_lb_ip = ext_n_cidr.split(" ")[0].split("/")[0]
            if event == self.ROW_DELETE:
                self.agent.withdraw_remote_ip([ovn_lb_ip], row)
            if event == self.ROW_CREATE:
                self.agent.expose_remote_ip([ovn_lb_ip], row)


class OVNLBMemberUpdateEvent(base_watcher.OVNLBMemberEvent):
    def __init__(self, bgp_agent):
        events = (self.ROW_UPDATE, self.ROW_DELETE,)
        super(OVNLBMemberUpdateEvent, self).__init__(
            bgp_agent, events)

    def match_fn(self, event, row, old):
        # Only interested in update events related to associated datapaths
        if event == self.ROW_DELETE:
            return bool(self.agent.ovn_local_cr_lrps)

        try:
            if row.datapaths == old.datapaths:
                return False
        except AttributeError:
            return False

        # Only process event if the local node has a cr-lrp ports associated
        return bool(self.agent.ovn_local_cr_lrps)

    def run(self, event, row, old):
        # Only process event if the local node has a cr-lrp port whose provider
        # datapath is included into the loadbalancer. This means the
        # loadbalancer has the VIP on a provider network
        # Also, the cr-lrp port needs to have subnet datapaths (LS) associated
        # to it that include the load balancer
        provider_dp = ""
        ovn_lb_cr_lrp = ""
        for cr_lrp_port, cr_lrp_info in self.agent.ovn_local_cr_lrps.items():
            if cr_lrp_info.get('provider_datapath') not in row.datapaths:
                continue
            match_subnets_datapaths = [
                subnet_dp for subnet_dp in cr_lrp_info[
                    'subnets_datapath'].values()
                if subnet_dp in row.datapaths or subnet_dp in old.datapaths]
            if match_subnets_datapaths:
                provider_dp = cr_lrp_info.get('provider_datapath')
                ovn_lb_cr_lrp = cr_lrp_port
                break
        if not provider_dp:
            return

        with _SYNC_STATE_LOCK.read_lock():
            if event == self.ROW_DELETE:
                # loadbalancer deleted. Withdraw the VIP through the cr-lrp
                return self.agent.withdraw_ovn_lb_on_provider(row.name,
                                                              provider_dp,
                                                              ovn_lb_cr_lrp)

            if len(row.datapaths) == 1 and len(old.datapaths) > 1:
                # last member deleted. Withdraw the VIP through the cr-lrp
                return self.agent.withdraw_ovn_lb_on_provider(row.name,
                                                              provider_dp,
                                                              ovn_lb_cr_lrp)

            # NOTE(ltomasbo): It is assumed that the rest of the datapaths in
            # the datapaths fields belongs to networks (Logical_Switch)
            # connected to the provider network datapath through a single
            # router (cr-lrp)
            if len(old.datapaths) == 1 and len(row.datapaths) > 1:
                # first member added, time to expose the VIP through the cr-lrp
                for vip in row.vips.keys():
                    ip = driver_utils.parse_vip_from_lb_table(vip)
                    if ip:
                        return self.agent.expose_ovn_lb_on_provider(
                            row.name, ip, provider_dp, ovn_lb_cr_lrp)


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

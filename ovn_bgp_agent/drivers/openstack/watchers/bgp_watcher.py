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
from oslo_config import cfg
from oslo_log import log as logging

from ovn_bgp_agent import constants
from ovn_bgp_agent.drivers.openstack.watchers import base_watcher
from ovn_bgp_agent.utils import helpers

CONF = cfg.CONF
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
            if not self._check_ip_associated(row.mac[0]):
                return False
            if not bool(row.up[0]):
                return False

            if row.chassis[0].name != self.agent.chassis:
                return False
            if hasattr(old, 'chassis'):
                if not old.chassis or row.chassis != old.chassis:
                    return True
            if hasattr(old, 'up'):
                if not bool(old.up[0]):
                    return True
        except (IndexError, AttributeError):
            return False

    def _run(self, event, row, old):
        if row.type not in constants.OVN_VIF_PORT_TYPES:
            return
        with _SYNC_STATE_LOCK.read_lock():
            ips = row.mac[0].split(' ')[1:]
            self.agent.expose_ip(ips, row)


class PortBindingChassisDeletedEvent(base_watcher.PortBindingChassisEvent):
    def __init__(self, bgp_agent):
        events = (self.ROW_UPDATE, self.ROW_DELETE,)
        super(PortBindingChassisDeletedEvent, self).__init__(
            bgp_agent, events)

    def match_fn(self, event, row, old):
        try:
            # single and dual-stack format
            if not self._check_ip_associated(row.mac[0]):
                return False
            if event == self.ROW_DELETE:
                return row.chassis[0].name == self.agent.chassis

            if hasattr(old, 'chassis'):
                if (old.chassis[0].name == self.agent.chassis and
                        (not row.chassis or row.chassis != old.chassis)):
                    return True
            if hasattr(old, 'up'):
                # this requires to have unchanged chassis and being the local
                # one. If there was a chassis change, then it was already
                # processed before
                if (row.chassis[0].name == self.agent.chassis and
                        bool(old.up[0]) and not bool(row.up[0])):
                    return True
        except (IndexError, AttributeError):
            return False
        return False

    def _run(self, event, row, old):
        if row.type not in constants.OVN_VIF_PORT_TYPES:
            return
        with _SYNC_STATE_LOCK.read_lock():
            ips = row.mac[0].split(' ')[1:]
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

    def _run(self, event, row, old):
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
                ips = nat.strip().split(" ")[1:-1]
                port = nat.strip().split(" ")[-1].split("\"")[1]
                old_cr_lrps.setdefault(port, set()).update(ips)
            for nat in row.nat_addresses:
                ips = nat.strip().split(" ")[1:-1]
                port = nat.strip().split(" ")[-1].split("\"")[1]
                ips_to_expose = [ip for ip in ips
                                 if ip not in old_cr_lrps.get(port, set())]
                if ips_to_expose:
                    self.agent.expose_ip(ips_to_expose, row,
                                         associated_port=port)


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

    def _run(self, event, row, old):
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
                ips = nat.strip().split(" ")[1:-1]
                port = nat.strip().split(" ")[-1].split("\"")[1]
                current_cr_lrps.setdefault(port, set()).update(ips)
            for nat in old.nat_addresses:
                ips = nat.strip().split(" ")[1:-1]
                port = nat.strip().split(" ")[-1].split("\"")[1]
                ips_to_withdraw = [ip for ip in ips
                                   if ip not in current_cr_lrps.get(port,
                                                                    set())]
                if ips_to_withdraw:
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
            if not self._check_ip_associated(row.mac[0]):
                return False
            return (not row.chassis and
                    row.logical_port.startswith('lrp-') and
                    "chassis-redirect-port" not in row.options.keys())
        except (IndexError, AttributeError):
            return False

    def _run(self, event, row, old):
        if row.type != constants.OVN_PATCH_VIF_PORT_TYPE:
            return
        with _SYNC_STATE_LOCK.read_lock():
            ip_address = row.mac[0].split(' ')[1]
            self.agent.expose_subnet(ip_address, row)


class SubnetRouterUpdateEvent(base_watcher.PortBindingChassisEvent):
    def __init__(self, bgp_agent):
        events = (self.ROW_UPDATE,)
        super(SubnetRouterUpdateEvent, self).__init__(
            bgp_agent, events)

    def match_fn(self, event, row, old):
        # This will match if the mac field has changed between old and row.
        # This can happen when you have multiple subnets in the same network,
        # those will be added/removed to/from the same lrp-port in the mac
        # field.
        # Format:
        # mac = [ff:ff:ff:ff:ff:ff subnet1/cidr subnet2/cidr [...]]
        try:
            # single and dual-stack format
            if (not self._check_ip_associated(row.mac[0]) and
                    not self._check_ip_associated(old.mac[0])):
                return False
            return (
                not row.chassis and
                row.logical_port.startswith("lrp-") and
                "chassis-redirect-port" not in row.options.keys() and
                old.mac != row.mac
            )
        except (IndexError, AttributeError):
            return False

    def _run(self, event, row, old):
        if row.type != constants.OVN_PATCH_VIF_PORT_TYPE:
            return
        with _SYNC_STATE_LOCK.read_lock():
            self.agent.update_subnet(old, row)


class SubnetRouterDetachedEvent(base_watcher.PortBindingChassisEvent):
    def __init__(self, bgp_agent):
        events = (self.ROW_DELETE,)
        super(SubnetRouterDetachedEvent, self).__init__(
            bgp_agent, events)

    def match_fn(self, event, row, old):
        try:
            # single and dual-stack format
            if not self._check_ip_associated(row.mac[0]):
                return False
            return (not row.chassis and
                    row.logical_port.startswith('lrp-') and
                    "chassis-redirect-port" not in row.options.keys())
        except (IndexError, AttributeError):
            return False

    def _run(self, event, row, old):
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
            # Handling the case for unknown MACs when configdrive is used
            # instead of dhcp
            if row.mac == ['unknown']:
                n_cidrs = row.external_ids.get(constants.OVN_CIDRS_EXT_ID_KEY,
                                               "").split()
                if not n_cidrs:
                    return False
            # single and dual-stack format
            elif not self._check_ip_associated(row.mac[0]):
                return False
            return (not old.chassis and row.chassis and
                    self.agent.ovn_local_lrps != [])
        except (IndexError, AttributeError):
            return False

    def _run(self, event, row, old):
        if row.type not in (constants.OVN_VM_VIF_PORT_TYPE,
                            constants.OVN_VIRTUAL_VIF_PORT_TYPE):
            return
        with _SYNC_STATE_LOCK.read_lock():
            if row.mac == ['unknown']:
                # Handling the case for unknown MACs when configdrive is used
                # instead of dhcp
                n_cidrs = row.external_ids.get(constants.OVN_CIDRS_EXT_ID_KEY,
                                               "")
                ips = [ip.split("/")[0] for ip in n_cidrs.split(" ")]
            else:
                ips = row.mac[0].split(' ')[1:]
            self.agent.expose_remote_ip(ips, row)


class TenantPortDeletedEvent(base_watcher.PortBindingChassisEvent):
    def __init__(self, bgp_agent):
        events = (self.ROW_UPDATE, self.ROW_DELETE,)
        super(TenantPortDeletedEvent, self).__init__(
            bgp_agent, events)

    def match_fn(self, event, row, old):
        try:
            if row.mac == ['unknown']:
                # Handling the case for unknown MACs when configdrive is used
                # instead of dhcp
                n_cidrs = row.external_ids.get(constants.OVN_CIDRS_EXT_ID_KEY,
                                               "").split()
                if not n_cidrs:
                    return False
            # single and dual-stack format
            elif not self._check_ip_associated(row.mac[0]):
                return False
            if event == self.ROW_UPDATE:
                return (old.chassis and not row.chassis and
                        self.agent.ovn_local_lrps != [])
            if event == self.ROW_DELETE:
                return (self.agent.ovn_local_lrps != [])
        except (IndexError, AttributeError):
            return False

    def _run(self, event, row, old):
        if row.type not in (constants.OVN_VM_VIF_PORT_TYPE,
                            constants.OVN_VIRTUAL_VIF_PORT_TYPE):
            return
        if event == self.ROW_UPDATE:
            chassis = old.chassis
        else:
            chassis = row.chassis
        with _SYNC_STATE_LOCK.read_lock():
            if row.mac == ['unknown']:
                # Handling the case for unknown MACs when configdrive is used
                # instead of dhcp
                n_cidrs = row.external_ids.get(constants.OVN_CIDRS_EXT_ID_KEY,
                                               "")
                ips = [ip.split("/")[0] for ip in n_cidrs.split(" ")]
            else:
                ips = row.mac[0].split(' ')[1:]
            self.agent.withdraw_remote_ip(ips, row, chassis)


class OVNLBVIPPortEvent(base_watcher.PortBindingChassisEvent):
    def __init__(self, bgp_agent):
        events = (self.ROW_CREATE, self.ROW_DELETE,)
        super(OVNLBVIPPortEvent, self).__init__(
            bgp_agent, events)

    def match_fn(self, event, row, old):
        # The ovn lb balancers are exposed through the cr-lrp, so if the
        # local agent does not have any cr-lrp associated there is no need
        # to process the event
        try:
            # it should not have mac, no chassis, and status down
            if not row.mac and not row.chassis and not row.up[0]:
                return bool(self.agent.ovn_local_cr_lrps)
            return False
        except (IndexError, AttributeError):
            return False

    def _run(self, event, row, old):
        if row.type != constants.OVN_VM_VIF_PORT_TYPE:
            return

        with _SYNC_STATE_LOCK.read_lock():
            # This is depending on the external-id information added by
            # neutron, regarding the neutron:cidrs
            ext_n_cidr = row.external_ids.get(constants.OVN_CIDRS_EXT_ID_KEY,
                                              "")
            if not ext_n_cidr:
                return

            ovn_lb_ip = ext_n_cidr.strip().split(" ")[0].split("/")[0]
            if event == self.ROW_DELETE:
                self.agent.withdraw_ovn_lb(ovn_lb_ip, row)
            if event == self.ROW_CREATE:
                self.agent.expose_ovn_lb(ovn_lb_ip, row)


class OVNLBMemberCreateEvent(base_watcher.OVNLBEvent):
    def __init__(self, bgp_agent):
        events = (self.ROW_CREATE,)
        super(OVNLBMemberCreateEvent, self).__init__(
            bgp_agent, events)

    def match_fn(self, event, row, old):
        # Only process event if the local node has a cr-lrp ports associated
        return bool(self.agent.ovn_local_cr_lrps)

    def _run(self, event, row, old):
        # Only process event if the local node has a cr-lrp port whose provider
        # datapath is included into the loadbalancer. This means the
        # loadbalancer has the VIP on a provider network
        # Also, the cr-lrp port needs to have subnet datapaths (LS) associated
        # to it that include the load balancer
        if not self.agent.ovn_local_cr_lrps:
            return
        try:
            row_dp = row.datapaths
        except AttributeError:
            row_dp = []

        row_dp, router_dps = helpers.get_lb_datapath_groups(row)
        if not row_dp:
            # No need to continue. There is no need to expose it as there is
            # no datapaths (aka members).
            return
        vip_port = self.agent.sb_idl.get_ovn_vip_port(row.name)
        if not vip_port:
            return
        vip_ip = vip_port.external_ids.get(constants.OVN_CIDRS_EXT_ID_KEY, "")
        if not vip_ip:
            return
        vip_ip = vip_ip.strip().split(" ")[0].split("/")[0]
        associated_cr_lrp_port = None

        if not router_dps and not (CONF.expose_tenant_networks or
                                   CONF.expose_ipv6_gua_tenant_networks):
            # assume all the members are connected through the same router
            # so only one member needs to be checked
            member_dp = row_dp[0]
            # get lrps on that dp (patch ports)
            router_lrps = (
                self.agent.sb_idl.get_lrps_for_datapath(member_dp))
            for lrp in router_lrps:
                router_dps.append(self.agent.sb_idl.get_port_datapath(lrp))

        for cr_lrp_port, cr_lrp_info in self.agent.ovn_local_cr_lrps.items():
            if vip_port.datapath != cr_lrp_info.get('provider_datapath'):
                continue
            if cr_lrp_info.get('subnets_datapath'):
                if set(row_dp).intersection(set(
                        cr_lrp_info.get('subnets_datapath').values())):
                    associated_cr_lrp_port = cr_lrp_port
                    break
            else:
                if cr_lrp_info.get('router_datapath') in router_dps:
                    associated_cr_lrp_port = cr_lrp_port
                    break
        else:
            return

        with _SYNC_STATE_LOCK.read_lock():
            return self.agent.expose_ovn_lb_on_provider(
                vip_ip, row.name, associated_cr_lrp_port)


class OVNLBMemberDeleteEvent(base_watcher.OVNLBEvent):
    def __init__(self, bgp_agent):
        events = (self.ROW_DELETE,)
        super(OVNLBMemberDeleteEvent, self).__init__(
            bgp_agent, events)

    def match_fn(self, event, row, old):
        # Only process event if the local node has the lb exported
        return bool(self.agent.provider_ovn_lbs.get(row.name))

    def _run(self, event, row, old):
        associated_cr_lrp_port = self.agent.provider_ovn_lbs[row.name].get(
            'gateway_port')
        if not associated_cr_lrp_port:
            # Something is wrong, not enough information to proceed
            return
        with _SYNC_STATE_LOCK.read_lock():
            # loadbalancer deleted. Withdraw the VIP through the cr-lrp
            return self.agent.withdraw_ovn_lb_on_provider(
                row.name, associated_cr_lrp_port)


class LocalnetCreateDeleteEvent(base_watcher.PortBindingChassisEvent):
    def __init__(self, bgp_agent):
        events = (self.ROW_CREATE, self.ROW_DELETE,)
        super(LocalnetCreateDeleteEvent, self).__init__(
            bgp_agent, events)

    def match_fn(self, event, row, old):
        return row.type == constants.OVN_LOCALNET_VIF_PORT_TYPE

    def _run(self, event, row, old):
        with _SYNC_STATE_LOCK.read_lock():
            self.agent.sync()


class ChassisCreateEventBase(base_watcher.Event):
    table = None

    def __init__(self, bgp_agent):
        self.agent = bgp_agent
        self.first_time = True
        events = (self.ROW_CREATE,)
        super(ChassisCreateEventBase, self).__init__(
            events, self.table, (('name', '=', self.agent.chassis),))
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

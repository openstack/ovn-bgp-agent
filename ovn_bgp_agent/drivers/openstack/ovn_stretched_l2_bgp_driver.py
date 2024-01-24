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

import collections
import dataclasses
import ipaddress
import threading

from oslo_concurrency import lockutils
from oslo_config import cfg
from oslo_log import log as logging

from ovn_bgp_agent import constants
from ovn_bgp_agent.drivers import driver_api
from ovn_bgp_agent.drivers.openstack.utils import bgp as bgp_utils
from ovn_bgp_agent.drivers.openstack.utils import driver_utils
from ovn_bgp_agent.drivers.openstack.utils import frr
from ovn_bgp_agent.drivers.openstack.utils import ovn
from ovn_bgp_agent.drivers.openstack.utils import ovs
from ovn_bgp_agent.drivers.openstack.watchers import bgp_watcher as watcher
from ovn_bgp_agent import exceptions as agent_exc
from ovn_bgp_agent.utils import linux_net


CONF = cfg.CONF
LOG = logging.getLogger(__name__)

OVN_TABLES = ["Port_Binding", "Chassis", "Datapath_Binding", "Chassis_Private"]


@dataclasses.dataclass(frozen=True, eq=True)
class HashedRoute:
    network: str
    prefix_len: int
    dst: str


class OVNBGPStretchedL2Driver(driver_api.AgentDriverBase):
    def __init__(self):
        self.ovn_local_cr_lrps = {}
        self.vrf_routes = set()
        self.ovn_routing_tables_routes = collections.defaultdict()
        self.allowed_address_scopes = set(CONF.address_scopes or [])
        self.propagated_lrp_ports = {}

        self._sb_idl = None
        self._post_fork_event = threading.Event()

    @property
    def sb_idl(self):
        if not self._sb_idl:
            self._post_fork_event.wait()
        return self._sb_idl

    @sb_idl.setter
    def sb_idl(self, val):
        self._sb_idl = val

    def start(self):
        self.ovs_idl = ovs.OvsIdl()
        self.ovs_idl.start(CONF.ovsdb_connection)

        # Base BGP configuration
        # Ensure FRR is configured to leak only kernel routes by default
        frr.set_default_redistribute(['kernel'])
        bgp_utils.ensure_base_bgp_configuration()

        # Clear vrf routing table
        if CONF.clear_vrf_routes_on_startup:
            linux_net.delete_routes_from_table(CONF.bgp_vrf_table_id)

        self.chassis = self.ovs_idl.get_own_chassis_id()
        self.ovn_remote = self.ovs_idl.get_ovn_remote()
        LOG.debug("Loaded chassis %s.", self.chassis)
        if self.allowed_address_scopes:
            LOG.debug("Configured allowed address scopes: %s",
                      ", ".join(self.allowed_address_scopes))

        self._post_fork_event.clear()

        events = self._get_events()
        self.sb_idl = ovn.OvnSbIdl(
            self.ovn_remote,
            chassis=self.chassis,
            tables=OVN_TABLES,
            events=events,
        ).start()

        # Now IDL connections can be safely used
        self._post_fork_event.set()

    def _get_events(self):
        return {
            watcher.SubnetRouterAttachedEvent(self),
            watcher.SubnetRouterUpdateEvent(self),
            watcher.SubnetRouterDetachedEvent(self),
            watcher.PortBindingChassisCreatedEvent(self),
            watcher.PortBindingChassisDeletedEvent(self),
        }

    @lockutils.synchronized('bgp')
    def frr_sync(self):
        LOG.debug("Ensuring VRF configuration for advertising routes")
        # Base BGP configuration
        # Ensure FRR is configured to leak the routes
        bgp_utils.ensure_base_bgp_configuration()

    @lockutils.synchronized("bgp")
    def sync(self):
        self.ovn_local_cr_lrps = {}
        self.ovn_routing_tables_routes = collections.defaultdict()
        self.vrf_routes = set()
        self.propagated_lrp_ports = {}

        LOG.debug("Syncing current routes.")

        # Get all current exposed routes
        vrf_routes = linux_net.get_routes_on_tables([CONF.bgp_vrf_table_id])

        for cr_lrp_port in self.sb_idl.get_cr_lrp_ports():
            if (not cr_lrp_port.mac or
                    len(cr_lrp_port.mac[0].strip().split(" ")) <= 1):
                continue

            self._expose_cr_lrp(cr_lrp_port.mac[0].strip().split(" ")[1:],
                                cr_lrp_port)

        # remove all left over routes
        delete_routes = []
        for route in vrf_routes:
            r = HashedRoute(
                network=route.dst,
                prefix_len=route.dst_len,
                dst=route.gateway if route.gateway else None)
            if r not in self.vrf_routes:
                delete_routes.append(route)

        linux_net.delete_ip_routes(delete_routes)

    def _add_route(self, network, prefix_len, dst=None):
        LOG.debug("Adding BGP route for Network %s/%d via %s",
                  network, prefix_len, dst)

        linux_net.add_ip_route(
            self.ovn_routing_tables_routes,
            network,
            CONF.bgp_vrf_table_id,
            CONF.bgp_nic,
            vlan=None,
            mask=prefix_len,
            via=dst)
        r = HashedRoute(
            network=network,
            prefix_len=prefix_len,
            dst=dst)
        self.vrf_routes.add(r)

        LOG.debug("Added BGP route for Network %s/%d via %s",
                  network, prefix_len, dst)

    def _del_route(self, network, prefix_len, dst=None):
        LOG.debug("Deleting BGP route for Network %s/%d via %s",
                  network, prefix_len, dst)

        linux_net.del_ip_route(
            self.ovn_routing_tables_routes,
            network,
            CONF.bgp_vrf_table_id,
            CONF.bgp_nic,
            vlan=None,
            mask=prefix_len,
            via=dst)
        r = HashedRoute(
            network=network,
            prefix_len=prefix_len,
            dst=dst)
        if r in self.vrf_routes:
            self.vrf_routes.remove(r)

        LOG.debug("Deleted BGP route for Network %s/%d via %s",
                  network, prefix_len, dst)

    def _address_scope_allowed(self, scope1, scope2, ip_version):
        if not self.allowed_address_scopes:
            # No address scopes to filter on => announce everything
            return True

        if scope1[ip_version] != scope2[ip_version]:
            # Not the same address scope => don't announce
            return False

        if scope1[ip_version] not in self.allowed_address_scopes:
            # This address scope does not match => don't announce
            return False

        return True

    @lockutils.synchronized("bgp")
    def expose_subnet(self, ip, row):
        try:
            cr_lrp = self.sb_idl.is_router_gateway_on_any_chassis(row.datapath)
        except agent_exc.DatapathNotFound:
            LOG.debug("Port %s not being exposed as its datapath %s was "
                      "removed", row.logical_port, row.datapath)
            return
        if not cr_lrp:
            return

        self._ensure_network_exposed(row, cr_lrp.logical_port)

    @lockutils.synchronized("bgp")
    def update_subnet(self, old, row):
        try:
            cr_lrp = self.sb_idl.is_router_gateway_on_any_chassis(row.datapath)
        except agent_exc.DatapathNotFound:
            LOG.debug("Port %s not being updated as its datapath %s was "
                      "removed", row.logical_port, row.datapath)
            return
        if (not cr_lrp or not cr_lrp.mac or
                len(cr_lrp.mac[0].strip().split(" ")) <= 1):
            return

        current_ips = row.mac[0].strip().split(" ")[1:]
        previous_ips = (
            old.mac[0].strip().split(" ")[1:]
            if old.mac or len(old.mac[0].strip().split(" ")) > 1
            else []
        )
        add_ips = list(
            filter(lambda ip: ip not in previous_ips, current_ips))
        delete_ips = list(
            filter(lambda ip: ip not in current_ips, previous_ips))

        self._update_network(row, cr_lrp.logical_port, add_ips, delete_ips)

    @lockutils.synchronized("bgp")
    def withdraw_subnet(self, ip, row):
        port_info = self.propagated_lrp_ports.get(row.logical_port)
        if not port_info:
            return

        self._withdraw_subnet(port_info, port_info["cr_lrp"])

        gateway = self.ovn_local_cr_lrps.get(port_info["cr_lrp"])
        if gateway and row.logical_port in gateway["lrp_ports"]:
            gateway["lrp_ports"].remove(row.logical_port)
        self.propagated_lrp_ports.pop(row.logical_port)

    def _withdraw_subnet(self, port_info, cr_lrp):
        gateway = self.ovn_local_cr_lrps.get(cr_lrp)
        if not gateway:
            # If we dont have it cached then its either not existing or
            # or we got an event while starting up which then the sync
            # function can fix.
            return
        gateway_ips = gateway["ips"]

        subnets = [
            ipaddress.ip_network(subnet)
            for subnet in port_info["subnets"]]

        for gateway_ip in gateway_ips:
            for subnet in subnets:
                if gateway_ip.version != subnet.version:
                    continue

                self._del_route(
                    network=str(subnet.network_address),
                    prefix_len=subnet.prefixlen,
                    dst=str(gateway_ip.ip))

            # Check if can delete the link-local route
            exposed_routes = linux_net.get_exposed_routes_on_network(
                [CONF.bgp_vrf_table_id],
                gateway_ip.network)

            if not exposed_routes:
                self._del_route(
                    network=str(gateway_ip.network.network_address),
                    prefix_len=gateway_ip.network.prefixlen)

    @lockutils.synchronized('bgp')
    def withdraw_ip(self, ips, row, associated_port=None):
        if not (row.type == constants.OVN_CHASSISREDIRECT_VIF_PORT_TYPE and
                row.logical_port.startswith("cr-")):
            return
        self._withdraw_cr_lrp(ips, row)

    def _withdraw_cr_lrp(self, ips, row):
        if self.allowed_address_scopes:
            # Validate address scopes
            address_scopes = self.ovn_local_cr_lrps[row.logical_port][
                "address_scopes"]
            if not any([
                    scope in self.allowed_address_scopes
                    for scope in address_scopes.values()]):
                return

        # Check if there are networks attached to the router,
        # and if so, remove them locally
        lrp_ports = self.ovn_local_cr_lrps[row.logical_port]["lrp_ports"]
        for lrp_logical_port in lrp_ports:
            port_info = self.propagated_lrp_ports.get(lrp_logical_port)
            if not port_info:
                continue
            # withdraw network
            self._withdraw_subnet(port_info, row.logical_port)
            self.propagated_lrp_ports.pop(lrp_logical_port, None)

        self.ovn_local_cr_lrps.pop(row.logical_port, None)

    @lockutils.synchronized("bgp")
    def expose_ip(self, ips, row, associated_port=None):
        if not (row.type == constants.OVN_CHASSISREDIRECT_VIF_PORT_TYPE and
                row.logical_port.startswith("cr-")):
            return
        self._expose_cr_lrp(ips, row)

    def _expose_cr_lrp(self, ips, row):
        LOG.debug("Adding BGP route for CR-LRP Port %s", row.logical_port)
        # Keeping information about the associated network for
        # tenant network advertisement
        self.ovn_local_cr_lrps[row.logical_port] = {
            "ips": [ipaddress.ip_interface(ip) for ip in ips],
            "address_scopes": {},
            "lrp_ports": set(),
        }

        if self.allowed_address_scopes:
            # Validate address scopes
            patch_port = row.logical_port.split("cr-lrp-")[1]
            port = self.sb_idl.get_port_by_name(patch_port)
            if not port:
                LOG.error("Patchport %s for CR-LRP %s missing, skipping.",
                          patch_port, row.logical_port)
                return
            address_scopes = driver_utils.get_addr_scopes(port)
            self.ovn_local_cr_lrps[row.logical_port][
                "address_scopes"] = address_scopes
            if not any([
                    scope in self.allowed_address_scopes
                    for scope in address_scopes.values()]):
                return

        # Check if there are networks attached to the router,
        # and if so, add the needed routes
        lrp_ports = self.sb_idl.get_lrp_ports_for_router(row.datapath)
        for lrp in lrp_ports:
            if (
                lrp.chassis or
                not lrp.logical_port.startswith("lrp-") or
                "chassis-redirect-port" in lrp.options.keys()
            ):
                continue
            # expose network
            self._ensure_network_exposed(lrp, row.logical_port)

    def _update_network(self, router_port, gateway_port, add_ips, delete_ips):
        gateway = self.ovn_local_cr_lrps.get(gateway_port)
        if not gateway:
            # If we dont have it cached then its either not existing or
            # or we got an event while starting up which then the sync
            # function can fix.
            return
        gateway_ips = gateway["ips"]
        if (not router_port.mac or
                len(router_port.mac[0].strip().split(" ")) <= 1):
            return

        # get all ips from the router port
        ips_to_add = [ipaddress.ip_interface(ip) for ip in add_ips]

        ips_to_delete = [ipaddress.ip_interface(ip) for ip in delete_ips]

        for router_ip in ips_to_add + ips_to_delete:
            if router_ip in gateway_ips:
                return

        address_scopes = None
        if self.allowed_address_scopes:
            patch_port = router_port.logical_port.split("lrp-")[1]
            port = self.sb_idl.get_port_by_name(patch_port)
            if not port:
                LOG.error("Patchport %s for CR-LRP %s missing, skipping.",
                          patch_port, gateway_port)
                return
            address_scopes = driver_utils.get_addr_scopes(port)
            # if we should filter on address scopes and this port has no
            # address scopes set we do not need to go further
            if not any(address_scopes.values()):
                return

        subnets = set()
        for gateway_ip in gateway_ips:
            for router_ip in ips_to_add:
                if gateway_ip.version != router_ip.version:
                    continue

                if not self._address_scope_allowed(
                    gateway["address_scopes"],
                    address_scopes,
                    router_ip.version):
                    continue

                # Add link-local route
                self._add_route(
                    network=str(gateway_ip.network.network_address),
                    prefix_len=gateway_ip.network.prefixlen)

                # add route for the tenant network pointing to the
                # gateway ip
                self._add_route(
                    network=str(router_ip.network.network_address),
                    prefix_len=router_ip.network.prefixlen,
                    dst=str(gateway_ip.ip))
                subnets.add(str(router_ip.network))

            for router_ip in ips_to_delete:
                if gateway_ip.version != router_ip.version:
                    continue

                if not self._address_scope_allowed(
                    gateway["address_scopes"],
                    address_scopes,
                    router_ip.version):
                    continue

                self._del_route(
                    network=str(router_ip.network.network_address),
                    prefix_len=router_ip.network.prefixlen,
                    dst=str(gateway_ip.ip))

            # We only need to check this if we really deleted a route for
            # a tenant network
            if ips_to_delete:
                # Check if can delete the link-local route
                exposed_routes = linux_net.get_exposed_routes_on_network(
                    [CONF.bgp_vrf_table_id],
                    gateway_ip.network
                )

                if not exposed_routes:
                    self._del_route(
                        network=str(gateway_ip.network.network_address),
                        prefix_len=gateway_ip.network.prefixlen)

        self.ovn_local_cr_lrps[gateway_port]["lrp_ports"].add(
            router_port.logical_port)
        self.propagated_lrp_ports[router_port.logical_port] = {
            "cr_lrp": gateway_port,
            "subnets": subnets
        }

    def _ensure_network_exposed(self, router_port, gateway_port):
        gateway = self.ovn_local_cr_lrps.get(gateway_port)
        if not gateway:
            # If we dont have it cached then its either not existing or
            # or we got an event while starting up which then the sync
            # function can fix.
            return
        gateway_ips = gateway["ips"]
        if (not router_port.mac or
                len(router_port.mac[0].strip().split(" ")) <= 1):
            return

        # get all ips from the router port
        router_ips = [
            ipaddress.ip_interface(ip)
            for ip in router_port.mac[0].strip().split(" ")[1:]]

        for router_ip in router_ips:
            if router_ip in gateway_ips:
                return

        address_scopes = None
        if self.allowed_address_scopes:
            patch_port = router_port.logical_port.split("lrp-")[1]
            port = self.sb_idl.get_port_by_name(patch_port)
            if not port:
                LOG.error("Patchport %s for CR-LRP %s missing, skipping.",
                          patch_port, gateway_port)
                return
            address_scopes = driver_utils.get_addr_scopes(port)
            # if we have address scopes configured and none of them matches
            # for this port, we can skip further processing
            if not any(address_scopes.values()):
                return

        subnets = set()
        for gateway_ip in gateway_ips:
            for router_ip in router_ips:
                if gateway_ip.version != router_ip.version:
                    continue

                if not self._address_scope_allowed(
                    gateway["address_scopes"],
                    address_scopes,
                    router_ip.version):
                    continue

                # Add link-local route
                self._add_route(
                    network=str(gateway_ip.network.network_address),
                    prefix_len=gateway_ip.network.prefixlen)

                # add route for the tenant network pointing to the
                # gateway ip
                self._add_route(
                    network=str(router_ip.network.network_address),
                    prefix_len=router_ip.network.prefixlen,
                    dst=str(gateway_ip.ip))
                subnets.add(str(router_ip.network))

        if subnets:
            self.ovn_local_cr_lrps[gateway_port]["lrp_ports"].add(
                router_port.logical_port)
            self.propagated_lrp_ports[router_port.logical_port] = {
                "cr_lrp": gateway_port,
                "subnets": subnets
            }

    @lockutils.synchronized("bgp")
    def expose_remote_ip(self, ip_address):
        raise NotImplementedError()

    @lockutils.synchronized("bgp")
    def withdraw_remote_ip(self, ip_address):
        raise NotImplementedError()

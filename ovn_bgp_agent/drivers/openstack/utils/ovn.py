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

from neutron_lib._i18n import _
from oslo_config import cfg
from oslo_log import log as logging
from ovs.stream import Stream
from ovsdbapp.backend import ovs_idl
from ovsdbapp.backend.ovs_idl import command
from ovsdbapp.backend.ovs_idl import connection
from ovsdbapp.backend.ovs_idl import idlutils
from ovsdbapp.backend.ovs_idl import rowview
from ovsdbapp import event
from ovsdbapp.schema.ovn_northbound import impl_idl as nb_impl_idl
from ovsdbapp.schema.ovn_southbound import impl_idl as sb_impl_idl

from ovn_bgp_agent import constants
from ovn_bgp_agent.drivers.openstack.utils import driver_utils
from ovn_bgp_agent import exceptions
from ovn_bgp_agent.utils import helpers

CONF = cfg.CONF
LOG = logging.getLogger(__name__)


class OvnIdl(connection.OvsdbIdl):
    def __init__(self, driver, remote, schema, **kwargs):
        super(OvnIdl, self).__init__(remote, schema, **kwargs)
        self.driver = driver
        self.notify_handler = OvnDbNotifyHandler(driver)

    def notify(self, event, row, updates=None):
        self.notify_handler.notify(event, row, updates)


class OvnDbNotifyHandler(event.RowEventHandler):
    def __init__(self, driver):
        super(OvnDbNotifyHandler, self).__init__()
        self.driver = driver


class OvnNbIdl(OvnIdl):
    SCHEMA = 'OVN_Northbound'

    def __init__(self, connection_string, events=None, tables=None,
                 leader_only=False):
        if connection_string.startswith("ssl"):
            self._check_and_set_ssl_files(self.SCHEMA)
        helper = self._get_ovsdb_helper(connection_string)
        self._events = events
        if tables is None:
            tables = ('Logical_Switch_Port', 'NAT', 'NB_Global')
        for table in tables:
            helper.register_table(table)
        super(OvnNbIdl, self).__init__(
            None, connection_string, helper, leader_only=leader_only)

    def _get_ovsdb_helper(self, connection_string):
        return idlutils.get_schema_helper(connection_string, self.SCHEMA)

    def _check_and_set_ssl_files(self, schema_name):
        priv_key_file = CONF.ovn.ovn_nb_private_key
        cert_file = CONF.ovn.ovn_nb_certificate
        ca_cert_file = CONF.ovn.ovn_nb_ca_cert

        if priv_key_file:
            Stream.ssl_set_private_key_file(priv_key_file)

        if cert_file:
            Stream.ssl_set_certificate_file(cert_file)

        if ca_cert_file:
            Stream.ssl_set_ca_cert_file(ca_cert_file)

    def start(self):
        conn = connection.Connection(
            self, timeout=CONF.ovsdb_connection_timeout)
        ovsdbNbConn = OvsdbNbOvnIdl(conn)
        if self._events:
            self.notify_handler.watch_events(self._events)
        return ovsdbNbConn


class OvnSbIdl(OvnIdl):
    SCHEMA = 'OVN_Southbound'

    def __init__(self, connection_string, chassis=None, events=None,
                 tables=None):
        if connection_string.startswith("ssl"):
            self._check_and_set_ssl_files(self.SCHEMA)
        helper = self._get_ovsdb_helper(connection_string)
        self._events = events
        if tables is None:
            tables = ('Chassis', 'Encap', 'Port_Binding', 'Datapath_Binding',
                      'SB_Global')
        for table in tables:
            helper.register_table(table)
        super(OvnSbIdl, self).__init__(
            None, connection_string, helper, leader_only=False)
        if chassis:
            table = ('Chassis_Private' if 'Chassis_Private' in tables
                     else 'Chassis')
            self.tables[table].condition = [['name', '==', chassis]]

    def _get_ovsdb_helper(self, connection_string):
        return idlutils.get_schema_helper(connection_string, self.SCHEMA)

    def _check_and_set_ssl_files(self, schema_name):
        priv_key_file = CONF.ovn.ovn_sb_private_key
        cert_file = CONF.ovn.ovn_sb_certificate
        ca_cert_file = CONF.ovn.ovn_sb_ca_cert

        if priv_key_file:
            Stream.ssl_set_private_key_file(priv_key_file)

        if cert_file:
            Stream.ssl_set_certificate_file(cert_file)

        if ca_cert_file:
            Stream.ssl_set_ca_cert_file(ca_cert_file)

    def start(self):
        conn = connection.Connection(
            self, timeout=CONF.ovsdb_connection_timeout)
        ovsdbSbConn = OvsdbSbOvnIdl(conn)
        if self._events:
            self.notify_handler.watch_events(self._events)
        return ovsdbSbConn


class Backend(ovs_idl.Backend):
    lookup_table = {}
    ovsdb_connection = None

    def __init__(self, connection):
        self.ovsdb_connection = connection
        super(Backend, self).__init__(connection)

    @property
    def idl(self):
        return self.ovsdb_connection.idl

    @property
    def tables(self):
        return self.idl.tables


class StaticMACBindingFindCommand(command.DbFindCommand):
    table = 'Static_MAC_Binding'

    def __init__(self, api, port, ip):
        super().__init__(
            api,
            self.table,
            ('logical_port', '=', port),
            ('ip', '=', ip),
            row=True,
        )


# FIXME(ltomasbo): This can be removed once ovsdbapp supports it
class StaticMACBindingAddCommand(command.AddCommand):
    table_name = 'Static_MAC_Binding'

    def __init__(self, api, port, ip, mac, override_dynamic_mac=False,
                 may_exist=False, **columns):
        super().__init__(api)
        self.port = port
        self.ip = ip
        self.mac = mac
        self.override_dynamic_mac = override_dynamic_mac
        self.may_exist = may_exist
        self.columns = columns

    def run_idl(self, txn):
        cmd = StaticMACBindingFindCommand(self.api, self.port, self.ip)
        cmd.run_idl(txn)
        static_mac_binding_result = cmd.result
        if static_mac_binding_result:
            if len(static_mac_binding_result) > 1:
                # With the current database schema, this cannot happen, but
                # better safe than sorry.
                raise RuntimeError(
                    _("Unexpected duplicates in database for port %s "
                      "and ip %s" % (self.port, self.ip)))
            binding = static_mac_binding_result[0]
            if self.may_exist:
                # When no changes are made to a record, the parent
                # `post_commit` method will not be called.
                #
                # Ensure consistent return to caller of `Command.execute()`
                # even when no changes have been applied.
                self.result = rowview.RowView(binding)
                return
            else:
                raise RuntimeError(
                    _("Static MAC Binding entry for port %s and ip %s exists" %
                      (self.port, self.ip)))
        binding = txn.insert(self.api.tables[self.table_name])
        binding.logical_port = self.port
        binding.ip = self.ip
        binding.mac = self.mac
        binding.override_dynamic_mac = self.override_dynamic_mac
        self.set_columns(binding, **self.columns)
        # Setting the result to something other than a :class:`rowview.RowView`
        # or :class:`ovs.db.idl.Row` typed value will make the parent
        # `post_commit` method retrieve the newly insterted row from IDL and
        # return that to the caller.
        self.result = binding.uuid


# FIXME(ltomasbo): This can be removed once ovsdbapp supports it
class StaticMACBindingDelCommand(command.BaseCommand):
    table_name = 'Static_MAC_Binding'

    def __init__(self, api, port, ip, if_exists=False, **columns):
        super().__init__(api)
        self.port = port
        self.ip = ip
        self.if_exists = if_exists
        self.columns = columns

    def run_idl(self, txn):
        cmd = StaticMACBindingFindCommand(self.api, self.port, self.ip)
        cmd.run_idl(txn)
        static_mac_binding_result = cmd.result
        if static_mac_binding_result:
            if len(static_mac_binding_result) > 1:
                # With the current database schema, this cannot happen, but
                # better safe than sorry.
                raise RuntimeError(
                    _("Unexpected duplicates in database for port %s "
                      "and ip %s" % (self.port, self.ip)))
            binding = static_mac_binding_result[0]
            binding.delete()
            return
        if self.if_exists:
            return
        else:
            raise RuntimeError(
                _("Static MAC Binding entry for port %s and ip %s does not "
                  "exist" % (self.port, self.ip)))


class GetLSPsForGwChassisCommand(command.ReadOnlyCommand):
    """Get all LSPs associated with a NAT entry.

    (FIPs) which its CR-LRP ports (gateway ports) are hosted on the given
    chassis.

    The resulted format is in tuple that can be consumed by the `wire` module.
    """
    def __init__(self, api, chassis_id):
        super().__init__(api)
        self.chassis_id = chassis_id

    def run_idl(self, txn):
        self.result = []
        for nat in self.api.tables['NAT'].rows.values():
            if nat.type != 'dnat_and_snat':
                continue

            try:
                gw_chassis = nat.gateway_port[0].status.get(
                    constants.OVN_STATUS_CHASSIS)
            except IndexError:
                continue

            if gw_chassis == self.chassis_id:
                ls_name = "neutron-{}".format(
                    nat.external_ids[constants.OVN_FIP_NET_EXT_ID_KEY])
                try:
                    lsp = self.api.lookup(
                        'Logical_Switch_Port', nat.logical_port[0])
                except IndexError:
                    LOG.debug("NAT %s does not have a logical_port set", nat)
                    continue
                self.result.append(
                    (nat.external_ip,
                     nat.gateway_port[0].mac,
                     ls_name,
                     lsp))


class OvsdbNbOvnIdl(nb_impl_idl.OvnNbApiIdlImpl, Backend):
    def __init__(self, connection):
        super(OvsdbNbOvnIdl, self).__init__(connection)
        self.idl._session.reconnect.set_probe_interval(60000)

    def get_network_vlan_tags(self):
        tags = []
        cmd = self.db_find_rows('Logical_Switch_Port', ('type', '=',
                                constants.OVN_LOCALNET_VIF_PORT_TYPE))
        for row in cmd.execute(check_error=True):
            if row.tag:
                tags.append(row.tag[0])
        return tags

    def get_network_vlan_tag_by_network_name(self, network_name):
        tags = []
        for row in self.get_localnet_ports_by_network_name(network_name):
            if row.tag:
                tags.append(row.tag[0])
        return tags

    def get_localnet_ports_by_network_name(self, network_name):
        conditions = (
            ('options', '=', {'network_name': network_name}),
            ('type', '=', constants.OVN_LOCALNET_VIF_PORT_TYPE),
        )
        cmd = self.db_find_rows('Logical_Switch_Port', *conditions)
        for row in cmd.execute(check_error=True):
            yield row

    def get_bgpvpn_networks_for_ports(self, ports,
                                      vpn_type=constants.OVN_EVPN_TYPE_L3):
        cmd = self.db_find_rows(
            'Logical_Switch',
            ('external_ids', '=', {constants.OVN_EVPN_TYPE_EXT_ID_KEY:
                                   vpn_type}))
        networks = []
        for row in cmd.execute(check_error=True):
            if not row.ports:
                continue

            localnet_ports = [p for p in row.ports if p in ports]
            if localnet_ports:
                networks.append(row)
        return networks

    def ls_has_virtual_ports(self, logical_switch):
        ls = self.lookup('Logical_Switch', logical_switch)
        for port in ls.ports:
            if port.type == constants.OVN_VIRTUAL_VIF_PORT_TYPE:
                return True
        return False

    def get_nat_by_logical_port(self, logical_port):
        cmd = self.db_find_rows('NAT', ('logical_port', '=', logical_port))
        nat_info = cmd.execute(check_error=True)
        return nat_info[0] if nat_info else []

    def get_active_lsp_on_chassis(self, chassis):
        ports = []
        cmd = self.db_find_rows('Logical_Switch_Port', ('up', '=', True))
        for row in cmd.execute(check_error=True):
            port_chassis = driver_utils.get_port_chassis(row, chassis)
            if port_chassis == chassis:
                ports.append(row)

        return ports

    def get_active_cr_lrp_on_chassis(self, chassis):
        ports = []
        rows = self.db_list_rows('Logical_Router_Port').execute(
            check_error=True)

        for row in rows:
            if not hasattr(row, 'status'):
                LOG.warning("OVN version does not include support for status "
                            "information. Therefore router ports and tenant "
                            "IPs cannot be exposed.")
                break
            if row.status.get(constants.OVN_STATUS_CHASSIS) == chassis:
                ports.append(row)
        return ports

    def get_active_local_lrps(self, local_gateway_ports):
        ports = []
        cmd = self.db_find_rows(
            'Logical_Switch_Port', ('up', '=', True),
            ('type', '=', constants.OVN_ROUTER_PORT_TYPE),
            ('external_ids', '=', {constants.OVN_DEVICE_OWNER_EXT_ID_KEY:
                                   constants.OVN_ROUTER_INTERFACE}))
        for row in cmd.execute(check_error=True):
            if (row.external_ids.get(constants.OVN_DEVICE_ID_EXT_ID_KEY)
                    in local_gateway_ports):
                ports.append(row)
        return ports

    def get_active_lsp(self, network):
        ports = []
        # port type ""
        cmd = self.db_find_rows(
            'Logical_Switch_Port', ('up', '=', True),
            ('type', '=', constants.OVN_VM_VIF_PORT_TYPE),
            ('external_ids', '=', {constants.OVN_LS_NAME_EXT_ID_KEY: network}))
        ports.extend(cmd.execute(check_error=True))
        # port type "virtual"
        cmd = self.db_find_rows(
            'Logical_Switch_Port', ('up', '=', True),
            ('type', '=', constants.OVN_VIRTUAL_VIF_PORT_TYPE),
            ('external_ids', '=', {constants.OVN_LS_NAME_EXT_ID_KEY: network}))
        ports.extend(cmd.execute(check_error=True))
        return ports

    def get_active_local_lbs(self, local_gateway_ports):
        lbs = []
        cmd = self.db_find_rows('Load_Balancer', ('vips', '!=', {}))

        for row in cmd.execute(check_error=True):
            for ext_id_key in constants.OVN_LB_EXT_ID_ROUTER_KEY:
                try:
                    router_name = row.external_ids[ext_id_key].replace(
                        'neutron-', '', 1)
                    if router_name in local_gateway_ports:
                        lbs.append(row)
                        break
                except KeyError:
                    continue
        return lbs

    def static_mac_binding_add(self, port, ip, mac, override_dynamic_mac=False,
                               may_exist=False):
        return StaticMACBindingAddCommand(self, port, ip, mac,
                                          override_dynamic_mac, may_exist)

    def static_mac_binding_del(self, port, ip, if_exists=False):
        return StaticMACBindingDelCommand(self, port, ip, if_exists)

    def get_router(self, router):
        router_name = 'neutron-' + router
        return self.lr_get(router_name).execute(check_error=True)

    def get_distributed_flag(self):
        """Return distributed flag set by Neutron.

        The method returns True by default if the flag is not set in Neutron.
        """
        nb_global_ext_ids = self.db_get(
            'NB_Global', '.', 'external_ids').execute(check_error=True)
        try:
            distributed = nb_global_ext_ids[constants.OVN_FIP_DISTRIBUTED]
        except KeyError:
            LOG.warning(
                "Agent did not find %s configuration in the OVN Northbound "
                "NB_Global table. This option determines if the traffic is "
                "centralized or distributed. The  agent default to "
                "distributed traffic but be aware Neutron by  default works "
                "in centralized manner. Please make sure Neutron has "
                "the enable_distributed_floating_ip config option set "
                "to True." % constants.OVN_FIP_DISTRIBUTED)
            distributed = "True"
        return True if distributed == "True" else False

    def get_nats_by_lrp(self, lrp):
        return self.db_find_rows(
            'NAT',
            ('gateway_port', '=', lrp.uuid),
            ('type', '=', constants.OVN_DNAT_AND_SNAT)
        ).execute(check_error=True)


class OvsdbSbOvnIdl(sb_impl_idl.OvnSbApiIdlImpl, Backend):
    def __init__(self, connection):
        super(OvsdbSbOvnIdl, self).__init__(connection)
        self.idl._session.reconnect.set_probe_interval(60000)

    def get_port_by_name(self, port):
        cmd = self.db_find_rows('Port_Binding', ('logical_port', '=', port))
        port_info = cmd.execute(check_error=True)
        return port_info[0] if port_info else []

    def get_ports_on_datapath(self, datapath, port_type=None):
        if port_type:
            cmd = self.db_find_rows('Port_Binding',
                                    ('datapath', '=', datapath),
                                    ('type', '=', port_type))
        else:
            cmd = self.db_find_rows('Port_Binding',
                                    ('datapath', '=', datapath))
        try:
            return cmd.execute(check_error=True)
        except ValueError:
            # Datapath has been removed.
            raise exceptions.DatapathNotFound(datapath=datapath)

    def get_ports_by_type(self, port_type):
        cmd = self.db_find_rows('Port_Binding',
                                ('type', '=', port_type))
        return cmd.execute(check_error=True)

    def is_provider_network(self, datapath):
        try:
            cmd = self.db_find_rows('Port_Binding',
                                    ('datapath', '=', datapath),
                                    ('type', '=',
                                     constants.OVN_LOCALNET_VIF_PORT_TYPE))
            return bool(cmd.execute(check_error=True))
        except ValueError:
            # Datapath has been removed.
            raise exceptions.DatapathNotFound(datapath=datapath)

    def get_localnet_for_datapath(self, datapath):
        try:
            cmd = self.db_find_rows('Port_Binding',
                                    ('datapath', '=', datapath),
                                    ('type', '=',
                                     constants.OVN_LOCALNET_VIF_PORT_TYPE))
            localnet_info = cmd.execute(check_error=True)
            return localnet_info[0].logical_port if localnet_info else []
        except ValueError:
            # Datapath has been removed.
            raise exceptions.DatapathNotFound(datapath=datapath)

    def get_fip_associated(self, port):
        cmd = self.db_find_rows(
            'Port_Binding', ('type', '=', constants.OVN_PATCH_VIF_PORT_TYPE))
        for row in cmd.execute(check_error=True):
            for fip in row.nat_addresses:
                if port in fip:
                    return fip.split(" ")[1], row.datapath
        return None, None

    def is_port_on_chassis(self, port_name, chassis):
        port_info = self.get_port_by_name(port_name)
        try:
            return (port_info and
                    port_info.chassis[0].name == chassis)
        except IndexError:
            pass
        return False

    def is_port_without_chassis(self, port_name):
        port_info = self.get_port_by_name(port_name)
        return (port_info and not port_info.chassis)

    def is_port_deleted(self, port_name):
        return False if self.get_port_by_name(port_name) else True

    def get_ports_on_chassis(self, chassis):
        rows = self.db_list_rows('Port_Binding').execute(check_error=True)
        return [r for r in rows if r.chassis and r.chassis[0].name == chassis]

    def get_cr_lrp_ports(self):
        return self.db_find_rows(
            "Port_Binding",
            ("type", "=", constants.OVN_CHASSISREDIRECT_VIF_PORT_TYPE),
        ).execute(check_error=True)

    def get_cr_lrp_ports_on_chassis(self, chassis):
        return [
            r.logical_port
            for r in self.get_cr_lrp_ports()
            if r.chassis and r.chassis[0].name == chassis
        ]

    def get_cr_lrp_nat_addresses_info(self, cr_lrp_port_name, chassis, sb_idl):
        # NOTE: Assuming logical_port format is "cr-lrp-XXXX"
        patch_port_name = cr_lrp_port_name.split("cr-lrp-")[1]
        patch_port_row = self.get_port_by_name(patch_port_name)
        if not patch_port_row:
            return [], None
        ips = []
        for row in patch_port_row.nat_addresses:
            nat_ips = row.split(" ")[1:-1]
            port = row.split(" ")[-1].split("\"")[1]
            if port and sb_idl and sb_idl.is_port_on_chassis(port, chassis):
                ips.extend(nat_ips)
        return ips, patch_port_row

    def get_provider_datapath_from_cr_lrp(self, cr_lrp):
        if cr_lrp.startswith('cr-lrp'):
            provider_port = cr_lrp.split("cr-lrp-")[1]
            return self.get_port_datapath(provider_port)
        return None

    def get_datapath_from_port_peer(self, port):
        peer_name = port.options['peer']
        return self.get_port_datapath(peer_name)

    def get_network_name_and_tag(self, datapath, bridge_mappings):
        for row in self.get_ports_on_datapath(
                datapath, constants.OVN_LOCALNET_VIF_PORT_TYPE):
            if (row.options and
                    row.options.get('network_name') in bridge_mappings):
                return row.options.get('network_name'), row.tag
        return None, None

    def get_network_vlan_tags(self):
        tags = []
        cmd = self.db_find_rows('Port_Binding', ('type', '=',
                                constants.OVN_LOCALNET_VIF_PORT_TYPE))
        for row in cmd.execute(check_error=True):
            if row.tag:
                tags.append(row.tag[0])
        return tags

    def get_network_vlan_tag_by_network_name(self, network_name):
        tags = []
        cmd = self.db_find_rows('Port_Binding', ('type', '=',
                                constants.OVN_LOCALNET_VIF_PORT_TYPE))
        for row in cmd.execute(check_error=True):
            if (row.tag and row.options and
                    row.options.get('network_name') == network_name):
                tags.append(row.tag[0])
        return tags

    def is_router_gateway_on_chassis(self, datapath, chassis):
        port_info = self.get_ports_on_datapath(
            datapath, constants.OVN_CHASSISREDIRECT_VIF_PORT_TYPE)
        try:
            if port_info and port_info[0].chassis[0].name == chassis:
                return port_info[0].logical_port
        except IndexError:
            return False

    def is_router_gateway_on_any_chassis(self, datapath):
        port_info = self.get_ports_on_datapath(
            datapath, constants.OVN_CHASSISREDIRECT_VIF_PORT_TYPE)
        try:
            if port_info and port_info[0].chassis[0].name:
                return port_info[0]
        except IndexError:
            return False

    def get_lrps_for_datapath(self, datapath):
        lrps = []
        for row in self.get_ports_on_datapath(
                datapath, constants.OVN_PATCH_VIF_PORT_TYPE):
            if row.options:
                lrps.append(row.options['peer'])
        return lrps

    def get_lrp_ports_for_router(self, datapath):
        return self.get_ports_on_datapath(
            datapath, constants.OVN_PATCH_VIF_PORT_TYPE)

    def get_lrp_ports_on_provider(self):
        provider_lrp_ports = []
        lrp_ports = self.get_ports_by_type(constants.OVN_PATCH_VIF_PORT_TYPE)
        for lrp_port in lrp_ports:
            if lrp_port.logical_port.startswith(
                    constants.OVN_LRP_PORT_NAME_PREFIX):
                continue
            if self.is_provider_network(lrp_port.datapath):
                provider_lrp_ports.append(lrp_port)

    def get_port_datapath(self, port_name):
        port_info = self.get_port_by_name(port_name)
        if port_info:
            return port_info.datapath

    def get_ip_from_port_peer(self, port):
        peer_name = port.options['peer']
        peer_port = self.get_port_by_name(peer_name)
        try:
            return peer_port.mac[0].split(' ')[1]
        except AttributeError:
            raise exceptions.PortNotFound(port=peer_name)

    def get_evpn_info_from_port_name(self, port_name):
        if port_name.startswith(constants.OVN_CRLRP_PORT_NAME_PREFIX):
            port_name = port_name.split(
                constants.OVN_CRLRP_PORT_NAME_PREFIX)[1]
        elif port_name.startswith(constants.OVN_LRP_PORT_NAME_PREFIX):
            port_name = port_name.split(constants.OVN_LRP_PORT_NAME_PREFIX)[1]

        port = self.get_port_by_name(port_name)
        return self.get_evpn_info(port)

    def get_evpn_info(self, port):
        try:
            return {'vni': int(
                    port.external_ids[constants.OVN_EVPN_VNI_EXT_ID_KEY]),
                    'bgp_as': int(
                    port.external_ids[constants.OVN_EVPN_AS_EXT_ID_KEY])}
        except (KeyError, ValueError):
            LOG.debug('Either "%s" or "%s" were not found or have an '
                      'invalid value in the port %s '
                      'external_ids %s', constants.OVN_EVPN_VNI_EXT_ID_KEY,
                      constants.OVN_EVPN_AS_EXT_ID_KEY, port.logical_port,
                      port.external_ids)
            return {}

    def get_port_if_local_chassis(self, port_name, chassis):
        port = self.get_port_by_name(port_name)
        if port.chassis[0].name == chassis:
            return port

    def get_virtual_ports_on_datapath_by_chassis(self, datapath, chassis):
        try:
            rows = self.get_ports_on_datapath(
                datapath, port_type=constants.OVN_VIRTUAL_VIF_PORT_TYPE)
        except exceptions.DatapathNotFound:
            return []
        return [r for r in rows if r.chassis and r.chassis[0].name == chassis]

    def get_ovn_lb(self, name):
        cmd = self.db_find_rows('Load_Balancer', ('name', '=', name))
        lb_info = cmd.execute(check_error=True)
        return lb_info[0] if lb_info else []

    def get_provider_ovn_lbs_on_cr_lrp(self, provider_dp, router_dp):
        # return {vip_port: vip_ip, vip_port2: vip_ip2, ...}
        # ovn-sbctl find port_binding type=\"\" chassis=[] mac=[] up=false
        cmd = self.db_find_rows('Port_Binding',
                                ('datapath', '=', provider_dp),
                                ('type', '=', constants.OVN_VM_VIF_PORT_TYPE),
                                ('chassis', '=', []),
                                ('mac', '=', []),
                                ('up', '=', False))
        lbs = {}
        for row in cmd.execute(check_error=True):
            # This is depending on the external-id information added by
            # neutron, regarding the neutron:cidrs
            ip_info = row.external_ids.get(
                constants.OVN_CIDRS_EXT_ID_KEY, "")
            if not ip_info:
                continue
            port_name = row.external_ids.get(
                constants.OVN_PORT_NAME_EXT_ID_KEY)
            if (not port_name or
                    len(port_name) <= len(constants.LB_VIP_PORT_PREFIX)):
                continue
            lb_name = port_name[len(constants.LB_VIP_PORT_PREFIX):]
            lb = self.get_ovn_lb(lb_name)
            if not lb:
                continue
            lb_dps, lr_dps = helpers.get_lb_datapaths(lb)
            if not lb_dps:
                lb_dps = lb.datapaths

            if not lr_dps:
                # assume all the members are connected through the same router
                # so only one datapath needs to be checked
                router_lrps = self.get_lrps_for_datapath(lb_dps[0])
                for lrp in router_lrps:
                    router_lrp_dp = self.get_port_datapath(lrp)
                    if router_lrp_dp == router_dp:
                        lb_ip = ip_info.split(" ")[0].split("/")[0]
                        lbs[lb.name] = lb_ip
                        break
            elif router_dp in lr_dps:
                lb_ip = ip_info.split(" ")[0].split("/")[0]
                lbs[lb.name] = lb_ip

        return lbs

    def get_ovn_vip_port(self, name):
        # ovn-sbctl find port_binding type=\"\" chassis=[] mac=[] up=false
        cmd = self.db_find_rows('Port_Binding',
                                ('type', '=', constants.OVN_VM_VIF_PORT_TYPE),
                                ('chassis', '=', []),
                                ('mac', '=', []),
                                ('up', '=', False))

        for row in cmd.execute(check_error=True):
            port_name = row.external_ids.get(
                constants.OVN_PORT_NAME_EXT_ID_KEY)
            if port_name[len(constants.LB_VIP_PORT_PREFIX):] == name:
                return row

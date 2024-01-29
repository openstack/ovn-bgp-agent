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

import shlex

from oslo_config import cfg
from oslo_log import log as logging
from oslo_privsep import priv_context

from ovn_bgp_agent import constants

LOG = logging.getLogger(__name__)

agent_opts = [
    cfg.IntOpt('reconcile_interval',
               help='Time (seconds) between re-sync actions.',
               default=300),
    cfg.IntOpt('frr_reconcile_interval',
               help='Time (seconds) between re-sync actions to ensure frr '
                    'configuration is correct, in case frr is restart.',
               default=15),
    cfg.BoolOpt('expose_tenant_networks',
                help='Expose VM IPs on tenant networks. '
                     'If this flag is enabled, it takes precedence over '
                     'expose_ipv6_gua_tenant_networks flag and all tenant '
                     'network IPs will be exposed.',
                default=False),
    cfg.StrOpt('advertisement_method_tenant_networks',
               help='The NB driver is capable of advertising the tenant '
                    'networks either per host or per subnet. '
                    'So either per /32 or /128 or per subnet like /24. '
                    'Choose "host" as value for this option to advertise per '
                    'host or choose "subnet" to announce per subnet prefix.',
               default=constants.ADVERTISEMENT_METHOD_HOST,
               choices=[constants.ADVERTISEMENT_METHOD_HOST,
                        constants.ADVERTISEMENT_METHOD_SUBNET]),
    cfg.BoolOpt('require_snat_disabled_for_tenant_networks',
                help='Require SNAT on the router port to be disabled before '
                     'exposing the tenant networks. Otherwise the exposed '
                     'tenant networks will be reachable from the outside, but'
                     'the connections set up from within the tenant vm will '
                     'always be SNAT-ed by the router, thus be the router ip. '
                     'When SNAT is disabled, OVN will do pure routing without '
                     'SNAT',
                default=False),
    cfg.BoolOpt('expose_ipv6_gua_tenant_networks',
                help='Expose only VM IPv6 IPs on tenant networks if they are '
                     'GUA. The expose_tenant_networks parameter takes '
                     'precedence over this one. So if it is set, all the '
                     'tenant network IPs will be exposed and not only the '
                     'IPv6 GUA IPs.',
                default=False),
    cfg.StrOpt('driver',
               help='Driver to be used',
               choices=('ovn_bgp_driver', 'ovn_evpn_driver',
                        'ovn_stretched_l2_bgp_driver', 'nb_ovn_bgp_driver'),
               default='ovn_bgp_driver'),
    cfg.StrOpt('ovsdb_connection',
               default='unix:/usr/local/var/run/openvswitch/db.sock',
               help='The connection string for the native OVSDB backend.\n'
                    'Use tcp:IP:PORT for TCP connection.\n'
                    'Use unix:FILE for unix domain socket connection.'),
    cfg.IntOpt('ovsdb_connection_timeout',
               default=180,
               help='Timeout in seconds for the OVSDB connection transaction'),
    cfg.StrOpt('bgp_AS',
               default='64999',
               help='AS number to be used by the Agent when running in BGP '
                    'mode and configuring the VRF route leaking.'),
    cfg.StrOpt('bgp_router_id',
               default=None,
               help='Router ID to be used by the Agent when running in BGP '
                    'mode and configuring the VRF route leaking.'),
    cfg.IPOpt('evpn_local_ip',
              default=None,
              help='IP address of local EVPN VXLAN (tunnel) endpoint. '
                   'This option can be used instead of the evpn_nic one. '
                   'If none specified, it will take the one from the '
                   'loopback device.'),
    cfg.StrOpt('evpn_nic',
               default=None,
               help='NIC with the IP address to use for the local EVPN '
                    'VXLAN (tunnel) endpoint. This option can be used '
                    'instead of the evpn_local_ip one. If none specified, '
                    'it will take the one from the loopback device.'),
    cfg.PortOpt('evpn_udp_dstport',
                default=4789,
                help='The UDP port used for EVPN VXLAN communication. By '
                     'default 4789 is being used.'),
    cfg.BoolOpt('clear_vrf_routes_on_startup',
                help='If enabled, all routes are removed from the VRF table'
                     '(specified by bgp_vrf_table_id option) at startup.',
                default=False),
    cfg.StrOpt('bgp_nic',
               default='bgp-nic',
               help='The name of the interface used within the VRF '
                    '(bgp_vrf option) to expose the IPs and/or Networks.'),
    cfg.StrOpt('bgp_vrf',
               default='bgp-vrf',
               help='The name of the VRF to be used to expose the IPs '
                    'and/or Networks through BGP.'),
    cfg.IntOpt('bgp_vrf_table_id',
               default=10,
               help='The Routing Table ID that the VRF (bgp_vrf option) '
                    'should use. If it does not exist, this table will be '
                    'created.'),
    cfg.ListOpt('address_scopes',
                default=None,
                help='Allows to filter on the address scope. Only networks'
                     ' with the same address scope on the provider and'
                     ' internal interface are announced.'),
    cfg.StrOpt('exposing_method',
               default='underlay',
               choices=('underlay', 'l2vni', 'vrf', 'dynamic', 'ovn'),
               help='The exposing mechanism to be used. underlay is the '
                    'default and simply expose it on the default/plain '
                    'network.'
                    'With l2vni the l2 is extended over the l3 infrastructure '
                    'and it is exposed on a given VNI (Type-2).'
                    'With vrf the routes are exposed in different VRFs/VNIs '
                    '(Type-5).'
                    'With dynamic, a mix between underlay, l2vni and vrf is '
                    'used, depending on the information annotated on the '
                    'ports. '
                    'Finally, with ovn, instead of using kernel networking a '
                    'dedicated ovn cluster per node is used for the traffic '
                    'redirection'),
]

root_helper_opts = [
    cfg.StrOpt('root_helper', default='sudo',
               help=("Root helper application. "
                     "Use 'sudo ovn-bgp-agent-rootwrap  "
                     "/etc/ovn-bgp-agent/rootwrap.conf' to use the real "
                     "root filter facility. Change to 'sudo' to skip the "
                     "filtering and just run the command directly.")),
    cfg.BoolOpt('use_helper_for_ns_read',
                default=True,
                help=("Use the root helper when listing the namespaces on a "
                      "system. This may not be required depending on the "
                      "security configuration. If the root helper is "
                      "not required, set this to False for a performance "
                      "improvement.")),
    # We can't just use root_helper=sudo ovn-bgp-agent-rootwrap-daemon $cfg
    # because it isn't appropriate for long-lived processes spawned with
    # create_process. Having a bool use_rootwrap_daemon option precludes
    # specifying the rootwrap daemon command, which may be necessary for Xen?
    cfg.StrOpt('root_helper_daemon',
               help=("""
Root helper daemon application to use when possible.

Use 'sudo ovn-bgp-agent-rootwrap-daemon /etc/ovn-bgp-agent/rootwrap.conf'
to run rootwrap in "daemon mode" which has been reported to improve
performance at scale. For more information on running rootwrap in
"daemon mode", see:

https://docs.openstack.org/oslo.rootwrap/latest/user/usage.html#daemon-mode
""")),
]

ovn_opts = [
    cfg.StrOpt('ovn_sb_private_key',
               default='/etc/pki/tls/private/ovn_bgp_agent.key',
               deprecated_group='DEFAULT',
               help='The PEM file with private key for SSL connection to '
                    'OVN-SB-DB'),
    cfg.StrOpt('ovn_sb_certificate',
               default='/etc/pki/tls/certs/ovn_bgp_agent.crt',
               deprecated_group='DEFAULT',
               help='The PEM file with certificate that certifies the '
                    'private key specified in ovn_sb_private_key'),
    cfg.StrOpt('ovn_sb_ca_cert',
               default='/etc/ipa/ca.crt',
               deprecated_group='DEFAULT',
               help='The PEM file with CA certificate that OVN should use to'
                    ' verify certificates presented to it by SSL peers'),
    cfg.StrOpt('ovn_sb_connection',
               default='',
               deprecated_group='DEFAULT',
               help='The connection string for the OVN_Southbound OVSDB.\n'
                    'Use tcp:IP:PORT for TCP connection.\n'
                    'Use unix:FILE for unix domain socket connection.'),
    cfg.StrOpt('ovn_nb_private_key',
               default='/etc/pki/tls/private/ovn_bgp_agent.key',
               deprecated_group='DEFAULT',
               help='The PEM file with private key for SSL connection to '
                    'OVN-NB-DB'),
    cfg.StrOpt('ovn_nb_certificate',
               default='/etc/pki/tls/certs/ovn_bgp_agent.crt',
               deprecated_group='DEFAULT',
               help='The PEM file with certificate that certifies the '
                    'private key specified in ovn_nb_private_key'),
    cfg.StrOpt('ovn_nb_ca_cert',
               default='/etc/ipa/ca.crt',
               deprecated_group='DEFAULT',
               help='The PEM file with CA certificate that OVN should use to'
                    ' verify certificates presented to it by SSL peers'),
    cfg.StrOpt('ovn_nb_connection',
               default='',
               deprecated_group='DEFAULT',
               help='The connection string for the OVN_Northbound OVSDB.\n'
                    'Use tcp:IP:PORT for TCP connection.\n'
                    'Use unix:FILE for unix domain socket connection.'),
]

local_ovn_cluster_opts = [
    cfg.StrOpt('ovn_nb_connection',
               default='unix:/var/run/ovn/ovnnb_db.sock',
               help='The connection string for the OVN_Northbound OVSDB.\n'
                    'Use tcp:IP:PORT for TCP connection.\n'
                    'Use unix:FILE for unix domain socket connection.'),
    cfg.ListOpt('external_nics',
                default=[],
                help='List of NICS that the local OVN cluster needs to be '
                     'connected to for the external connectivity.'),
    cfg.ListOpt('peer_ips',
                default=[],
                help='List of peer IPs used for redirecting the outgoing '
                     'traffic (ECMP supported).'),
    cfg.ListOpt('provider_networks_pool_prefixes',
                default=['192.168.0.0/16'],
                help='List of prefixes for provider networks'),
]

CONF = cfg.CONF
EXTRA_LOG_LEVEL_DEFAULTS = [
    'oslo.privsep.daemon=INFO'
]

logging.register_options(CONF)


def register_opts():
    CONF.register_opts(agent_opts)
    CONF.register_opts(root_helper_opts, "agent")
    CONF.register_opts(ovn_opts, "ovn")
    CONF.register_opts(local_ovn_cluster_opts, "local_ovn_cluster")


def init(args, **kwargs):
    CONF(args=args, project='bgp-agent', **kwargs)


def setup_logging():
    logging.set_defaults(default_log_levels=logging.get_default_log_levels() +
                         EXTRA_LOG_LEVEL_DEFAULTS)
    logging.setup(CONF, 'bgp-agent')
    LOG.info("Logging enabled!")


def get_root_helper(conf):
    return conf.agent.root_helper


def setup_privsep():
    priv_context.init(root_helper=shlex.split(get_root_helper(cfg.CONF)))


def list_opts():
    return [
        ("DEFAULT", agent_opts),
        ("agent", root_helper_opts),
        ("ovn", ovn_opts),
        ("local_ovn_cluster", local_ovn_cluster_opts),
    ]

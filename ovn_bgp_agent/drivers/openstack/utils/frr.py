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

import tempfile

from jinja2 import Template
from oslo_config import cfg
from oslo_log import log as logging
from oslo_serialization import jsonutils

from ovn_bgp_agent import constants
import ovn_bgp_agent.privileged.vtysh

CONF = cfg.CONF

LOG = logging.getLogger(__name__)

DEFAULT_REDISTRIBUTE = {'connected'}

CONFIGURE_ND_TEMPLATE = '''
interface {{ intf }}
{% if is_dhcpv6 %}
 ipv6 nd managed-config-flag
{% endif %}
{% for server in dns_servers %}
 ipv6 nd rdnss {{ server }}
{% endfor %}
 ipv6 nd prefix {{ prefix }}
 no ipv6 nd suppress-ra
exit
'''

ADD_VRF_TEMPLATE = '''
vrf {{ vrf_name }}
  vni {{ vni }}
exit-vrf

router bgp {{ bgp_as }} vrf {{ vrf_name }}
  address-family ipv4 unicast
{% for redist in redistribute %}
    redistribute {{ redist }}
{% endfor %}
  exit-address-family
  address-family ipv6 unicast
{% for redist in redistribute %}
    redistribute {{ redist }}
{% endfor %}
  exit-address-family
  address-family l2vpn evpn
    advertise ipv4 unicast
    advertise ipv6 unicast
{% if route_distinguishers|length > 0 %}
    rd {{ route_distinguishers[0] }}
{% else %}
    rd {{ local_ip }}:{{ vni }}
{% endif %}
{% for route_target in route_targets %}
    route-target import {{ route_target }}
    route-target export {{ route_target }}
{% endfor %}
{% for route_target in export_targets %}
    route-target export {{ route_target }}
{% endfor %}
{% for route_target in import_targets %}
    route-target import {{ route_target }}
{% endfor %}
  exit-address-family

'''

DEL_VRF_TEMPLATE = '''
no vrf {{ vrf_name }}
no interface veth-{{ vrf_name }}
no router bgp {{ bgp_as }} vrf {{ vrf_name }}

'''

LEAK_VRF_TEMPLATE = '''
router bgp {{ bgp_as }}
  address-family ipv4 unicast
    import vrf {{ vrf_name }}
  exit-address-family

  address-family ipv6 unicast
    import vrf {{ vrf_name }}
  exit-address-family

router bgp {{ bgp_as }} vrf {{ vrf_name }}
  bgp router-id {{ bgp_router_id }}
  address-family ipv4 unicast
{% for redist in redistribute %}
    redistribute {{ redist }}
{% endfor %}
  exit-address-family

  address-family ipv6 unicast
{% for redist in redistribute %}
    redistribute {{ redist }}
{% endfor %}
  exit-address-family

'''


def _get_router_id():
    output = ovn_bgp_agent.privileged.vtysh.run_vtysh_command(
        command='show ip bgp summary json')
    return jsonutils.loads(output).get('ipv4Unicast', {}).get('routerId')


def _run_vtysh_config_with_tempfile(vrf_config):
    try:
        f = tempfile.NamedTemporaryFile(mode='w')
        f.write(vrf_config)
        f.flush()
    except (IOError, OSError) as e:
        LOG.error('Failed to create the VRF configuration '
                  'file. Error: %s', e)
        if f is not None:
            f.close()
        raise

    try:
        ovn_bgp_agent.privileged.vtysh.run_vtysh_config(f.name)
    finally:
        if f is not None:
            f.close()


def set_default_redistribute(redist_opts):
    if not isinstance(redist_opts, set):
        redist_opts = set(redist_opts)

    if redist_opts == DEFAULT_REDISTRIBUTE:
        # no update required.
        return

    DEFAULT_REDISTRIBUTE.clear()
    DEFAULT_REDISTRIBUTE.update(redist_opts)


def nd_reconfigure(interface, prefix, opts):
    LOG.info('FRR IPv6 ND reconfiguration (intf %s, prefix %s)', interface,
             prefix)
    nd_template = Template(CONFIGURE_ND_TEMPLATE)

    # Need to define what setting is for SLAAC
    if (not opts.get('dhcpv6_stateless', False) or
            opts.get('dhcpv6_stateless', '') not in ('true', True)):
        prefix += ' no-autoconfig'

    # Parse dns servers from dhcp options.
    dns_servers = []
    if opts.get('dns_server'):
        dns_servers = [s.strip() for s in opts['dns_server'][1:-1].split(',')]

    is_dhcpv6 = True  # Need a better way to define this one.

    nd_config = nd_template.render(
        intf=interface,
        prefix=prefix,
        dns_servers=dns_servers,
        is_dhcpv6=is_dhcpv6,
    )

    _run_vtysh_config_with_tempfile(nd_config)


def vrf_leak(vrf, bgp_as, bgp_router_id=None, template=LEAK_VRF_TEMPLATE):
    LOG.info("Add VRF leak for VRF %s on router bgp %s", vrf, bgp_as)
    if not bgp_router_id:
        bgp_router_id = _get_router_id()
        if not bgp_router_id:
            LOG.error("Unknown router-id, needed for route leaking")
            return

    vrf_template = Template(template)
    vrf_config = vrf_template.render(vrf_name=vrf, bgp_as=bgp_as,
                                     redistribute=DEFAULT_REDISTRIBUTE,
                                     bgp_router_id=bgp_router_id)
    _run_vtysh_config_with_tempfile(vrf_config)


def vrf_reconfigure(evpn_info, action):
    LOG.info("FRR reconfiguration (action = %s) for evpn: %s",
             action, evpn_info)

    # If we have more actions, we can define them in this list.
    vrf_templates = {
        'add-vrf': ADD_VRF_TEMPLATE,
        'del-vrf': DEL_VRF_TEMPLATE,
    }
    if action not in vrf_templates:
        LOG.error("Unknown FRR reconfiguration action: %s", action)
        return

    # Set default opts, so all params are available for the templates
    # Then update them with evpn_info
    opts = dict(route_targets=[], route_distinguishers=[], export_targets=[],
                import_targets=[], local_ip=CONF.evpn_local_ip,
                redistribute=DEFAULT_REDISTRIBUTE,
                bgp_as=CONF.bgp_AS, vrf_name='', vni=0)
    opts.update(evpn_info)

    if not opts['vrf_name']:
        opts['vrf_name'] = "{}{}".format(constants.OVN_EVPN_VRF_PREFIX,
                                         evpn_info['vni'])

    vrf_template = Template(vrf_templates.get(action))
    vrf_config = vrf_template.render(**opts)

    _run_vtysh_config_with_tempfile(vrf_config)

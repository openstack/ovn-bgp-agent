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

import json
import tempfile

from jinja2 import Template
from oslo_log import log as logging

from ovn_bgp_agent import constants
import ovn_bgp_agent.privileged.vtysh

LOG = logging.getLogger(__name__)

DEFAULT_REDISTRIBUTE = {'connected'}

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
  exit-address-family

'''

DEL_VRF_TEMPLATE = '''
no vrf {{ vrf_name }}
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
    return json.loads(output).get('ipv4Unicast', {}).get('routerId')


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
    if action == "add-vrf":
        vrf_template = Template(ADD_VRF_TEMPLATE)
        vrf_config = vrf_template.render(
            vrf_name="{}{}".format(constants.OVN_EVPN_VRF_PREFIX,
                                   evpn_info['vni']),
            bgp_as=evpn_info['bgp_as'],
            redistribute=DEFAULT_REDISTRIBUTE,
            vni=evpn_info['vni'])
    elif action == "del-vrf":
        vrf_template = Template(DEL_VRF_TEMPLATE)
        vrf_config = vrf_template.render(
            vrf_name="{}{}".format(constants.OVN_EVPN_VRF_PREFIX,
                                   evpn_info['vni']),
            bgp_as=evpn_info['bgp_as'])
    else:
        LOG.error("Unknown FRR reconfiguration action: %s", action)
        return
    _run_vtysh_config_with_tempfile(vrf_config)

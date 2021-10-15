#!/bin/bash
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

# Save trace setting
_XTRACE_OVN_BGP_AGENT_PLUGIN=$(set +o | grep xtrace)
set +o xtrace
source $DEST/ovn-bgp-agent/devstack/lib/ovn-bgp-agent

# Main loop
if is_service_enabled q-svc ovn-controller; then
    # Stack
    if [[ "$1" == "stack" && "$2" == "install" ]]; then
        install_frr
        configure_frr
        init_frr
        install_ovn_bgp_agent
        configure_ovn_bgp_agent
        init_ovn_bgp_agent
    elif [[ "$1" == "stack" && "$2" == "extra" ]]; then
        start_ovn_bgp_agent
        start_frr
    fi

    # Unstack
    if [[ "$1" == "unstack" ]]; then
        stop_ovn_bgp_agent
        stop_frr
    fi

    # Clean
    if [[ "$1" == "clean" ]]; then
        cleanup_ovn_bgp_agent
        cleanup_frr
    fi
fi

# Restore xtrace
$_XTRACE_OVN_BGP_AGENT_PLUGIN

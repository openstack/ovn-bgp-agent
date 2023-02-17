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

OVN_VIF_PORT_TYPES = ("", "chassisredirect", "virtual")

OVN_VIRTUAL_VIF_PORT_TYPE = "virtual"
OVN_VM_VIF_PORT_TYPE = ""
OVN_PATCH_VIF_PORT_TYPE = "patch"
OVN_CHASSISREDIRECT_VIF_PORT_TYPE = "chassisredirect"
OVN_LOCALNET_VIF_PORT_TYPE = "localnet"

OVN_CIDRS_EXT_ID_KEY = 'neutron:cidrs'
OVN_PORT_NAME_EXT_ID_KEY = 'neutron:port_name'
LB_VIP_PORT_PREFIX = "ovn-lb-vip-"

OVS_RULE_COOKIE = "999"
OVS_VRF_RULE_COOKIE = "998"

FRR_SOCKET_PATH = "/run/frr/"

IP_VERSION_6 = 6
IP_VERSION_4 = 4

BGP_MODE = 'BGP'
EVPN_MODE = 'EVPN'

OVN_EVPN_VNI_EXT_ID_KEY = 'neutron_bgpvpn:vni'
OVN_EVPN_AS_EXT_ID_KEY = 'neutron_bgpvpn:as'
OVN_EVPN_VRF_PREFIX = "vrf-"
OVN_EVPN_BRIDGE_PREFIX = "br-"
OVN_EVPN_VXLAN_PREFIX = "vxlan-"
OVN_EVPN_VLAN_PREFIX = "vlan-"
OVN_EVPN_LO_PREFIX = "lo-"
OVN_EVPN_VETH_VRF_PREFIX = "veth-vrf-"
OVN_EVPN_VETH_OVS_PREFIX = "veth-ovs-"
OVN_INTEGRATION_BRIDGE = 'br-int'
OVN_LRP_PORT_NAME_PREFIX = 'lrp-'
OVN_CRLRP_PORT_NAME_PREFIX = 'cr-lrp-'

OVS_PATCH_PROVNET_PORT_PREFIX = 'patch-provnet-'

LINK_UP = "up"
LINK_DOWN = "down"

SUBNET_POOL_ADDR_SCOPE4 = "neutron:subnet_pool_addr_scope4"
SUBNET_POOL_ADDR_SCOPE6 = "neutron:subnet_pool_addr_scope6"

EXPOSE = "expose"
WITHDRAW = "withdraw"

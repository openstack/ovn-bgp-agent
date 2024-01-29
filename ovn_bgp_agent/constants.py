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

import socket


OVN_VIF_PORT_TYPES = ("", "chassisredirect", "virtual")

OVN_VIRTUAL_VIF_PORT_TYPE = "virtual"
OVN_VM_VIF_PORT_TYPE = ""
OVN_PATCH_VIF_PORT_TYPE = "patch"
OVN_ROUTER_PORT_TYPE = "router"
OVN_CHASSISREDIRECT_VIF_PORT_TYPE = "chassisredirect"
OVN_LOCALNET_VIF_PORT_TYPE = "localnet"
OVN_SNAT = "snat"
OVN_DNAT_AND_SNAT = "dnat_and_snat"
OVN_CR_LRP_PORT_TYPE = 'crlrp'
OVN_ROUTER_INTERFACE = 'network:router_interface'

OVN_CIDRS_EXT_ID_KEY = 'neutron:cidrs'
OVN_PORT_NAME_EXT_ID_KEY = 'neutron:port_name'
OVN_LS_NAME_EXT_ID_KEY = 'neutron:network_name'
OVN_LR_NAME_EXT_ID_KEY = 'neutron:router_name'
OVN_DEVICE_ID_EXT_ID_KEY = 'neutron:device_id'
OVN_DEVICE_OWNER_EXT_ID_KEY = 'neutron:device_owner'
OVN_FIP_EXT_ID_KEY = 'neutron:port_fip'
OVN_FIP_NET_EXT_ID_KEY = 'neutron:fip_network_id'
LB_VIP_PORT_PREFIX = "ovn-lb-vip-"
OVN_LB_PF_NAME_PREFIX = "pf-floatingip-"
OVN_LB_VIP_IP_EXT_ID_KEY = 'neutron:vip'
OVN_LB_VIP_FIP_EXT_ID_KEY = 'neutron:vip_fip'
OVN_LB_VIP_PORT_EXT_ID_KEY = 'neutron:vip_port_id'
OVN_LB_LR_REF_EXT_ID_KEY = 'lr_ref'

OVN_LB_EXT_ID_ROUTER_KEY = [
    OVN_LB_LR_REF_EXT_ID_KEY,
    OVN_LR_NAME_EXT_ID_KEY
]

OVS_RULE_COOKIE = "999"
OVS_VRF_RULE_COOKIE = "998"

FRR_SOCKET_PATH = "/run/frr/"

IP_VERSION_6 = 6
IP_VERSION_4 = 4

ARP_IPV4_PREFIX = "169.254."
NDP_IPV6_PREFIX = "fd53:d91e:400:7f17::"

IPV4_OCTET_RANGE = 256

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

OVN_REQUESTED_CHASSIS = "requested-chassis"
OVN_STATUS_CHASSIS = "hosting-chassis"
OVN_HOST_ID_EXT_ID_KEY = "neutron:host_id"
OVN_CHASSIS_AT_OPTIONS = "options"
OVN_CHASSIS_AT_EXT_IDS = "external-ids"

# Exposing method names
EXPOSE_METHOD_UNDERLAY = 'underlay'
EXPOSE_METHOD_L2VNI = 'l2vni'
EXPOSE_METHOD_VRF = 'vrf'
EXPOSE_METHOD_OVN = 'ovn'
EXPOSE_METHOD_DYNAMIC = 'dynamic'

# Advertisement method names for tenant networks
ADVERTISEMENT_METHOD_HOST = 'host'
ADVERTISEMENT_METHOD_SUBNET = 'subnet'

# OVN Cluster related constants
OVN_CLUSTER_BRIDGE = 'bgp'
OVN_CLUSTER_ROUTER = 'bgp-router'
OVN_CLUSTER_ROUTER_INTERNAL_MAC = '40:44:00:00:00:06'

# FIXME(ltomasbo): This can be removed once ovsdbapp version is >=1.13.0
POLICY_ACTION_REROUTE = 'reroute'
POLICY_ACTION_TYPES = (POLICY_ACTION_REROUTE)
LR_POLICY_PRIORITY_MAX = 32767

ROUTE_DISCARD = 'discard'

# Family constants
AF_INET = socket.AF_INET
AF_INET6 = socket.AF_INET6

# Path to file containing routing tables
ROUTING_TABLES_FILE = '/etc/iproute2/rt_tables'
ROUTING_TABLE_MIN = 1
ROUTING_TABLE_MAX = 252

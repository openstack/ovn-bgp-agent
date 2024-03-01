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


class OVNBGPAgentException(Exception):
    """Base OVN BGP Agebt Exception.

    To correctly use this class, inherit from it and define
    a 'message' property. That message will get printf'd
    with the keyword arguments provided to the constructor.
    """

    message = _("An unknown exception occurred.")

    def __init__(self, **kwargs):
        super().__init__(self.message % kwargs)
        self.msg = self.message % kwargs

    def __str__(self):
        return self.msg


class InvalidPortIP(OVNBGPAgentException):
    """OVN Port has Invalid IP.

    :param ip: The (wrong) IP of the port
    """

    message = _("OVN port with invalid IP: %(ip)s.")


class PortNotFound(OVNBGPAgentException):
    """OVN Port not found.

    :param port: The port name or UUID.
    """

    message = _("OVN port was not found: %(port)s.")


class DatapathNotFound(OVNBGPAgentException):
    """Datapath not found

    :param datapath: The datapath UUID
    """

    message = _("Datapath was not found: %(datapath)s.")


class PatchPortNotFound(OVNBGPAgentException):
    """Patch Port not found

    :param localnet: The localnet name
    """

    message = _("Patch port not found for localnet: %(localnet)s.")


class ExposeDeniedForAddressScope(OVNBGPAgentException):
    """Address Scope test failed

    :param addresses: The ip address used for checking address_scope
    :param address_scopes: The address scopes
    :param configured_scopes: The allowed address scopes in configuration
    """

    message = _("Exposing addresses %(addresses)s with address scopes "
                "%(address_scopes)s was denied, required scopes: "
                "%(configured_scopes)s")


class WireFailure(OVNBGPAgentException):
    """Wire port failed

    :param cidr: The cidr that failed to wire.
    :param message: The failure message
    """

    message = _("Failure with wiring for CIDR %(cidr)s: %(message)s")


class UnwireFailure(OVNBGPAgentException):
    """Unwire port failed

    :param cidr: The cidr that failed to wire.
    :param message: The failure message
    """

    message = _("Failure with removing wiring for CIDR %(cidr)s: %(message)s")


class IpAddressAlreadyExists(RuntimeError):
    message = _("IP address %(ip)s already configured on %(device)s.")

    def __init__(self, message=None, ip=None, device=None):
        message = message or self.message % {'ip': ip, 'device': device}
        super(IpAddressAlreadyExists, self).__init__(message)


class NetworkInterfaceNotFound(RuntimeError):
    message = _("Network interface %(device)s not found")

    def __init__(self, message=None, device=None):
        message = message or self.message % {'device': device}
        super(NetworkInterfaceNotFound, self).__init__(message)


class InterfaceAlreadyExists(RuntimeError):
    message = _("Interface %(device)s already exists.")

    def __init__(self, message=None, device=None):
        message = message or self.message % {'device': device}
        super(InterfaceAlreadyExists, self).__init__(message)


class InterfaceOperationNotSupported(RuntimeError):
    message = _("Operation not supported on interface %(device)s.")

    def __init__(self, message=None, device=None):
        message = message or self.message % {'device': device}
        super(InterfaceOperationNotSupported, self).__init__(message)


class InvalidArgument(RuntimeError):
    message = _("Invalid parameter/value used on interface %(device)s.")

    def __init__(self, message=None, device=None):
        message = message or self.message % {'device': device}
        super(InvalidArgument, self).__init__(message)

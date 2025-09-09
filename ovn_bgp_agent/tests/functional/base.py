#    Derived from: neutron/tests/functional/base.py
#                  neutron/tests/base.py
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

import abc
import functools
import inspect
import os
import shutil
import sys
from unittest import mock

import eventlet.timeout
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import fileutils
from oslo_utils import uuidutils
from oslotest import base
from ovsdbapp.backend.ovs_idl import connection
from ovsdbapp.tests.functional import base as ovsdbapp_base

import ovn_bgp_agent
from ovn_bgp_agent import config
from ovn_bgp_agent.drivers.openstack import nb_ovn_bgp_driver
from ovn_bgp_agent.drivers.openstack.utils import ovn
from ovn_bgp_agent.tests.functional import fixtures

CONF = cfg.CONF
LOG = logging.getLogger(__name__)
PRIVSEP_HELPER_CMD = 'privsep-helper'


def _get_test_log_path():
    return os.environ.get('OS_LOG_PATH', '/tmp')


# This is the directory from which infra fetches log files for functional tests
DEFAULT_LOG_DIR = os.path.join(_get_test_log_path(), 'functional-logs')


# NOTE(ralonsoh): this timeout catch method needs to be reimplemented without
# using eventlet.
class _CatchTimeoutMetaclass(abc.ABCMeta):
    def __init__(cls, name, bases, dct):
        super(_CatchTimeoutMetaclass, cls).__init__(name, bases, dct)
        for name, method in inspect.getmembers(
                # NOTE(ihrachys): we should use isroutine because it will catch
                # both unbound methods (python2) and functions (python3)
                cls, predicate=inspect.isroutine):
            if name.startswith('test_'):
                setattr(cls, name, cls._catch_timeout(method))

    @staticmethod
    def _catch_timeout(f):
        @functools.wraps(f)
        def func(self, *args, **kwargs):
            try:
                return f(self, *args, **kwargs)
            except eventlet.Timeout as e:
                self.fail('Execution of this test timed out: %s' % e)
        return func


def setup_logging(component_name):
    """Sets up the logging options for a log with supplied name."""
    logging.setup(cfg.CONF, component_name)
    LOG.info("Logging enabled!")
    LOG.info("%(prog)s version %(version)s",
             {'prog': sys.argv[0], 'version': ovn_bgp_agent.__version__})
    LOG.debug("command line: %s", " ".join(sys.argv))


def sanitize_log_path(path):
    """Sanitize the string so that its log path is shell friendly"""
    return path.replace(' ', '-').replace('(', '_').replace(')', '_')


def get_privsep_helper_executable_path():
    """Return privsep-helper path based on the used venv."""
    privsep_path = shutil.which(PRIVSEP_HELPER_CMD)
    if privsep_path is None:
        raise RuntimeError("%s executable not found" % PRIVSEP_HELPER_CMD)
    return privsep_path


def configure_functional_test(id_):
    def flags(**kw):
        """Override some configuration values.

        The keyword arguments are the names of configuration options to
        override and their values.

        If a group argument is supplied, the overrides are applied to
        the specified configuration option group.

        All overrides are automatically cleared at the end of the current
        test by the fixtures cleanup process.
        """
        group = kw.pop('group', None)
        for k, v in kw.items():
            CONF.set_override(k, v, group)

    COMPONENT_NAME = 'ovn_bgp_agent'
    PRIVILEGED_GROUP = 'privsep'

    logging.register_options(CONF)
    setup_logging(COMPONENT_NAME)
    fileutils.ensure_tree(DEFAULT_LOG_DIR, mode=0o755)
    log_file = sanitize_log_path(
        os.path.join(DEFAULT_LOG_DIR, "%s.txt" % id_))

    config.register_opts()
    flags(log_file=log_file)
    config.setup_privsep()
    privsep_helper = get_privsep_helper_executable_path()
    flags(
        helper_command=' '.join(['sudo', '-E', privsep_helper]),
        group=PRIVILEGED_GROUP)


# Test worker cannot survive eventlet's Timeout exception, which effectively
# kills the whole worker, with all test cases scheduled to it. This metaclass
# makes all test cases convert Timeout exceptions into unittest friendly
# failure mode (self.fail).
class BaseFunctionalTestCase(base.BaseTestCase,
                             metaclass=_CatchTimeoutMetaclass):
    """Base class for functional tests."""

    def setUp(self):
        super(BaseFunctionalTestCase, self).setUp()
        configure_functional_test(self.id())


class BaseFunctionalNorthboundTestCase(ovsdbapp_base.FunctionalTestCase):
    schemas = ['OVN_Northbound', 'Open_vSwitch']
    COMPONENT_NAME = 'ovn_bgp_agent'
    PRIVILEGED_GROUP = 'privsep'

    def setUp(self):
        super().setUp()
        self.nb_api = self.useFixture(
            fixtures.NbApiFixture(self.connection['OVN_Northbound'])).obj


class BaseFunctionalNBAgentTestCase(BaseFunctionalNorthboundTestCase):
    @classmethod
    def create_connection(cls, schema):
        if schema == 'OVN_Northbound':
            idl = ovn.OvnNbIdl.from_server(cls.schema_map[schema], schema)
            return connection.Connection(idl, timeout=5)
        else:
            return super().create_connection(schema)

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.agent_config = {
            None: {
                'exposing_method': 'vrf',
                'ovsdb_connection': cls.schema_map['Open_vSwitch'],
            },
            'ovn': {
                'ovn_nb_connection': cls.schema_map['OVN_Northbound'],
            },
        }

    def setUp(self):
        super().setUp()
        configure_functional_test(self.id())

        # TODO(jlibosva): Find a way to isolate vrf and frr processes
        self.bgp_utils = mock.patch.object(
            nb_ovn_bgp_driver, 'bgp_utils').start()

        self.ovs_api = self.configure_local_ovs()

        self.set_agent()

        self.agent = nb_ovn_bgp_driver.NBOVNBGPDriver()
        self.agent.start()

    def set_agent(self):
        for group, options in self.__class__.agent_config.items():
            for key, value in options.items():
                CONF.set_override(key, value, group)

        # We do not want to interfere with the syncs
        self.agent_sync = mock.patch.object(
            nb_ovn_bgp_driver.NBOVNBGPDriver, 'sync').start()
        self.agent_frr_sync = mock.patch.object(
            nb_ovn_bgp_driver.NBOVNBGPDriver, 'frr_sync').start()

    def configure_local_ovs(self):
        ovs_api = self.useFixture(
            fixtures.OvsApiFixture(self.connection['Open_vSwitch'])).obj

        system_id = uuidutils.generate_uuid()
        ovs_config_external_ids = {
            'system-id': system_id,
            'hostname': f'func-{system_id}',
            'ovn-nb-remote': self.schema_map['OVN_Northbound'],
        }

        ovs_api.db_set(
            'Open_vSwitch', '.', external_ids=ovs_config_external_ids
        ).execute(check_error=True)

        return ovs_api

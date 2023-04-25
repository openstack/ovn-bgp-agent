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

import sys

from oslo_config import cfg
from oslo_log import log as logging
from oslo_service import loopingcall
from oslo_service import service

from ovn_bgp_agent import config
from ovn_bgp_agent.drivers import driver_api


CONF = cfg.CONF
LOG = logging.getLogger(__name__)


class BGPAgent(service.Service):
    """BGP OVN Agent."""

    def __init__(self):
        super(BGPAgent, self).__init__()
        self.agent_driver = driver_api.AgentDriverBase.get_instance(
            CONF.driver)

    def start(self):
        LOG.info("Service '%s' starting", self.__class__.__name__)
        super(BGPAgent, self).start()
        self.agent_driver.start()

        LOG.info("Service '%s' started", self.__class__.__name__)
        sync_routes = loopingcall.FixedIntervalLoopingCall(self.sync)
        sync_routes.start(interval=CONF.reconcile_interval)
        sync_frr = loopingcall.FixedIntervalLoopingCall(self.frr_sync)
        sync_frr.start(interval=CONF.frr_reconcile_interval)

    def sync(self):
        LOG.info("Running reconciliation loop to ensure routes/rules are "
                 "in place.")
        try:
            self.agent_driver.sync()
        except Exception as e:
            LOG.exception("Unexpected exception while running the sync: %s", e)

    def frr_sync(self):
        LOG.info("Running reconciliation loop to ensure frr configuration is "
                 "in place.")
        try:
            self.agent_driver.frr_sync()
        except Exception as e:
            LOG.exception("Unexpected exception while running the frr sync: "
                          "%s", e)

    def wait(self):
        super(BGPAgent, self).wait()
        LOG.info("Service '%s' stopped", self.__class__.__name__)

    def stop(self, graceful=False):
        LOG.info("Service '%s' stopping", self.__class__.__name__)
        super(BGPAgent, self).stop(graceful)


def start():
    config.register_opts()
    config.init(sys.argv[1:])
    config.setup_logging()
    config.setup_privsep()

    bgp_agent_launcher = service.launch(config.CONF, BGPAgent())
    bgp_agent_launcher.wait()

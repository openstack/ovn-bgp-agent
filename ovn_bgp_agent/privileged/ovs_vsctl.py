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

from oslo_concurrency import processutils
from oslo_log import log as logging

import ovn_bgp_agent.privileged.ovs_vsctl

LOG = logging.getLogger(__name__)


@ovn_bgp_agent.privileged.ovs_vsctl_cmd.entrypoint
def ovs_cmd(command, args, timeout=None):
    full_args = [command]
    if timeout is not None:
        full_args += ['--timeout=%s' % timeout]
    full_args += args
    try:
        return processutils.execute(*full_args)
    except processutils.ProcessExecutionError:
        full_args += ['-O', 'OpenFlow13']
        try:
            return processutils.execute(*full_args)
        except Exception as e:
            LOG.exception("Unable to execute %s %s. Exception: %s",
                          command, full_args, e)
            raise
    except Exception as e:
        LOG.exception("Unable to execute %s %s. Exception: %s", command,
                      full_args, e)
        raise

# Copyright 2024 Red Hat, Inc.
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

import copy

from ovsdbapp.backend.ovs_idl import event

from ovn_bgp_agent import constants
from ovn_bgp_agent.tests.functional import base
from ovn_bgp_agent.tests import utils


class DistributedWaitEvent(event.WaitEvent):
    event_name = 'DistributedWaitEvent'

    def __init__(self, timeout=5):
        table = 'NB_Global'
        events = (self.ROW_UPDATE,)
        super().__init__(events, table, None, timeout=timeout)

    def match_fn(self, event, row, old):
        return row.external_ids != getattr(old, 'external_ids')


class DistributedFlagChangedEventTestCase(
    base.BaseFunctionalNBAgentTestCase):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.agent_config = copy.copy(cls.agent_config)
        cls.agent_config.setdefault(None, {})[
            'advertisement_method_tenant_networks'] = 'subnet'

    def _make_nb_global_event(self):
        nb_global_event = DistributedWaitEvent()
        self.nb_api.ovsdb_connection.idl.notify_handler.watch_event(
            nb_global_event)
        return nb_global_event

    def _wait_for_events_added(self, events):
        def _events_intersect():
            registered_events = set(idl.notify_handler._watched_events)
            intersection = events & registered_events
            return intersection == events

        idl = self.agent.nb_idl.ovsdb_connection.idl

        utils.wait_until_true(
            _events_intersect,
            timeout=5,
            sleep=0.1,
            exception=AssertionError(
                "Events %s still not registered in the agent" % events))

    def _wait_for_events_removed(self, events):
        def _events_disjunctive():
            registered_events = set(idl.notify_handler._watched_events)
            return not bool(events & registered_events)

        idl = self.agent.nb_idl.ovsdb_connection.idl

        utils.wait_until_true(
            _events_disjunctive,
            timeout=5,
            sleep=0.1,
            exception=AssertionError(
                "Events %s still registered in the agent" % events))

    def test_distributed_flag_changed(self):
        distributed = self.nb_api.db_get(
            'NB_Global', '.', 'external_ids').execute(check_error=True).get(
                constants.OVN_FIP_DISTRIBUTED)

        self.assertIsNone(distributed)

        distributed_events = set(self.agent._get_additional_events(
            distributed=True))
        centralized_events = set(self.agent._get_additional_events(
            distributed=False))

        # At start there is no distributed flag but the agent should default to
        # distributed
        self._wait_for_events_added(distributed_events)
        self._wait_for_events_removed(centralized_events)

        nb_global_event = self._make_nb_global_event()
        self.nb_api.db_set('NB_Global', '.', external_ids={
            constants.OVN_FIP_DISTRIBUTED: "False"}).execute(check_error=True)

        self.assertTrue(nb_global_event.wait())

        self._wait_for_events_added(centralized_events)
        self._wait_for_events_removed(distributed_events)

        nb_global_event = self._make_nb_global_event()
        self.nb_api.db_set('NB_Global', '.', external_ids={
            constants.OVN_FIP_DISTRIBUTED: "True"}).execute(check_error=True)

        self.assertTrue(nb_global_event.wait())

        self._wait_for_events_added(distributed_events)
        self._wait_for_events_removed(centralized_events)

        nb_global_event = self._make_nb_global_event()
        self.nb_api.db_set('NB_Global', '.', external_ids={
            constants.OVN_FIP_DISTRIBUTED: "False"}).execute(check_error=True)

        self.assertTrue(nb_global_event.wait())

        self._wait_for_events_added(centralized_events)
        self._wait_for_events_removed(distributed_events)

        nb_global_event = self._make_nb_global_event()
        self.nb_api.db_remove(
            'NB_Global', '.', 'external_ids',
            constants.OVN_FIP_DISTRIBUTED).execute(check_error=True)

        self.assertTrue(nb_global_event.wait())

        self._wait_for_events_added(distributed_events)
        self._wait_for_events_removed(centralized_events)

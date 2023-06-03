# Copyright 2022 Red Hat, Inc.
# All Rights Reserved.
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

import eventlet


class WaitTimeout(Exception):
    """Default exception coming from wait_until_true() function."""


def create_row(**kwargs):
    return type('FakeRow', (object,), kwargs)


def wait_until_true(predicate, timeout=60, sleep=1, exception=None):
    """Wait until callable predicate is evaluated as True

    Imported from ``neutron.common.utils``.

    :param predicate: Callable deciding whether waiting should continue.
    Best practice is to instantiate predicate with functools.partial()
    :param timeout: Timeout in seconds how long should function wait.
    :param sleep: Polling interval for results in seconds.
    :param exception: Exception instance to raise on timeout. If None is passed
                      (default) then WaitTimeout exception is raised.
    """
    try:
        with eventlet.Timeout(timeout):
            while not predicate():
                eventlet.sleep(sleep)
    except eventlet.Timeout:
        if exception is not None:
            # pylint: disable=raising-bad-type
            raise exception
        raise WaitTimeout('Timed out after %d seconds' % timeout)

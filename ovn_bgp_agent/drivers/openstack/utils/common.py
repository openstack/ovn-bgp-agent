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


def get_from_external_ids(row, key):
    try:
        return row.external_ids[key]
    except (AttributeError, KeyError):
        pass


def ip_matches_in_row(row, ip, key):
    """Return True if given ip is in external_ids under given key.

    Return also True if passed ip is None and key is not present.

    Return None if external_ids is not present in row.

    Otherwise return False
    """
    try:
        return ip == row.external_ids.get(key)
    except AttributeError:
        pass

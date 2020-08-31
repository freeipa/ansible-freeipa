#!/usr/bin/env python

# Authors:
#   Sergio Oliveira Campos <seocam@redhat.com>
#
# Copyright (C) 2020 Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import pytest
import functools

from unittest import TestCase

from utils import get_test_playbooks, get_server_host, run_playbook


def prepare_test(test_name, test_path):
    """Decorator for the tests generated automatically from playbooks.

    Injects 2 arguments to the test (`test_path` and `test_name`) and
    name the test method using test name (to ensure test reports are useful).
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            kwargs["test_path"] = test_path
            kwargs["test_name"] = test_name
            return func(*args, **kwargs)

        return wrapper

    decorator.__name__ = test_name
    return decorator


# Dynamically create the TestCase classes with respective
#   test_* methods.
for test_dir_name, playbooks_in_dir in get_test_playbooks().items():
    _tests = {}
    for playbook in playbooks_in_dir:
        test_name = playbook["name"].replace("-", "_")
        test_path = playbook["path"]

        @pytest.mark.skipif(
            not get_server_host(),
            reason="Environment variable IPA_SERVER_HOST must be set",
        )
        @pytest.mark.playbook
        @prepare_test(test_name, test_path)
        def method(self, test_path, test_name):
            run_playbook(test_path)

        _tests[test_name] = method
    globals()[test_dir_name] = type(test_dir_name, tuple([TestCase]), _tests,)

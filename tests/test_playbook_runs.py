#!/usr/bin/env python

import os
import functools
import tempfile

from subprocess import Popen

from unittest import TestCase

import pytest

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


def get_inventory_content():
    ipa_server_host = os.getenv("IPA_SERVER_HOST")
    return "[ipaserver]\n{}".format(ipa_server_host).encode("utf8")


def run_playbook(playbook):
    with tempfile.NamedTemporaryFile() as inventory_file:
        inventory_file.write(get_inventory_content())
        inventory_file.flush()
        cmd = [
            "ansible-playbook",
            "-i",
            inventory_file.name,
            playbook,
        ]
        process = Popen(cmd, cwd=SCRIPT_DIR)
        process.wait()

    return process


def list_test_yaml(dir_path):
    yamls = []
    for yaml_name in os.listdir(dir_path):
        if yaml_name.startswith("test_") and yaml_name.endswith(".yml"):
            yamls.append(
                {
                    "path": os.path.join(dir_path, yaml_name),
                    "name": yaml_name.split(".")[0],
                }
            )
    return yamls


def get_test_groups():
    test_dirs = os.listdir(SCRIPT_DIR)
    groups = {}
    for test_group_dir in test_dirs:
        group_dir_path = os.path.join(SCRIPT_DIR, test_group_dir)
        if not os.path.isdir(group_dir_path):
            continue
        yamls = list_test_yaml(group_dir_path)
        if yamls:
            groups[test_group_dir] = yamls
    return groups


def prepare_test(test_name, test_path):
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            kwargs["test_path"] = test_path
            return func(*args, **kwargs)

        return wrapper

    decorator.__name__ = test_name
    return decorator


# Dynamically create the TestCase classes with respective
#   test_* methods.
for group_name, group_tests in get_test_groups().items():
    _tests = {}
    for test_config in group_tests:
        test_name = test_config["name"].replace("-", "_")
        test_path = test_config["path"]

        @pytest.mark.skipif(
            os.getenv("IPA_SERVER_HOST") is None,
            reason="Environment variable IPA_SERVER_HOST must be set",
        )
        @prepare_test(test_name, test_path)
        def method(self, test_path):
            result = run_playbook(test_path)
            assert result.returncode == 0

        _tests[test_name] = method
    globals()[group_name] = type(group_name, (TestCase,), _tests)

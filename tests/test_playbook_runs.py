#!/usr/bin/env python

import os
import functools
import tempfile

import subprocess

from unittest import TestCase

import pytest

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


def is_docker_env():
    if os.getenv("RUN_TESTS_IN_DOCKER", "0") == "0":
        return False
    return True


def get_ssh_password():
    return os.getenv("IPA_SSH_PASSWORD")


def get_server_host():
    return os.getenv("IPA_SERVER_HOST")


def get_molecule_scenario():
    return get_server_host()


def get_inventory_content():
    ipa_server_host = get_server_host()

    if is_docker_env():
        ipa_server_host += " ansible_connection=docker"

    sshpass = get_ssh_password()
    if sshpass:
        ipa_server_host += " ansible_ssh_pass=%s" % sshpass

    lines = [
        "[ipaserver]",
        ipa_server_host,
        "[ipaserver:vars]",
        "ipaserver_domain=test.local",
        "ipaserver_realm=TEST.LOCAL",
    ]
    return "\n".join(lines).encode("utf8")


def write_logs(result, test_name):
    log_dir = os.path.join(SCRIPT_DIR, "logs")
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)

    # Write stdout log for test
    log_path = os.path.join(log_dir, test_name + ".log")
    with open(log_path, "w") as log_file:
        log_file.write(result.stdout.decode("utf-8"))

    # Write stderr log for test
    error_log_path = os.path.join(log_dir, test_name + "-error.log")
    with open(error_log_path, "w") as log_file:
        log_file.write(result.stderr.decode("utf-8"))


def run_playbook(playbook, test_name):
    with tempfile.NamedTemporaryFile() as inventory_file:
        inventory_file.write(get_inventory_content())
        inventory_file.flush()
        cmd = [
            "ansible-playbook",
            "-i",
            inventory_file.name,
            playbook,
        ]
        process = subprocess.run(
            cmd, cwd=SCRIPT_DIR, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
    write_logs(process, test_name)

    return process


def list_test_yaml(dir_path):
    yamls = []
    for yaml_name in sorted(os.listdir(dir_path)):
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
    for test_group_dir in sorted(test_dirs):
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
            kwargs["test_name"] = test_name
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
            not get_server_host(),
            reason="Environment variable IPA_SERVER_HOST must be set",
        )
        @prepare_test(test_name, test_path)
        def method(self, test_path, test_name):
            result = run_playbook(test_path, test_name)
            status_code_msg = "ansible-playbook return code: {}".format(
                result.returncode
            )
            assert_msg = "\n".join(
                [
                    "",
                    "-" * 30 + " Captured stdout " + "-" * 30,
                    result.stdout.decode("utf8"),
                    "-" * 30 + " Captured stderr " + "-" * 30,
                    result.stderr.decode("utf8"),
                    "-" * 30 + " Playbook Return Code " + "-" * 30,
                    status_code_msg,
                ]
            )
            # Need to get the last bytes of msg otherwise Azure
            #   will cut it out.
            assert result.returncode == 0, assert_msg[-2500:]

        _tests[test_name] = method
    globals()[group_name] = type(group_name, tuple([TestCase]), _tests,)

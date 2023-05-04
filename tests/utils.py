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

import os
import pytest
import re
import subprocess
import tempfile
import testinfra

from unittest import TestCase


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


def get_docker_env():
    docker_env = os.getenv("RUN_TESTS_IN_DOCKER", None)
    if docker_env in ["1", "True", "true", "yes", True]:
        docker_env = "docker"
    return docker_env


def get_ssh_password():
    return os.getenv("IPA_SSH_PASSWORD")


def get_server_host():
    return os.getenv("IPA_SERVER_HOST")


def get_disabled_test(group_name, test_name):
    disabled_modules = [
        disabled.strip()
        for disabled in os.environ.get("IPA_DISABLED_MODULES", "").split(",")
    ]
    disabled_tests = [
        disabled.strip()
        for disabled in os.environ.get("IPA_DISABLED_TESTS", "").split(",")
        if disabled.strip()
    ]

    if not any([disabled_modules, disabled_tests]):
        return False

    return group_name in disabled_modules or test_name in disabled_tests


def get_enabled_test(group_name, test_name):
    enabled_modules = [
        enabled.strip()
        for enabled in os.environ.get("IPA_ENABLED_MODULES", "").split(",")
        if enabled.strip()
    ]
    enabled_tests = [
        enabled.strip()
        for enabled in os.environ.get("IPA_ENABLED_TESTS", "").split(",")
        if enabled.strip()
    ]

    if not any([enabled_modules, enabled_tests]):
        return True

    group_enabled = group_name in enabled_modules
    test_enabled = test_name in enabled_tests

    return group_enabled or test_enabled


def get_inventory_content():
    """Create the content of an inventory file for a test run."""
    ipa_server_host = get_server_host()

    container_engine = get_docker_env()
    if container_engine is not None:
        ipa_server_host += f" ansible_connection={container_engine}"

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


def get_test_name_from_playbook_path(playbook):
    """
    Create a test name based of a playbook path.

    For example:
        Input: /home/johndoe/ansible-freeipa/tests/dnszone/test_dnszone_mod.yml
        Output: dnszone_test_dnszone_mod
    """
    playbook_abspath = os.path.abspath(playbook)
    playbook_rel_to_tests_dir = playbook_abspath.replace(SCRIPT_DIR, "")
    playbook_slug = playbook_rel_to_tests_dir.strip("/").replace("/", "_")
    return os.path.splitext(playbook_slug)[0]


def write_logs(result, test_name):
    """Write logs of a ansible run logs to `test/logs/`."""
    log_dir = os.path.join(SCRIPT_DIR, "logs")
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)

    # Write stdout log for test
    log_path = os.path.join(log_dir, "ansible_" + test_name + ".log")
    with open(log_path, "w") as log_file:
        log_file.write(result.stdout.decode("utf-8"))

    # Write stderr log for test
    error_log_path = os.path.join(log_dir, test_name + "-error.log")
    with open(error_log_path, "w") as log_file:
        log_file.write(result.stderr.decode("utf-8"))


def _run_playbook(playbook):
    """
    Create a inventory using a temporary file and run ansible using it.

    The logs of the run will be placed in `tests/logs/`.
    """
    with tempfile.NamedTemporaryFile() as inventory_file:
        inventory_file.write(get_inventory_content())
        inventory_file.flush()
        cmd_options = ["-i", inventory_file.name]
        verbose = os.environ.get("IPA_VERBOSITY", None)
        if verbose is not None:
            cmd_options.append(verbose)
        cmd = ["ansible-playbook"] + cmd_options + [playbook]
        # pylint: disable=subprocess-run-check
        process = subprocess.run(
            cmd, cwd=SCRIPT_DIR, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
    test_name = get_test_name_from_playbook_path(playbook)
    write_logs(process, test_name)

    return process


def run_playbook(playbook, allow_failures=False):
    """
    Run an Ansible playbook and assert the return code.

    Call ansible (using _run_playbook function) and assert the result of
    the execution.

    In case of failure the tail of the error message will be displayed
    as an assertion message.

    The full log of the execution will be available in the directory
    `tests/logs/`.
    """
    result = _run_playbook(playbook)

    if allow_failures:
        return result

    status_code_msg = "ansible-playbook return code: {0}".format(
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

    return result


def list_test_yaml(dir_path):
    """
    List the test playbooks inside a given directory.

    A test playbook is any file inside the directory which the name starts with
    `test_` and the extension is `.yml`.
    """
    yamls = []
    for root, _dirs, files in os.walk(dir_path):
        for yaml_name in files:
            if yaml_name.startswith("test_") and yaml_name.endswith(".yml"):
                test_yaml_path = os.path.join(root, yaml_name)
                yamls.append(
                    {
                        "path": test_yaml_path,
                        "name": yaml_name.split(".")[0],
                    }
                )
    return yamls


def get_test_playbooks():
    """
    Get playbook tests grouped by first level directory.

    This function visits the first level of directories inside `tests/` and
    look for ansible playbooks on them.

    Returns a dict with the directories found in `tests/` as key and a
    list of test playbook files inside of it.

    A test playbook is any file inside the directory which the name starts with
    `test_` and the extension is `.yml`.
    """
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


def kinit_admin(host, admin="admin", password="SomeADMINpassword"):
    return host.run_test("kinit " + admin + "<<< " + password)


def kdestroy(host):
    return host.run_test("kdestroy -A")


class AnsibleFreeIPATestCase(TestCase):
    def setUp(self):
        container_engine = get_docker_env()
        if container_engine:
            protocol = f"{container_engine}://"
            user = ""
            ssh_identity_file = None
        else:
            protocol = "ssh://"

            password = get_ssh_password() or ""
            if password:
                password = ":" + password

            current_user = os.getenv("USER")
            ansible_user = os.getenv("ANSIBLE_REMOTE_USER", current_user)
            user = ansible_user + password + "@"
            ssh_identity_file = os.getenv("ANSIBLE_PRIVATE_KEY_FILE", None)

        host_connection_info = protocol + user + get_server_host()
        self.master = testinfra.get_host(
            host_connection_info, ssh_identity_file=ssh_identity_file,
        )

    @staticmethod
    def run_playbook(playbook, allow_failures=False):
        return run_playbook(playbook, allow_failures)

    @staticmethod
    def run_playbook_with_exp_msg(playbook, expected_msg):
        result = run_playbook(playbook, allow_failures=True)
        assert (
            expected_msg in result.stdout.decode("utf8")
            or
            expected_msg in result.stderr.decode("utf8")
        )

    @staticmethod
    def __is_text_on_data(text, data):
        return re.search(text, data) is not None

    def check_details(self, expected_output, cmd, extra_cmds=None):
        cmd = "ipa " + cmd
        if extra_cmds:
            cmd += " " + " ".join(extra_cmds)
        kinit_admin(self.master)
        res = self.master.run(cmd)
        if res.rc != 0:
            for output in expected_output:
                assert self.__is_text_on_data(output, res.stderr), (
                    f"\n{'='*40}\nExpected: {output}\n{'='*40}\n"
                    + f"Output:\n{res.stderr}{'='*40}\n"
                )
        else:
            for output in expected_output:
                assert self.__is_text_on_data(output, res.stdout), (
                    f"\n{'='*40}\nExpected: {output}\n{'='*40}\n"
                    + f"Output:\n{res.stdout}{'='*40}\n"
                )
        kdestroy(self.master)

    def check_notexists(self, members, cmd, extra_cmds=None):
        cmd = "ipa " + cmd
        if extra_cmds:
            cmd += " " + " ".join(extra_cmds)
        kinit_admin(self.master)
        res = self.master.run(cmd)
        for member in members:
            assert not self.__is_text_on_data(member, res.stdout), (
                f"\n{'='*40}\nExpected: {member}\n{'='*40}\n"
                + f"Output:\n{res.stdout}{'='*40}\n"
            )
        kdestroy(self.master)

    def mark_xfail_using_ansible_freeipa_version(self, version, reason):
        package = self.master.package("ansible-freeipa")

        if not package.is_installed:
            return

        if package.version == version:
            pytest.xfail(reason)

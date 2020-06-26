#!/usr/bin/env python

import os
import tempfile
import textwrap
import json

from subprocess import Popen, PIPE

import pytest

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


def get_inventory_content():
    ipa_server_host = os.getenv("IPA_SERVER_HOST")
    ipa_base_dn = os.getenv("IPA_BASE_DN")
    return textwrap.dedent('''\
    url = "ldaps://{}"
    base_dn = "{}"

    connconfig = dict(
        user = "cn=Directory Manager",
        password = "SomeDMpassword",
    )
    ''').format(ipa_server_host, ipa_base_dn).encode("utf8")


def run_inventory():
    with tempfile.NamedTemporaryFile() as inventory_file:
        inventory_file.write(get_inventory_content())
        inventory_file.flush()
        cmd = [
            "ansible-inventory",
            "-i",
            inventory_file.name,
            "--list",
        ]
        process = Popen(cmd, stdout=PIPE, stderr=PIPE, cwd=SCRIPT_DIR)
        process.wait()
    return process


@pytest.mark.skipif(
    os.getenv("IPA_SERVER_HOST") is None or os.getenv("IPA_BASE_DN") is None,
    reason="Environment variable IPA_SERVER_HOST and IPA_BASE_DN must be set",
)
def test_inventory():
    process = run_inventory()
    stdout, stderr = process.communicate()
    result = json.loads(stdout)
    assert "ipaservers" in result

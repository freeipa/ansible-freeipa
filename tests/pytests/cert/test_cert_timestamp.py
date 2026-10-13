"""Test ipacert certificate timestamp parsing."""

import importlib.util
import os
import sys
from unittest import mock

import pytest

MODULE_PATH = os.path.join(
    os.path.dirname(__file__), "..", "..", "..", "plugins", "modules",
    "ipacert.py"
)

# The module utils require FreeIPA libraries, which are not needed here.
with mock.patch.dict(sys.modules, {
    "ansible.module_utils.ansible_freeipa_module": mock.MagicMock()
}):
    _spec = importlib.util.spec_from_file_location("ipacert", MODULE_PATH)
    ipacert = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(ipacert)


@pytest.mark.parametrize("value,expected", [
    ("Fri Oct 15 10:52:56 2027 UTC", "20271015105256Z"),
    ("Tue Jan  5 00:00:01 2021 UTC", "20210105000001Z"),
])
def test_parse_cert_timestamp(value, expected):
    assert ipacert.parse_cert_timestamp(value) == expected


def test_parse_cert_timestamp_locale_independent():
    """The weekday name must not be validated against the locale."""
    assert ipacert.parse_cert_timestamp(
        "Pt Oct 15 10:52:56 2027 UTC") == "20271015105256Z"


def test_parse_cert_timestamp_invalid():
    with pytest.raises(ValueError):
        ipacert.parse_cert_timestamp("garbage")

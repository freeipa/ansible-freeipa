#!/usr/bin/python3

# Test ipaclient python3 binding
from ipaclient.install.client import SECURE_PATH  # noqa: F401

# Check ipapython version to be >= 4.6
from ipapython.version import NUM_VERSION, VERSION
if NUM_VERSION < 40600:
    raise Exception("ipa %s not usable with python3" % VERSION)

# -*- coding: utf-8 -*-

# Authors:
#   Rafael Guterres Jeffman <rjeffman@redhat.com>
#
# Copyright (C) 2025 Red Hat
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

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

ANSIBLE_METADATA = {
    "metadata_version": "1.0",
    "supported_by": "community",
    "status": ["preview"],
}

DOCUMENTATION = """
---
module: ipapasskeyconfig
short_description: Manage FreeIPA passkeyconfig
description: Manage FreeIPA passkeyconfig
extends_documentation_fragment:
  - ipamodule_base_docs
options:
  require_user_verification:
    description: Require user verification for passkey authentication
    required: false
    type: bool
    default: true
    aliases: ["iparequireuserverification"]
author:
  - Rafael Guterres Jeffman (@rjeffman)
"""

EXAMPLES = """
# Set passkeyconfig
- ipapasskeyconfig:
    ipaadmin_password: SomeADMINpassword
    require_user_verification: false

# Get current passkeyconfig
- ipapasskeyconfig:
    ipaadmin_password: SomeADMINpassword
"""

RETURN = """
passkeyconfig:
  description: Dict of passkeyconfig settings
  returned: always
  type: dict
  contains:
    require_user_verification:
        description: Require user verification for passkey authentication
        type: bool
        returned: always
"""


from ansible.module_utils.ansible_freeipa_module import \
    IPAAnsibleModule, compare_args_ipa, ipalib_errors
from ansible.module_utils import six

if six.PY3:
    unicode = str


def find_passkeyconfig(module):
    """Find the current passkeyconfig settings."""
    try:
        _result = module.ipa_command_no_name(
            "passkeyconfig_show", {"all": True})
    except ipalib_errors.NotFound:
        # An exception is raised if passkeyconfig is not found.
        return None
    return _result["result"]


def gen_args(require_user_verification):
    _args = {}
    if require_user_verification is not None:
        _args["iparequireuserverification"] = require_user_verification
    return _args


def main():
    ansible_module = IPAAnsibleModule(
        argument_spec=dict(
            # passkeyconfig
            require_user_verification=dict(
                required=False, type='bool',
                aliases=["iparequireuserverification"],
                default=None
            ),
        ),
        supports_check_mode=True,
    )

    ansible_module._ansible_debug = True

    # Get parameters
    require_user_verification = (
        ansible_module.params_get("require_user_verification")
    )

    # Init
    changed = False
    exit_args = {}

    # Connect to IPA API
    with ansible_module.ipa_connect():

        if not ansible_module.ipa_command_exists("passkeyconfig_show"):
            msg = "Managing passkeyconfig is not supported by your IPA version"
            ansible_module.fail_json(msg=msg)

        result = find_passkeyconfig(ansible_module)

        if result is None:
            ansible_module.fail_json(msg="Could not retrieve passkeyconfig")

        if require_user_verification is not None:
            # Generate args
            args = gen_args(require_user_verification)

            # Check if there are different settings in the find result.
            # If yes: modify
            if not compare_args_ipa(ansible_module, args, result):
                changed = True
                if not ansible_module.check_mode:
                    try:
                        ansible_module.ipa_command_no_name(
                            "passkeyconfig_mod", args)
                    except ipalib_errors.EmptyModlist:
                        changed = False
                    except Exception as e:
                        ansible_module.fail_json(
                            msg="passkeyconfig_mod failed: %s" % str(e))
        else:
            # No parameters provided, just return current config
            pass

        # Get updated config if changes were made
        if changed:
            result = find_passkeyconfig(ansible_module)

        # Prepare exit args
        exit_args["passkeyconfig"] = {}
        if result:
            # Map IPA API field to module parameter
            if "iparequireuserverification" in result:
                exit_args["passkeyconfig"]["require_user_verification"] = \
                    result["iparequireuserverification"][0]

    # Done
    ansible_module.exit_json(changed=changed, **exit_args)


if __name__ == "__main__":
    main()

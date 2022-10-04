# -*- coding: utf-8 -*-

# Authors:
#   Rafael Guterres Jeffman <rjeffman@redhat.com>
#   Thomas Woerner <twoerner@redhat.com>
#
# Copyright (C) 2019-2022 Red Hat
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
module: ipasudocmd
short_description: Manage FreeIPA sudo command
description: Manage FreeIPA sudo command
extends_documentation_fragment:
  - ipamodule_base_docs
options:
  name:
    description: The sudo command
    type: list
    elements: str
    required: true
    aliases: ["sudocmd"]
  description:
    description: The command description
    type: str
    required: false
  state:
    description: State to ensure
    type: str
    default: present
    choices: ["present", "absent"]
author:
  - Rafael Guterres Jeffman (@rjeffman)
  - Thomas Woerner (@t-woerner)
"""

EXAMPLES = """
# Ensure sudocmd is present
- ipasudocmd:
    ipaadmin_password: SomeADMINpassword
    name: /usr/bin/su
    state: present

# Ensure sudocmd is absent
- ipasudocmd:
    ipaadmin_password: SomeADMINpassword
    name: /usr/bin/su
    state: absent
"""

RETURN = """
"""

from ansible.module_utils.ansible_freeipa_module import \
    IPAAnsibleModule, compare_args_ipa


def find_sudocmd(module, name):
    _args = {
        "all": True,
        "sudocmd": name,
    }

    _result = module.ipa_command("sudocmd_find", name, _args)

    if len(_result["result"]) > 1:
        module.fail_json(
            msg="There is more than one sudocmd '%s'" % (name))
    elif len(_result["result"]) == 1:
        return _result["result"][0]

    return None


def gen_args(description):
    _args = {}
    if description is not None:
        _args["description"] = description

    return _args


def main():
    ansible_module = IPAAnsibleModule(
        argument_spec=dict(
            # general
            name=dict(type="list", elements="str", aliases=["sudocmd"],
                      required=True),
            # present
            description=dict(type="str", default=None),
            # state
            state=dict(type="str", default="present",
                       choices=["present", "absent"]),
        ),
        supports_check_mode=True,
    )

    ansible_module._ansible_debug = True

    # Get parameters

    # general
    names = ansible_module.params_get("name")

    # present
    description = ansible_module.params_get("description")
    # state
    state = ansible_module.params_get("state")

    # Check parameters
    invalid = []
    if state == "absent":
        invalid = ["description"]

    ansible_module.params_fail_used_invalid(invalid, state)

    # Init

    changed = False
    exit_args = {}

    # Connect to IPA API
    with ansible_module.ipa_connect():

        commands = []

        for name in names:
            # Make sure hostgroup exists
            res_find = find_sudocmd(ansible_module, name)

            # Create command
            if state == "present":
                # Generate args
                args = gen_args(description)
                if res_find is not None:
                    # For all settings in args, check if there are
                    # different settings in the find result.
                    # If yes: modify
                    if not compare_args_ipa(ansible_module, args,
                                            res_find):
                        commands.append([name, "sudocmd_mod", args])
                else:
                    commands.append([name, "sudocmd_add", args])
                    # Set res_find to empty dict for next step
                    res_find = {}
            elif state == "absent":
                if res_find is not None:
                    commands.append([name, "sudocmd_del", {}])
            else:
                ansible_module.fail_json(msg="Unkown state '%s'" % state)

        changed = ansible_module.execute_ipa_commands(commands)

    # Done

    ansible_module.exit_json(changed=changed, **exit_args)


if __name__ == "__main__":
    main()

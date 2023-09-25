# -*- coding: utf-8 -*-

# Authors:
#   Thomas Woerner <twoerner@redhat.com>
#
# Copyright (C) 2020-2022 Red Hat
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
module: ipalocation
short_description: Manage FreeIPA location
description: Manage FreeIPA location
extends_documentation_fragment:
  - ipamodule_base_docs
options:
  name:
    description: The list of location name strings.
    type: list
    elements: str
    required: true
    aliases: ["idnsname"]
  description:
    description: The IPA location string
    type: str
    required: false
  state:
    description: The state to ensure.
    type: str
    choices: ["present", "absent"]
    default: present
    required: false
author:
  - Thomas Woerner (@t-woerner)
"""

EXAMPLES = """
# Ensure location my_location1 is present
- ipalocation:
    ipaadmin_password: SomeADMINpassword
    name: my_location1
    description: My location 1

# Ensure location my_location1 is absent
- ipalocation:
    ipaadmin_password: SomeADMINpassword
    name: my_location1
    state: absent
"""

RETURN = """
"""


from ansible.module_utils.ansible_freeipa_module import \
    IPAAnsibleModule, compare_args_ipa


def find_location(module, name):
    """Find if a location with the given name already exist."""
    try:
        _result = module.ipa_command("location_show", name, {"all": True})
    except Exception:  # pylint: disable=broad-except
        # An exception is raised if location name is not found.
        return None
    return _result["result"]


def gen_args(description):
    _args = {}
    if description is not None:
        _args["description"] = description
    return _args


def main():
    ansible_module = IPAAnsibleModule(
        argument_spec=dict(
            name=dict(type="list", elements="str", aliases=["idnsname"],
                      required=True),
            # present
            description=dict(required=False, type='str', default=None),
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
    if state == "present":
        if len(names) != 1:
            ansible_module.fail_json(
                msg="Only one location be added at a time.")

    if state == "absent":
        if len(names) < 1:
            ansible_module.fail_json(msg="No name given.")
        invalid = ["description"]

    ansible_module.params_fail_used_invalid(invalid, state)

    # Init

    changed = False
    exit_args = {}

    # Connect to IPA API
    with ansible_module.ipa_connect():
        commands = []
        for name in names:
            # Make sure location exists
            res_find = find_location(ansible_module, name)

            # Create command
            if state == "present":

                # Generate args
                args = gen_args(description)

                # Found the location
                if res_find is not None:
                    # For all settings is args, check if there are
                    # different settings in the find result.
                    # If yes: modify
                    if not compare_args_ipa(ansible_module, args,
                                            res_find):
                        commands.append([name, "location_mod", args])
                else:
                    commands.append([name, "location_add", args])

            elif state == "absent":
                if res_find is not None:
                    commands.append([name, "location_del", {}])

            else:
                ansible_module.fail_json(msg="Unkown state '%s'" % state)

        # Execute commands
        changed = ansible_module.execute_ipa_commands(commands)

    # Done

    ansible_module.exit_json(changed=changed, **exit_args)


if __name__ == "__main__":
    main()

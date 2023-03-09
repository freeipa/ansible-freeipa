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
module: ipasudocmdgroup
short_description: Manage FreeIPA sudocmd groups
description: Manage FreeIPA sudocmd groups
extends_documentation_fragment:
  - ipamodule_base_docs
options:
  name:
    description: The sudocmodgroup name
    type: list
    elements: str
    required: true
    aliases: ["cn"]
  description:
    description: The sudocmdgroup description
    type: str
    required: false
  nomembers:
    description: Suppress processing of membership attributes
    required: false
    type: bool
  sudocmd:
    description: List of sudocmds assigned to this sudocmdgroup.
    required: false
    type: list
    elements: str
  action:
    description: Work on sudocmdgroup or member level
    type: str
    default: sudocmdgroup
    choices: ["member", "sudocmdgroup"]
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
# Ensure sudocmd-group 'network' is present
- ipasudocmdgroup:
    ipaadmin_password: SomeADMINpassword
    name: network
    state: present

# Ensure sudocmdgroup and sudocmd are present in 'network' sudocmdgroup
- ipasudocmdgroup:
    ipaadmin_password: SomeADMINpassword
    name: network
    sudocmd:
    - /usr/sbin/ifconfig
    - /usr/sbin/iwlist
    action: member

# Ensure sudocmdgroup and sudocmd are absent in 'network' sudocmdgroup
- ipasudocmdgroup:
    ipaadmin_password: SomeADMINpassword
    name: network
    sudocmd:
    - /usr/sbin/ifconfig
    - /usr/sbin/iwlist
    action: member
    state: absent

# Ensure sudocmd-group 'network' is absent
- ipasudocmdgroup:
    ipaadmin_password: SomeADMINpassword
    name: network
    action: member
    state: absent
"""

RETURN = """
"""

from ansible.module_utils.ansible_freeipa_module import \
    IPAAnsibleModule, compare_args_ipa, gen_add_del_lists, \
    gen_add_list, gen_intersection_list, ipalib_errors


def find_sudocmdgroup(module, name):
    args = {"all": True}

    try:
        _result = module.ipa_command("sudocmdgroup_show", name, args)
    except ipalib_errors.NotFound:
        return None
    return _result["result"]


def gen_args(description, nomembers):
    _args = {}
    if description is not None:
        _args["description"] = description
    if nomembers is not None:
        _args["nomembers"] = nomembers

    return _args


def gen_member_args(sudocmd):
    _args = {}
    if sudocmd is not None:
        _args["member_sudocmd"] = sudocmd

    return _args


def main():
    ansible_module = IPAAnsibleModule(
        argument_spec=dict(
            # general
            name=dict(type="list", elements="str", aliases=["cn"],
                      required=True),
            # present
            description=dict(type="str", default=None),
            nomembers=dict(required=False, type='bool', default=None),
            sudocmd=dict(required=False, type='list', elements="str",
                         default=None),
            action=dict(type="str", default="sudocmdgroup",
                        choices=["member", "sudocmdgroup"]),
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
    nomembers = ansible_module.params_get("nomembers")
    sudocmd = ansible_module.params_get("sudocmd")
    action = ansible_module.params_get("action")
    # state
    state = ansible_module.params_get("state")

    # Check parameters
    invalid = []

    if state == "present":
        if len(names) != 1:
            ansible_module.fail_json(
                msg="Only one sudocmdgroup can be added at a time.")
        if action == "member":
            invalid = ["description", "nomembers"]

    if state == "absent":
        if len(names) < 1:
            ansible_module.fail_json(
                msg="No name given.")
        invalid = ["description", "nomembers"]
        if action == "sudocmdgroup":
            invalid.extend(["sudocmd"])

    ansible_module.params_fail_used_invalid(invalid, state, action)

    # Init

    changed = False
    exit_args = {}

    # Connect to IPA API
    with ansible_module.ipa_connect():

        commands = []

        for name in names:
            # Make sure hostgroup exists
            res_find = find_sudocmdgroup(ansible_module, name)

            # Create command
            if state == "present":
                # Generate args
                args = gen_args(description, nomembers)

                if action == "sudocmdgroup":
                    # Found the hostgroup
                    if res_find is not None:
                        # For all settings is args, check if there are
                        # different settings in the find result.
                        # If yes: modify
                        if not compare_args_ipa(ansible_module, args,
                                                res_find):
                            commands.append([name, "sudocmdgroup_mod", args])
                    else:
                        commands.append([name, "sudocmdgroup_add", args])
                        # Set res_find to empty dict for next step
                        res_find = {}

                    member_args = gen_member_args(sudocmd)
                    if not compare_args_ipa(ansible_module, member_args,
                                            res_find):
                        # Generate addition and removal lists
                        sudocmd_add, sudocmd_del = \
                            gen_add_del_lists(
                                sudocmd,
                                res_find.get("member_sudocmd"))

                        # Add members
                        if len(sudocmd_add) > 0:
                            commands.append([name, "sudocmdgroup_add_member",
                                             {
                                                 "sudocmd": sudocmd_add
                                             }
                                             ])
                        # Remove members
                        if len(sudocmd_del) > 0:
                            commands.append([name,
                                             "sudocmdgroup_remove_member",
                                             {
                                                 "sudocmd": sudocmd_del
                                             }
                                             ])
                elif action == "member":
                    if res_find is None:
                        ansible_module.fail_json(
                            msg="No sudocmdgroup '%s'" % name)

                    # Ensure members are present
                    sudocmd = gen_add_list(
                        sudocmd, res_find.get("member_sudocmd") or [])
                    if sudocmd:
                        commands.append([name, "sudocmdgroup_add_member",
                                         {"sudocmd": sudocmd}
                                         ])
            elif state == "absent":
                if action == "sudocmdgroup":
                    if res_find is not None:
                        commands.append([name, "sudocmdgroup_del", {}])

                elif action == "member":
                    if res_find is None:
                        ansible_module.fail_json(
                            msg="No sudocmdgroup '%s'" % name)

                    sudocmd = gen_intersection_list(
                        sudocmd, res_find.get("member_sudocmd") or [])
                    if sudocmd:
                        commands.append([name, "sudocmdgroup_remove_member",
                                         {"sudocmd": sudocmd}
                                         ])
            else:
                ansible_module.fail_json(msg="Unkown state '%s'" % state)

        changed = ansible_module.execute_ipa_commands(
            commands, fail_on_member_errors=True)

    # Done

    ansible_module.exit_json(changed=changed, **exit_args)


if __name__ == "__main__":
    main()

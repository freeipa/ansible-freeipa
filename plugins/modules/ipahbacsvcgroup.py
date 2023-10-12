# -*- coding: utf-8 -*-

# Authors:
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
module: ipahbacsvcgroup
short_description: Manage FreeIPA hbacsvcgroups
description: Manage FreeIPA hbacsvcgroups
extends_documentation_fragment:
  - ipamodule_base_docs
options:
  name:
    description: The hbacsvcgroup name
    type: list
    elements: str
    required: true
    aliases: ["cn"]
  description:
    description: The hbacsvcgroup description
    type: str
    required: false
  hbacsvc:
    description: List of hbacsvc names assigned to this hbacsvcgroup.
    required: false
    type: list
    elements: str
  nomembers:
    description: Suppress processing of membership attributes
    required: false
    type: bool
  action:
    description: Work on hbacsvcgroup or member level
    type: str
    default: hbacsvcgroup
    choices: ["member", "hbacsvcgroup"]
  state:
    description: State to ensure
    type: str
    default: present
    choices: ["present", "absent"]
author:
  - Thomas Woerner (@t-woerner)
"""

EXAMPLES = """
# Ensure hbacsvcgroup login is present
- ipahbacsvcgroup:
    ipaadmin_password: SomeADMINpassword
    name: login
    hbacsvc:
    - sshd

# Ensure hbacsvc sshd is present in existing login hbacsvcgroup
- ipahbacsvcgroup:
    ipaadmin_password: SomeADMINpassword
    name: databases
    hbacsvc:
    - sshd
    action: member

# Ensure hbacsvc sshd is abdsent in existing login hbacsvcgroup
- ipahbacsvcgroup:
    ipaadmin_password: SomeADMINpassword
    name: databases
    hbacsvc:
    - sshd
    action: member
    state: absent

# Ensure hbacsvcgroup login is absent
- ipahbacsvcgroup:
    ipaadmin_password: SomeADMINpassword
    name: login
    state: absent
"""

RETURN = """
"""

from ansible.module_utils.ansible_freeipa_module import \
    IPAAnsibleModule, compare_args_ipa, gen_add_del_lists, gen_add_list, \
    gen_intersection_list


def find_hbacsvcgroup(module, name):
    _args = {
        "all": True,
        "cn": name,
    }

    _result = module.ipa_command("hbacsvcgroup_find", name, _args)

    if len(_result["result"]) > 1:
        module.fail_json(
            msg="There is more than one hbacsvcgroup '%s'" % (name))
    elif len(_result["result"]) == 1:
        return _result["result"][0]

    return None


def gen_args(description, nomembers):
    _args = {}
    if description is not None:
        _args["description"] = description
    if nomembers is not None:
        _args["nomembers"] = nomembers

    return _args


def gen_member_args(hbacsvc):
    _args = {}
    if hbacsvc is not None:
        _args["member_hbacsvc"] = hbacsvc

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
            hbacsvc=dict(required=False, type='list', elements="str",
                         default=None),
            action=dict(type="str", default="hbacsvcgroup",
                        choices=["member", "hbacsvcgroup"]),
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
    hbacsvc = ansible_module.params_get_lowercase("hbacsvc")
    action = ansible_module.params_get("action")
    # state
    state = ansible_module.params_get("state")

    # Check parameters

    invalid = []

    if state == "present":
        if len(names) != 1:
            ansible_module.fail_json(
                msg="Only one hbacsvcgroup can be added at a time.")
        if action == "member":
            invalid = ["description", "nomembers"]

    if state == "absent":
        if len(names) < 1:
            ansible_module.fail_json(
                msg="No name given.")
        invalid = ["description", "nomembers"]
        if action == "hbacsvcgroup":
            invalid.extend(["hbacsvc"])

    ansible_module.params_fail_used_invalid(invalid, state, action)

    # Init

    changed = False
    exit_args = {}

    # Connect to IPA API
    with ansible_module.ipa_connect():

        commands = []

        for name in names:
            # Make sure hbacsvcgroup exists
            res_find = find_hbacsvcgroup(ansible_module, name)

            hbacsvc_add, hbacsvc_del = [], []

            # Create command
            if state == "present":
                # Generate args
                args = gen_args(description, nomembers)

                if action == "hbacsvcgroup":
                    # Found the hbacsvcgroup
                    if res_find is not None:
                        # For all settings is args, check if there are
                        # different settings in the find result.
                        # If yes: modify
                        if not compare_args_ipa(ansible_module, args,
                                                res_find):
                            commands.append([name, "hbacsvcgroup_mod", args])
                    else:
                        commands.append([name, "hbacsvcgroup_add", args])
                        # Set res_find to empty dict for next step
                        res_find = {}

                    member_args = gen_member_args(hbacsvc)
                    if not compare_args_ipa(ansible_module, member_args,
                                            res_find):
                        # Generate addition and removal lists
                        if hbacsvc is not None:
                            hbacsvc_add, hbacsvc_del = gen_add_del_lists(
                                hbacsvc, res_find.get("member_hbacsvc"))

                elif action == "member":
                    if res_find is None:
                        ansible_module.fail_json(
                            msg="No hbacsvcgroup '%s'" % name)

                    # Ensure members are present
                    if hbacsvc:
                        hbacsvc_add = gen_add_list(
                            hbacsvc, res_find.get("member_hbacsvc"))

            elif state == "absent":
                if action == "hbacsvcgroup":
                    if res_find is not None:
                        commands.append([name, "hbacsvcgroup_del", {}])

                elif action == "member":
                    if res_find is None:
                        ansible_module.fail_json(
                            msg="No hbacsvcgroup '%s'" % name)

                    # Ensure members are absent
                    if hbacsvc:
                        hbacsvc_del = gen_intersection_list(
                            hbacsvc, res_find.get("member_hbacsvc"))

            else:
                ansible_module.fail_json(msg="Unkown state '%s'" % state)

            # Manage members
            if len(hbacsvc_add) > 0:
                commands.append([name, "hbacsvcgroup_add_member",
                                 {
                                     "hbacsvc": hbacsvc_add
                                 }])
            # Remove members
            if len(hbacsvc_del) > 0:
                commands.append([name,
                                 "hbacsvcgroup_remove_member",
                                 {
                                     "hbacsvc": hbacsvc_del
                                 }])

        # Execute commands
        changed = ansible_module.execute_ipa_commands(
            commands, fail_on_member_errors=True)

    # Done

    ansible_module.exit_json(changed=changed, **exit_args)


if __name__ == "__main__":
    main()

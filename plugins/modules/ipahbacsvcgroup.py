#!/usr/bin/python
# -*- coding: utf-8 -*-

# Authors:
#   Thomas Woerner <twoerner@redhat.com>
#
# Copyright (C) 2019 Red Hat
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

ANSIBLE_METADATA = {
    "metadata_version": "1.0",
    "supported_by": "community",
    "status": ["preview"],
}


DOCUMENTATION = """
---
module: ipahbacsvcgroup
short description: Manage FreeIPA hbacsvcgroups
description: Manage FreeIPA hbacsvcgroups
options:
  ipaadmin_principal:
    description: The admin principal
    default: admin
  ipaadmin_password:
    description: The admin password
    required: false
  name:
    description: The hbacsvcgroup name
    required: false
    aliases: ["cn"]
  description:
    description: The hbacsvcgroup description
    required: false
  hbacsvc:
    description: List of hbacsvc names assigned to this hbacsvcgroup.
    required: false
    type: list
  nomembers:
    description: Suppress processing of membership attributes
    required: false
    type: bool
  action:
    description: Work on hbacsvcgroup or member level
    default: hbacsvcgroup
    choices: ["member", "hbacsvcgroup"]
  state:
    description: State to ensure
    default: present
    choices: ["present", "absent"]
author:
    - Thomas Woerner
"""

EXAMPLES = """
# Ensure hbacsvcgroup login is present
- ipahbacsvcgroup:
    ipaadmin_password: MyPassword123
    name: login
    hbacsvc:
    - sshd

# Ensure hbacsvc sshd is present in existing login hbacsvcgroup
- ipahbacsvcgroup:
    ipaadmin_password: MyPassword123
    name: databases
    hbacsvc:
    - sshd
    action: member

# Ensure hbacsvc sshd is abdsent in existing login hbacsvcgroup
- ipahbacsvcgroup:
    ipaadmin_password: MyPassword123
    name: databases
    hbacsvc:
    - sshd
    action: member
    state: absent

# Ensure hbacsvcgroup login is absent
- ipahbacsvcgroup:
    ipaadmin_password: MyPassword123
    name: login
    state: absent
"""

RETURN = """
"""

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_text
from ansible.module_utils.ansible_freeipa_module import temp_kinit, \
    temp_kdestroy, valid_creds, api_connect, api_command, compare_args_ipa


def find_hbacsvcgroup(module, name):
    _args = {
        "all": True,
        "cn": to_text(name),
    }

    _result = api_command(module, "hbacsvcgroup_find", to_text(name), _args)

    if len(_result["result"]) > 1:
        module.fail_json(
            msg="There is more than one hbacsvcgroup '%s'" % (name))
    elif len(_result["result"]) == 1:
        return _result["result"][0]
    else:
        return None


def gen_args(description, nomembers):
    _args = {}
    if description is not None:
        _args["description"] = to_text(description)
    if nomembers is not None:
        _args["nomembers"] = nomembers

    return _args


def gen_member_args(hbacsvc):
    _args = {}
    if hbacsvc is not None:
        _args["member_hbacsvc"] = [to_text(svc) for svc in hbacsvc]

    return _args


def main():
    ansible_module = AnsibleModule(
        argument_spec=dict(
            # general
            ipaadmin_principal=dict(type="str", default="admin"),
            ipaadmin_password=dict(type="str", required=False, no_log=True),

            name=dict(type="list", aliases=["cn"], default=None,
                      required=True),
            # present
            description=dict(type="str", default=None),
            nomembers=dict(required=False, type='bool', default=None),
            hbacsvc=dict(required=False, type='list', default=None),
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
    ipaadmin_principal = ansible_module.params.get("ipaadmin_principal")
    ipaadmin_password = ansible_module.params.get("ipaadmin_password")
    names = ansible_module.params.get("name")

    # present
    description = ansible_module.params.get("description")
    nomembers = ansible_module.params.get("nomembers")
    hbacsvc = ansible_module.params.get("hbacsvc")
    action = ansible_module.params.get("action")
    # state
    state = ansible_module.params.get("state")

    # Check parameters

    if state == "present":
        if len(names) != 1:
            ansible_module.fail_json(
                msg="Only one hbacsvcgroup can be added at a time.")
        if action == "member":
            invalid = ["description", "nomembers"]
            for x in invalid:
                if vars()[x] is not None:
                    ansible_module.fail_json(
                        msg="Argument '%s' can not be used with action "
                        "'%s'" % (x, action))

    if state == "absent":
        if len(names) < 1:
            ansible_module.fail_json(
                msg="No name given.")
        invalid = ["description", "nomembers"]
        if action == "hbacsvcgroup":
            invalid.extend(["hbacsvc"])
        for x in invalid:
            if vars()[x] is not None:
                ansible_module.fail_json(
                    msg="Argument '%s' can not be used with state '%s'" %
                    (x, state))

    # Init

    changed = False
    exit_args = {}
    ccache_dir = None
    ccache_name = None
    try:
        if not valid_creds(ansible_module, ipaadmin_principal):
            ccache_dir, ccache_name = temp_kinit(ipaadmin_principal,
                                                 ipaadmin_password)
        api_connect()

        commands = []

        for name in names:
            # Make sure hbacsvcgroup exists
            res_find = find_hbacsvcgroup(ansible_module, name)

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
                        hbacsvc_add = list(
                            set(hbacsvc or []) -
                            set(res_find.get("member_hbacsvc", [])))
                        hbacsvc_del = list(
                            set(res_find.get("member_hbacsvc", [])) -
                            set(hbacsvc or []))

                        # Add members
                        if len(hbacsvc_add) > 0:
                            commands.append([name, "hbacsvcgroup_add_member",
                                             {
                                                 "hbacsvc":
                                                 [to_text(svc)
                                                  for svc in hbacsvc_add],
                                             }])
                        # Remove members
                        if len(hbacsvc_del) > 0:
                            commands.append([name,
                                             "hbacsvcgroup_remove_member",
                                             {
                                                 "hbacsvc":
                                                 [to_text(svc)
                                                  for svc in hbacsvc_del],
                                             }])
                elif action == "member":
                    if res_find is None:
                        ansible_module.fail_json(
                            msg="No hbacsvcgroup '%s'" % name)

                    # Ensure members are present
                    commands.append([name, "hbacsvcgroup_add_member",
                                     {
                                         "hbacsvc": [to_text(svc)
                                                     for svc in hbacsvc],
                                     }])
            elif state == "absent":
                if action == "hbacsvcgroup":
                    if res_find is not None:
                        commands.append([name, "hbacsvcgroup_del", {}])

                elif action == "member":
                    if res_find is None:
                        ansible_module.fail_json(
                            msg="No hbacsvcgroup '%s'" % name)

                    # Ensure members are absent
                    commands.append([name, "hbacsvcgroup_remove_member",
                                     {
                                         "hbacsvc": [to_text(svc)
                                                     for svc in hbacsvc],
                                     }])
            else:
                ansible_module.fail_json(msg="Unkown state '%s'" % state)

        # Execute commands
        errors = []
        for name, command, args in commands:
            try:
                result = api_command(ansible_module, command, to_text(name),
                                     args)
                if "completed" in result:
                    if result["completed"] > 0:
                        changed = True
                else:
                    changed = True
            except Exception as e:
                ansible_module.fail_json(msg="%s: %s: %s" % (command, name,
                                                             str(e)))
            # Get all errors
            # All "already a member" and "not a member" failures in the
            # result are ignored. All others are reported.
            if "failed" in result and "member" in result["failed"]:
                failed = result["failed"]["member"]
                for member_type in failed:
                    for member, failure in failed[member_type]:
                        if "already a member" not in failure \
                           and "not a member" not in failure:
                            errors.append("%s: %s %s: %s" % (
                                command, member_type, member, failure))
        if len(errors) > 0:
            ansible_module.fail_json(msg=", ".join(errors))

    except Exception as e:
        ansible_module.fail_json(msg=str(e))

    finally:
        temp_kdestroy(ccache_dir, ccache_name)

    # Done

    ansible_module.exit_json(changed=changed, **exit_args)


if __name__ == "__main__":
    main()

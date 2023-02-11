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
module: ipahbacrule
short_description: Manage FreeIPA HBAC rules
description: Manage FreeIPA HBAC rules
extends_documentation_fragment:
  - ipamodule_base_docs
options:
  name:
    description: The hbacrule name
    type: list
    elements: str
    required: true
    aliases: ["cn"]
  description:
    description: The hbacrule description
    type: str
    required: false
  usercategory:
    description: User category the rule applies to
    type: str
    required: false
    aliases: ["usercat"]
    choices: ["all", ""]
  hostcategory:
    description: Host category the rule applies to
    type: str
    required: false
    aliases: ["hostcat"]
    choices: ["all", ""]
  servicecategory:
    description: Service category the rule applies to
    type: str
    required: false
    aliases: ["servicecat"]
    choices: ["all", ""]
  nomembers:
    description: Suppress processing of membership attributes
    required: false
    type: bool
  host:
    description: List of host names assigned to this hbacrule.
    required: false
    type: list
    elements: str
  hostgroup:
    description: List of host groups assigned to this hbacrule.
    required: false
    type: list
    elements: str
  hbacsvc:
    description: List of HBAC service names assigned to this hbacrule.
    required: false
    type: list
    elements: str
  hbacsvcgroup:
    description: List of HBAC service names assigned to this hbacrule.
    required: false
    type: list
    elements: str
  user:
    description: List of user names assigned to this hbacrule.
    required: false
    type: list
    elements: str
  group:
    description: List of user groups assigned to this hbacrule.
    required: false
    type: list
    elements: str
  action:
    description: Work on hbacrule or member level
    type: str
    default: hbacrule
    choices: ["member", "hbacrule"]
  state:
    description: State to ensure
    type: str
    default: present
    choices: ["present", "absent", "enabled", "disabled"]
author:
  - Thomas Woerner (@t-woerner)
"""

EXAMPLES = """
# Ensure HBAC Rule allhosts is present
- ipahbacrule:
    ipaadmin_password: SomeADMINpassword
    name: allhosts
    usercategory: all

# Ensure host server is present in HBAC Rule allhosts
- ipahbacrule:
    ipaadmin_password: SomeADMINpassword
    name: allhosts
    host: server
    action: member

# Ensure HBAC Rule sshd-pinky is present
- ipahbacrule:
    ipaadmin_password: SomeADMINpassword
    name: sshd-pinky
    hostcategory: all

# Ensure user pinky is present in HBAC Rule sshd-pinky
- ipahbacrule:
    ipaadmin_password: SomeADMINpassword
    name: sshd-pinky
    user: pinky
    action: member

# Ensure HBAC service sshd is present in HBAC Rule sshd-pinky
- ipahbacrule:
    ipaadmin_password: SomeADMINpassword
    name: sshd-pinky
    hbacsvc: sshd
    action: member

# Ensure HBAC Rule sshd-pinky is disabled
- ipahbacrule:
    ipaadmin_password: SomeADMINpassword
    name: sshd-pinky
    state: disabled

# Ensure HBAC Rule sshd-pinky is enabled
- ipahbacrule:
    ipaadmin_password: SomeADMINpassword
    name: sshd-pinky
    state: enabled

# Ensure HBAC Rule sshd-pinky is absent
- ipahbacrule:
    ipaadmin_password: SomeADMINpassword
    name: sshd-pinky
    state: absent
"""

RETURN = """
"""

from ansible.module_utils.ansible_freeipa_module import \
    IPAAnsibleModule, compare_args_ipa, gen_member_manage_commands, \
    create_ipa_mapping, ipa_api_map, transform_lowercase, \
    transform_host_param


def find_hbacrule(module, name):
    _args = {
        "all": True,
        "cn": name,
    }

    _result = module.ipa_command("hbacrule_find", name, _args)

    if len(_result["result"]) > 1:
        module.fail_json(
            msg="There is more than one hbacrule '%s'" % (name))
    elif len(_result["result"]) == 1:
        return _result["result"][0]

    return None


def gen_args(description, usercategory, hostcategory, servicecategory,
             nomembers):
    _args = {}
    if description is not None:
        _args["description"] = description
    if usercategory is not None:
        _args["usercategory"] = usercategory
    if hostcategory is not None:
        _args["hostcategory"] = hostcategory
    if servicecategory is not None:
        _args["servicecategory"] = servicecategory
    if nomembers is not None:
        _args["nomembers"] = nomembers

    return _args


def main():
    ansible_module = IPAAnsibleModule(
        argument_spec=dict(
            # general
            name=dict(type="list", elements="str", aliases=["cn"],
                      required=True),
            # present
            description=dict(type="str", default=None),
            usercategory=dict(type="str", default=None,
                              aliases=["usercat"], choices=["all", ""]),
            hostcategory=dict(type="str", default=None,
                              aliases=["hostcat"], choices=["all", ""]),
            servicecategory=dict(type="str", default=None,
                                 aliases=["servicecat"], choices=["all", ""]),
            nomembers=dict(required=False, type='bool', default=None),
            host=dict(required=False, type='list', elements="str",
                      default=None),
            hostgroup=dict(required=False, type='list', elements="str",
                           default=None),
            hbacsvc=dict(required=False, type='list', elements="str",
                         default=None),
            hbacsvcgroup=dict(required=False, type='list', elements="str",
                              default=None),
            user=dict(required=False, type='list', elements="str",
                      default=None),
            group=dict(required=False, type='list', elements="str",
                       default=None),
            action=dict(type="str", default="hbacrule",
                        choices=["member", "hbacrule"]),
            # state
            state=dict(type="str", default="present",
                       choices=["present", "absent",
                                "enabled", "disabled"]),
        ),
        supports_check_mode=True,
    )

    ansible_module._ansible_debug = True

    # Get parameters

    # general
    names = ansible_module.params_get("name")

    # present
    description = ansible_module.params_get("description")
    usercategory = ansible_module.params_get("usercategory")
    hostcategory = ansible_module.params_get("hostcategory")
    servicecategory = ansible_module.params_get("servicecategory")
    nomembers = ansible_module.params_get("nomembers")
    host = ansible_module.params_get("host")
    hostgroup = ansible_module.params_get("hostgroup")
    hbacsvc = ansible_module.params_get("hbacsvc")
    hbacsvcgroup = ansible_module.params_get("hbacsvcgroup")
    user = ansible_module.params_get("user")
    group = ansible_module.params_get("group")
    action = ansible_module.params_get("action")
    # state
    state = ansible_module.params_get("state")

    # Check parameters

    invalid = []

    if state == "present":
        if len(names) != 1:
            ansible_module.fail_json(
                msg="Only one hbacrule can be added at a time.")
        if action == "member":
            invalid = ["description", "usercategory", "hostcategory",
                       "servicecategory", "nomembers"]
        else:
            if hostcategory == 'all' and any([host, hostgroup]):
                ansible_module.fail_json(
                    msg="Hosts cannot be added when host category='all'")
            if usercategory == 'all' and any([user, group]):
                ansible_module.fail_json(
                    msg="Users cannot be added when user category='all'")
            if servicecategory == 'all' and any([hbacsvc, hbacsvcgroup]):
                ansible_module.fail_json(
                    msg="Services cannot be added when service category='all'")

    elif state == "absent":
        if len(names) < 1:
            ansible_module.fail_json(msg="No name given.")
        invalid = ["description", "usercategory", "hostcategory",
                   "servicecategory", "nomembers"]
        if action == "hbacrule":
            invalid.extend(["host", "hostgroup", "hbacsvc", "hbacsvcgroup",
                            "user", "group"])

    elif state in ["enabled", "disabled"]:
        if len(names) < 1:
            ansible_module.fail_json(msg="No name given.")
        if action == "member":
            ansible_module.fail_json(
                msg="Action member can not be used with states enabled and "
                "disabled")
        invalid = ["description", "usercategory", "hostcategory",
                   "servicecategory", "nomembers", "host", "hostgroup",
                   "hbacsvc", "hbacsvcgroup", "user", "group"]
    else:
        ansible_module.fail_json(msg="Invalid state '%s'" % state)

    ansible_module.params_fail_used_invalid(invalid, state, action)

    # Init

    changed = False
    exit_args = {}

    # Connect to IPA API
    with ansible_module.ipa_connect():
        commands = []

        for name in names:
            # Make sure hbacrule exists
            res_find = find_hbacrule(ansible_module, name)

            # Create command
            if state == "present":
                # Generate args
                args = gen_args(description, usercategory, hostcategory,
                                servicecategory, nomembers)

                if action == "hbacrule":
                    # Found the hbacrule
                    if res_find is not None:
                        # Remove usercategory, hostcategory and
                        # servicecategory from args if "" and category
                        # not in res_find (needed for idempotency)
                        if "usercategory" in args and \
                           args["usercategory"] == "" and \
                           "usercategory" not in res_find:
                            del args["usercategory"]
                        if "hostcategory" in args and \
                           args["hostcategory"] == "" and \
                           "hostcategory" not in res_find:
                            del args["hostcategory"]
                        if "servicecategory" in args and \
                           args["servicecategory"] == "" and \
                           "servicecategory" not in res_find:
                            del args["servicecategory"]

                        # For all settings is args, check if there are
                        # different settings in the find result.
                        # If yes: modify
                        if not compare_args_ipa(ansible_module, args,
                                                res_find):
                            commands.append([name, "hbacrule_mod", args])
                    else:
                        commands.append([name, "hbacrule_add", args])
                        # Set res_find to empty dict for next step
                        res_find = {}

                elif action == "member":
                    if res_find is None:
                        ansible_module.fail_json(msg="No hbacrule '%s'" % name)

            elif state == "absent":
                if action == "hbacrule":
                    if res_find is not None:
                        commands.append([name, "hbacrule_del", {}])

                elif action == "member":
                    if res_find is None:
                        ansible_module.fail_json(msg="No hbacrule '%s'" % name)

            elif state == "enabled":
                if res_find is None:
                    ansible_module.fail_json(msg="No hbacrule '%s'" % name)
                # hbacrule_enable is not failing on an enabled hbacrule
                # Therefore it is needed to have a look at the ipaenabledflag
                # in res_find.
                # FreeIPA 4.9.10+ and 4.10 use proper mapping for
                # boolean values, so we need to convert it to str
                # for comparison.
                # See: https://github.com/freeipa/freeipa/pull/6294
                enabled_flag = str(res_find.get("ipaenabledflag", [False])[0])
                if enabled_flag.upper() != "TRUE":
                    commands.append([name, "hbacrule_enable", {}])

            elif state == "disabled":
                if res_find is None:
                    ansible_module.fail_json(msg="No hbacrule '%s'" % name)
                # hbacrule_disable is not failing on an enabled hbacrule
                # Therefore it is needed to have a look at the ipaenabledflag
                # in res_find.
                # FreeIPA 4.9.10+ and 4.10 use proper mapping for
                # boolean values, so we need to convert it to str
                # for comparison.
                # See: https://github.com/freeipa/freeipa/pull/6294
                enabled_flag = str(res_find.get("ipaenabledflag", [False])[0])
                if enabled_flag.upper() != "FALSE":
                    commands.append([name, "hbacrule_disable", {}])

            else:
                ansible_module.fail_json(msg="Unkown state '%s'" % state)

            # Manage HBAC rule members.
            commands.extend(
                gen_member_manage_commands(
                    ansible_module,
                    res_find,
                    name,
                    "hbacrule_add_host",
                    "hbacrule_remove_host",
                    create_ipa_mapping(
                        ipa_api_map(
                            "host", "host", "memberhost_host",
                            transform={"host": transform_host_param},
                        ),
                        ipa_api_map(
                            "hostgroup", "hostgroup", "memberhost_hostgroup",
                            transform={"hostgroup": transform_lowercase},
                        ),
                    )
                )
            )
            commands.extend(
                gen_member_manage_commands(
                    ansible_module,
                    res_find,
                    name,
                    "hbacrule_add_service",
                    "hbacrule_remove_service",
                    create_ipa_mapping(
                        ipa_api_map(
                            "hbacsvc", "hbacsvc", "memberservice_hbacsvc",
                            transform={"hbacsvc": transform_lowercase},
                        ),
                        ipa_api_map(
                            "hbacsvcgroup",
                            "hbacsvcgroup",
                            "memberservice_hbacsvcgroup",
                            transform={"hbacsvcgroup": transform_lowercase},
                        ),
                    )
                )
            )
            commands.extend(
                gen_member_manage_commands(
                    ansible_module,
                    res_find,
                    name,
                    "hbacrule_add_user",
                    "hbacrule_remove_user",
                    create_ipa_mapping(
                        ipa_api_map(
                            "user", "user", "memberuser_user",
                            transform={"user": transform_lowercase},
                        ),
                        ipa_api_map(
                            "group", "group", "memberuser_group",
                            transform={"group": transform_lowercase},
                        ),
                    )
                )
            )

        # Execute commands
        changed = ansible_module.execute_ipa_commands(
            commands, fail_on_member_errors=True)

    # Done

    ansible_module.exit_json(changed=changed, **exit_args)


if __name__ == "__main__":
    main()

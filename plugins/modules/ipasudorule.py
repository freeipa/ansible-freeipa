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
module: ipasudorule
short_description: Manage FreeIPA sudo rules
description: Manage FreeIPA sudo rules
extends_documentation_fragment:
  - ipamodule_base_docs
options:
  name:
    description: The sudorule name
    type: list
    elements: str
    required: true
    aliases: ["cn"]
  description:
    description: The sudorule description
    type: str
    required: false
  user:
    description: List of users assigned to the sudo rule.
    type: list
    elements: str
    required: false
  usercategory:
    description: User category the sudo rule applies to
    type: str
    required: false
    choices: ["all", ""]
    aliases: ["usercat"]
  group:
    description: List of user groups assigned to the sudo rule.
    type: list
    elements: str
    required: false
  runasgroupcategory:
    description: RunAs Group category applied to the sudo rule.
    type: str
    required: false
    choices: ["all", ""]
    aliases: ["runasgroupcat"]
  runasusercategory:
    description: RunAs User category applied to the sudorule.
    type: str
    required: false
    choices: ["all", ""]
    aliases: ["runasusercat"]
  nomembers:
    description: Suppress processing of membership attributes
    required: false
    type: bool
  host:
    description: List of host names assigned to this sudorule.
    required: false
    type: list
    elements: str
  hostgroup:
    description: List of host groups assigned to this sudorule.
    required: false
    type: list
    elements: str
  hostcategory:
    description: Host category the sudo rule applies to.
    type: str
    required: false
    choices: ["all", ""]
    aliases: ["hostcat"]
  allow_sudocmd:
    description: List of allowed sudocmds assigned to this sudorule.
    required: false
    type: list
    elements: str
  allow_sudocmdgroup:
    description: List of allowed sudocmd groups assigned to this sudorule.
    required: false
    type: list
    elements: str
  deny_sudocmd:
    description: List of denied sudocmds assigned to this sudorule.
    required: false
    type: list
    elements: str
  deny_sudocmdgroup:
    description: List of denied sudocmd groups assigned to this sudorule.
    required: false
    type: list
    elements: str
  cmdcategory:
    description: Command category the sudo rule applies to
    type: str
    required: false
    choices: ["all", ""]
    aliases: ["cmdcat"]
  order:
    description: Order to apply this rule.
    required: false
    type: int
    aliases: ["sudoorder"]
  sudooption:
    description: List of sudo options.
    required: false
    type: list
    elements: str
    aliases: ["options"]
  runasuser:
    description: List of users for Sudo to execute as.
    required: false
    type: list
    elements: str
  runasgroup:
    description: List of groups for Sudo to execute as.
    required: false
    type: list
    elements: str
  hostmask:
    description: Host masks of allowed hosts.
    required: false
    type: list
    elements: str
  action:
    description: Work on sudorule or member level
    type: str
    default: sudorule
    choices: ["member", "sudorule"]
  state:
    description: State to ensure
    type: str
    default: present
    choices: ["present", "absent", "enabled", "disabled"]
author:
  - Rafael Guterres Jeffman (@rjeffman)
  - Thomas Woerner (@t-woerner)
"""

EXAMPLES = """
# Ensure Sudo Rule tesrule1 is present
- ipasudorule:
    ipaadmin_password: SomeADMINpassword
    name: testrule1

# Ensure sudocmd is present in Sudo Rule
- ipasudorule:
    ipaadmin_password: pass1234
    name: testrule1
    allow_sudocmd:
      - /sbin/ifconfig
      - /usr/bin/vim
    action: member
    state: absent

# Ensure host server is present in Sudo Rule
- ipasudorule:
    ipaadmin_password: SomeADMINpassword
    name: testrule1
    host: server
    action: member

# Ensure hostgroup cluster is present in Sudo Rule
- ipasudorule:
    ipaadmin_password: SomeADMINpassword
    name: testrule1
    hostgroup: cluster
    action: member

# Ensure sudo rule for usercategory "all" is enabled
- ipasudorule:
    ipaadmin_password: SomeADMINpassword
    name: allusers
    usercategory: all
    state: enabled

# Ensure sudo rule for hostcategory "all" is enabled
- ipasudorule:
    ipaadmin_password: SomeADMINpassword
    name: allhosts
    hostcategory: all
    state: enabled

# Ensure sudo rule applies for hosts with hostmasks
- ipasudorule:
    ipaadmin_password: SomeADMINpassword
    name: testrule1
    hostmask:
    - 192.168.122.1/24
    - 192.168.120.1/24
    action: member

# Ensure Sudo Rule tesrule1 is absent
- ipasudorule:
    ipaadmin_password: SomeADMINpassword
    name: testrule1
    state: absent
"""

RETURN = """
"""

from ansible.module_utils.ansible_freeipa_module import \
    IPAAnsibleModule, compare_args_ipa, gen_member_manage_commands, \
    create_ipa_mapping, ipa_api_map, transform_lowercase, \
    transform_host_param, transform_hostmask


def find_sudorule(module, name):
    _args = {
        "all": True,
        "cn": name,
    }

    _result = module.ipa_command("sudorule_find", name, _args)

    if len(_result["result"]) > 1:
        module.fail_json(
            msg="There is more than one sudorule '%s'" % (name))
    elif len(_result["result"]) == 1:
        return _result["result"][0]

    return None


def gen_args(description, usercat, hostcat, cmdcat, runasusercat,
             runasgroupcat, order, nomembers):
    _args = {}

    if description is not None:
        _args['description'] = description
    if usercat is not None:
        _args['usercategory'] = usercat
    if hostcat is not None:
        _args['hostcategory'] = hostcat
    if cmdcat is not None:
        _args['cmdcategory'] = cmdcat
    if runasusercat is not None:
        _args['ipasudorunasusercategory'] = runasusercat
    if runasgroupcat is not None:
        _args['ipasudorunasgroupcategory'] = runasgroupcat
    if order is not None:
        _args['sudoorder'] = order
    if nomembers is not None:
        _args['nomembers'] = nomembers

    return _args


def main():
    ansible_module = IPAAnsibleModule(
        argument_spec=dict(
            # general
            name=dict(type="list", elements="str", aliases=["cn"],
                      required=True),
            # present
            description=dict(required=False, type="str", default=None),
            usercategory=dict(required=False, type="str", default=None,
                              choices=["all", ""], aliases=['usercat']),
            hostcategory=dict(required=False, type="str", default=None,
                              choices=["all", ""], aliases=['hostcat']),
            nomembers=dict(required=False, type='bool', default=None),
            host=dict(required=False, type='list', elements="str",
                      default=None),
            hostgroup=dict(required=False, type='list', elements="str",
                           default=None),
            hostmask=dict(required=False, type='list', elements="str",
                          default=None),
            user=dict(required=False, type='list', elements="str",
                      default=None),
            group=dict(required=False, type='list', elements="str",
                       default=None),
            allow_sudocmd=dict(required=False, type="list", elements="str",
                               default=None),
            deny_sudocmd=dict(required=False, type="list", elements="str",
                              default=None),
            allow_sudocmdgroup=dict(required=False, type="list",
                                    elements="str", default=None),
            deny_sudocmdgroup=dict(required=False, type="list", elements="str",
                                   default=None),
            cmdcategory=dict(required=False, type="str", default=None,
                             choices=["all", ""], aliases=['cmdcat']),
            runasusercategory=dict(required=False, type="str", default=None,
                                   choices=["all", ""],
                                   aliases=['runasusercat']),
            runasgroupcategory=dict(required=False, type="str", default=None,
                                    choices=["all", ""],
                                    aliases=['runasgroupcat']),
            runasuser=dict(required=False, type="list", elements="str",
                           default=None),
            runasgroup=dict(required=False, type="list", elements="str",
                            default=None),
            order=dict(type="int", required=False, aliases=['sudoorder']),
            sudooption=dict(required=False, type='list', elements="str",
                            default=None, aliases=["options"]),
            action=dict(type="str", default="sudorule",
                        choices=["member", "sudorule"]),
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
    cmdcategory = ansible_module.params_get('cmdcategory')
    usercategory = ansible_module.params_get("usercategory")
    hostcategory = ansible_module.params_get("hostcategory")
    runasusercategory = ansible_module.params_get("runasusercategory")
    runasgroupcategory = ansible_module.params_get("runasgroupcategory")
    hostcategory = ansible_module.params_get("hostcategory")
    nomembers = ansible_module.params_get("nomembers")
    host = ansible_module.params_get("host")
    hostgroup = ansible_module.params_get("hostgroup")
    user = ansible_module.params_get("user")
    group = ansible_module.params_get("group")
    allow_sudocmd = ansible_module.params_get('allow_sudocmd')
    allow_sudocmdgroup = \
        ansible_module.params_get('allow_sudocmdgroup')
    order = ansible_module.params_get("order")
    action = ansible_module.params_get("action")

    # state
    state = ansible_module.params_get("state")

    # Check parameters
    invalid = []

    if state == "present":
        if len(names) != 1:
            ansible_module.fail_json(
                msg="Only one sudorule can be added at a time.")
        if action == "member":
            invalid = ["description", "usercategory", "hostcategory",
                       "cmdcategory", "runasusercategory",
                       "runasgroupcategory", "order", "nomembers"]

        else:
            if hostcategory == 'all' and any([host, hostgroup]):
                ansible_module.fail_json(
                    msg="Hosts cannot be added when host category='all'")
            if usercategory == 'all' and any([user, group]):
                ansible_module.fail_json(
                    msg="Users cannot be added when user category='all'")
            if cmdcategory == 'all' \
               and any([allow_sudocmd, allow_sudocmdgroup]):
                ansible_module.fail_json(
                    msg="Commands cannot be added when command category='all'")

    elif state == "absent":
        if len(names) < 1:
            ansible_module.fail_json(msg="No name given.")
        invalid = ["description", "usercategory", "hostcategory",
                   "cmdcategory", "runasusercategory",
                   "runasgroupcategory", "nomembers", "order"]
        if action == "sudorule":
            invalid.extend(["host", "hostgroup", "hostmask", "user", "group",
                            "runasuser", "runasgroup", "allow_sudocmd",
                            "allow_sudocmdgroup", "deny_sudocmd",
                            "deny_sudocmdgroup", "sudooption"])

    elif state in ["enabled", "disabled"]:
        if len(names) < 1:
            ansible_module.fail_json(msg="No name given.")
        if action == "member":
            ansible_module.fail_json(
                msg="Action member can not be used with states enabled and "
                "disabled")
        invalid = ["description", "usercategory", "hostcategory",
                   "cmdcategory", "runasusercategory", "runasgroupcategory",
                   "nomembers", "nomembers", "host", "hostgroup", "hostmask",
                   "user", "group", "allow_sudocmd", "allow_sudocmdgroup",
                   "deny_sudocmd", "deny_sudocmdgroup", "runasuser",
                   "runasgroup", "order", "sudooption"]
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
            # Make sure sudorule exists
            res_find = find_sudorule(ansible_module, name)

            # Create command
            if state == "present":
                # Generate args
                args = gen_args(description, usercategory, hostcategory,
                                cmdcategory, runasusercategory,
                                runasgroupcategory, order, nomembers)
                if action == "sudorule":
                    # Found the sudorule
                    if res_find is not None:
                        # Remove empty usercategory, hostcategory,
                        # cmdcaterory, runasusercategory and hostcategory
                        # from args if "" and if the category is not in the
                        # sudorule. The empty string is used to reset the
                        # category.
                        remove_args = [
                            "usercategory", "hostcategory", "cmdcategory",
                            "ipasudorunasusercategory",
                            "ipasudorunasgroupcategory",
                        ]
                        for arg in remove_args:
                            if args.get(arg) == "" and arg not in res_find:
                                del args[arg]

                        # For all settings is args, check if there are
                        # different settings in the find result.
                        # If yes: modify
                        if not compare_args_ipa(ansible_module, args,
                                                res_find):
                            commands.append([name, "sudorule_mod", args])
                    else:
                        commands.append([name, "sudorule_add", args])
                        # Set res_find to empty dict for next step
                        res_find = {}

                elif action == "member":
                    if res_find is None:
                        ansible_module.fail_json(msg="No sudorule '%s'" % name)

            elif state == "absent":
                if action == "sudorule":
                    if res_find is not None:
                        commands.append([name, "sudorule_del", {}])

                elif action == "member":
                    if res_find is None:
                        ansible_module.fail_json(msg="No sudorule '%s'" % name)

            elif state == "enabled":
                if res_find is None:
                    ansible_module.fail_json(msg="No sudorule '%s'" % name)
                # sudorule_enable is not failing on an enabled sudorule
                # Therefore it is needed to have a look at the ipaenabledflag
                # in res_find.
                # FreeIPA 4.9.10+ and 4.10 use proper mapping for
                # boolean values, so we need to convert it to str
                # for comparison.
                # See: https://github.com/freeipa/freeipa/pull/6294
                enabled_flag = str(res_find.get("ipaenabledflag", [False])[0])
                if enabled_flag.upper() != "TRUE":
                    commands.append([name, "sudorule_enable", {}])

            elif state == "disabled":
                if res_find is None:
                    ansible_module.fail_json(msg="No sudorule '%s'" % name)
                # sudorule_disable is not failing on an disabled sudorule
                # Therefore it is needed to have a look at the ipaenabledflag
                # in res_find.
                # FreeIPA 4.9.10+ and 4.10 use proper mapping for
                # boolean values, so we need to convert it to str
                # for comparison.
                # See: https://github.com/freeipa/freeipa/pull/6294
                enabled_flag = str(res_find.get("ipaenabledflag", [False])[0])
                if enabled_flag.upper() != "FALSE":
                    commands.append([name, "sudorule_disable", {}])

            else:
                ansible_module.fail_json(msg="Unkown state '%s'" % state)

            # Manage members

            commands.extend(
                gen_member_manage_commands(
                    ansible_module,
                    res_find,
                    name,
                    "sudorule_add_host",
                    "sudorule_remove_host",
                    create_ipa_mapping(
                        ipa_api_map(
                            "host", "host", "memberhost_host",
                            transform={"host": transform_host_param},
                        ),
                        ipa_api_map(
                            "hostgroup", "hostgroup", "memberhost_hostgroup",
                            transform={"hostgroup": transform_lowercase},
                        ),
                        ipa_api_map(
                            "hostmask", "hostmask", "hostmask",
                            transform={
                                "hostmask": transform_hostmask
                            },
                        ),
                    ),
                )
            )

            commands.extend(
                gen_member_manage_commands(
                    ansible_module,
                    res_find,
                    name,
                    "sudorule_add_user",
                    "sudorule_remove_user",
                    create_ipa_mapping(
                        ipa_api_map(
                            "user", "user", "memberuser_user",
                            transform={"user": transform_lowercase},
                        ),
                        ipa_api_map(
                            "group", "group", "memberuser_group",
                            transform={"group": transform_lowercase},
                        ),
                    ),
                )
            )

            commands.extend(
                gen_member_manage_commands(
                    ansible_module,
                    res_find,
                    name,
                    "sudorule_add_allow_command",
                    "sudorule_remove_allow_command",
                    create_ipa_mapping(
                        ipa_api_map(
                            "sudocmd",
                            "allow_sudocmd",
                            "memberallowcmd_sudocmd",
                        ),
                        ipa_api_map(
                            "sudocmdgroup",
                            "allow_sudocmdgroup",
                            "memberallowcmd_sudocmdgroup",
                            transform={
                                "allow_sudocmdgroup": transform_lowercase
                            },
                        ),
                    ),
                )
            )

            commands.extend(
                gen_member_manage_commands(
                    ansible_module,
                    res_find,
                    name,
                    "sudorule_add_deny_command",
                    "sudorule_remove_deny_command",
                    create_ipa_mapping(
                        ipa_api_map(
                            "sudocmd",
                            "deny_sudocmd",
                            "memberdenycmd_sudocmd",
                        ),
                        ipa_api_map(
                            "sudocmdgroup",
                            "deny_sudocmdgroup",
                            "memberdenycmd_sudocmdgroup",
                            transform={
                                "deny_sudocmdgroup": transform_lowercase
                            },
                        ),
                    ),
                )
            )

            commands.extend(
                gen_member_manage_commands(
                    ansible_module,
                    res_find,
                    name,
                    "sudorule_add_runasuser",
                    "sudorule_remove_runasuser",
                    create_ipa_mapping(
                        ipa_api_map(
                            "user",
                            "runasuser",
                            ("ipasudorunas_user", "ipasudorunasextuser"),
                            transform={"runasuser": transform_lowercase},
                        ),
                    ),
                )
            )

            commands.extend(
                gen_member_manage_commands(
                    ansible_module,
                    res_find,
                    name,
                    "sudorule_add_runasgroup",
                    "sudorule_remove_runasgroup",
                    create_ipa_mapping(
                        ipa_api_map(
                            "group",
                            "runasgroup",
                            (
                                "ipasudorunasgroup_group",
                                "ipasudorunasextgroup"
                            ),
                            transform={
                                "runasgroup": transform_lowercase
                            },
                        ),
                    ),
                )
            )

            commands.extend(
                gen_member_manage_commands(
                    ansible_module,
                    res_find,
                    name,
                    "sudorule_add_option",
                    "sudorule_remove_option",
                    create_ipa_mapping(
                        ipa_api_map(
                            "ipasudoopt", "sudooption", "ipasudoopt",
                        ),
                    ),
                    batch_update=False
                )
            )

        # Execute commands
        changed = ansible_module.execute_ipa_commands(
            commands, fail_on_member_errors=True)

    # Done

    ansible_module.exit_json(changed=changed, **exit_args)


if __name__ == "__main__":
    main()

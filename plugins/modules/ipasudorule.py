#!/usr/bin/python
# -*- coding: utf-8 -*-

# Authors:
#   Rafael Guterres Jeffman <rjeffman@redhat.com>
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
module: ipasudorule
short description: Manage FreeIPA sudo rules
description: Manage FreeIPA sudo rules
options:
  ipaadmin_principal:
    description: The admin principal
    default: admin
  ipaadmin_password:
    description: The admin password
    required: false
  name:
    description: The sudorule name
    required: true
    aliases: ["cn"]
  description:
    description: The sudorule description
    required: false
  user:
    description: List of users assigned to the sudo rule.
    required: false
  usercat:
    description: User category the sudo rule applies to
    required: false
    choices: ["all"]
    aliases: ["usercategory"]
  usergroup:
    description: List of user groups assigned to the sudo rule.
    required: false
  runasgroupcat:
    description: RunAs Group category applied to the sudo rule.
    required: false
    choices: ["all"]
    aliases: ["runasgroupcategory"]
  runasusercat:
    description: RunAs User category applied to the sudorule.
    required: false
    choices: ["all"]
    aliases: ["runasusercategory"]
  nomembers:
    description: Suppress processing of membership attributes
    required: false
    type: bool
  host:
    description: List of host names assigned to this sudorule.
    required: false
    type: list
  hostgroup:
    description: List of host groups assigned to this sudorule.
    required: false
    type: list
  hostcat:
    description: Host category the sudo rule applies to.
    required: false
    choices: ["all"]
    aliases: ["hostcategory"]
  sudocmds:
    description: List of sudocmds assigned to this sudorule.
    required: false
    type: list
    aliases: ["cmd"]
  sudocmdgroups:
    description: List of sudocmd groups assigned to this sudorule.
    required: false
    type: list
    aliases: ["cmdgroup"]
  cmdcat:
    description: Cammand category the sudo rule applies to
    required: false
    choices: ["all"]
    aliases: ['cmdcategory']
  action:
    description: Work on sudorule or member level
    default: sudorule
    choices: ["member", "sudorule"]
  state:
    description: State to ensure
    default: present
    choices: ["present", "absent", "enabled", "disabled"]
author:
    - Rafael Jeffman
"""

EXAMPLES = """
# Ensure Sudo Rule tesrule1 is present
- ipasudorule:
    ipaadmin_password: MyPassword123
    name: testrule1

# Ensure sudocmd is present in Sudo Rule
- ipasudorule:
  ipaadmin_password: pass1234
  name: testrule1
  sudocmds:
  - /sbin/ifconfig
  - /usr/bin/vim
  action: member
  state: absent

# Ensure host server is present in Sudo Rule
- ipasudorule:
    ipaadmin_password: MyPassword123
    name: testrule1
    host: server
    action: member

# Ensure hostgroup cluster is present in Sudo Rule
- ipasudorule:
    ipaadmin_password: MyPassword123
    name: testrule1
    hostgroup: cluster
    action: member

# Ensure sudo rule for usercategory "all"
- ipasudorule:
    ipaadmin_password: MyPassword123
    name: allusers
    usercat: all
    action: enabled

# Ensure sudo rule for hostcategory "all"
- ipasudorule:
    ipaadmin_password: MyPassword123
    name: allhosts
    hostcat: all
    action: enabled

# Ensure Sudo Rule tesrule1 is absent
- ipasudorule:
    ipaadmin_password: MyPassword123
    name: testrule1
    state: absent
"""

RETURN = """
"""

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.ansible_freeipa_module import temp_kinit, \
    temp_kdestroy, valid_creds, api_connect, api_command, compare_args_ipa, \
    module_params_get


def find_sudorule(module, name):
    _args = {
        "all": True,
        "cn": name,
    }

    _result = api_command(module, "sudorule_find", name, _args)

    if len(_result["result"]) > 1:
        module.fail_json(
            msg="There is more than one sudorule '%s'" % (name))
    elif len(_result["result"]) == 1:
        return _result["result"][0]
    else:
        return None


def gen_args(description, usercat, hostcat, cmdcat, runasusercat,
             runasgroupcat, nomembers):
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
        _args['runasusercategory'] = runasusercat
    if runasgroupcat is not None:
        _args['runasgroupcategory'] = runasgroupcat
    if nomembers is not None:
        _args['nomembers'] = nomembers

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
            description=dict(required=False, type="str", default=None),
            usercat=dict(required=False, type="str", default=None,
                         choices=["all"], aliases=["usercategory"]),
            hostcat=dict(required=False, type="str", default=None,
                         choices=["all"], aliases=["hostcategory"]),
            nomembers=dict(required=False, type='bool', default=None),
            host=dict(required=False, type='list', default=None),
            hostgroup=dict(required=False, type='list', default=None),
            user=dict(required=False, type='list', default=None),
            group=dict(required=False, type='list', default=None),
            sudocmds=dict(required=False, type="list", default=None,
                          aliases=['cmd']),
            sudocmdgroups=dict(required=False, type="list", default=None,
                               aliases=['cmdgroup']),
            cmdcat=dict(required=False, type="str", default=None,
                        choices=["all"], aliases=["cmdcategory"]),
            runasusercat=dict(required=False, type="str", default=None,
                              choices=["all"], aliases=["runasusercategory"]),
            runasgroupcan=dict(required=False, type="str", default=None,
                               choices=["all"],
                               aliases=["runasgroupcategory"]),
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
    ipaadmin_principal = module_params_get(ansible_module,
                                           "ipaadmin_principal")
    ipaadmin_password = module_params_get(ansible_module, "ipaadmin_password")
    names = module_params_get(ansible_module, "name")

    # present
    # The 'noqa' variables are not used here, but required for vars().
    # The use of 'noqa' ensures flake8 does not complain about them.
    description = module_params_get(ansible_module, "description")
    cmdcat = module_params_get(ansible_module, 'cmdcat')
    usercat = module_params_get(ansible_module, "usercat")
    hostcat = module_params_get(ansible_module, "hostcat")
    runasusercat = module_params_get(ansible_module, "runasusercat")
    runasgroupcat = module_params_get(ansible_module, "runasgroupcat")
    hostcat = module_params_get(ansible_module, "hostcat")
    nomembers = module_params_get(ansible_module, "nomembers")
    host = module_params_get(ansible_module, "host")
    hostgroup = module_params_get(ansible_module, "hostgroup")
    user = module_params_get(ansible_module, "user")
    group = module_params_get(ansible_module, "group")
    sudocmds = module_params_get(ansible_module, 'cmd')
    sudocmdgroups = module_params_get(ansible_module, 'cmdgroup')
    action = module_params_get(ansible_module, "action")

    # state
    state = module_params_get(ansible_module, "state")

    # Check parameters

    if state == "present":
        if len(names) != 1:
            ansible_module.fail_json(
                msg="Only one sudorule can be added at a time.")
        if action == "member":
            invalid = ["description", "usercat", "hostcat", "cmdcat",
                       "runasusercat", "runasgroupcat", "nomembers"]

            for x in invalid:
                if x in vars() and vars()[x] is not None:
                    ansible_module.fail_json(
                        msg="Argument '%s' can not be used with action "
                        "'%s'" % (x, action))

    elif state == "absent":
        if len(names) < 1:
            ansible_module.fail_json(msg="No name given.")
        invalid = ["description", "usercat", "hostcat", "cmdcat",
                   "runasusercat", "runasgroupcat", "nomembers"]
        if action == "sudorule":
            invalid.extend(["host", "hostgroup", "user", "group",
                            "sudocmds", "sudocmdgroups"])
        for x in invalid:
            if vars()[x] is not None:
                ansible_module.fail_json(
                    msg="Argument '%s' can not be used with state '%s'" %
                    (x, state))

    elif state in ["enabled", "disabled"]:
        if len(names) < 1:
            ansible_module.fail_json(msg="No name given.")
        if action == "member":
            ansible_module.fail_json(
                msg="Action member can not be used with states enabled and "
                "disabled")
        invalid = ["description", "usercat", "hostcat", "cmdcat",
                   "runasusercat", "runasgroupcat", "nomembers", "nomembers",
                   "host", "hostgroup", "user", "group", "sudocmds",
                   "sudocmdgroups"]
        for x in invalid:
            if vars()[x] is not None:
                ansible_module.fail_json(
                    msg="Argument '%s' can not be used with state '%s'" %
                    (x, state))
    else:
        ansible_module.fail_json(msg="Invalid state '%s'" % state)

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
            # Make sure sudorule exists
            res_find = find_sudorule(ansible_module, name)

            # Create command
            if state == "present":
                # Generate args
                args = gen_args(description, usercat, hostcat, cmdcat,
                                runasusercat, runasgroupcat, nomembers)
                if action == "sudorule":
                    # Found the sudorule
                    if res_find is not None:
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

                    # Generate addition and removal lists
                    host_add = list(
                        set(host or []) -
                        set(res_find.get("member_host", [])))
                    host_del = list(
                        set(res_find.get("member_host", [])) -
                        set(host or []))
                    hostgroup_add = list(
                        set(hostgroup or []) -
                        set(res_find.get("member_hostgroup", [])))
                    hostgroup_del = list(
                        set(res_find.get("member_hostgroup", [])) -
                        set(hostgroup or []))

                    user_add = list(
                        set(user or []) -
                        set(res_find.get("member_user", [])))
                    user_del = list(
                        set(res_find.get("member_user", [])) -
                        set(user or []))
                    group_add = list(
                        set(group or []) -
                        set(res_find.get("member_group", [])))
                    group_del = list(
                        set(res_find.get("member_group", [])) -
                        set(group or []))

                    cmd_add = list(
                        set(sudocmds or []) -
                        set(res_find.get("member_cmd", [])))
                    cmd_del = list(
                        set(res_find.get("member_cmd", [])) -
                        set(sudocmds or []))
                    cmdgroup_add = list(
                        set(sudocmdgroups or []) -
                        set(res_find.get("member_cmdgroup", [])))
                    cmdgroup_del = list(
                        set(res_find.get("member_cmdgroup", [])) -
                        set(sudocmdgroups or []))

                    # Add hosts and hostgroups
                    if len(host_add) > 0 or len(hostgroup_add) > 0:
                        commands.append([name, "sudorule_add_host",
                                         {
                                             "host": host_add,
                                             "hostgroup": hostgroup_add,
                                         }])
                    # Remove hosts and hostgroups
                    if len(host_del) > 0 or len(hostgroup_del) > 0:
                        commands.append([name, "sudorule_remove_host",
                                         {
                                             "host": host_del,
                                             "hostgroup": hostgroup_del,
                                         }])

                    # Add users and groups
                    if len(user_add) > 0 or len(group_add) > 0:
                        commands.append([name, "sudorule_add_user",
                                         {
                                             "user": user_add,
                                             "group": group_add,
                                         }])
                    # Remove users and groups
                    if len(user_del) > 0 or len(group_del) > 0:
                        commands.append([name, "sudorule_remove_user",
                                         {
                                             "user": user_del,
                                             "group": group_del,
                                         }])

                    # Add commands
                    if len(cmd_add) > 0 or len(cmdgroup_add) > 0:
                        commands.append([name, "sudorule_add_allow_command",
                                         {
                                             "sudocmd": cmd_add,
                                             "sudocmdgroup": cmdgroup_add,
                                         }])

                    if len(cmd_del) > 0 or len(cmdgroup_del) > 0:
                        commands.append([name, "sudorule_add_deny_command",
                                         {
                                             "sudocmd": cmd_del,
                                             "sudocmdgroup": cmdgroup_del
                                         }])

                elif action == "member":
                    if res_find is None:
                        ansible_module.fail_json(msg="No sudorule '%s'" % name)

                    # Add hosts and hostgroups
                    if host is not None or hostgroup is not None:
                        commands.append([name, "sudorule_add_host",
                                         {
                                             "host": host,
                                             "hostgroup": hostgroup,
                                         }])

                    # Add users and groups
                    if user is not None or group is not None:
                        commands.append([name, "sudorule_add_user",
                                         {
                                             "user": user,
                                             "group": group,
                                         }])

                    # Add commands
                    if sudocmds is not None:
                        commands.append([name, "sudorule_add_allow_command",
                                         {
                                             "sudocmd": sudocmds,
                                         }])

            elif state == "absent":
                if action == "sudorule":
                    if res_find is not None:
                        commands.append([name, "sudorule_del", {}])

                elif action == "member":
                    if res_find is None:
                        ansible_module.fail_json(msg="No sudorule '%s'" % name)

                    # Remove hosts and hostgroups
                    if host is not None or hostgroup is not None:
                        commands.append([name, "sudorule_remove_host",
                                         {
                                             "host": host,
                                             "hostgroup": hostgroup,
                                         }])

                    # Remove users and groups
                    if user is not None or group is not None:
                        commands.append([name, "sudorule_remove_user",
                                         {
                                             "user": user,
                                             "group": group,
                                         }])

                    # Remove commands
                    if sudocmds is not None:
                        commands.append([name, "sudorule_add_deny_command",
                                         {
                                             "sudocmd": sudocmds,
                                         }])

            elif state == "enabled":
                if res_find is None:
                    ansible_module.fail_json(msg="No sudorule '%s'" % name)
                # sudorule_enable is not failing on an enabled sudorule
                # Therefore it is needed to have a look at the ipaenabledflag
                # in res_find.
                if "ipaenabledflag" not in res_find or \
                   res_find["ipaenabledflag"][0] != "TRUE":
                    commands.append([name, "sudorule_enable", {}])

            elif state == "disabled":
                if res_find is None:
                    ansible_module.fail_json(msg="No sudorule '%s'" % name)
                # sudorule_disable is not failing on an disabled sudorule
                # Therefore it is needed to have a look at the ipaenabledflag
                # in res_find.
                if "ipaenabledflag" not in res_find or \
                   res_find["ipaenabledflag"][0] != "FALSE":
                    commands.append([name, "sudorule_disable", {}])

            else:
                ansible_module.fail_json(msg="Unkown state '%s'" % state)

        # Execute commands

        errors = []
        for name, command, args in commands:
            try:
                result = api_command(ansible_module, command, name,
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
            if "failed" in result and len(result["failed"]) > 0:
                for item in result["failed"]:
                    failed_item = result["failed"][item]
                    for member_type in failed_item:
                        for member, failure in failed_item[member_type]:
                            if "already a member" in failure \
                               or "not a member" in failure:
                                continue
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

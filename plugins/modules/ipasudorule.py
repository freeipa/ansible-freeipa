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
extends_documentation_fragment:
  - ipamodule_base_docs
options:
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
  usercategory:
    description: User category the sudo rule applies to
    required: false
    choices: ["all", ""]
    aliases: ["usercat"]
  group:
    description: List of user groups assigned to the sudo rule.
    required: false
  runasgroupcategory:
    description: RunAs Group category applied to the sudo rule.
    required: false
    choices: ["all", ""]
    aliases: ["runasgroupcat"]
  runasusercategory:
    description: RunAs User category applied to the sudorule.
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
  hostgroup:
    description: List of host groups assigned to this sudorule.
    required: false
    type: list
  hostcategory:
    description: Host category the sudo rule applies to.
    required: false
    choices: ["all", ""]
    aliases: ["hostcat"]
  allow_sudocmd:
    description: List of allowed sudocmds assigned to this sudorule.
    required: false
    type: list
  allow_sudocmdgroup:
    description: List of allowed sudocmd groups assigned to this sudorule.
    required: false
    type: list
  deny_sudocmd:
    description: List of denied sudocmds assigned to this sudorule.
    required: false
    type: list
  deny_sudocmdgroup:
    description: List of denied sudocmd groups assigned to this sudorule.
    required: false
    type: list
  cmdcategory:
    description: Command category the sudo rule applies to
    required: false
    choices: ["all", ""]
    aliases: ["cmdcat"]
  order:
    description: Order to apply this rule.
    required: false
    type: int
  sudooption:
    description: List of sudo options.
    required: false
    type: list
    aliases: ["options"]
  runasuser:
    description: List of users for Sudo to execute as.
    required: false
    type: list
  runasgroup:
    description: List of groups for Sudo to execute as.
    required: false
    type: list
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

# Ensure sudo rule for usercategory "all"
- ipasudorule:
    ipaadmin_password: SomeADMINpassword
    name: allusers
    usercategory: all
    action: enabled

# Ensure sudo rule for hostcategory "all"
- ipasudorule:
    ipaadmin_password: SomeADMINpassword
    name: allhosts
    hostcategory: all
    action: enabled

# Ensure Sudo Rule tesrule1 is absent
- ipasudorule:
    ipaadmin_password: SomeADMINpassword
    name: testrule1
    state: absent
"""

RETURN = """
"""

from ansible.module_utils.ansible_freeipa_module import \
    IPAAnsibleModule, compare_args_ipa, gen_add_del_lists, gen_add_list, \
    gen_intersection_list


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
            name=dict(type="list", aliases=["cn"], default=None,
                      required=True),
            # present
            description=dict(required=False, type="str", default=None),
            usercategory=dict(required=False, type="str", default=None,
                              choices=["all", ""], aliases=['usercat']),
            hostcategory=dict(required=False, type="str", default=None,
                              choices=["all", ""], aliases=['hostcat']),
            nomembers=dict(required=False, type='bool', default=None),
            host=dict(required=False, type='list', default=None),
            hostgroup=dict(required=False, type='list', default=None),
            user=dict(required=False, type='list', default=None),
            group=dict(required=False, type='list', default=None),
            allow_sudocmd=dict(required=False, type="list", default=None),
            deny_sudocmd=dict(required=False, type="list", default=None),
            allow_sudocmdgroup=dict(required=False, type="list", default=None),
            deny_sudocmdgroup=dict(required=False, type="list", default=None),
            cmdcategory=dict(required=False, type="str", default=None,
                             choices=["all", ""], aliases=['cmdcat']),
            runasusercategory=dict(required=False, type="str", default=None,
                                   choices=["all", ""],
                                   aliases=['runasusercat']),
            runasgroupcategory=dict(required=False, type="str", default=None,
                                    choices=["all", ""],
                                    aliases=['runasgroupcat']),
            runasuser=dict(required=False, type="list", default=None),
            runasgroup=dict(required=False, type="list", default=None),
            order=dict(type="int", required=False, aliases=['sudoorder']),
            sudooption=dict(required=False, type='list', default=None,
                            aliases=["options"]),
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
    # The 'noqa' variables are not used here, but required for vars().
    # The use of 'noqa' ensures flake8 does not complain about them.
    description = ansible_module.params_get("description")  # noqa
    cmdcategory = ansible_module.params_get('cmdcategory')  # noqa
    usercategory = ansible_module.params_get("usercategory")  # noqa
    hostcategory = ansible_module.params_get("hostcategory")  # noqa
    runasusercategory = ansible_module.params_get(          # noqa
                                          "runasusercategory")
    runasgroupcategory = ansible_module.params_get(         # noqa
                                           "runasgroupcategory")
    hostcategory = ansible_module.params_get("hostcategory")  # noqa
    nomembers = ansible_module.params_get("nomembers")  # noqa
    host = ansible_module.params_get("host")
    hostgroup = ansible_module.params_get("hostgroup")
    user = ansible_module.params_get("user")
    group = ansible_module.params_get("group")
    allow_sudocmd = ansible_module.params_get('allow_sudocmd')
    allow_sudocmdgroup = ansible_module.params_get('allow_sudocmdgroup')
    deny_sudocmd = ansible_module.params_get('deny_sudocmd')
    deny_sudocmdgroup = ansible_module.params_get('deny_sudocmdgroup')
    sudooption = ansible_module.params_get("sudooption")
    order = ansible_module.params_get("order")
    runasuser = ansible_module.params_get("runasuser")
    runasgroup = ansible_module.params_get("runasgroup")
    action = ansible_module.params_get("action")

    # state
    state = ansible_module.params_get("state")

    # Check parameters

    if state == "present":
        if len(names) != 1:
            ansible_module.fail_json(
                msg="Only one sudorule can be added at a time.")
        if action == "member":
            invalid = ["description", "usercategory", "hostcategory",
                       "cmdcategory", "runasusercategory",
                       "runasgroupcategory", "order", "nomembers"]

            for arg in invalid:
                if arg in vars() and vars()[arg] is not None:
                    ansible_module.fail_json(
                        msg="Argument '%s' can not be used with action "
                        "'%s'" % (arg, action))
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
            invalid.extend(["host", "hostgroup", "user", "group",
                            "runasuser", "runasgroup", "allow_sudocmd",
                            "allow_sudocmdgroup", "deny_sudocmd",
                            "deny_sudocmdgroup", "sudooption"])
        for arg in invalid:
            if vars()[arg] is not None:
                ansible_module.fail_json(
                    msg="Argument '%s' can not be used with state '%s'" %
                    (arg, state))

    elif state in ["enabled", "disabled"]:
        if len(names) < 1:
            ansible_module.fail_json(msg="No name given.")
        if action == "member":
            ansible_module.fail_json(
                msg="Action member can not be used with states enabled and "
                "disabled")
        invalid = ["description", "usercategory", "hostcategory",
                   "cmdcategory", "runasusercategory", "runasgroupcategory",
                   "nomembers", "nomembers", "host", "hostgroup",
                   "user", "group", "allow_sudocmd", "allow_sudocmdgroup",
                   "deny_sudocmd", "deny_sudocmdgroup", "runasuser",
                   "runasgroup", "order", "sudooption"]
        for arg in invalid:
            if vars()[arg] is not None:
                ansible_module.fail_json(
                    msg="Argument '%s' can not be used with state '%s'" %
                    (arg, state))
    else:
        ansible_module.fail_json(msg="Invalid state '%s'" % state)

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
                        if "usercategory" in args \
                           and args["usercategory"] == "" \
                           and "usercategory" not in res_find:
                            del args["usercategory"]
                        if "hostcategory" in args \
                           and args["hostcategory"] == "" \
                           and "hostcategory" not in res_find:
                            del args["hostcategory"]
                        if "cmdcategory" in args \
                           and args["cmdcategory"] == "" \
                           and "cmdcategory" not in res_find:
                            del args["cmdcategory"]
                        if "ipasudorunasusercategory" in args \
                           and args["ipasudorunasusercategory"] == "" \
                           and "ipasudorunasusercategory" not in res_find:
                            del args["ipasudorunasusercategory"]
                        if "ipasudorunasgroupcategory" in args \
                           and args["ipasudorunasgroupcategory"] == "" \
                           and "ipasudorunasgroupcategory" not in res_find:
                            del args["ipasudorunasgroupcategory"]

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
                    host_add, host_del = gen_add_del_lists(
                        host, res_find.get('memberhost_host', []))

                    hostgroup_add, hostgroup_del = gen_add_del_lists(
                        hostgroup, res_find.get('memberhost_hostgroup', []))

                    user_add, user_del = gen_add_del_lists(
                        user, res_find.get('memberuser_user', []))

                    group_add, group_del = gen_add_del_lists(
                        group, res_find.get('memberuser_group', []))

                    allow_cmd_add, allow_cmd_del = gen_add_del_lists(
                        allow_sudocmd,
                        res_find.get('memberallowcmd_sudocmd', []))

                    allow_cmdgroup_add, allow_cmdgroup_del = gen_add_del_lists(
                        allow_sudocmdgroup,
                        res_find.get('memberallowcmd_sudocmdgroup', []))

                    deny_cmd_add, deny_cmd_del = gen_add_del_lists(
                        deny_sudocmd,
                        res_find.get('memberdenycmd_sudocmd', []))

                    deny_cmdgroup_add, deny_cmdgroup_del = gen_add_del_lists(
                        deny_sudocmdgroup,
                        res_find.get('memberdenycmd_sudocmdgroup', []))

                    sudooption_add, sudooption_del = gen_add_del_lists(
                        sudooption, res_find.get('ipasudoopt', []))

                    runasuser_add, runasuser_del = gen_add_del_lists(
                        runasuser, res_find.get('ipasudorunas_user', []))

                    runasgroup_add, runasgroup_del = gen_add_del_lists(
                        runasgroup, res_find.get('ipasudorunas_group', []))

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

                    # Add commands allowed
                    if len(allow_cmd_add) > 0 or len(allow_cmdgroup_add) > 0:
                        commands.append([name, "sudorule_add_allow_command",
                                         {"sudocmd": allow_cmd_add,
                                          "sudocmdgroup": allow_cmdgroup_add,
                                          }])

                    if len(allow_cmd_del) > 0 or len(allow_cmdgroup_del) > 0:
                        commands.append([name, "sudorule_remove_allow_command",
                                         {"sudocmd": allow_cmd_del,
                                          "sudocmdgroup": allow_cmdgroup_del
                                          }])

                    # Add commands denied
                    if len(deny_cmd_add) > 0 or len(deny_cmdgroup_add) > 0:
                        commands.append([name, "sudorule_add_deny_command",
                                         {"sudocmd": deny_cmd_add,
                                          "sudocmdgroup": deny_cmdgroup_add,
                                          }])

                    if len(deny_cmd_del) > 0 or len(deny_cmdgroup_del) > 0:
                        commands.append([name, "sudorule_remove_deny_command",
                                         {"sudocmd": deny_cmd_del,
                                          "sudocmdgroup": deny_cmdgroup_del
                                          }])

                    # Add RunAS Users
                    if len(runasuser_add) > 0:
                        commands.append([name, "sudorule_add_runasuser",
                                         {"user": runasuser_add}])
                    # Remove RunAS Users
                    if len(runasuser_del) > 0:
                        commands.append([name, "sudorule_remove_runasuser",
                                         {"user": runasuser_del}])

                    # Add RunAS Groups
                    if len(runasgroup_add) > 0:
                        commands.append([name, "sudorule_add_runasgroup",
                                         {"group": runasgroup_add}])
                    # Remove RunAS Groups
                    if len(runasgroup_del) > 0:
                        commands.append([name, "sudorule_remove_runasgroup",
                                         {"group": runasgroup_del}])

                    # Add sudo options
                    for sudoopt in sudooption_add:
                        commands.append([name, "sudorule_add_option",
                                         {"ipasudoopt": sudoopt}])

                    # Remove sudo options
                    for sudoopt in sudooption_del:
                        commands.append([name, "sudorule_remove_option",
                                         {"ipasudoopt": sudoopt}])

                elif action == "member":
                    if res_find is None:
                        ansible_module.fail_json(msg="No sudorule '%s'" % name)

                    # Generate add lists for host, hostgroup, user, group,
                    # allow_sudocmd, allow_sudocmdgroup, deny_sudocmd,
                    # deny_sudocmdgroup, sudooption, runasuser, runasgroup
                    # and res_find to only try to add the items that not in
                    # the sudorule already
                    if host is not None and \
                       "memberhost_host" in res_find:
                        host = gen_add_list(
                            host, res_find["memberhost_host"])
                    if hostgroup is not None and \
                       "memberhost_hostgroup" in res_find:
                        hostgroup = gen_add_list(
                            hostgroup, res_find["memberhost_hostgroup"])
                    if user is not None and \
                       "memberuser_user" in res_find:
                        user = gen_add_list(
                            user, res_find["memberuser_user"])
                    if group is not None and \
                       "memberuser_group" in res_find:
                        group = gen_add_list(
                            group, res_find["memberuser_group"])
                    if allow_sudocmd is not None and \
                       "memberallowcmd_sudocmd" in res_find:
                        allow_sudocmd = gen_add_list(
                            allow_sudocmd, res_find["memberallowcmd_sudocmd"])
                    if allow_sudocmdgroup is not None and \
                       "memberallowcmd_sudocmdgroup" in res_find:
                        allow_sudocmdgroup = gen_add_list(
                            allow_sudocmdgroup,
                            res_find["memberallowcmd_sudocmdgroup"])
                    if deny_sudocmd is not None and \
                       "memberdenycmd_sudocmd" in res_find:
                        deny_sudocmd = gen_add_list(
                            deny_sudocmd, res_find["memberdenycmd_sudocmd"])
                    if deny_sudocmdgroup is not None and \
                       "memberdenycmd_sudocmdgroup" in res_find:
                        deny_sudocmdgroup = gen_add_list(
                            deny_sudocmdgroup,
                            res_find["memberdenycmd_sudocmdgroup"])
                    if sudooption is not None and \
                       "ipasudoopt" in res_find:
                        sudooption = gen_add_list(
                            sudooption, res_find["ipasudoopt"])
                    if runasuser is not None and \
                       "ipasudorunas_user" in res_find:
                        runasuser = gen_add_list(
                            runasuser, res_find["ipasudorunas_user"])
                    if runasgroup is not None and \
                       "ipasudorunasgroup_group" in res_find:
                        runasgroup = gen_add_list(
                            runasgroup, res_find["ipasudorunasgroup_group"])

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
                    if allow_sudocmd is not None \
                       or allow_sudocmdgroup is not None:
                        commands.append([name, "sudorule_add_allow_command",
                                         {"sudocmd": allow_sudocmd,
                                          "sudocmdgroup": allow_sudocmdgroup,
                                          }])

                    # Add commands
                    if deny_sudocmd is not None \
                       or deny_sudocmdgroup is not None:
                        commands.append([name, "sudorule_add_deny_command",
                                         {"sudocmd": deny_sudocmd,
                                          "sudocmdgroup": deny_sudocmdgroup,
                                          }])

                    # Add RunAS Users
                    if runasuser is not None and len(runasuser) > 0:
                        commands.append([name, "sudorule_add_runasuser",
                                         {"user": runasuser}])

                    # Add RunAS Groups
                    if runasgroup is not None and len(runasgroup) > 0:
                        commands.append([name, "sudorule_add_runasgroup",
                                         {"group": runasgroup}])

                    # Add options
                    if sudooption is not None:
                        existing_opts = res_find.get('ipasudoopt', [])
                        for sudoopt in sudooption:
                            if sudoopt not in existing_opts:
                                commands.append([name, "sudorule_add_option",
                                                 {"ipasudoopt": sudoopt}])

            elif state == "absent":
                if action == "sudorule":
                    if res_find is not None:
                        commands.append([name, "sudorule_del", {}])

                elif action == "member":
                    if res_find is None:
                        ansible_module.fail_json(msg="No sudorule '%s'" % name)

                    # Generate intersection lists for host, hostgroup, user,
                    # group, allow_sudocmd, allow_sudocmdgroup, deny_sudocmd
                    # deny_sudocmdgroup, sudooption, runasuser, runasgroup
                    # and res_find to only try to remove the items that are
                    # in sudorule
                    if host is not None:
                        if "memberhost_host" in res_find:
                            host = gen_intersection_list(
                                host, res_find["memberhost_host"])
                        else:
                            host = None
                    if hostgroup is not None:
                        if "memberhost_hostgroup" in res_find:
                            hostgroup = gen_intersection_list(
                                hostgroup, res_find["memberhost_hostgroup"])
                        else:
                            hostgroup = None
                    if user is not None:
                        if "memberuser_user" in res_find:
                            user = gen_intersection_list(
                                user, res_find["memberuser_user"])
                        else:
                            user = None
                    if group is not None:
                        if "memberuser_group" in res_find:
                            group = gen_intersection_list(
                                group, res_find["memberuser_group"])
                        else:
                            group = None
                    if allow_sudocmd is not None:
                        if "memberallowcmd_sudocmd" in res_find:
                            allow_sudocmd = gen_intersection_list(
                                allow_sudocmd,
                                res_find["memberallowcmd_sudocmd"])
                        else:
                            allow_sudocmd = None
                    if allow_sudocmdgroup is not None:
                        if "memberallowcmd_sudocmdgroup" in res_find:
                            allow_sudocmdgroup = gen_intersection_list(
                                allow_sudocmdgroup,
                                res_find["memberallowcmd_sudocmdgroup"])
                        else:
                            allow_sudocmdgroup = None
                    if deny_sudocmd is not None:
                        if "memberdenycmd_sudocmd" in res_find:
                            deny_sudocmd = gen_intersection_list(
                                deny_sudocmd,
                                res_find["memberdenycmd_sudocmd"])
                        else:
                            deny_sudocmd = None
                    if deny_sudocmdgroup is not None:
                        if "memberdenycmd_sudocmdgroup" in res_find:
                            deny_sudocmdgroup = gen_intersection_list(
                                deny_sudocmdgroup,
                                res_find["memberdenycmd_sudocmdgroup"])
                        else:
                            deny_sudocmdgroup = None
                    if sudooption is not None:
                        if "ipasudoopt" in res_find:
                            sudooption = gen_intersection_list(
                                sudooption, res_find["ipasudoopt"])
                        else:
                            sudooption = None
                    if runasuser is not None:
                        if "ipasudorunas_user" in res_find:
                            runasuser = gen_intersection_list(
                                runasuser, res_find["ipasudorunas_user"])
                        else:
                            runasuser = None
                    if runasgroup is not None:
                        if "ipasudorunasgroup_group" in res_find:
                            runasgroup = gen_intersection_list(
                                runasgroup,
                                res_find["ipasudorunasgroup_group"])
                        else:
                            runasgroup = None

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

                    # Remove allow commands
                    if allow_sudocmd is not None \
                       or allow_sudocmdgroup is not None:
                        commands.append([name, "sudorule_remove_allow_command",
                                         {"sudocmd": allow_sudocmd,
                                          "sudocmdgroup": allow_sudocmdgroup
                                          }])

                    # Remove deny commands
                    if deny_sudocmd is not None \
                       or deny_sudocmdgroup is not None:
                        commands.append([name, "sudorule_remove_deny_command",
                                         {"sudocmd": deny_sudocmd,
                                          "sudocmdgroup": deny_sudocmdgroup
                                          }])

                    # Remove RunAS Users
                    if runasuser is not None:
                        commands.append([name, "sudorule_remove_runasuser",
                                         {"user": runasuser}])

                    # Remove RunAS Groups
                    if runasgroup is not None:
                        commands.append([name, "sudorule_remove_runasgroup",
                                         {"group": runasgroup}])

                    # Remove options
                    if sudooption is not None:
                        existing_opts = res_find.get('ipasudoopt', [])
                        for sudoopt in sudooption:
                            if sudoopt in existing_opts:
                                commands.append([name,
                                                 "sudorule_remove_option",
                                                 {"ipasudoopt": sudoopt}])

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

        # Check mode exit
        if ansible_module.check_mode:
            ansible_module.exit_json(changed=len(commands) > 0, **exit_args)

        # Execute commands

        errors = []
        for name, command, args in commands:
            try:
                result = ansible_module.ipa_command(command, name, args)

                if "completed" in result:
                    if result["completed"] > 0:
                        changed = True
                else:
                    changed = True
            except Exception as ex:
                ansible_module.fail_json(msg="%s: %s: %s" % (command, name,
                                                             str(ex)))
            # Get all errors
            # result are ignored. All others are reported.
            if "failed" in result and len(result["failed"]) > 0:
                for item in result["failed"]:
                    failed_item = result["failed"][item]
                    for member_type in failed_item:
                        for member, failure in failed_item[member_type]:
                            errors.append("%s: %s %s: %s" % (
                                command, member_type, member, failure))
        if len(errors) > 0:
            ansible_module.fail_json(msg=", ".join(errors))

    # Done

    ansible_module.exit_json(changed=changed, **exit_args)


if __name__ == "__main__":
    main()

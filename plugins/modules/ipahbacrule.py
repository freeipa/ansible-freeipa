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
module: ipahbacrule
short description: Manage FreeIPA HBAC rules
description: Manage FreeIPA HBAC rules
options:
  ipaadmin_principal:
    description: The admin principal
    default: admin
  ipaadmin_password:
    description: The admin password
    required: false
  name:
    description: The hbacrule name
    required: true
    aliases: ["cn"]
  description:
    description: The hbacrule description
    required: false
  usercategory:
    description: User category the rule applies to
    required: false
    aliases: ["usercat"]
    choices: ["all"]
  hostcategory:
    description: Host category the rule applies to
    required: false
    aliases: ["hostcat"]
    choices: ["all"]
  servicecategory:
    description: Service category the rule applies to
    required: false
    aliases: ["servicecat"]
    choices: ["all"]
  nomembers:
    description: Suppress processing of membership attributes
    required: false
    type: bool
  host:
    description: List of host names assigned to this hbacrule.
    required: false
    type: list
  hostgroup:
    description: List of host groups assigned to this hbacrule.
    required: false
    type: list
  hbacsvc:
    description: List of HBAC service names assigned to this hbacrule.
    required: false
    type: list
  hbacsvcgroup:
    description: List of HBAC service names assigned to this hbacrule.
    required: false
    type: list
  user:
    description: List of user names assigned to this hbacrule.
    required: false
    type: list
  group:
    description: List of user groups assigned to this hbacrule.
    required: false
    type: list
  action:
    description: Work on hbacrule or member level
    default: hbacrule
    choices: ["member", "hbacrule"]
  state:
    description: State to ensure
    default: present
    choices: ["present", "absent", "enabled", "disabled"]
author:
    - Thomas Woerner
"""

EXAMPLES = """
# Ensure HBAC Rule allhosts is present
- ipahbacrule:
    ipaadmin_password: MyPassword123
    name: allhosts
    usercategory: all

# Ensure host server is present in HBAC Rule allhosts
- ipahbacrule:
    ipaadmin_password: MyPassword123
    name: allhosts
    host: server
    action: member

# Ensure HBAC Rule sshd-pinky is present
- ipahbacrule:
    ipaadmin_password: MyPassword123
    name: sshd-pinky
    hostcategory: all

# Ensure user pinky is present in HBAC Rule sshd-pinky
- ipahbacrule:
    ipaadmin_password: MyPassword123
    name: sshd-pinky
    user: pinky
    action: member

# Ensure HBAC service sshd is present in HBAC Rule sshd-pinky
- ipahbacrule:
    ipaadmin_password: MyPassword123
    name: sshd-pinky
    hbacsvc: sshd
    action: member

# Ensure HBAC Rule sshd-pinky is disabled
- ipahbacrule:
    ipaadmin_password: MyPassword123
    name: sshd-pinky
    state: disabled

# Ensure HBAC Rule sshd-pinky is enabled
- ipahbacrule:
    ipaadmin_password: MyPassword123
    name: sshd-pinky
    state: enabled

# Ensure HBAC Rule sshd-pinky is absent
- ipahbacrule:
    ipaadmin_password: MyPassword123
    name: sshd-pinky
    state: absent
"""

RETURN = """
"""

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.ansible_freeipa_module import temp_kinit, \
    temp_kdestroy, valid_creds, api_connect, api_command, compare_args_ipa, \
    module_params_get


def find_hbacrule(module, name):
    _args = {
        "all": True,
        "cn": name,
    }

    _result = api_command(module, "hbacrule_find", name, _args)

    if len(_result["result"]) > 1:
        module.fail_json(
            msg="There is more than one hbacrule '%s'" % (name))
    elif len(_result["result"]) == 1:
        return _result["result"][0]
    else:
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
    ansible_module = AnsibleModule(
        argument_spec=dict(
            # general
            ipaadmin_principal=dict(type="str", default="admin"),
            ipaadmin_password=dict(type="str", required=False, no_log=True),

            name=dict(type="list", aliases=["cn"], default=None,
                      required=True),
            # present
            description=dict(type="str", default=None),
            usercategory=dict(type="str", default=None,
                              aliases=["usercat"], choices=["all"]),
            hostcategory=dict(type="str", default=None,
                              aliases=["hostcat"], choices=["all"]),
            servicecategory=dict(type="str", default=None,
                                 aliases=["servicecat"], choices=["all"]),
            nomembers=dict(required=False, type='bool', default=None),
            host=dict(required=False, type='list', default=None),
            hostgroup=dict(required=False, type='list', default=None),
            hbacsvc=dict(required=False, type='list', default=None),
            hbacsvcgroup=dict(required=False, type='list', default=None),
            user=dict(required=False, type='list', default=None),
            group=dict(required=False, type='list', default=None),
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
    ipaadmin_principal = module_params_get(ansible_module,
                                           "ipaadmin_principal")
    ipaadmin_password = module_params_get(ansible_module, "ipaadmin_password")
    names = module_params_get(ansible_module, "name")

    # present
    description = module_params_get(ansible_module, "description")
    usercategory = module_params_get(ansible_module, "usercategory")
    hostcategory = module_params_get(ansible_module, "hostcategory")
    servicecategory = module_params_get(ansible_module, "servicecategory")
    nomembers = module_params_get(ansible_module, "nomembers")
    host = module_params_get(ansible_module, "host")
    hostgroup = module_params_get(ansible_module, "hostgroup")
    hbacsvc = module_params_get(ansible_module, "hbacsvc")
    hbacsvcgroup = module_params_get(ansible_module, "hbacsvcgroup")
    user = module_params_get(ansible_module, "user")
    group = module_params_get(ansible_module, "group")
    action = module_params_get(ansible_module, "action")
    # state
    state = module_params_get(ansible_module, "state")

    # Check parameters

    if state == "present":
        if len(names) != 1:
            ansible_module.fail_json(
                msg="Only one hbacrule can be added at a time.")
        if action == "member":
            invalid = ["description", "usercategory", "hostcategory",
                       "servicecategory", "nomembers"]
            for x in invalid:
                if vars()[x] is not None:
                    ansible_module.fail_json(
                        msg="Argument '%s' can not be used with action "
                        "'%s'" % (x, action))

    elif state == "absent":
        if len(names) < 1:
            ansible_module.fail_json(msg="No name given.")
        invalid = ["description", "usercategory", "hostcategory",
                   "servicecategory", "nomembers"]
        if action == "hbacrule":
            invalid.extend(["host", "hostgroup", "hbacsvc", "hbacsvcgroup",
                            "user", "group"])
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
        invalid = ["description", "usercategory", "hostcategory",
                   "servicecategory", "nomembers", "host", "hostgroup",
                   "hbacsvc", "hbacsvcgroup", "user", "group"]
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

                    hbacsvc_add = list(
                        set(hbacsvc or []) -
                        set(res_find.get("member_hbacsvc", [])))
                    hbacsvc_del = list(
                        set(res_find.get("member_hbacsvc", [])) -
                        set(hbacsvc or []))
                    hbacsvcgroup_add = list(
                        set(hbacsvcgroup or []) -
                        set(res_find.get("member_hbacsvcgroup", [])))
                    hbacsvcgroup_del = list(
                        set(res_find.get("member_hbacsvcgroup", [])) -
                        set(hbacsvcgroup or []))

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

                    # Add hosts and hostgroups
                    if len(host_add) > 0 or len(hostgroup_add) > 0:
                        commands.append([name, "hbacrule_add_host",
                                         {
                                             "host": host_add,
                                             "hostgroup": hostgroup_add,
                                         }])
                    # Remove hosts and hostgroups
                    if len(host_del) > 0 or len(hostgroup_del) > 0:
                        commands.append([name, "hbacrule_remove_host",
                                         {
                                             "host": host_del,
                                             "hostgroup": hostgroup_del,
                                         }])

                    # Add hbacsvcs and hbacsvcgroups
                    if len(hbacsvc_add) > 0 or len(hbacsvcgroup_add) > 0:
                        commands.append([name, "hbacrule_add_service",
                                         {
                                             "hbacsvc": hbacsvc_add,
                                             "hbacsvcgroup": hbacsvcgroup_add,
                                         }])
                    # Remove hbacsvcs and hbacsvcgroups
                    if len(hbacsvc_del) > 0 or len(hbacsvcgroup_del) > 0:
                        commands.append([name, "hbacrule_remove_service",
                                         {
                                             "hbacsvc": hbacsvc_del,
                                             "hbacsvcgroup": hbacsvcgroup_del,
                                         }])

                    # Add users and groups
                    if len(user_add) > 0 or len(group_add) > 0:
                        commands.append([name, "hbacrule_add_user",
                                         {
                                             "user": user_add,
                                             "group": group_add,
                                         }])
                    # Remove users and groups
                    if len(user_del) > 0 or len(group_del) > 0:
                        commands.append([name, "hbacrule_remove_user",
                                         {
                                             "user": user_del,
                                             "group": group_del,
                                         }])

                elif action == "member":
                    if res_find is None:
                        ansible_module.fail_json(msg="No hbacrule '%s'" % name)

                    # Add hosts and hostgroups
                    if host is not None or hostgroup is not None:
                        commands.append([name, "hbacrule_add_host",
                                         {
                                             "host": host,
                                             "hostgroup": hostgroup,
                                         }])

                    # Add hbacsvcs and hbacsvcgroups
                    if hbacsvc is not None or hbacsvcgroup is not None:
                        commands.append([name, "hbacrule_add_service",
                                         {
                                             "hbacsvc": hbacsvc,
                                             "hbacsvcgroup": hbacsvcgroup,
                                         }])

                    # Add users and groups
                    if user is not None or group is not None:
                        commands.append([name, "hbacrule_add_user",
                                         {
                                             "user": user,
                                             "group": group,
                                         }])

            elif state == "absent":
                if action == "hbacrule":
                    if res_find is not None:
                        commands.append([name, "hbacrule_del", {}])

                elif action == "member":
                    if res_find is None:
                        ansible_module.fail_json(msg="No hbacrule '%s'" % name)

                    # Remove hosts and hostgroups
                    if host is not None or hostgroup is not None:
                        commands.append([name, "hbacrule_remove_host",
                                         {
                                             "host": host,
                                             "hostgroup": hostgroup,
                                         }])

                    # Remove hbacsvcs and hbacsvcgroups
                    if hbacsvc is not None or hbacsvcgroup is not None:
                        commands.append([name, "hbacrule_remove_service",
                                         {
                                             "hbacsvc": hbacsvc,
                                             "hbacsvcgroup": hbacsvcgroup,
                                         }])

                    # Remove users and groups
                    if user is not None or group is not None:
                        commands.append([name, "hbacrule_remove_user",
                                         {
                                             "user": user,
                                             "group": group,
                                         }])

            elif state == "enabled":
                if res_find is None:
                    ansible_module.fail_json(msg="No hbacrule '%s'" % name)
                # hbacrule_enable is not failing on an enabled hbacrule
                # Therefore it is needed to have a look at the ipaenabledflag
                # in res_find.
                if "ipaenabledflag" not in res_find or \
                   res_find["ipaenabledflag"][0] != "TRUE":
                    commands.append([name, "hbacrule_enable", {}])

            elif state == "disabled":
                if res_find is None:
                    ansible_module.fail_json(msg="No hbacrule '%s'" % name)
                # hbacrule_disable is not failing on an disabled hbacrule
                # Therefore it is needed to have a look at the ipaenabledflag
                # in res_find.
                if "ipaenabledflag" not in res_find or \
                   res_find["ipaenabledflag"][0] != "FALSE":
                    commands.append([name, "hbacrule_disable", {}])

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

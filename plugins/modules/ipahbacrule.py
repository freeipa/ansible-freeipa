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
short description: Manage FreeIPA HBAC rules
description: Manage FreeIPA HBAC rules
extends_documentation_fragment:
  - ipamodule_base_docs
options:
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
    choices: ["all", ""]
  hostcategory:
    description: Host category the rule applies to
    required: false
    aliases: ["hostcat"]
    choices: ["all", ""]
  servicecategory:
    description: Service category the rule applies to
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
    IPAAnsibleModule, compare_args_ipa, gen_add_del_lists, gen_add_list, \
    gen_intersection_list, ensure_fqdn


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
            name=dict(type="list", aliases=["cn"], default=None,
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

        # Get default domain
        default_domain = ansible_module.ipa_get_domain()

        # Ensure fqdn host names, use default domain for simple names
        if host is not None:
            _host = [ensure_fqdn(x, default_domain) for x in host]
            host = _host

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

                    # Generate addition and removal lists
                    host_add, host_del = gen_add_del_lists(
                        host, res_find.get("memberhost_host"))

                    hostgroup_add, hostgroup_del = gen_add_del_lists(
                        hostgroup, res_find.get("memberhost_hostgroup"))

                    hbacsvc_add, hbacsvc_del = gen_add_del_lists(
                        hbacsvc, res_find.get("memberservice_hbacsvc"))

                    hbacsvcgroup_add, hbacsvcgroup_del = gen_add_del_lists(
                        hbacsvcgroup,
                        res_find.get("memberservice_hbacsvcgroup"))

                    user_add, user_del = gen_add_del_lists(
                        user, res_find.get("memberuser_user"))

                    group_add, group_del = gen_add_del_lists(
                        group, res_find.get("memberuser_group"))

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

                    # Generate add lists for host, hostgroup and
                    # res_find to only try to add hosts and hostgroups
                    # that not in hbacrule already
                    if host is not None and \
                       "memberhost_host" in res_find:
                        host = gen_add_list(
                            host, res_find["memberhost_host"])
                    if hostgroup is not None and \
                       "memberhost_hostgroup" in res_find:
                        hostgroup = gen_add_list(
                            hostgroup, res_find["memberhost_hostgroup"])

                    # Add hosts and hostgroups
                    if host is not None or hostgroup is not None:
                        commands.append([name, "hbacrule_add_host",
                                         {
                                             "host": host,
                                             "hostgroup": hostgroup,
                                         }])

                    # Generate add lists for hbacsvc, hbacsvcgroup and
                    # res_find to only try to add hbacsvcs and hbacsvcgroups
                    # that not in hbacrule already
                    if hbacsvc is not None and \
                       "memberservice_hbacsvc" in res_find:
                        hbacsvc = gen_add_list(
                            hbacsvc, res_find["memberservice_hbacsvc"])
                    if hbacsvcgroup is not None and \
                       "memberservice_hbacsvcgroup" in res_find:
                        hbacsvcgroup = gen_add_list(
                            hbacsvcgroup,
                            res_find["memberservice_hbacsvcgroup"])

                    # Add hbacsvcs and hbacsvcgroups
                    if hbacsvc is not None or hbacsvcgroup is not None:
                        commands.append([name, "hbacrule_add_service",
                                         {
                                             "hbacsvc": hbacsvc,
                                             "hbacsvcgroup": hbacsvcgroup,
                                         }])

                    # Generate add lists for user, group and
                    # res_find to only try to add users and groups
                    # that not in hbacrule already
                    if user is not None and \
                       "memberuser_user" in res_find:
                        user = gen_add_list(
                            user, res_find["memberuser_user"])
                    if group is not None and \
                       "memberuser_group" in res_find:
                        group = gen_add_list(
                            group, res_find["memberuser_group"])

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

                    # Generate intersection lists for host, hostgroup and
                    # res_find to only try to remove hosts and hostgroups
                    # that are in hbacrule
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

                    # Remove hosts and hostgroups
                    if host is not None or hostgroup is not None:
                        commands.append([name, "hbacrule_remove_host",
                                         {
                                             "host": host,
                                             "hostgroup": hostgroup,
                                         }])

                    # Generate intersection lists for hbacsvc, hbacsvcgroup
                    # and res_find to only try to remove hbacsvcs and
                    # hbacsvcgroups that are in hbacrule
                    if hbacsvc is not None:
                        if "memberservice_hbacsvc" in res_find:
                            hbacsvc = gen_intersection_list(
                                hbacsvc, res_find["memberservice_hbacsvc"])
                        else:
                            hbacsvc = None
                    if hbacsvcgroup is not None:
                        if "memberservice_hbacsvcgroup" in res_find:
                            hbacsvcgroup = gen_intersection_list(
                                hbacsvcgroup,
                                res_find["memberservice_hbacsvcgroup"])
                        else:
                            hbacsvcgroup = None

                    # Remove hbacsvcs and hbacsvcgroups
                    if hbacsvc is not None or hbacsvcgroup is not None:
                        commands.append([name, "hbacrule_remove_service",
                                         {
                                             "hbacsvc": hbacsvc,
                                             "hbacsvcgroup": hbacsvcgroup,
                                         }])

                    # Generate intersection lists for user, group and
                    # res_find to only try to remove users and groups
                    # that are in hbacrule
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

        changed = ansible_module.execute_ipa_commands(
            commands, fail_on_member_errors=True)

    # Done

    ansible_module.exit_json(changed=changed, **exit_args)


if __name__ == "__main__":
    main()

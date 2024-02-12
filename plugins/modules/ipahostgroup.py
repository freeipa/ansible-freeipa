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
module: ipahostgroup
short_description: Manage FreeIPA hostgroups
description: Manage FreeIPA hostgroups
extends_documentation_fragment:
  - ipamodule_base_docs
options:
  name:
    description: The hostgroup name
    type: list
    elements: str
    required: true
    aliases: ["cn"]
  description:
    description: The hostgroup description
    type: str
    required: false
  nomembers:
    description: Suppress processing of membership attributes
    required: false
    type: bool
  host:
    description: List of host names assigned to this hostgroup.
    required: false
    type: list
    elements: str
  hostgroup:
    description: List of hostgroup names assigned to this hostgroup.
    required: false
    type: list
    elements: str
  membermanager_user:
    description:
    - List of member manager users assigned to this hostgroup.
    - Only usable with IPA versions 4.8.4 and up.
    required: false
    type: list
    elements: str
  membermanager_group:
    description:
    - List of member manager groups assigned to this hostgroup.
    - Only usable with IPA versions 4.8.4 and up.
    required: false
    type: list
    elements: str
  rename:
    description:
    - Rename hostgroup to the given name.
    - Only usable with IPA versions 4.8.7 and up.
    type: str
    required: false
    aliases: ["new_name"]
  action:
    description: Work on hostgroup or member level
    type: str
    default: hostgroup
    choices: ["member", "hostgroup"]
  state:
    description: State to ensure
    type: str
    default: present
    choices: ["present", "absent", "renamed"]
author:
  - Thomas Woerner (@t-woerner)
"""

EXAMPLES = """
# Ensure host-group databases is present
- ipahostgroup:
    ipaadmin_password: SomeADMINpassword
    name: databases
    host:
    - db.example.com
    hostgroup:
    - mysql-server
    - oracle-server

# Ensure hosts and hostgroups are present in existing databases hostgroup
- ipahostgroup:
    ipaadmin_password: SomeADMINpassword
    name: databases
    host:
    - db.example.com
    hostgroup:
    - mysql-server
    - oracle-server
    action: member

# Ensure hosts and hostgroups are absent in databases hostgroup
- ipahostgroup:
    ipaadmin_password: SomeADMINpassword
    name: databases
    host:
    - db.example.com
    hostgroup:
    - mysql-server
    - oracle-server
    action: member
    state: absent

# Rename hostgroup
- ipahostgroup:
    ipaadmin_password: SomeADMINpassword
    name: databases
    rename: datalake

# Ensure host-group databases is absent
- ipahostgroup:
    ipaadmin_password: SomeADMINpassword
    name: databases
    state: absent
"""

RETURN = """
"""

from ansible.module_utils.ansible_freeipa_module import \
    IPAAnsibleModule, compare_args_ipa, gen_add_del_lists, gen_add_list, \
    gen_intersection_list, ensure_fqdn


def find_hostgroup(module, name):
    _args = {
        "all": True,
        "cn": name,
    }

    _result = module.ipa_command("hostgroup_find", name, _args)

    if len(_result["result"]) > 1:
        module.fail_json(
            msg="There is more than one hostgroup '%s'" % (name))
    elif len(_result["result"]) == 1:
        return _result["result"][0]

    return None


def gen_args(description, nomembers, rename):
    _args = {}
    if description is not None:
        _args["description"] = description
    if nomembers is not None:
        _args["nomembers"] = nomembers
    if rename is not None:
        _args["rename"] = rename

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
            host=dict(required=False, type='list', elements="str",
                      default=None),
            hostgroup=dict(required=False, type='list', elements="str",
                           default=None),
            membermanager_user=dict(required=False, type='list',
                                    elements="str", default=None),
            membermanager_group=dict(required=False, type='list',
                                     elements="str", default=None),
            rename=dict(required=False, type='str', default=None,
                        aliases=["new_name"]),
            action=dict(type="str", default="hostgroup",
                        choices=["member", "hostgroup"]),
            # state
            state=dict(type="str", default="present",
                       choices=["present", "absent", "renamed"]),
        ),
        supports_check_mode=True,
    )

    ansible_module._ansible_debug = True

    # Get parameters

    # general
    names = ansible_module.params_get_lowercase("name")

    # present
    description = ansible_module.params_get("description")
    nomembers = ansible_module.params_get("nomembers")
    host = ansible_module.params_get("host")
    hostgroup = ansible_module.params_get_lowercase("hostgroup")
    membermanager_user = ansible_module.params_get_lowercase(
        "membermanager_user"
    )
    membermanager_group = ansible_module.params_get_lowercase(
        "membermanager_group"
    )
    rename = ansible_module.params_get_lowercase("rename")
    action = ansible_module.params_get("action")
    # state
    state = ansible_module.params_get("state")

    # Check parameters

    invalid = []
    if state == "present":
        if len(names) != 1:
            ansible_module.fail_json(
                msg="Only one hostgroup can be added at a time.")
        invalid = ["rename"]
        if action == "member":
            invalid.extend(["description", "nomembers"])

    if state == "renamed":
        if len(names) != 1:
            ansible_module.fail_json(
                msg="Only one hostgroup can be added at a time.")
        if action == "member":
            ansible_module.fail_json(
                msg="Action '%s' can not be used with state '%s'" %
                (action, state))
        invalid = [
            "description", "nomembers", "host", "hostgroup",
            "membermanager_user", "membermanager_group"
        ]

    if state == "absent":
        if len(names) < 1:
            ansible_module.fail_json(
                msg="No name given.")
        invalid = ["description", "nomembers", "rename"]
        if action == "hostgroup":
            invalid.extend(["host", "hostgroup"])

    ansible_module.params_fail_used_invalid(invalid, state, action)

    # Init

    changed = False
    exit_args = {}

    # Connect to IPA API
    with ansible_module.ipa_connect():

        has_add_membermanager = ansible_module.ipa_command_exists(
            "hostgroup_add_member_manager")
        if ((membermanager_user is not None or
             membermanager_group is not None) and not has_add_membermanager):
            ansible_module.fail_json(
                msg="Managing a membermanager user or group is not supported "
                "by your IPA version"
            )
        has_mod_rename = ansible_module.ipa_command_param_exists(
            "hostgroup_mod", "rename")
        if not has_mod_rename and rename is not None:
            ansible_module.fail_json(
                msg="Renaming hostgroups is not supported by your IPA version")

        # If hosts are given, ensure that the hosts are FQDN and also
        # lowercase to be able to do a proper comparison to exising hosts
        # in the hostgroup.
        # Fixes #666 (ipahostgroup not idempotent and with error)
        if host is not None:
            default_domain = ansible_module.ipa_get_domain()
            host = [ensure_fqdn(_host, default_domain).lower()
                    for _host in host]

        commands = []

        for name in names:
            # clean add/del lists
            host_add, host_del = [], []
            hostgroup_add, hostgroup_del = [], []
            membermanager_user_add, membermanager_user_del = [], []
            membermanager_group_add, membermanager_group_del = [], []

            # Make sure hostgroup exists
            res_find = find_hostgroup(ansible_module, name)

            # Create command
            if state == "present":
                # Generate args
                args = gen_args(description, nomembers, rename)

                if action == "hostgroup":
                    # Found the hostgroup
                    if res_find is not None:
                        # For all settings is args, check if there are
                        # different settings in the find result.
                        # If yes: modify
                        if not compare_args_ipa(ansible_module, args,
                                                res_find):
                            commands.append([name, "hostgroup_mod", args])
                    else:
                        commands.append([name, "hostgroup_add", args])
                        # Set res_find to empty dict for next step
                        res_find = {}

                    # Generate addition and removal lists
                    host_add, host_del = gen_add_del_lists(
                        host, res_find.get("member_host")
                    )

                    hostgroup_add, hostgroup_del = gen_add_del_lists(
                        hostgroup, res_find.get("member_hostgroup")
                    )

                    if has_add_membermanager:
                        membermanager_user_add, membermanager_user_del = \
                            gen_add_del_lists(
                                membermanager_user,
                                res_find.get("membermanager_user")
                            )

                        membermanager_group_add, membermanager_group_del = \
                            gen_add_del_lists(
                                membermanager_group,
                                res_find.get("membermanager_group")
                            )

                elif action == "member":
                    if res_find is None:
                        ansible_module.fail_json(
                            msg="No hostgroup '%s'" % name)

                    # Reduce add lists for member_host and member_hostgroup,
                    # to new entries only that are not in res_find.
                    host_add = gen_add_list(
                        host, res_find.get("member_host")
                    )
                    hostgroup_add = gen_add_list(
                        hostgroup, res_find.get("member_hostgroup")
                    )

                    if has_add_membermanager:
                        # Reduce add list for membermanager_user and
                        # membermanager_group to new entries only that are
                        # not in res_find.
                        membermanager_user_add = gen_add_list(
                            membermanager_user,
                            res_find.get("membermanager_user")
                        )
                        membermanager_group_add = gen_add_list(
                            membermanager_group,
                            res_find.get("membermanager_group")
                        )

            elif state == "renamed":
                if res_find is not None:
                    if rename != name:
                        commands.append(
                            [name, "hostgroup_mod", {"rename": rename}]
                        )
                else:
                    # If a hostgroup with the desired name exists, do nothing.
                    new_find = find_hostgroup(ansible_module, rename)
                    if new_find is None:
                        # Fail only if the either hostsgroups do not exist.
                        ansible_module.fail_json(
                            msg="Attribute `rename` can not be used, unless "
                                "hostgroup exists."
                        )

            elif state == "absent":
                if action == "hostgroup":
                    if res_find is not None:
                        commands.append([name, "hostgroup_del", {}])

                elif action == "member":
                    if res_find is None:
                        ansible_module.fail_json(
                            msg="No hostgroup '%s'" % name)

                    # Reduce del lists of member_host and member_hostgroup,
                    # to the entries only that are in res_find.
                    if host is not None:
                        host_del = gen_intersection_list(
                            host, res_find.get("member_host")
                        )
                    if hostgroup is not None:
                        hostgroup_del = gen_intersection_list(
                            hostgroup, res_find.get("member_hostgroup")
                        )

                    if has_add_membermanager:
                        # Get lists of membermanager users that exist
                        # in IPA and should be removed.
                        membermanager_user_del = gen_intersection_list(
                            membermanager_user,
                            res_find.get("membermanager_user")
                        )
                        membermanager_group_del = gen_intersection_list(
                            membermanager_group,
                            res_find.get("membermanager_group")
                        )

            else:
                ansible_module.fail_json(msg="Unkown state '%s'" % state)

            # Manage members

            # Add members
            if host_add or hostgroup_add:
                commands.append([
                    name, "hostgroup_add_member",
                    {
                        "host": host_add,
                        "hostgroup": hostgroup_add,
                    }
                ])

            # Remove members
            if host_del or hostgroup_del:
                commands.append([
                    name, "hostgroup_remove_member",
                    {
                        "host": host_del,
                        "hostgroup": hostgroup_del,
                    }
                ])

            #  Manage membermanager users and groups
            if has_add_membermanager:
                # Add membermanager users and groups
                if membermanager_user_add or membermanager_group_add:
                    commands.append([
                        name, "hostgroup_add_member_manager",
                        {
                            "user": membermanager_user_add,
                            "group": membermanager_group_add,
                        }
                    ])
                # Remove membermanager users and groups
                if membermanager_user_del or membermanager_group_del:
                    commands.append([
                        name, "hostgroup_remove_member_manager",
                        {
                            "user": membermanager_user_del,
                            "group": membermanager_group_del,
                        }
                    ])

        # Execute commands

        changed = ansible_module.execute_ipa_commands(
            commands, fail_on_member_errors=True)

    # Done

    ansible_module.exit_json(changed=changed, **exit_args)


if __name__ == "__main__":
    main()

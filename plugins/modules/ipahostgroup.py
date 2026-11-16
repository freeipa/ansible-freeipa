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
    required: false
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
  query_param:
    description: The fields to query with state=query
    required: false
    type: list
    elements: str
    choices: ["ALL", "BASE", "PKEY_ONLY",
              "dn", "objectclass", "ipauniqueid",
              "name", "description",
              "host", "hostgroup",
              "membermanager_user", "membermanager_group"]
  action:
    description: Work on hostgroup or member level
    type: str
    default: hostgroup
    choices: ["member", "hostgroup"]
  state:
    description: State to ensure
    type: str
    default: present
    choices: ["present", "absent", "renamed",
              "query"]
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

# Query all hostgroups (primary keys only)
- ipahostgroup:
    ipaadmin_password: SomeADMINpassword
    state: query
    query_param: PKEY_ONLY
  register: result

# Query a specific hostgroup with all parameters
- ipahostgroup:
    ipaadmin_password: SomeADMINpassword
    name: databases
    state: query
    query_param: ALL
  register: result

# Query description for all hostgroups
- ipahostgroup:
    ipaadmin_password: SomeADMINpassword
    state: query
    query_param:
    - description
  register: result
"""

RETURN = """
"""

from ansible.module_utils._text import to_text
from ansible.module_utils.ansible_freeipa_module import \
    IPAAnsibleModule, compare_args_ipa, gen_member_add_del_lists, \
    ensure_fqdn, ipalib_errors


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


def hostgroup_find_query(module, name):
    _args = {"all": True}

    try:
        if name:
            _args["cn"] = name
        _result = module.ipa_command_no_name(
            "hostgroup_find", _args).get("result")
        if _result and name:
            _result = _result[0]
    except ipalib_errors.NotFound:
        return None

    return _result


def convert_result(res):
    _res = {}
    for key in res:
        if isinstance(res[key], list):
            if len(res[key]) == 1:
                _res[key] = to_text(res[key][0])
            else:
                _res[key] = [to_text(item) for item in res[key]]
        else:
            _res[key] = to_text(res[key])
    return _res


PARAM_MAPPING = {
    "dn": {"return_only": True},
    "objectclass": {"return_only": True},
    "ipauniqueid": {"return_only": True},

    "name": {"api_name": "cn", "gen_args": False},

    "description": {},
    "nomembers": {"query": False},

    "host": {"api_name": "member_host", "gen_args": False,
             "lowercase": True, "member": True},
    "hostgroup": {"api_name": "member_hostgroup", "gen_args": False,
                  "lowercase": True, "member": True},
    "membermanager_user": {"gen_args": False, "lowercase": True,
                           "member": True},
    "membermanager_group": {"gen_args": False, "lowercase": True,
                            "member": True},

    "rename": {"gen_args": False, "query": False},

    # Module-level params (not per-item, checked via self.params)
    "query_param": {"module_param": True},
}

QUERY_FIELDS = {
    "prefix": "hostgroups",
    "primary_key": "cn",
    "base": ["name", "description"]
}


def main():
    query_param_settings = IPAAnsibleModule.build_query_param_settings(
        PARAM_MAPPING, QUERY_FIELDS)

    ansible_module = IPAAnsibleModule(
        argument_spec=dict(
            # general
            name=dict(type="list", elements="str", aliases=["cn"],
                      default=None, required=False),
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
            # query
            query_param=dict(
                type="list", elements="str", default=None,
                choices=["ALL", "BASE", "PKEY_ONLY"]
                + query_param_settings["ALL"],
                required=False),
            action=dict(type="str", default="hostgroup",
                        choices=["member", "hostgroup"]),
            # state
            state=dict(type="str", default="present",
                       choices=["present", "absent", "renamed", "query"]),
        ),
        supports_check_mode=True,
    )

    ansible_module._ansible_debug = True

    # Get parameters

    # general
    names = ansible_module.params_get_lowercase("name")

    # Extract mapped params
    hostgroup_params = IPAAnsibleModule.extract_params(
        ansible_module, PARAM_MAPPING)
    rename = hostgroup_params.get("rename")

    # present
    host = ansible_module.params_get("host")
    hostgroup = ansible_module.params_get_lowercase("hostgroup")
    membermanager_user = ansible_module.params_get_lowercase(
        "membermanager_user"
    )
    membermanager_group = ansible_module.params_get_lowercase(
        "membermanager_group"
    )
    # query
    query_param = ansible_module.params_get("query_param")
    action = ansible_module.params_get("action")
    # state
    state = ansible_module.params_get("state")

    # Check parameters

    if state != "query":
        if names is None or len(names) < 1:
            ansible_module.fail_json(
                msg="No name given.")

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

    if state == "query":
        if action == "member":
            ansible_module.fail_json(
                msg="Query is not possible with action=member")

    if state != "query":
        invalid.append("query_param")

    ansible_module.params_fail_used_invalid(invalid, state, action,
                                            hostgroup_params, PARAM_MAPPING)

    # Init

    changed = False
    exit_args = {}

    # Connect to IPA API
    with ansible_module.ipa_connect():

        if state == "query":
            exit_args = ansible_module.execute_query(
                names, query_param, hostgroup_find_query,
                query_param_settings, convert_result=convert_result)

            ansible_module.exit_json(changed=False, hostgroup=exit_args)

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
            # Make sure hostgroup exists
            res_find = find_hostgroup(ansible_module, name)

            # Create command
            if state == "present":
                # Generate args
                args = IPAAnsibleModule.gen_args_from_mapping(
                    PARAM_MAPPING, hostgroup_params)

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

                elif action == "member":
                    if res_find is None:
                        ansible_module.fail_json(
                            msg="No hostgroup '%s'" % name)

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

            else:
                ansible_module.fail_json(msg="Unkown state '%s'" % state)

            # Compute member add/del lists
            member_params = {
                "host": host,
                "hostgroup": hostgroup,
                "membermanager_user":
                    membermanager_user if has_add_membermanager else None,
                "membermanager_group":
                    membermanager_group if has_add_membermanager else None,
            }
            member_lists = gen_member_add_del_lists(
                PARAM_MAPPING, member_params,
                res_find or {}, action, state)
            host_add, host_del = member_lists.get(
                "host", ([], []))
            hostgroup_add, hostgroup_del = member_lists.get(
                "hostgroup", ([], []))
            membermanager_user_add, membermanager_user_del = member_lists.get(
                "membermanager_user", ([], []))
            membermanager_group_add, membermanager_group_del = \
                member_lists.get("membermanager_group", ([], []))

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

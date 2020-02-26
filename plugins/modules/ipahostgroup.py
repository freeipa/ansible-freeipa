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
module: ipahostgroup
short description: Manage FreeIPA hostgroups
description: Manage FreeIPA hostgroups
options:
  ipaadmin_principal:
    description: The admin principal
    default: admin
  ipaadmin_password:
    description: The admin password
    required: false
  name:
    description: The hostgroup name
    required: false
    aliases: ["cn"]
  description:
    description: The hostgroup description
    required: false
  nomembers:
    description: Suppress processing of membership attributes
    required: false
    type: bool
  host:
    description: List of host names assigned to this hostgroup.
    required: false
    type: list
  hostgroup:
    description: List of hostgroup names assigned to this hostgroup.
    required: false
    type: list
  action:
    description: Work on hostgroup or member level
    default: hostgroup
    choices: ["member", "hostgroup"]
  state:
    description: State to ensure
    default: present
    choices: ["present", "absent"]
author:
    - Thomas Woerner
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

# Ensure host-group databases is absent
- ipahostgroup:
    ipaadmin_password: SomeADMINpassword
    name: databases
    state: absent
"""

RETURN = """
"""

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.ansible_freeipa_module import temp_kinit, \
    temp_kdestroy, valid_creds, api_connect, api_command, compare_args_ipa, \
    module_params_get


def find_hostgroup(module, name):
    _args = {
        "all": True,
        "cn": name,
    }

    _result = api_command(module, "hostgroup_find", name, _args)

    if len(_result["result"]) > 1:
        module.fail_json(
            msg="There is more than one hostgroup '%s'" % (name))
    elif len(_result["result"]) == 1:
        return _result["result"][0]
    else:
        return None


def gen_args(description, nomembers):
    _args = {}
    if description is not None:
        _args["description"] = description
    if nomembers is not None:
        _args["nomembers"] = nomembers

    return _args


def gen_member_args(host, hostgroup):
    _args = {}
    if host is not None:
        _args["member_host"] = host
    if hostgroup is not None:
        _args["member_hostgroup"] = hostgroup

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
            host=dict(required=False, type='list', default=None),
            hostgroup=dict(required=False, type='list', default=None),
            action=dict(type="str", default="hostgroup",
                        choices=["member", "hostgroup"]),
            # state
            state=dict(type="str", default="present",
                       choices=["present", "absent"]),
        ),
        supports_check_mode=True,
    )

    ansible_module._ansible_debug = True

    # Get parameters

    # general
    ipaadmin_principal = module_params_get(ansible_module,
                                           "ipaadmin_principal")
    ipaadmin_password = module_params_get(ansible_module,
                                          "ipaadmin_password")
    names = module_params_get(ansible_module, "name")

    # present
    description = module_params_get(ansible_module, "description")
    nomembers = module_params_get(ansible_module, "nomembers")
    host = module_params_get(ansible_module, "host")
    hostgroup = module_params_get(ansible_module, "hostgroup")
    action = module_params_get(ansible_module, "action")
    # state
    state = module_params_get(ansible_module, "state")

    # Check parameters

    if state == "present":
        if len(names) != 1:
            ansible_module.fail_json(
                msg="Only one hostgroup can be added at a time.")
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
        if action == "hostgroup":
            invalid.extend(["host", "hostgroup"])
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
            # Make sure hostgroup exists
            res_find = find_hostgroup(ansible_module, name)

            # Create command
            if state == "present":
                # Generate args
                args = gen_args(description, nomembers)

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

                    member_args = gen_member_args(host, hostgroup)
                    if not compare_args_ipa(ansible_module, member_args,
                                            res_find):
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

                        # Add members
                        if len(host_add) > 0 or len(hostgroup_add) > 0:
                            commands.append([name, "hostgroup_add_member",
                                             {
                                                 "host": host_add,
                                                 "hostgroup": hostgroup_add,
                                             }])
                        # Remove members
                        if len(host_del) > 0 or len(hostgroup_del) > 0:
                            commands.append([name, "hostgroup_remove_member",
                                             {
                                                 "host": host_del,
                                                 "hostgroup": hostgroup_del,
                                             }])
                elif action == "member":
                    if res_find is None:
                        ansible_module.fail_json(
                            msg="No hostgroup '%s'" % name)

                    # Ensure members are present
                    commands.append([name, "hostgroup_add_member",
                                     {
                                         "host": host,
                                         "hostgroup": hostgroup,
                                     }])
            elif state == "absent":
                if action == "hostgroup":
                    if res_find is not None:
                        commands.append([name, "hostgroup_del", {}])

                elif action == "member":
                    if res_find is None:
                        ansible_module.fail_json(
                            msg="No hostgroup '%s'" % name)

                    # Ensure members are absent
                    commands.append([name, "hostgroup_remove_member",
                                     {
                                         "host": host,
                                         "hostgroup": hostgroup,
                                     }])
            else:
                ansible_module.fail_json(msg="Unkown state '%s'" % state)

        # Execute commands
        for name, command, args in commands:
            try:
                result = api_command(ansible_module, command, name, args)
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
            errors = []
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

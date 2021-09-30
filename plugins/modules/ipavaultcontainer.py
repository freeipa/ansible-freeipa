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
module: ipavaultcontainer
short description: Manage vault containers.
description: Manage vault containers. KRA service must be enabled.
options:
  ipaadmin_principal:
    description: The admin principal
    default: admin
  ipaadmin_password:
    description: The admin password
    required: false
  username:
    description: Username of the user vault container.
    required: false
    type: list
  service:
    description: Service name of the service vault container.
    required: false
    type: list
  shared:
    description: Shared vault container.
    required: false
    type: bool
  users:
    description: Users members of the vault container.
    required: false
    type: list
  services:
    description: Services members of the vault container.
    required: false
    type: list
  groups:
    description: Groups members of the vault container.
    required: false
    type: list
  action:
    description: Work on vaultcontainer or member level.
    default: vault
    choices: ["vaultcontainer", "member"]
  state:
    description: State to ensure
    default: present
    choices: ["present", "absent"]
author:
    - Rafael Jeffman
"""

EXAMPLES = """
# Ensure vaultcontainer for user01 is present
- ipavaultcontainer:
    ipaadmin_password: MyPassword123
    username: user01

# Ensure vaultcontainer for user01 is present with users, groups and services.
- ipavaultcontainer:
    ipaadmin_password: MyPassword123
    username: user01
    user:
    - admin, user01, user02
    groups:
    - ipausers
    services:
    - HTTP/example.com
    action: member

# Ensure vaultcontainer is absent
- ipavaultcontainer:
    ipaadmin_password: MyPassword123
    username: user01
    state: absent

# Ensure shared vaultcontainer is present
- ipavaultcontainer:
    ipaadmin_password: MyPassword123
    shared: True

# Ensure service vaultcontainer is present
- ipavaultcontainer:
    ipaadmin_password: MyPassword123
    service: HTTP/example.com
"""

RETURN = """
"""

from ansible.module_utils.ansible_freeipa_module import \
    IPAAnsibleModule, gen_intersection_list, gen_add_list, filter_service


def find_vaultcontainer(module, username, service, shared):
    _args = {
        "all": True,
    }
    if username is not None:
        _args['username'] = username
    elif service is not None:
        _args['service'] = service
    else:
        _args['shared'] = shared

    try:
        _result = module.ipa_command_no_name("vaultcontainer_show", _args)
    except Exception:
        return None
    else:
        return _result.get("result", None)


def gen_args(username, service, shared, users, groups, services):
    _args = {}

    if username is not None:
        _args['username'] = username
    elif service is not None:
        _args['service'] = service
    else:
        _args['shared'] = shared

    if users is not None:
        _args['user'] = users
    if groups is not None:
        _args['group'] = groups
    if services is not None:
        _args['services'] = services

    return _args


def main():
    ansible_module = IPAAnsibleModule(
        argument_spec=dict(
            # present
            username=dict(type="str", default=None, required=False),
            service=dict(type="str", required=False, default=None),
            shared=dict(type="bool", required=False, default=None),

            users=dict(required=False, type='list', default=None),
            groups=dict(required=False, type='list', default=None),
            services=dict(required=False, type='list', default=None),

            # state
            action=dict(type="str", default="vaultcontainer",
                        choices=["vaultcontainer", "member"]),
            state=dict(type="str", default="present",
                       choices=["present", "absent"]),
        ),
        supports_check_mode=True,
        mutually_exclusive=[['username', 'service', 'shared']],
        required_one_of=[['username', 'service', 'shared']]
    )

    ansible_module._ansible_debug = True

    # Get parameters

    # general
    ipaapi_context = ansible_module.params_get("ipaapi_context")

    # present
    username = ansible_module.params_get("username")
    service = ansible_module.params_get("service")
    shared = ansible_module.params_get("shared")
    services = ansible_module.params_get("services")
    users = ansible_module.params_get("users")
    groups = ansible_module.params_get("groups")

    action = ansible_module.params_get("action")
    state = ansible_module.params_get("state")

    # Check parameters
    invalid = ["users", "groups", "services"]

    # In any state, member parameters are only valid for 'member' action.
    if action == "member":
        invalid = []

    for param in invalid:
        if vars()[param] is not None:
            ansible_module.fail_json(
                msg="Argument '%s' can not be used with "
                    "action '%s' and state '%s'"
                    % (param, action, state))

    # Init

    commands = []

    user_add = user_del = None
    group_add = group_del = None
    service_add = service_del = None

    with ansible_module.ipa_connect(context=ipaapi_context):
        res_find = find_vaultcontainer(ansible_module,
                                       username, service, shared)

        if state == "present":
            # State present is either used for modify members, or check if
            # vaultcontainer exists, so we must fail if it doesn't exist.
            if res_find is None:
                if not shared:
                    msg = (
                        "Vaultcontainer for '%s' not found."
                        % (username or service)
                    )
                else:
                    msg = "Shared vaultcontainer not found."
                ansible_module.fail(msg=msg)

            if action == "member":
                user_add = gen_add_list(
                    users, res_find.get('owner_user', [])
                )
                group_add = gen_add_list(
                    groups, res_find.get('owner_group', [])
                )
                service_add = filter_service(
                    services,
                    res_find.get('owner_service', []),
                    lambda svc, services: svc not in services
                )

        elif state == "absent":
            if res_find is not None:
                if action == "vaultcontainer":
                    if username is not None:
                        args = {'username': username}
                    elif service is not None:
                        args = {'service': service}
                    elif shared:
                        args = {'shared': shared}
                    else:
                        ansible_module.fail(
                            msg="No vaultcontainer type selected.")
                    commands.append([None, "vaultcontainer_del", args])

                elif action == "member":
                    # Generate adittion and removal lists
                    user_del = gen_intersection_list(
                        users, res_find.get('owner_user', [])
                    )
                    group_del = gen_intersection_list(
                        groups, res_find.get('owner_group', [])
                    )
                    service_del = filter_service(
                        services,
                        res_find.get('owner_service', []),
                        lambda svc, services: svc in services
                    )

        # Add users, groups and services
        if any([user_add, group_add, service_add]):
            member_add = gen_args(username, service, shared,
                                  user_add, group_add, service_add)
            commands.append(
                [None, "vaultcontainer_add_owner", member_add])

        # Remove users and groups
        if any([user_del, group_del, service_del]):
            member_del = \
                gen_args(username, service, shared,
                         user_del, group_del, service_del)
            commands.append(
                [None, "vaultcontainer_remove_owner", member_del])

        # Changed may already be set to True if vaultcontainer
        # has been created.
        changed = ansible_module.execute_ipa_commands(
            commands, fail_on_member_errors=True)

    # Done
    ansible_module.exit_json(changed=changed)


if __name__ == "__main__":
    main()

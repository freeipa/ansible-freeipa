# -*- coding: utf-8 -*-
"""ansible-freeipa iparole module implementation."""

# Authors:
#   Rafael Guterres Jeffman <rjeffman@redhat.com>
#   Thomas Woerner <twoerner@redhat.com>
#
# Copyright (C) 2020-2022 Red Hat
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
module: iparole
short_description: Manage FreeIPA role
description: Manage FreeIPA role
extends_documentation_fragment:
  - ipamodule_base_docs
options:
  name:
    description: The list of role name strings.
    type: list
    elements: str
    required: true
    aliases: ["cn"]
  description:
    description: A description for the role.
    type: str
    required: false
  rename:
    description: Rename the role object.
    type: str
    required: false
    aliases: ["new_name"]
  privilege:
    description: List of privileges
    type: list
    elements: str
    required: false
  user:
    description: List of users.
    type: list
    elements: str
    required: false
  group:
    description: List of groups.
    type: list
    elements: str
    required: false
  host:
    description: List of hosts.
    type: list
    elements: str
    required: false
  hostgroup:
    description: List of hostgroups.
    type: list
    elements: str
    required: false
  service:
    description: List of services.
    type: list
    elements: str
    required: false
  action:
    description: Work on role or member level.
    type: str
    choices: ["role", "member"]
    default: role
    required: false
  state:
    description: The state to ensure.
    type: str
    choices: ["present", "absent", "renamed"]
    default: present
    required: false
author:
  - Rafael Guterres Jeffman (@rjeffman)
  - Thomas Woerner (@t-woerner)
"""

EXAMPLES = """
- name: Ensure a role named `somerole` is present.
  iparole:
    ipaadmin_password: SomeADMINpassword
    name: somerole

- name: Ensure user `pinky` is a memmer of role `somerole`.
  iparole:
    ipaadmin_password: SomeADMINpassword
    name: somerole
    user:
    - pinky
    action: member

- name: Ensure a role named `somerole` is absent.
  iparole:
    ipaadmin_password: SomeADMINpassword
    name: somerole
    state: absent
"""

from ansible.module_utils._text import to_text
from ansible.module_utils.ansible_freeipa_module import \
    IPAAnsibleModule, compare_args_ipa, gen_member_manage_commands, \
    create_ipa_mapping, ipa_api_map, transform_lowercase, \
    transform_host_param, transform_service_principal
from ansible.module_utils import six

if six.PY3:
    unicode = str


def find_role(module, name):
    """Find if a role with the given name already exist."""
    try:
        _result = module.ipa_command("role_show", name, {"all": True})
    except Exception:  # pylint: disable=broad-except
        # An exception is raised if role name is not found.
        return None
    else:
        _res = _result["result"]
        for member in ["member_service", "memberof_privilege"]:
            if member in _res:
                _res[member] = [to_text(x).lower() for x in _res[member]]
        return _res


def gen_args(module):
    """Generate arguments for executing commands."""
    arg_map = {
        "description": "description",
        "rename": "rename",
    }
    args = {}

    for param, arg in arg_map.items():
        value = module.params_get(param)
        if value is not None:
            args[arg] = value

    return args


def check_parameters(module):
    """Check if parameters passed for module processing are valid."""
    action = module.params_get("action")
    state = module.params_get("state")

    invalid = []

    if state == "renamed":
        if action == "member":
            module.fail_json(
                msg="Invalid action 'member' with state 'renamed'.")
        invalid = [
            "description",
            "user", "group",
            "host", "hostgroup",
            "service",
            "privilege",
        ]

    if state == "present":
        invalid = ["rename"]
        if action == "member":
            invalid.extend(['description'])

    if state == "absent":
        invalid.extend(['description', 'rename'])
        if action != "member":
            invalid.extend(['privilege'])

    module.params_fail_used_invalid(invalid, state, action)


def manage_members(module, res_find, name):
    _cmds = []

    _cmds.extend(
        gen_member_manage_commands(
            module,
            res_find,
            name,
            "role_add_privilege",
            "role_remove_privilege",
            create_ipa_mapping(
                ipa_api_map(
                    "privilege", "privilege", "memberof_privilege",
                    transform={"privilege": transform_lowercase},
                ),
            )
        )
    )

    _cmds.extend(
        gen_member_manage_commands(
            module,
            res_find,
            name,
            "role_add_member",
            "role_remove_member",
            create_ipa_mapping(
                ipa_api_map(
                    "host", "host", "member_host",
                    transform={"host": transform_host_param},
                ),
                ipa_api_map(
                    "service", "service", "member_service",
                    transform={
                        "service":
                            lambda svc: transform_lowercase(
                                transform_service_principal(svc)
                            )
                    },
                ),
                *[
                    ipa_api_map(
                        arg, arg, "member_%s" % arg,
                        transform={arg: transform_lowercase},
                    )
                    for arg in ["user", "group", "hostgroup"]
                ]
            )
        )
    )

    return _cmds


def role_commands_for_name(module, state, action, name):
    """Define commands for the Role module."""
    commands = []

    res_find = find_role(module, name)

    if state == "renamed":
        args = gen_args(module)
        if res_find is None:
            module.fail_json(msg="No role '%s'" % name)
        else:
            commands.append([name, 'role_mod', args])

    if state == "present":
        args = gen_args(module)

        if action == "role":
            if res_find is None:
                commands.append([name, 'role_add', args])
                res_find = {}
            else:
                if not compare_args_ipa(module, args, res_find):
                    commands.append([name, 'role_mod', args])

        if action == "member":
            if res_find is None:
                module.fail_json(msg="No role '%s'" % name)

    if state == "absent":
        if action == "role" and res_find is not None:
            commands.append([name, 'role_del', {}])
        if action == "member" and res_find is None:
            module.fail_json(msg="No role '%s'" % name)

    # Manage members
    commands.extend(manage_members(module, res_find, name))

    return commands


def create_module():
    """Create module description."""
    ansible_module = IPAAnsibleModule(
        argument_spec=dict(
            # generalgroups
            name=dict(type="list", elements="str", aliases=["cn"],
                      required=True),
            # present
            description=dict(required=False, type="str", default=None),
            rename=dict(required=False, type="str", default=None,
                        aliases=["new_name"]),
            # members
            privilege=dict(required=False, type='list', elements="str",
                           default=None),
            user=dict(required=False, type='list', elements="str",
                      default=None),
            group=dict(required=False, type='list', elements="str",
                       default=None),
            host=dict(required=False, type='list', elements="str",
                      default=None),
            hostgroup=dict(required=False, type='list', elements="str",
                           default=None),
            service=dict(required=False, type='list', elements="str",
                         default=None),

            # state
            action=dict(type="str", default="role",
                        choices=["role", "member"]),
            state=dict(type="str", default="present",
                       choices=["present", "absent", "renamed"]),
        ),
        supports_check_mode=True,
        mutually_exclusive=[],
        required_one_of=[]
    )

    ansible_module._ansible_debug = True  # pylint: disable=protected-access

    return ansible_module


def main():
    """Process role module script."""
    ansible_module = create_module()
    check_parameters(ansible_module)

    # Init

    # Connect to IPA API
    with ansible_module.ipa_connect():

        state = ansible_module.params_get("state")
        action = ansible_module.params_get("action")
        names = ansible_module.params_get("name")
        commands = []

        for name in names:
            cmds = role_commands_for_name(ansible_module, state, action, name)
            commands.extend(cmds)

        exit_args = {}

        # Execute commands

        changed = ansible_module.execute_ipa_commands(
            commands, fail_on_member_errors=True)

    # Done
    ansible_module.exit_json(changed=changed, **exit_args)


if __name__ == "__main__":
    main()

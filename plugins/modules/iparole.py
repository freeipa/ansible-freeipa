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

# pylint: disable=wrong-import-position
# pylint: disable=import-error
# pylint: disable=no-name-in-module
from ansible.module_utils._text import to_text
from ansible.module_utils.ansible_freeipa_module import \
    IPAAnsibleModule, gen_add_del_lists, compare_args_ipa, \
    gen_intersection_list, ListOf, Hostname, Service
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
    return _result["result"]


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


def ensure_absent_state(module, name, action, res_find):
    """Define commands to ensure absent state."""
    commands = []

    if action == "role":
        commands.append([name, 'role_del', {}])

    if action == "member":

        _members = module.params_get_lowercase("privilege")
        if _members is not None:
            del_list = gen_intersection_list(
                _members,
                result_get_value_lowercase(res_find, "memberof_privilege")
            )
            if del_list:
                commands.append([name, "role_remove_privilege",
                                 {"privilege": del_list}])

        member_args = {}

        member_types = [
            ("user", lambda value: value.lower()),
            ("group", lambda value: value.lower()),
            ("hostgroup", lambda value: value.lower()),
            ("host", Hostname(module.ipa_get_domain())),
            ("service", Service(module.ipa_get_realm())),
        ]
        for key, datatype in member_types:
            _members = module.params_get_with_type_cast(key, ListOf(datatype))
            if _members is not None:
                del_list = gen_intersection_list(
                    _members,
                    result_get_value_lowercase(res_find, "member_%s" % key)
                )

                if del_list:
                    member_args[key] = [to_text(item) for item in del_list]

        # Only add remove command if there's at least one member no manage.
        if member_args:
            commands.append([name, "role_remove_member", member_args])

    return commands


def result_get_value_lowercase(res_find, key, default=None):
    """
    Retrieve a member of a dictionary converted to lowercase.

    If field data is a string it is returned in lowercase. If
    field data is a list or tuple, it is assumed that all values
    are strings and the result is a list of strings in lowercase.

    If 'key' is not found in the dictionary, returns 'default'.
    """
    existing = res_find.get(key)
    if existing is not None:
        if isinstance(existing, (list, tuple)):
            existing = [to_text(item).lower() for item in existing]
        else:
            existing = to_text(existing).lower()
    else:
        existing = default
    return existing


def ensure_role_with_members_is_present(module, name, res_find, action):
    """Define commands to ensure member are present for action `role`."""
    commands = []

    _members = module.params_get_lowercase("privilege")
    if _members:
        add_list, del_list = gen_add_del_lists(
            _members,
            result_get_value_lowercase(res_find, "memberof_privilege")
        )

        if add_list:
            commands.append([name, "role_add_privilege",
                             {"privilege": add_list}])
        if action == "role" and del_list:
            commands.append([name, "role_remove_privilege",
                             {"privilege": del_list}])

    add_members = {}
    del_members = {}

    member_types = [
        ("user", lambda value: value.lower()),
        ("group", lambda value: value.lower()),
        ("hostgroup", lambda value: value.lower()),
        ("host", Hostname(module.ipa_get_domain())),
        ("service", Service(module.ipa_get_realm())),
    ]
    for key, datatype in member_types:
        _members = module.params_get_with_type_cast(key, ListOf(datatype))
        if _members is not None:
            add_list, del_list = gen_add_del_lists(
                _members,
                result_get_value_lowercase(res_find, "member_%s" % key)
            )
            if add_list:
                add_members[key] = [to_text(item) for item in add_list]
            if del_list:
                del_members[key] = [to_text(item) for item in del_list]

    if add_members:
        commands.append([name, "role_add_member", add_members])
    # Only remove members if ensuring role, not acting on members.
    if action == "role" and del_members:
        commands.append([name, "role_remove_member", del_members])

    return commands


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

        cmds = ensure_role_with_members_is_present(
            module, name, res_find, action
        )
        commands.extend(cmds)

    if state == "absent" and res_find is not None:
        cmds = ensure_absent_state(module, name, action, res_find)
        commands.extend(cmds)

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

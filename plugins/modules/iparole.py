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
    gen_intersection_list, ensure_fqdn
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


def get_member_host_with_fqdn_lowercase(module, mod_member):
    """Retrieve host members from module, as FQDN, lowercase."""
    default_domain = module.ipa_get_domain()
    hosts = module.params_get(mod_member)
    return (
        [ensure_fqdn(host, default_domain).lower() for host in hosts]
        if hosts
        else hosts
    )


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
        for key in ['user', 'group', 'hostgroup']:
            _members = module.params_get_lowercase(key)
            if _members:
                del_list = gen_intersection_list(
                    _members,
                    result_get_value_lowercase(res_find, "member_%s" % key)
                )
                if del_list:
                    member_args[key] = del_list

        # ensure hosts are FQDN.
        _members = get_member_host_with_fqdn_lowercase(module, "host")
        if _members:
            del_list = gen_intersection_list(
                _members, res_find.get('member_host'))
            if del_list:
                member_args["host"] = del_list

        _services = get_service_param(module, "service")
        if _services:
            _existing = result_get_value_lowercase(res_find, "member_service")
            items = gen_intersection_list(_services.keys(), _existing)
            if items:
                member_args["service"] = [_services[key] for key in items]

        # Only add remove command if there's at least one member no manage.
        if member_args:
            commands.append([name, "role_remove_member", member_args])

    return commands


def get_service_param(module, key):
    """
    Retrieve dict of services, with realm, from the module parameters.

    As the services are compared in a case insensitive manner, but
    are recorded in a case preserving way, a dict mapping the services
    in lowercase to the provided module parameter is generated, so
    that dict keys can be used for comparison and the values are used
    with IPA API.
    """
    _services = module.params_get(key)
    if _services is not None:
        ipa_realm = module.ipa_get_realm()
        _services = [
            to_text(svc) if '@' in svc else ('%s@%s' % (svc, ipa_realm))
            for svc in _services
        ]
        if _services:
            _services = {svc.lower(): svc for svc in _services}
    return _services


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
        if isinstance(existing, (str, unicode)):
            existing = existing.lower()
    else:
        existing = default
    return existing


def gen_services_add_del_lists(module, mod_member, res_find, res_member):
    """Generate add/del lists for service principals."""
    add_list, del_list = None, None
    _services = get_service_param(module, mod_member)
    if _services is not None:
        _existing = result_get_value_lowercase(res_find, res_member)
        add_list, del_list = gen_add_del_lists(_services.keys(), _existing)
        if add_list:
            add_list = [_services[key] for key in add_list]
        if del_list:
            del_list = [to_text(item) for item in del_list]
    return add_list, del_list


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

    for key in ["user", "group", "hostgroup"]:
        _members = module.params_get_lowercase(key)
        if _members is not None:
            add_list, del_list = gen_add_del_lists(
                _members,
                result_get_value_lowercase(res_find, "member_%s" % key)
            )
            if add_list:
                add_members[key] = add_list
            if del_list:
                del_members[key] = del_list

    # ensure hosts are FQDN.
    _members = get_member_host_with_fqdn_lowercase(module, "host")
    if _members:
        add_list, del_list = gen_add_del_lists(
            _members, res_find.get('member_host'))
        if add_list:
            add_members["host"] = add_list
        if del_list:
            del_members["host"] = del_list

    (add_services, del_services) = gen_services_add_del_lists(
        module, "service", res_find, "member_service")
    if add_services:
        add_members["service"] = add_services
    if del_services:
        del_members["service"] = del_services

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

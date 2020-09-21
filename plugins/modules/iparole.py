#!/usr/bin/python
# -*- coding: utf-8 -*-
"""ansible-freeipa iparole module implementation."""

# Authors:
#   Rafael Guterres Jeffman <rjeffman@redhat.com>
#
# Copyright (C) 2020 Red Hat
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
module: iparole
short description: Manage FreeIPA role
description: Manage FreeIPA role
options:
  ipaadmin_principal:
    description: The admin principal.
    default: admin
  ipaadmin_password:
    description: The admin password.
    required: false
  role:
    description: The list of role name strings.
    required: true
    aliases: ["cn"]
  description:
    description: A description for the role.
    required: false
  rename:
    description: Rename the role object.
    required: false
  user:
    description: List of users.
    required: false
  group:
    description: List of groups.
    required: false
  host:
    description: List of hosts.
    required: false
  hostgroup:
    description: List of hostgroups.
    required: false
  service:
    description: List of services.
    required: false
  action:
    description: Work on role or member level.
    choices: ["role", "member"]
    default: role
    required: false
  state:
    description: The state to ensure.
    choices: ["present", "absent"]
    default: present
    required: true
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
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_text
from ansible.module_utils.ansible_freeipa_module import \
    temp_kinit, temp_kdestroy, valid_creds, api_connect, api_command, \
    gen_add_del_lists, compare_args_ipa, module_params_get, api_get_realm
import six


if six.PY3:
    unicode = str


def find_role(module, name):
    """Find if a role with the given name already exist."""
    try:
        _result = api_command(module, "role_show", name, {"all": True})
    except Exception:  # pylint: disable=broad-except
        # An exception is raised if role name is not found.
        return None
    else:
        return _result["result"]


def gen_args(module):
    """Generate arguments for executing commands."""
    arg_map = {
        "description": "description",
        "rename": "rename",
    }
    args = {}

    for param, arg in arg_map.items():
        value = module_params_get(module, param)
        if value is not None:
            args[arg] = value

    return args


def check_parameters(module):
    """Check if parameters passed for module processing are valid."""
    action = module_params_get(module, "action")
    state = module_params_get(module, "state")

    invalid = []

    if state == "present":
        if action == "member":
            invalid.extend(['description', 'rename'])

    if state == "absent":
        invalid.extend(['description', 'rename'])
        if action != "member":
            invalid.extend(['privilege'])

    for arg in invalid:
        if module_params_get(module, arg) is not None:
            module.fail_json(
                msg="Argument '%s' can not be used with action '%s'" %
                (arg, state))


def verify_credentials(module):
    """Ensure there are valid Kerberos credentials."""
    ccache_dir = None
    ccache_name = None

    ipaadmin_principal = module_params_get(module, "ipaadmin_principal")
    ipaadmin_password = module_params_get(module, "ipaadmin_password")

    if not valid_creds(module, ipaadmin_principal):
        ccache_dir, ccache_name = temp_kinit(ipaadmin_principal,
                                             ipaadmin_password)

    return (ccache_dir, ccache_name)


def member_intersect(module, attr, memberof, res_find):
    """Filter member arguments from role found by intersection."""
    params = module_params_get(module, attr)
    if not res_find:
        return params
    filtered = []
    if params:
        existing = res_find.get(memberof, [])
        filtered = list(set(params) & set(existing))
    return filtered


def member_difference(module, attr, memberof, res_find):
    """Filter member arguments from role found by difference."""
    params = module_params_get(module, attr)
    if not res_find:
        return params
    filtered = []
    if params:
        existing = res_find.get(memberof, [])
        filtered = list(set(params) - set(existing))
    return filtered


def ensure_absent_state(module, name, action, res_find):
    """Define commands to ensure absent state."""
    commands = []

    if action == "role":
        commands.append([name, 'role_del', {}])

    if action == "member":

        members = member_intersect(
            module, 'privilege', 'memberof_privilege', res_find)
        if members:
            commands.append([name, "role_remove_privilege",
                             {"privilege": members}])

        member_args = {}
        for key in ['user', 'group', 'host', 'hostgroup']:
            items = member_intersect(
                        module, key, 'member_%s' % key, res_find)
            if items:
                member_args[key] = items

        _services = filter_service(module, res_find,
                                   lambda res, svc: res.startswith(svc))
        if _services:
            member_args['service'] = _services

        # Only add remove command if there's at least one member no manage.
        if member_args:
            commands.append([name, "role_remove_member", member_args])

    return commands


def filter_service(module, res_find, predicate):
    """
    Filter service based on predicate.

    Compare service name with existing ones matching
    at least until `@` from principal name.

    Predicate is a callable that accepts the existing service, and the
    modified service to be compared to.
    """
    _services = []
    service = module_params_get(module, 'service')
    if service:
        existing = [to_text(x) for x in res_find.get('member_service', [])]
        for svc in service:
            svc = svc if '@' in svc else ('%s@' % svc)
            found = [x for x in existing if predicate(x, svc)]
            _services.extend(found)
    return _services


def ensure_role_with_members_is_present(module, name, res_find):
    """Define commands to ensure member are present for action `role`."""
    commands = []
    privilege_add, privilege_del = gen_add_del_lists(
        module_params_get(module, "privilege"),
        res_find.get('memberof_privilege', []))

    if privilege_add:
        commands.append([name, "role_add_privilege",
                         {"privilege": privilege_add}])
    if privilege_del:
        commands.append([name, "role_remove_privilege",
                         {"privilege": privilege_del}])

    add_members = {}
    del_members = {}

    for key in ["user", "group", "host", "hostgroup"]:
        add_list, del_list = gen_add_del_lists(
            module_params_get(module, key),
            res_find.get('member_%s' % key, [])
        )
        if add_list:
            add_members[key] = add_list
        if del_list:
            del_members[key] = [to_text(item) for item in del_list]

    service = [
        to_text(svc) if '@' in svc else ('%s@%s' % (svc, api_get_realm()))
        for svc in (module_params_get(module, 'service') or [])
    ]
    existing = [str(svc) for svc in res_find.get('member_service', [])]
    add_list, del_list = gen_add_del_lists(service, existing)
    if add_list:
        add_members['service'] = add_list
    if del_list:
        del_members['service'] = [to_text(item) for item in del_list]

    if add_members:
        commands.append([name, "role_add_member", add_members])
    if del_members:
        commands.append([name, "role_remove_member", del_members])

    return commands


def ensure_members_are_present(module, name, res_find):
    """Define commands to ensure members are present for action `member`."""
    commands = []

    members = member_difference(
        module, 'privilege', 'memberof_privilege', res_find)
    if members:
        commands.append([name, "role_add_privilege",
                         {"privilege": members}])

    member_args = {}
    for key in ['user', 'group', 'host', 'hostgroup']:
        items = member_difference(
                    module, key, 'member_%s' % key, res_find)
        if items:
            member_args[key] = items

    _services = filter_service(module, res_find,
                               lambda res, svc: not res.startswith(svc))
    if _services:
        member_args['service'] = _services

    if member_args:
        commands.append([name, "role_add_member", member_args])

    return commands


def process_command_failures(command, result):
    """Process the result of a command, looking for errors."""
    # Get all errors
    # All "already a member" and "not a member" failures in the
    # result are ignored. All others are reported.
    errors = []
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
    return errors


def process_commands(module, commands):
    """Process the list of IPA API commands."""
    errors = []
    exit_args = {}
    changed = False
    for name, command, args in commands:
        try:
            result = api_command(module, command, name, args)
            if "completed" in result:
                if result["completed"] > 0:
                    changed = True
            else:
                changed = True

            errors = process_command_failures(command, result)
        except Exception as exception:  # pylint: disable=broad-except
            module.fail_json(
                msg="%s: %s: %s" % (command, name, str(exception)))

    if errors:
        module.fail_json(msg=", ".join(errors))

    return changed, exit_args


def role_commands_for_name(module, state, action, name):
    """Define commands for the Role module."""
    commands = []

    rename = module_params_get(module, "rename")

    res_find = find_role(module, name)

    if state == "present":
        args = gen_args(module)

        if action == "role":
            if res_find is None:
                if rename is not None:
                    module.fail_json(msg="Cannot `rename` inexistent role.")
                commands.append([name, 'role_add', args])
                res_find = {}
            else:
                if not compare_args_ipa(module, args, res_find):
                    commands.append([name, 'role_mod', args])

        if action == "member":
            if res_find is None:
                module.fail_json(msg="No role '%s'" % name)

        cmds = ensure_role_with_members_is_present(module, name, res_find)
        commands.extend(cmds)

    if state == "absent" and res_find is not None:
        cmds = ensure_absent_state(module, name, action, res_find)
        commands.extend(cmds)

    return commands


def create_module():
    """Create module description."""
    ansible_module = AnsibleModule(
        argument_spec=dict(
            # generalgroups
            ipaadmin_principal=dict(type="str", default="admin"),
            ipaadmin_password=dict(type="str", required=False, no_log=True),

            name=dict(type="list", aliases=["cn"], default=None,
                      required=True),
            # present
            description=dict(required=False, type="str", default=None),
            rename=dict(required=False, type="str", default=None),

            # members
            privilege=dict(required=False, type='list', default=None),
            user=dict(required=False, type='list', default=None),
            group=dict(required=False, type='list', default=None),
            host=dict(required=False, type='list', default=None),
            hostgroup=dict(required=False, type='list', default=None),
            service=dict(required=False, type='list', default=None),

            # state
            action=dict(type="str", default="role",
                        choices=["role", "member"]),
            state=dict(type="str", default="present",
                       choices=["present", "absent"]),
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
    ccache_dir = None
    ccache_name = None
    try:
        ccache_dir, ccache_name = verify_credentials(ansible_module)
        api_connect()

        state = module_params_get(ansible_module, "state")
        action = module_params_get(ansible_module, "action")
        names = module_params_get(ansible_module, "name")
        commands = []

        for name in names:
            cmds = role_commands_for_name(ansible_module, state, action, name)
            commands.extend(cmds)

        changed, exit_args = process_commands(ansible_module, commands)

    except Exception as exception:  # pylint: disable=broad-except
        ansible_module.fail_json(msg=str(exception))

    finally:
        temp_kdestroy(ccache_dir, ccache_name)

    # Done
    ansible_module.exit_json(changed=changed, **exit_args)


if __name__ == "__main__":
    main()

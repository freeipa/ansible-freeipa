#!/usr/bin/python
# -*- coding: utf-8 -*-

# Authors:
#   Mark Hahl <mhahl@redhat.com>
#   Jake Reynolds <jakealexis@gmail.com>
#
# Copyright (C) 2021 Red Hat
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


from ansible.module_utils._text import to_text
from ansible.module_utils.ansible_freeipa_module import (
    api_command, api_command_no_name, api_connect, compare_args_ipa,
    gen_add_del_lists, temp_kdestroy, temp_kinit, valid_creds,
    ipalib_errors
)
from ansible.module_utils.basic import AnsibleModule

ANSIBLE_METADATA = {
    "metadata_version": "1.0",
    "supported_by": "community",
    "status": ["preview"],
}


DOCUMENTATION = """
---
module: ipaautomember
short description: Add and delete FreeIPA Auto Membership Rules.
description: Add, modify and delete an IPA Auto Membership Rules.
options:
  ipaadmin_principal:
    description: The admin principal
    default: admin
  ipaadmin_password:
    description: The admin password
    required: false
  ipa_context:
    description: |
      The context in which the module will execute. Executing in a server
      context is preferred, use `client` to execute in a client context if
      the server cannot be accessed.
    choices: ["server", "client"]
    default: server
  name:
    description: The automember rule
    required: true
    aliases: ["cn"]
  description:
    description: A description of this auto member rule
    required: false
  automember_type:
    description: Grouping to which the rule applies
    required: true
    type: str
    choices: ["group", "hostgroup"]
  exclusive:
    description: List of dictionaries containing the attribute and expression.
    type: list
    elements: dict
    aliases: ["automemberexclusiveregex"]
    options:
      key:
        description: The attribute of the regex
        type: str
        required: true
      expression:
        description: The expression of the regex
        type: str
        required: true
  inclusive:
    description: List of dictionaries containing the attribute and expression.
    type: list
    elements: dict
    aliases: ["automemberinclusiveregex"]
    options:
      key:
        description: The attribute of the regex
        type: str
        required: true
      expression:
        description: The expression of the regex
        type: str
        required: true
  action:
    description: Work on automember or member level
    default: automember
    choices: ["member", "automember"]
  state:
    description: State to ensure
    default: present
    choices: ["present", "absent"]
author:
    - Mark Hahl
    - Jake Reynolds
"""

EXAMPLES = """
# Ensure an automember rule exists
- ipaautomember:
    ipaadmin_password: SomeADMINpassword
    name: admins
    description: "example description"
    automember_type: group
    state: present
    inclusive:
    - key: "mail"
      expression: "example.com$

# Delete an automember rule
- ipaautomember:
    ipaadmin_password: SomeADMINpassword
    name: admins
    description: "my automember rule"
    automember_type: group
    state: absent

# Add an inclusive condition to an existing rule
- ipaautomember:
    ipaadmin_password: SomeADMINpassword
    name: "My domain hosts"
    automember_tye: hostgroup
    action: member
    inclusive:
      - key: fqdn
        expression: ".*.mydomain.com"

"""

RETURN = """
"""


def find_automember(module, name, grouping):
    _args = {
        "all": True,
        "type": to_text(grouping)
    }

    try:
        _result = api_command(module, "automember_show", to_text(name), _args)
    except ipalib_errors.NotFound:
        return None
    return _result["result"]


def gen_condition_args(grouping,
                       key,
                       inclusiveregex=None,
                       exclusiveregex=None):
    _args = {}
    if grouping is not None:
        _args['type'] = to_text(grouping)
    if key is not None:
        _args['key'] = to_text(key)
    if inclusiveregex is not None:
        _args['automemberinclusiveregex'] = to_text(inclusiveregex)
    if exclusiveregex is not None:
        _args['automemberexclusiveregex'] = to_text(exclusiveregex)

    return _args


def gen_args(description, grouping):
    _args = {}
    if description is not None:
        _args["description"] = to_text(description)
    if grouping is not None:
        _args['type'] = to_text(grouping)

    return _args


def transform_conditions(conditions):
    """Transform a list of dicts into a list with the format of key=value."""
    transformed = ['%s=%s' % (condition['key'], condition['expression'])
                   for condition in conditions]
    return transformed


def main():
    ansible_module = AnsibleModule(
        argument_spec=dict(
            # general
            ipaadmin_principal=dict(type="str", default="admin"),
            ipaadmin_password=dict(type="str", required=False, no_log=True),

            inclusive=dict(type="list",
                           aliases=["automemberinclusiveregex"], default=None,
                           options=dict(
                               key=dict(type="str", required=True),
                               expression=dict(type="str", required=True)
                           ),
                           elements="dict", required=False),
            exclusive=dict(type="list", aliases=[
                           "automemberexclusiveregex"], default=None,
                           options=dict(
                               key=dict(type="str", required=True),
                               expression=dict(type="str", required=True)
                           ),
                           elements="dict", required=False),
            name=dict(type="list", aliases=["cn"],
                      default=None, required=True),
            description=dict(type="str", default=None),
            automember_type=dict(type='str', required=False,
                                 choices=['group', 'hostgroup']),
            action=dict(type="str", default="automember",
                        choices=["member", "automember"]),
            state=dict(type="str", default="present",
                       choices=["present", "absent", "rebuild"]),
            users=dict(type="list", default=None),
            hosts=dict(type="list", default=None),
        ),
        supports_check_mode=True,
    )

    ansible_module._ansible_debug = True

    # Get parameters

    # general
    ipaadmin_principal = ansible_module.params.get("ipaadmin_principal")
    ipaadmin_password = ansible_module.params.get("ipaadmin_password")
    ipa_context = ansible_module.params.get("ipa_context")
    names = ansible_module.params.get("name")

    # present
    description = ansible_module.params.get("description")

    # conditions
    inclusive = ansible_module.params.get("inclusive")
    exclusive = ansible_module.params.get("exclusive")

    # action
    action = ansible_module.params.get("action")
    # state
    state = ansible_module.params.get("state")

    # grouping/type
    automember_type = ansible_module.params.get("automember_type")

    rebuild_users = ansible_module.params.get("users")
    rebuild_hosts = ansible_module.params.get("hosts")

    if (rebuild_hosts or rebuild_users) and state != "rebuild":
        ansible_module.fail_json(
            msg="'hosts' and 'users' are only valid with state: rebuild")
    if not automember_type and state != "rebuild":
        ansible_module.fail_json(
            msg="'automember_type' is required unless state: rebuild")

    # Init
    changed = False
    exit_args = {}
    ccache_dir = None
    ccache_name = None
    res_find = None

    try:
        if not valid_creds(ansible_module, ipaadmin_principal):
            ccache_dir, ccache_name = temp_kinit(ipaadmin_principal,
                                                 ipaadmin_password)
        api_connect(ipa_context)

        commands = []

        for name in names:
            # Make sure automember rule exists
            res_find = find_automember(ansible_module, name, automember_type)

            # Create command
            if state == 'present':
                args = gen_args(description, automember_type)

                if action == "automember":
                    if res_find is not None:
                        if not compare_args_ipa(ansible_module,
                                                args,
                                                res_find,
                                                ignore=['type']):
                            commands.append([name, 'automember_mod', args])
                    else:
                        commands.append([name, 'automember_add', args])
                        res_find = {}

                    inclusive_add, inclusive_del = gen_add_del_lists(
                        transform_conditions(inclusive or []),
                        res_find.get("automemberinclusiveregex", [])
                    )

                    exclusive_add, exclusive_del = gen_add_del_lists(
                        transform_conditions(exclusive or []),
                        res_find.get("automemberexclusiveregex", [])
                    )

                elif action == "member":
                    if res_find is None:
                        ansible_module.fail_json(
                            msg="No automember '%s'" % name)

                    inclusive_add = transform_conditions(inclusive or [])
                    inclusive_del = []
                    exclusive_add = transform_conditions(exclusive or [])
                    exclusive_del = []

                for _inclusive in inclusive_add:
                    key, regex = _inclusive.split("=", 1)
                    condition_args = gen_condition_args(
                        automember_type, key, inclusiveregex=regex)
                    commands.append([name, 'automember_add_condition',
                                     condition_args])

                for _inclusive in inclusive_del:
                    key, regex = _inclusive.split("=", 1)
                    condition_args = gen_condition_args(
                        automember_type, key, inclusiveregex=regex)
                    commands.append([name, 'automember_remove_condition',
                                     condition_args])

                for _exclusive in exclusive_add:
                    key, regex = _exclusive.split("=", 1)
                    condition_args = gen_condition_args(
                        automember_type, key, exclusiveregex=regex)
                    commands.append([name, 'automember_add_condition',
                                     condition_args])

                for _exclusive in exclusive_del:
                    key, regex = _exclusive.split("=", 1)
                    condition_args = gen_condition_args(
                        automember_type, key, exclusiveregex=regex)
                    commands.append([name, 'automember_remove_condition',
                                     condition_args])

            elif state == 'absent':
                if action == "automember":
                    if res_find is not None:
                        commands.append([name, 'automember_del',
                                         {'type': to_text(automember_type)}])

                elif action == "member":
                    if res_find is None:
                        ansible_module.fail_json(
                            msg="No automember '%s'" % name)

                    if inclusive is not None:
                        for _inclusive in transform_conditions(inclusive):
                            key, regex = _inclusive.split("=", 1)
                            condition_args = gen_condition_args(
                                automember_type, key, inclusiveregex=regex)
                            commands.append(
                                [name, 'automember_remove_condition',
                                 condition_args])

                    if exclusive is not None:
                        for _exclusive in transform_conditions(exclusive):
                            key, regex = _exclusive.split("=", 1)
                            condition_args = gen_condition_args(
                                automember_type, key, exclusiveregex=regex)
                            commands.append([name,
                                             'automember_remove_condition',
                                            condition_args])

            elif state == "rebuild":
                if automember_type:
                    commands.append([None, 'automember_rebuild',
                                     {"type": to_text(automember_type)}])
                if rebuild_users:
                    commands.append([None, 'automember_rebuild',
                                    {"users": [
                                        to_text(_u)
                                        for _u in rebuild_users]}])
                if rebuild_hosts:
                    commands.append([None, 'automember_rebuild',
                                    {"hosts": [
                                        to_text(_h)
                                        for _h in rebuild_hosts]}])

        # Check mode exit
        if ansible_module.check_mode:
            ansible_module.exit_json(changed=len(commands) > 0, **exit_args)

        errors = []
        for name, command, args in commands:
            try:
                if name is None:
                    result = api_command_no_name(ansible_module, command, args)
                else:
                    result = api_command(ansible_module, command,
                                         to_text(name), args)

                if "completed" in result:
                    if result["completed"] > 0:
                        changed = True
                else:
                    changed = True
            except Exception as ex:
                ansible_module.fail_json(msg="%s: %s: %s" % (command, name,
                                                             str(ex)))
            # Get all errors
            if "failed" in result and len(result["failed"]) > 0:
                for item in result["failed"]:
                    failed_item = result["failed"][item]
                    for member_type in failed_item:
                        for member, failure in failed_item[member_type]:
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

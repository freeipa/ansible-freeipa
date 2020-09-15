#!/usr/bin/python
# -*- coding: utf-8 -*-

# Authors:
#   Mark Hahl <mhahl@redhat.com>
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


from ansible.module_utils._text import to_text
from ansible.module_utils.ansible_freeipa_module import (api_command,
                                                         api_connect,
                                                         compare_args_ipa,
                                                         temp_kdestroy,
                                                         temp_kinit,
                                                         valid_creds)
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
description:
- Add, modify and delete an IPA Auto Membership Rules.
options:
  ipaadmin_principal:
    description: The admin principal
    default: admin
  ipaadmin_password:
    description: The admin password
    required: false
  name:
    description: The automember rule
    required: true
    aliases: ["cn"]
  description:
    description: A description of this auto member rule
    required: false
  type:
    description:
    - Grouping to which the rule applies
    required: true
    type: str
    choices: ["group", "hostgroup"]
  exclusive:
    description:
    - List of dictionaries containing the attribute and expression.
    type: list
    elements: dict
    aliases: ["automemberexclusiveregex"]
  inclusive:
    description:
    - List of dictionaries containing the attribute and expression.
    type: list
    elements: dict
    aliases: ["automemberinclusiveregex"]
  state:
    description: State to ensure
    default: present
    choices: ["present", "absent"]
author:
    - Mark Hahl
"""

EXAMPLES = """
# Ensure an automember rule exists
- ipaautomember:
    ipaadmin_password: SomeADMINpassword
    name: admins
    description: "example description"
    type: group
    state: present
    inclusive:
    - key: "mail"
      expression: "example.com$

"""

RETURN = """
"""


def find_automember(module, name, grouping):
    _args = {
        "all": True,
        "type": to_text(grouping)
    }

    _result = api_command(module, "automember_find", to_text(name), _args)

    if len(_result["result"]) > 1:
        module.fail_json(
            msg="There is more than one automember '%s'" % (name))
    elif len(_result["result"]) == 1:
        return _result["result"][0]
    else:
        return None


def gen_condition_args(grouping,
                       key,
                       inclusiveregex,
                       exclusiveregex):
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
    transformed = []
    for condition in conditions:
        transformed.append('='.join(str(x) for x in condition.values()))
    return transformed


def gen_condition_commands(name,
                           grouping,
                           module_conditions,
                           current_conditions):
    """Return a list of commands to add/remove automember rule conditions."""
    commands = []
    add_diff = set(module_conditions) - set(current_conditions)
    remove_diff = set(current_conditions) - set(module_conditions)

    for item in add_diff:
        key, condition = item.split("=")
        condition_args = gen_condition_args(grouping, key, condition, None)
        commands.append([name, 'automember_add_condition', condition_args])

    for item in remove_diff:
        key, condition = item.split("=")
        condition_args = gen_condition_args(grouping, key, condition, None)
        commands.append([name, 'automember_remove_condition', condition_args])

    return commands


def main():
    ansible_module = AnsibleModule(
        argument_spec=dict(
            # general
            ipaadmin_principal=dict(type="str", default="admin"),
            ipaadmin_password=dict(type="str", required=False, no_log=True),

            inclusive=dict(type="list", aliases=[
                           "automemberinclusiveregex"], default=None),
            exclusive=dict(type="list", aliases=[
                           "automemberexclusiveregex"], default=None),
            name=dict(type="list", aliases=["cn"],
                      default=None, required=True),
            description=dict(type="str", default=None),
            type=dict(type='str', required=True,
                      choices=['group', 'hostgroup']),
            state=dict(type="str", default="present",
                       choices=["present", "absent"]),
        ),
        supports_check_mode=True,
    )

    ansible_module._ansible_debug = True

    # Get parameters

    # general
    ipaadmin_principal = ansible_module.params.get("ipaadmin_principal")
    ipaadmin_password = ansible_module.params.get("ipaadmin_password")
    names = ansible_module.params.get("name")

    # present
    description = ansible_module.params.get("description")

    # conditions
    inclusive = ansible_module.params.get("inclusive")
    exclusive = ansible_module.params.get("exclusive")

    # state
    state = ansible_module.params.get("state")

    # grouping/type
    grouping = ansible_module.params.get("type")

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
        api_connect()

        commands = []

        for name in names:
            # Make sure automember rule exists
            res_find = find_automember(ansible_module, name, grouping)

            # Create command
            if state == 'present':
                args = gen_args(description, grouping)

                if res_find is not None:
                    if not compare_args_ipa(ansible_module,
                                            args, res_find, ['type']):
                        commands.append([name, 'automember_mod', args])
                else:
                    commands.append([name, 'automember_add', args])
                    res_find = {}

                if inclusive is not None:

                    # Get the conditions from the module
                    module_conditions = transform_conditions(inclusive)

                    # Get the conditions from the existing automember rule.
                    current_conditions = res_find.get(
                        'automemberinclusiveregex', [])

                    # Append the commands to the list
                    commands.extend(gen_condition_commands(
                        name, grouping, module_conditions, current_conditions))

                if exclusive is not None and False:

                    # Get the conditions from the module
                    module_conditions = transform_conditions(exclusive)

                    # Get the conditions from the existing automember rule.
                    current_conditions = res_find.get(
                        'automemberexclusiveregex', [])

                    # Append the commands to the list
                    commands.extend(gen_condition_commands(
                        name, grouping, module_conditions, current_conditions))
            elif state == 'absent':
                if res_find is not None:
                    commands.append(
                        [name, 'automember_del', {'type': to_text(grouping)}])

        for name, command, args in commands:
            try:
                result = api_command(
                    ansible_module, command, to_text(name), args)

                # Check if any changes were made by any command
                if command in ('automember_del',
                               'automember_remove_condition'):
                    changed |= "Deleted" in result['summary']

                elif command in ('automember_add',
                                 'automember_add_condition'):
                    changed |= "Added" in result['summary']

                elif command == 'automember_mod':
                    changed |= "Modified" in result['summary']

            except Exception as e:
                ansible_module.fail_json(msg=str(e))

    except Exception as e:
        ansible_module.fail_json(msg=str(e))

    finally:
        temp_kdestroy(ccache_dir, ccache_name)

    # Done
    ansible_module.exit_json(changed=changed, **exit_args)


if __name__ == "__main__":
    main()

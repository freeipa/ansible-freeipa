# -*- coding: utf-8 -*-

# Authors:
#   Mark Hahl <mhahl@redhat.com>
#   Jake Reynolds <jakealexis@gmail.com>
#   Thomas Woerner <twoerner@redhat.com>
#
# Copyright (C) 2021-2022 Red Hat
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
module: ipaautomember
short_description: Add and delete FreeIPA Auto Membership Rules.
description: Add, modify and delete an IPA Auto Membership Rules.
extends_documentation_fragment:
  - ipamodule_base_docs
options:
  name:
    description: The automember rule
    required: false
    type: list
    elements: str
    aliases: ["cn"]
  description:
    description: A description of this auto member rule
    required: false
    type: str
  automember_type:
    description: Grouping to which the rule applies
    required: false
    type: str
    choices: ["group", "hostgroup"]
  exclusive:
    description: List of dictionaries containing the attribute and expression.
    type: list
    elements: dict
    aliases: ["automemberexclusiveregex"]
    suboptions:
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
    suboptions:
      key:
        description: The attribute of the regex
        type: str
        required: true
      expression:
        description: The expression of the regex
        type: str
        required: true
  users:
    description: Users to rebuild membership for.
    type: list
    elements: str
    required: false
  hosts:
    description: Hosts to rebuild membership for.
    type: list
    elements: str
    required: false
  no_wait:
    description: Don't wait for rebuilding membership.
    type: bool
  default_group:
    description: Default (fallback) group for all unmatched entries.
    type: str
  action:
    description: Work on automember or member level
    type: str
    default: automember
    choices: ["member", "automember"]
  state:
    description: State to ensure
    type: str
    default: present
    choices: ["present", "absent", "rebuilt", "orphans_removed"]
author:
  - Mark Hahl (@mhahl)
  - Jake Reynolds (@jake2184)
  - Thomas Woerner (@t-woerner)
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
      expression: "example.com"

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
    automember_type: hostgroup
    action: member
    inclusive:
      - key: fqdn
        expression: ".*.mydomain.com"

# Ensure group membership for all users has been rebuilt
- ipaautomember:
    ipaadmin_password: SomeADMINpassword
    automember_type: group
    state: rebuilt

# Ensure group membership for given users has been rebuilt
- ipaautomember:
    ipaadmin_password: SomeADMINpassword
    users:
    - user1
    - user2
    state: rebuilt

# Ensure hostgroup membership for all hosts has been rebuilt
- ipaautomember:
    ipaadmin_password: SomeADMINpassword
    automember_type: hostgroup
    state: rebuilt

# Ensure hostgroup membership for given hosts has been rebuilt
- ipaautomember:
    ipaadmin_password: SomeADMINpassword
    hosts:
    - host1.mydomain.com
    - host2.mydomain.com
    state: rebuilt

# Ensure default group fallback_group for all unmatched group entries is set
- ipaautomember:
    ipaadmin_password: SomeADMINpassword
    automember_type: group
    default_group: fallback_group

# Ensure default group for all unmatched group entries is not set
- ipaautomember:
    ipaadmin_password: SomeADMINpassword
    default_group: ""
    automember_type: group
    state: absent

# Ensure default hostgroup fallback_hostgroup for all unmatched group entries
# is set
- ipaautomember:
    ipaadmin_password: SomeADMINpassword
    automember_type: hostgroup
    default_group: fallback_hostgroup

# Ensure default hostgroup for all unmatched group entries is not set
- ipaautomember:
    ipaadmin_password: SomeADMINpassword
    automember_type: hostgroup
    default_group: ""
    state: absent

# Example playbook to ensure all orphan automember group rules are removed:
- ipaautomember:
    ipaadmin_password: SomeADMINpassword
    automember_type: group
    state: orphans_removed

# Example playbook to ensure all orphan automember hostgroup rules are removed:
- ipaautomember:
    ipaadmin_password: SomeADMINpassword
    automember_type: hostgroup
    state: orphans_removed
"""

RETURN = """
"""

from ansible.module_utils.ansible_freeipa_module import (
    IPAAnsibleModule, compare_args_ipa, gen_add_del_lists, ipalib_errors, DN
)


def find_automember(module, name, automember_type):
    _args = {
        "all": True,
        "type": automember_type
    }

    try:
        _result = module.ipa_command("automember_show", name, _args)
    except ipalib_errors.NotFound:
        return None
    return _result["result"]


def find_automember_orphans(module, automember_type):
    _args = {
        "all": True,
        "type": automember_type
    }

    try:
        _result = module.ipa_command_no_name("automember_find_orphans", _args)
    except ipalib_errors.NotFound:
        return None
    return _result


def find_automember_default_group(module, automember_type):
    _args = {
        "all": True,
        "type": automember_type
    }

    try:
        _result = module.ipa_command_no_name("automember_default_group_show",
                                             _args)
    except ipalib_errors.NotFound:
        return None
    return _result["result"]


def gen_condition_args(automember_type,
                       key,
                       inclusiveregex=None,
                       exclusiveregex=None):
    _args = {}
    if automember_type is not None:
        _args['type'] = automember_type
    if key is not None:
        _args['key'] = key
    if inclusiveregex is not None:
        _args['automemberinclusiveregex'] = inclusiveregex
    if exclusiveregex is not None:
        _args['automemberexclusiveregex'] = exclusiveregex

    return _args


def gen_rebuild_args(automember_type, rebuild_users, rebuild_hosts, no_wait):
    _args = {"no_wait": no_wait}
    if automember_type is not None:
        _args['type'] = automember_type
    if rebuild_users is not None:
        _args["users"] = rebuild_users
    if rebuild_hosts is not None:
        _args["hosts"] = rebuild_hosts
    return _args


def gen_args(description, automember_type):
    _args = {}
    if description is not None:
        _args["description"] = description
    if automember_type is not None:
        _args['type'] = automember_type
    return _args


def transform_conditions(conditions):
    """Transform a list of dicts into a list with the format of key=value."""
    transformed = ['%s=%s' % (condition['key'], condition['expression'])
                   for condition in conditions]
    return transformed


def check_condition_keys(ansible_module, conditions, aciattrs):
    if conditions is None:
        return
    for condition in conditions:
        if condition["key"] not in aciattrs:
            ansible_module.fail_json(
                msg="Invalid automember condition key '%s'" % condition["key"])


def main():
    ansible_module = IPAAnsibleModule(
        argument_spec=dict(
            # general
            inclusive=dict(type="list",
                           aliases=["automemberinclusiveregex"],
                           default=None,
                           options=dict(
                               key=dict(type="str", required=True,
                                        no_log=False),
                               expression=dict(type="str", required=True)
                           ),
                           elements="dict",
                           required=False),
            exclusive=dict(type="list",
                           aliases=["automemberexclusiveregex"],
                           default=None,
                           options=dict(
                               key=dict(type="str", required=True,
                                        no_log=False),
                               expression=dict(type="str", required=True)
                           ),
                           elements="dict",
                           required=False),
            name=dict(type="list", elements="str", aliases=["cn"],
                      default=None, required=False),
            description=dict(type="str", default=None),
            automember_type=dict(type='str', required=False,
                                 choices=['group', 'hostgroup']),
            no_wait=dict(type="bool", default=None),
            default_group=dict(type="str", default=None),
            action=dict(type="str", default="automember",
                        choices=["member", "automember"]),
            state=dict(type="str", default="present",
                       choices=["present", "absent", "rebuilt",
                                "orphans_removed"]),
            users=dict(type="list", elements="str", default=None),
            hosts=dict(type="list", elements="str", default=None),
        ),
        supports_check_mode=True,
    )

    ansible_module._ansible_debug = True

    # Get parameters

    # general
    names = ansible_module.params_get("name")
    if names is None:
        names = []

    # present
    description = ansible_module.params_get("description")

    # conditions
    inclusive = ansible_module.params_get("inclusive")
    exclusive = ansible_module.params_get("exclusive")

    # no_wait for rebuilt
    no_wait = ansible_module.params_get("no_wait")

    # default_group
    default_group = ansible_module.params_get("default_group")

    # action
    action = ansible_module.params_get("action")
    # state
    state = ansible_module.params_get("state")

    # grouping/type
    automember_type = ansible_module.params_get("automember_type")

    rebuild_users = ansible_module.params_get("users")
    rebuild_hosts = ansible_module.params_get("hosts")

    # Check parameters
    invalid = []

    if state in ["rebuilt", "orphans_removed"]:
        invalid = ["name", "description", "exclusive", "inclusive",
                   "default_group"]

        if action == "member":
            ansible_module.fail_json(
                msg="'action=member' is not usable with state '%s'" % state)

        if state == "rebuilt":
            if automember_type == "group" and rebuild_hosts is not None:
                ansible_module.fail_json(
                    msg="state %s: hosts can not be set when type is '%s'" %
                    (state, automember_type))
            if automember_type == "hostgroup" and rebuild_users is not None:
                ansible_module.fail_json(
                    msg="state %s: users can not be set when type is '%s'" %
                    (state, automember_type))

        elif state == "orphans_removed":
            invalid.extend(["users", "hosts"])

            if not automember_type:
                ansible_module.fail_json(
                    msg="'automember_type' is required unless state: rebuilt")

    else:
        if default_group is not None:
            for param in ["name", "exclusive", "inclusive", "users", "hosts"
                          "no_wait"]:
                if ansible_module.params.get(param) is not None:
                    msg = "Cannot use {0} together with default_group"
                    ansible_module.fail_json(msg=msg.format(param))
            if action == "member":
                ansible_module.fail_json(
                    msg="Cannot use default_group with action:member")
            if state == "absent":
                ansible_module.fail_json(
                    msg="Cannot use default_group with state:absent")

        else:
            invalid = ["users", "hosts", "no_wait"]

        if not automember_type:
            ansible_module.fail_json(
                msg="'automember_type' is required.")

    ansible_module.params_fail_used_invalid(invalid, state, action)

    # Init
    changed = False
    exit_args = {}
    res_find = None

    with ansible_module.ipa_connect():

        commands = []

        for name in names:
            # Make sure automember rule exists
            res_find = find_automember(ansible_module, name, automember_type)

            # Check inclusive and exclusive conditions
            if inclusive is not None or exclusive is not None:
                # automember_type is either "group" or "hostgorup"
                if automember_type == "group":
                    _type = u"user"
                elif automember_type == "hostgroup":
                    _type = u"host"
                else:
                    ansible_module.fail_json(
                        msg="Bad automember type '%s'" % automember_type)

                try:
                    aciattrs = ansible_module.ipa_command(
                        "json_metadata", _type, {}
                    )['objects'][_type]['aciattrs']
                except Exception as ex:
                    ansible_module.fail_json(
                        msg="%s: %s: %s" % ("json_metadata", _type, str(ex)))

                check_condition_keys(ansible_module, inclusive, aciattrs)
                check_condition_keys(ansible_module, exclusive, aciattrs)

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

                    if inclusive is not None:
                        inclusive_add, inclusive_del = gen_add_del_lists(
                            transform_conditions(inclusive),
                            res_find.get("automemberinclusiveregex", [])
                        )
                    else:
                        inclusive_add, inclusive_del = [], []

                    if exclusive is not None:
                        exclusive_add, exclusive_del = gen_add_del_lists(
                            transform_conditions(exclusive),
                            res_find.get("automemberexclusiveregex", [])
                        )
                    else:
                        exclusive_add, exclusive_del = [], []

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
                                         {'type': automember_type}])

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

        if len(names) == 0:
            if state == "rebuilt":
                args = gen_rebuild_args(automember_type, rebuild_users,
                                        rebuild_hosts, no_wait)
                commands.append([None, 'automember_rebuild', args])

            elif state == "orphans_removed":
                res_find = find_automember_orphans(ansible_module,
                                                   automember_type)
                if res_find["count"] > 0:
                    commands.append([None, 'automember_find_orphans',
                                     {'type': automember_type,
                                      'remove': True}])

            elif default_group is not None and state == "present":
                res_find = find_automember_default_group(ansible_module,
                                                         automember_type)

                if default_group == "":
                    if isinstance(res_find["automemberdefaultgroup"], list):
                        commands.append([None,
                                         'automember_default_group_remove',
                                         {'type': automember_type}])

                else:
                    dn_default_group = [DN(('cn', default_group),
                                           ('cn', '%ss' % automember_type),
                                           ('cn', 'accounts'),
                                           ansible_module.ipa_get_basedn())]
                    if repr(res_find["automemberdefaultgroup"]) != \
                       repr(dn_default_group):
                        commands.append(
                            [None, 'automember_default_group_set',
                             {'type': automember_type,
                              'automemberdefaultgroup': default_group}])

            else:
                ansible_module.fail_json(msg="Invalid operation")

        # Execute commands

        changed = ansible_module.execute_ipa_commands(commands)

        # result["failed"] is used only for INCLUDE_RE, EXCLUDE_RE
        # if entries could not be added that are already there and
        # if entries could not be removed that are not there.
        # All other issues like invalid attributes etc. are handled
        # as exceptions. Therefore the error section is not here as
        # in other modules.

    # Done
    ansible_module.exit_json(changed=changed, **exit_args)


if __name__ == "__main__":
    main()

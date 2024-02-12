# -*- coding: utf-8 -*-

# Authors:
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
module: ipadelegation
short_description: Manage FreeIPA delegations
description: Manage FreeIPA delegations and delegation attributes
extends_documentation_fragment:
  - ipamodule_base_docs
options:
  name:
    description: The list of delegation name strings.
    type: list
    elements: str
    required: true
    aliases: ["aciname"]
  permission:
    description: Permissions to grant (read, write). Default is write.
    type: list
    elements: str
    required: false
    aliases: ["permissions"]
  attribute:
    description: Attribute list to which the delegation applies
    type: list
    elements: str
    required: false
    aliases: ["attrs"]
  membergroup:
    description: User group to apply delegation to
    type: str
    required: false
    aliases: ["memberof"]
  group:
    description: User group ACI grants access to
    type: str
    required: false
  action:
    description: Work on delegation or member level.
    type: str
    choices: ["delegation", "member"]
    default: delegation
    required: false
  state:
    description: The state to ensure.
    type: str
    choices: ["present", "absent"]
    default: present
    required: false
author:
  - Thomas Woerner (@t-woerner)
"""

EXAMPLES = """
# Ensure delegation "basic manager attributes" is present
- ipadelegation:
    ipaadmin_password: SomeADMINpassword
    name: "basic manager attributes"
    permission: read
    attribute:
    - businesscategory
    - employeetype
    group: managers
    membergroup: employees

# Ensure delegation "basic manager attributes" member attribute
# departmentnumber is present
- ipadelegation:
    ipaadmin_password: SomeADMINpassword
    name: "basic manager attributes"
    attribute:
    - departmentnumber
    action: member

# Ensure delegation "basic manager attributes" member attributes
# employeetype and employeenumber are present
- ipadelegation:
    ipaadmin_password: SomeADMINpassword
    name: "basic manager attributes"
    attribute:
    - employeenumber
    - employeetype
    action: member
    state: absent

# Ensure delegation "basic manager attributes" is absent
- ipadelegation:
    ipaadmin_password: SomeADMINpassword
    name: "basic manager attributes"
    state: absent
"""

RETURN = """
"""


from ansible.module_utils.ansible_freeipa_module import \
    IPAAnsibleModule, compare_args_ipa


def find_delegation(module, name):
    """Find if a delegation with the given name already exist."""
    try:
        _result = module.ipa_command("delegation_show", name, {"all": True})
    except Exception:  # pylint: disable=broad-except
        # An exception is raised if delegation name is not found.
        return None
    return _result["result"]


def gen_args(permission, attribute, membergroup, group):
    _args = {}
    if permission is not None:
        _args["permissions"] = permission
    if attribute is not None:
        _args["attrs"] = attribute
    if membergroup is not None:
        _args["memberof"] = membergroup
    if group is not None:
        _args["group"] = group
    return _args


def main():
    ansible_module = IPAAnsibleModule(
        argument_spec=dict(
            # general
            name=dict(type="list", elements="str", aliases=["aciname"],
                      required=True),
            # present
            permission=dict(required=False, type='list', elements="str",
                            aliases=["permissions"], default=None),
            attribute=dict(required=False, type='list', elements="str",
                           aliases=["attrs"], default=None),
            membergroup=dict(type="str", aliases=["memberof"], default=None),
            group=dict(type="str", default=None),
            action=dict(type="str", default="delegation",
                        choices=["member", "delegation"]),
            # state
            state=dict(type="str", default="present",
                       choices=["present", "absent"]),
        ),
        supports_check_mode=True,
    )

    ansible_module._ansible_debug = True

    # Get parameters

    # general
    names = ansible_module.params_get("name")

    # present
    permission = ansible_module.params_get_lowercase("permission")
    attribute = ansible_module.params_get_lowercase("attribute")
    membergroup = ansible_module.params_get("membergroup")
    group = ansible_module.params_get_lowercase("group")
    action = ansible_module.params_get("action")
    # state
    state = ansible_module.params_get("state")

    # Check parameters

    invalid = []

    if state == "present":
        if len(names) != 1:
            ansible_module.fail_json(
                msg="Only one delegation be added at a time.")
        if action == "member":
            invalid = ["permission", "membergroup", "group"]

    if state == "absent":
        if len(names) < 1:
            ansible_module.fail_json(msg="No name given.")
        invalid = ["permission", "membergroup", "group"]
        if action == "delegation":
            invalid.append("attribute")

    ansible_module.params_fail_used_invalid(invalid, state, action)

    if permission is not None:
        perm = [p for p in permission if p not in ("read", "write")]
        if perm:
            ansible_module.fail_json(msg="Invalid permission '%s'" % perm)
        if len(set(permission)) != len(permission):
            ansible_module.fail_json(
                msg="Invalid permission '%s', items are not unique" %
                repr(permission))

    if attribute is not None:
        if len(set(attribute)) != len(attribute):
            ansible_module.fail_json(
                msg="Invalid attribute '%s', items are not unique" %
                repr(attribute))

    # Init

    changed = False
    exit_args = {}

    # Connect to IPA API
    with ansible_module.ipa_connect():

        commands = []
        for name in names:
            args = {}
            # Make sure delegation exists
            res_find = find_delegation(ansible_module, name)

            # Create command
            if state == "present":

                # Generate args
                args = gen_args(permission, attribute, membergroup, group)

                if action == "delegation":
                    # Found the delegation
                    if res_find is None:
                        commands.append([name, "delegation_add", args])

                elif action == "member":
                    if res_find is None:
                        ansible_module.fail_json(
                            msg="No delegation '%s'" % name)

                    if attribute is None:
                        ansible_module.fail_json(msg="No attributes given")

                    # New attribute list (add given ones to find result)
                    # Make list with unique entries
                    attrs = list(set(list(res_find["attrs"]) + attribute))
                    args["attrs"] = attrs

            elif state == "absent":
                if action == "delegation":
                    if res_find is not None:
                        commands.append([name, "delegation_del", {}])

                elif action == "member":
                    if res_find is None:
                        ansible_module.fail_json(
                            msg="No delegation '%s'" % name)

                    if attribute is None:
                        ansible_module.fail_json(msg="No attributes given")

                    # New attribute list (remove given ones from find result)
                    # Make list with unique entries
                    attrs = list(set(res_find["attrs"]) - set(attribute))
                    if len(attrs) < 1:
                        ansible_module.fail_json(
                            msg="At minimum one attribute is needed.")
                    args["attrs"] = attrs

            else:
                ansible_module.fail_json(msg="Unkown state '%s'" % state)

            # Manage members
            if (
                args and res_find and
                not compare_args_ipa(ansible_module, args, res_find)
            ):
                commands.append([name, "delegation_mod", args])

        # Execute commands

        changed = ansible_module.execute_ipa_commands(commands)

    # Done

    ansible_module.exit_json(changed=changed, **exit_args)


if __name__ == "__main__":
    main()

# -*- coding: utf-8 -*-

# Authors:
#   Thomas Woerner <twoerner@redhat.com>
#
# Copyright (C) 2022 Red Hat
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
module: ipaservicedelegationtarget
short_description: Manage FreeIPA servicedelegationtarget
description: |
  Manage FreeIPA servicedelegationtarget and servicedelegationtarget members
extends_documentation_fragment:
  - ipamodule_base_docs
options:
  name:
    description: The list of servicedelegationtarget name strings.
    type: list
    elements: str
    required: true
    aliases: ["cn"]
  principal:
    description: |
      The list of principals. A principal can be of the format:
      fqdn, fqdn@REALM, service/fqdn, service/fqdn@REALM, host/fqdn,
      host/fqdn@REALM, alias$, alias$@REALM, where fqdn and fqdn@REALM
      are host principals and the same as host/fqdn and host/fqdn@REALM.
      Host princpals are only usable with IPA versions 4.9.0 and up.
    type: list
    elements: str
    required: false
  action:
    description: Work on servicedelegationtarget or member level.
    type: str
    choices: ["servicedelegationtarget", "member"]
    default: servicedelegationtarget
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
# Ensure servicedelegationtarget delegation-target is present
- ipaservicedelegationtarget:
    ipaadmin_password: SomeADMINpassword
    name: delegation-target

# Ensure servicedelegationtarget delegation-target member principal
# test/example.com is present
- ipaservicedelegationtarget:
    ipaadmin_password: SomeADMINpassword
    name: delegation-target
    principal: test/example.com
    action: member

# Ensure servicedelegationtarget delegation-target member principal
# test/example.com is absent
- ipaservicedelegationtarget:
    ipaadmin_password: SomeADMINpassword
    name: delegation-target
    principal: test/example.com
    action: member
    state: absent

# Ensure servicedelegationtarget delegation-target is absent
- ipaservicedelegationtarget:
    ipaadmin_password: SomeADMINpassword
    name: delegation-target
    state: absent
"""

RETURN = """
"""


from ansible.module_utils.ansible_freeipa_module import \
    IPAAnsibleModule, gen_add_del_lists, gen_add_list, gen_intersection_list, \
    servicedelegation_normalize_principals
from ansible.module_utils import six

if six.PY3:
    unicode = str


def find_servicedelegationtarget(module, name):
    """Find if a servicedelegationtarget with the given name already exist."""
    try:
        _result = module.ipa_command("servicedelegationtarget_show", name,
                                     {"all": True})
    except Exception:  # pylint: disable=broad-except
        # An exception is raised if servicedelegationtarget name is not found.
        return None
    return _result["result"]


def main():
    ansible_module = IPAAnsibleModule(
        argument_spec=dict(
            # general
            name=dict(type="list", elements="str", aliases=["cn"],
                      required=True),
            # present
            principal=dict(required=False, type='list', elements="str",
                           default=None),

            action=dict(type="str", default="servicedelegationtarget",
                        choices=["member", "servicedelegationtarget"]),
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
    principal = ansible_module.params_get("principal")

    action = ansible_module.params_get("action")

    # state
    state = ansible_module.params_get("state")

    # Check parameters

    invalid = []

    if state == "present":
        if len(names) != 1:
            ansible_module.fail_json(
                msg="Only one servicedelegationtarget can be added at a time.")

    if state == "absent":
        if len(names) < 1:
            ansible_module.fail_json(msg="No name given.")
        if action == "servicedelegationtarget":
            invalid.append("principal")

    ansible_module.params_fail_used_invalid(invalid, state, action)

    # Init

    changed = False
    exit_args = {}

    # Connect to IPA API
    with ansible_module.ipa_connect():

        # Normalize principals
        if principal:
            principal = servicedelegation_normalize_principals(
                ansible_module, principal, state == "present")

        commands = []
        principal_add = principal_del = []
        for name in names:
            # Make sure servicedelegationtarget exists
            res_find = find_servicedelegationtarget(ansible_module, name)

            # Create command
            if state == "present":

                if action == "servicedelegationtarget":
                    # A servicedelegationtarget does not have normal options.
                    # There is no servicedelegationtarget-mod command.
                    # Principal members are handled with the _add_member and
                    # _remove_member commands further down.
                    if res_find is None:
                        commands.append([name, "servicedelegationtarget_add",
                                         {}])
                        res_find = {}

                    # Generate addition and removal lists
                    principal_add, principal_del = gen_add_del_lists(
                        principal, res_find.get("memberprincipal"))

                elif action == "member":
                    if res_find is None:
                        ansible_module.fail_json(
                            msg="No servicedelegationtarget '%s'" % name)

                    # Reduce add lists for principal
                    # to new entries only that are not in res_find.
                    if principal is not None and \
                       "memberprincipal" in res_find:
                        principal_add = gen_add_list(
                            principal, res_find["memberprincipal"])
                    else:
                        principal_add = principal

            elif state == "absent":
                if action == "servicedelegationtarget":
                    if res_find is not None:
                        commands.append([name, "servicedelegationtarget_del",
                                         {}])

                elif action == "member":
                    if res_find is None:
                        ansible_module.fail_json(
                            msg="No servicedelegationtarget '%s'" % name)

                    # Reduce del lists of principal
                    # to the entries only that are in res_find.
                    if principal is not None:
                        principal_del = gen_intersection_list(
                            principal, res_find.get("memberprincipal"))
                    else:
                        principal_del = principal

            else:
                ansible_module.fail_json(msg="Unkown state '%s'" % state)

            # Handle members

            # Add principal members
            if principal_add is not None and len(principal_add) > 0:
                commands.append(
                    [name, "servicedelegationtarget_add_member",
                     {
                         "principal": principal_add,
                     }])
            # Remove principal members
            if principal_del is not None and len(principal_del) > 0:
                commands.append(
                    [name, "servicedelegationtarget_remove_member",
                     {
                         "principal": principal_del,
                     }])

        # Execute commands

        changed = ansible_module.execute_ipa_commands(
            commands, fail_on_member_errors=True)

    # Done

    ansible_module.exit_json(changed=changed, **exit_args)


if __name__ == "__main__":
    main()

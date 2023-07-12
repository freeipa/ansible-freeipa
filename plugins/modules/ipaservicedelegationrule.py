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
module: ipaservicedelegationrule
short_description: Manage FreeIPA servicedelegationrule
description: |
  Manage FreeIPA servicedelegationrule and servicedelegationrule members
extends_documentation_fragment:
  - ipamodule_base_docs
options:
  name:
    description: The list of servicedelegationrule name strings.
    type: list
    elements: str
    required: true
    aliases: ["cn"]
  principal:
    description: |
      The list of principals. A principal can be of the format:
      fqdn, fqdn@REALM, service/fqdn, service/fqdn@REALM, host/fqdn,
      host/fqdn@REALM, alias$, alias$@REALM, where fqdn and fqdn@REALM
      are host principals and the same as host/fqdn and host/fqd
      Host princpals are only usable with IPA versions 4.9.0 and up.
    type: list
    elements: str
    required: false
  target:
    description: |
      The list of service delegation targets.
    type: list
    elements: str
    required: false
    aliases: ["servicedelegationtarget"]
  action:
    description: Work on servicedelegationrule or member level.
    type: str
    choices: ["servicedelegationrule", "member"]
    default: servicedelegationrule
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
# Ensure servicedelegationrule delegation-rule is present
- ipaservicedelegationrule:
    ipaadmin_password: SomeADMINpassword
    name: delegation-rule

# Ensure servicedelegationrule delegation-rule member principal
# test/example.com is present
- ipaservicedelegationrule:
    ipaadmin_password: SomeADMINpassword
    name: delegation-rule
    principal: test/example.com
    action: member

# Ensure servicedelegationrule delegation-rule member principal
# test/example.com is absent
- ipaservicedelegationrule:
    ipaadmin_password: SomeADMINpassword
    name: delegation-rule
    principal: test/example.com
    action: member
    state: absent

# Ensure servicedelegationrule delegation-rule member target
# test/example.com is present
- ipaservicedelegationrule:
    ipaadmin_password: SomeADMINpassword
    name: delegation-rule
    target: delegation-target
    action: member

# Ensure servicedelegationrule delegation-rule member target
# test/example.com is absent
- ipaservicedelegationrule:
    ipaadmin_password: SomeADMINpassword
    name: delegation-rule
    target: delegation-target
    action: member
    state: absent

# Ensure servicedelegationrule delegation-rule is absent
- ipaservicedelegationrule:
    ipaadmin_password: SomeADMINpassword
    name: delegation-rule
    state: absent
"""

RETURN = """
"""


from ansible.module_utils.ansible_freeipa_module import \
    IPAAnsibleModule, gen_add_del_lists, gen_add_list, gen_intersection_list, \
    servicedelegation_normalize_principals, ipalib_errors
from ansible.module_utils import six

if six.PY3:
    unicode = str


def find_servicedelegationrule(module, name):
    """Find if a servicedelegationrule with the given name already exist."""
    try:
        _result = module.ipa_command("servicedelegationrule_show", name,
                                     {"all": True})
    except Exception:  # pylint: disable=broad-except
        # An exception is raised if servicedelegationrule name is not found.
        return None
    return _result["result"]


def check_targets(module, targets):
    def _check_exists(module, _type, name):
        # Check if item of type _type exists using the show command
        try:
            module.ipa_command("%s_show" % _type, name, {})
        except ipalib_errors.NotFound as e:
            msg = str(e)
            if "%s not found" % _type in msg:
                return False
            module.fail_json(msg="%s_show failed: %s" % (_type, msg))
        return True

    for _target in targets:
        if not _check_exists(module, "servicedelegationtarget", _target):
            module.fail_json(
                msg="Service delegation target '%s' does not exist" % _target)


def main():
    ansible_module = IPAAnsibleModule(
        argument_spec=dict(
            # general
            name=dict(type="list", elements="str", aliases=["cn"],
                      required=True),
            # present
            principal=dict(required=False, type='list', elements="str",
                           default=None),
            target=dict(required=False, type='list', elements="str",
                        aliases=["servicedelegationtarget"], default=None),

            action=dict(type="str", default="servicedelegationrule",
                        choices=["member", "servicedelegationrule"]),
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
    target = ansible_module.params_get("target")

    action = ansible_module.params_get("action")

    # state
    state = ansible_module.params_get("state")

    # Check parameters

    invalid = []

    if state == "present":
        if len(names) != 1:
            ansible_module.fail_json(
                msg="Only one servicedelegationrule can be added at a time.")

    if state == "absent":
        if len(names) < 1:
            ansible_module.fail_json(msg="No name given.")
        if action == "servicedelegationrule":
            invalid = ["principal", "target"]

    ansible_module.params_fail_used_invalid(invalid, state, action)

    # Init

    membertarget = "ipaallowedtarget_servicedelegationtarget"
    changed = False
    exit_args = {}

    # Connect to IPA API
    with ansible_module.ipa_connect():

        # Normalize principals
        if principal:
            principal = servicedelegation_normalize_principals(
                ansible_module, principal, state == "present")
        if target and state == "present":
            check_targets(ansible_module, target)

        commands = []
        principal_add = principal_del = []
        target_add = target_del = []
        for name in names:
            # Make sure servicedelegationrule exists
            res_find = find_servicedelegationrule(ansible_module, name)

            # Create command
            if state == "present":

                if action == "servicedelegationrule":
                    # A servicedelegationrule does not have normal options.
                    # There is no servicedelegationtarget-mod command.
                    # Principal members are handled with the _add_member and
                    # _remove_member commands further down.
                    if res_find is None:
                        commands.append([name, "servicedelegationrule_add",
                                         {}])
                        res_find = {}

                    # Generate addition and removal lists for principal
                    principal_add, principal_del = gen_add_del_lists(
                        principal, res_find.get("memberprincipal"))

                    # Generate addition and removal lists for target
                    target_add, target_del = gen_add_del_lists(
                        target, res_find.get(membertarget))

                elif action == "member":
                    if res_find is None:
                        ansible_module.fail_json(
                            msg="No servicedelegationrule '%s'" % name)

                    # Reduce add lists for principal
                    # to new entries only that are not in res_find.
                    if principal is not None and \
                       "memberprincipal" in res_find:
                        principal_add = gen_add_list(
                            principal, res_find["memberprincipal"])
                    else:
                        principal_add = principal

                    # Reduce add lists for target
                    # to new entries only that are not in res_find.
                    if target is not None and membertarget in res_find:
                        target_add = gen_add_list(
                            target, res_find[membertarget])
                    else:
                        target_add = target

            elif state == "absent":
                if action == "servicedelegationrule":
                    if res_find is not None:
                        commands.append([name, "servicedelegationrule_del",
                                         {}])

                elif action == "member":
                    if res_find is None:
                        ansible_module.fail_json(
                            msg="No servicedelegationrule '%s'" % name)

                    # Reduce del lists of principals to the entries only
                    # that are in res_find.
                    if principal is not None:
                        principal_del = gen_intersection_list(
                            principal, res_find.get("memberprincipal"))
                    else:
                        principal_del = principal

                    # Reduce del lists of targets to the entries only
                    # that are in res_find.
                    if target is not None:
                        target_del = gen_intersection_list(
                            target, res_find.get(membertarget))
                    else:
                        target_del = target

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

            # Add target members
            if target_add is not None and len(target_add) > 0:
                commands.append(
                    [name, "servicedelegationrule_add_target",
                     {
                         "servicedelegationtarget": target_add,
                     }])
            # Remove target members
            if target_del is not None and len(target_del) > 0:
                commands.append(
                    [name, "servicedelegationrule_remove_target",
                     {
                         "servicedelegationtarget": target_del,
                     }])

        # Execute commands

        changed = ansible_module.execute_ipa_commands(
            commands, fail_on_member_errors=True)

    # Done

    ansible_module.exit_json(changed=changed, **exit_args)


if __name__ == "__main__":
    main()

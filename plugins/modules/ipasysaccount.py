# -*- coding: utf-8 -*-

# Authors:
#   Thomas Woerner <twoerner@redhat.com>
#
# Copyright (C) 2025 Red Hat
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
module: ipasysaccount
short_description: Manage FreeIPA system account
description: Manage FreeIPA system account
extends_documentation_fragment:
  - ipamodule_base_docs
  - ipamodule_base_docs.delete_continue
options:
  name:
    description: The list of sysaccount name strings (internally uid).
    required: true
    type: list
    elements: str
    aliases: ["login"]
  description:
    description: A description for the sysaccount.
    type: str
    required: false
  privileged:
    description: Allow password updates without reset.
    type: bool
    required: false
  random:
    description: Generate a random user password.
    required: false
    type: bool
  password:
    description: Set the user password.
    required: false
    type: str
    aliases: ["userpassword"]
  update_password:
    description:
      Set password for a sysaccount in present state only on creation or always
    type: str
    choices: ["always", "on_create"]
    required: false
  state:
    description: The state to ensure.
    choices: ["present", "absent", "enabled", "disabled"]
    default: present
    type: str
author:
  - Thomas Woerner (@t-woerner)
"""

EXAMPLES = """
# Ensure sysaccount my-app is present
- ipasysaccount:
    ipaadmin_password: SomeADMINpassword
    name: my-app
    random: true

# Ensure sysaccount my-app is absent
- ipasysaccount:
    ipaadmin_password: SomeADMINpassword
    name: my-app
    state: absent

# Ensure existing sysaccount my-app is privileged
- ipasysaccount:
    ipaadmin_password: SomeADMINpassword
    name: my-app
    privileged: true

# Ensure existing sysaccount my-app is not privileged
- ipasysaccount:
    ipaadmin_password: SomeADMINpassword
    name: my-app
    privileged: false

# Ensure existing sysaccount my-app is disabled
- ipasysaccount:
    ipaadmin_password: SomeADMINpassword
    name: my-app
    state: disabled

# Ensure existing sysaccount my-app is enabled
- ipasysaccount:
    ipaadmin_password: SomeADMINpassword
    name: my-app
    state: enabled
"""

RETURN = """
sysaccount:
  description: Sysaccount dict with random password
  returned: |
    If random is yes and user sysaccount not exist or update_password is yes
  type: dict
  contains:
    randompassword:
      description: The generated random password
      type: str
"""


from ansible.module_utils.ansible_freeipa_module import \
    IPAAnsibleModule, compare_args_ipa, ipalib_errors
from ansible.module_utils import six

if six.PY3:
    unicode = str


def find_sysaccount(module, name):
    """Find if a sysaccount with the given name already exist."""
    try:
        _result = module.ipa_command("sysaccount_show", name, {"all": True})
    except ipalib_errors.NotFound:
        # An exception is raised if sysaccount name is not found.
        return None
    return _result["result"]


def gen_args(description, random, privileged, password):
    _args = {}
    if description is not None:
        _args["description"] = description
    if random is not None:
        _args["random"] = random
    if privileged is not None:
        _args["privileged"] = privileged
    if password is not None:
        _args["userpassword"] = password
    return _args


# pylint: disable=unused-argument
def result_handler(module, result, command, name, args, exit_args, errors):
    if "random" in args and command in ["sysaccount_add", "sysaccount_mod"] \
       and "randompassword" in result["result"]:
        exit_args["randompassword"] = \
            result["result"]["randompassword"]


def main():
    ansible_module = IPAAnsibleModule(
        argument_spec=dict(
            # general
            name=dict(type="list", elements="str", required=True,
                      aliases=["login"]),
            # present
            description=dict(required=False, type='str', default=None),
            random=dict(required=False, type='bool', default=None),
            privileged=dict(required=False, type='bool', default=None),
            password=dict(required=False, type='str',
                          aliases=["userpassword"], default=None),

            # mod
            update_password=dict(type='str', default=None, no_log=False,
                                 choices=['always', 'on_create']),

            # state
            state=dict(type="str", default="present",
                       choices=["present", "absent", "enabled", "disabled"]),
        ),
        supports_check_mode=True,
        ipa_module_options=["delete_continue"],
        mutually_exclusive=[["random", "password"]]
    )

    ansible_module._ansible_debug = True

    # Get parameters

    # general
    names = ansible_module.params_get("name")

    # present
    description = ansible_module.params_get("description")
    random = ansible_module.params_get("random")
    privileged = ansible_module.params_get("privileged")
    password = ansible_module.params_get("password")

    # mod
    update_password = ansible_module.params_get("update_password")

    # absent
    delete_continue = ansible_module.params_get("delete_continue")

    # state
    state = ansible_module.params_get("state")

    # Check parameters

    invalid = []

    if state == "present" and len(names) != 1:
        ansible_module.fail_json(
            msg="Only one sysaccount can be added at a time.")

    if state in ["absent", "enabled", "disabled"]:
        if len(names) < 1:
            ansible_module.fail_json(msg="No name given.")
        invalid = ["description", "random", "privileged", "password"]

    ansible_module.params_fail_used_invalid(invalid, state)

    # Init

    changed = False
    exit_args = {}

    # Connect to IPA API
    with ansible_module.ipa_connect():

        if not ansible_module.ipa_command_exists("sysaccount_add"):
            ansible_module.fail_json(
                msg=("Managing sysaccounts is not supported by your "
                     "IPA version")
            )

        commands = []
        for name in names:
            # Make sure sysaccount exists
            res_find = find_sysaccount(ansible_module, name)

            # Create command
            if state == "present":

                # Generate args
                args = gen_args(description, random, privileged, password)

                # Found the sysaccount
                if res_find is not None:
                    # Ignore password and random with
                    # update_password == on_create
                    if update_password == "on_create":
                        if "userpassword" in args:
                            del args["userpassword"]
                        if "random" in args:
                            del args["random"]
                    # if using "random:false" password should not be
                    # generated.
                    if not args.get("random", True):
                        del args["random"]

                    # For all settings is args, check if there are
                    # different settings in the find result.
                    # If yes: modify
                    if not compare_args_ipa(ansible_module, args,
                                            res_find):
                        commands.append([name, "sysaccount_mod", args])
                else:
                    commands.append([name, "sysaccount_add", args])

            elif state == "absent":
                if res_find is not None:
                    commands.append(
                        [name, "sysaccount_del", {"continue": delete_continue}]
                    )

            elif state == "enabled":
                if res_find is not None and res_find["nsaccountlock"]:
                    commands.append([name, "sysaccount_enable", {}])

            elif state == "disabled":
                if res_find is not None and not res_find["nsaccountlock"]:
                    commands.append([name, "sysaccount_disable", {}])

            else:
                ansible_module.fail_json(msg="Unkown state '%s'" % state)

        # Execute commands

        changed = ansible_module.execute_ipa_commands(
            commands, result_handler, keeponly=["randompassword"],
            exit_args=exit_args)

    # Done

    ansible_module.exit_json(changed=changed, sysaccount=exit_args)


if __name__ == "__main__":
    main()

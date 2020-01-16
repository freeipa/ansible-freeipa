#!/usr/bin/python
# -*- coding: utf-8 -*-

# Authors:
#   Rafael Guterres Jeffman <rjeffman@redhat.com>
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

ANSIBLE_METADATA = {
    "metadata_version": "1.0",
    "supported_by": "community",
    "status": ["preview"],
}


DOCUMENTATION = """
---
module: ipasudocmd
short description: Manage FreeIPA sudo command
description: Manage FreeIPA sudo command
options:
  ipaadmin_principal:
    description: The admin principal
    default: admin
  ipaadmin_password:
    description: The admin password
    required: false
  name:
    description: The sudo command
    required: true
    aliases: ["sudocmd"]
  description:
    description: The command description
    required: false
  state:
    description: State to ensure
    default: present
    choices: ["present", "absent"]
author:
    - Rafael Jeffman
"""

EXAMPLES = """
# Ensure sudocmd is present
- ipacommand:
    ipaadmin_password: MyPassword123
    name: su
    state: present

# Ensure sudocmd is absent
- ipacommand:
    ipaadmin_password: MyPassword123
    name: su
    state: absent
"""

RETURN = """
"""

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_text
from ansible.module_utils.ansible_freeipa_module import temp_kinit, \
    temp_kdestroy, valid_creds, api_connect, api_command, compare_args_ipa


def find_sudocmd(module, name):
    _args = {
        "all": True,
        "sudocmd": to_text(name),
    }

    _result = api_command(module, "sudocmd_find", to_text(name), _args)

    if len(_result["result"]) > 1:
        module.fail_json(
            msg="There is more than one sudocmd '%s'" % (name))
    elif len(_result["result"]) == 1:
        return _result["result"][0]
    else:
        return None


def gen_args(description):
    _args = {}
    if description is not None:
        _args["description"] = to_text(description)

    return _args


def main():
    ansible_module = AnsibleModule(
        argument_spec=dict(
            # general
            ipaadmin_principal=dict(type="str", default="admin"),
            ipaadmin_password=dict(type="str", required=False, no_log=True),

            name=dict(type="list", aliases=["sudocmd"], default=None,
                      required=True),
            # present
            description=dict(type="str", default=None),
            # state
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
    # state
    state = ansible_module.params.get("state")

    # Check parameters
    if state == "absent":
        invalid = ["description"]
        for x in invalid:
            if vars()[x] is not None:
                ansible_module.fail_json(
                    msg="Argument '%s' can not be used with state '%s'" %
                    (x, state))

    # Init

    changed = False
    exit_args = {}
    ccache_dir = None
    ccache_name = None
    try:
        if not valid_creds(ansible_module, ipaadmin_principal):
            ccache_dir, ccache_name = temp_kinit(ipaadmin_principal,
                                                 ipaadmin_password)
        api_connect()

        commands = []

        for name in names:
            # Make sure hostgroup exists
            res_find = find_sudocmd(ansible_module, name)

            # Create command
            if state == "present":
                # Generate args
                args = gen_args(description)
                if res_find is not None:
                    # For all settings in args, check if there are
                    # different settings in the find result.
                    # If yes: modify
                    if not compare_args_ipa(ansible_module, args,
                                            res_find):
                        commands.append([name, "sudocmd_mod", args])
                else:
                    commands.append([name, "sudocmd_add", args])
                    # Set res_find to empty dict for next step
                    res_find = {}
            elif state == "absent":
                if res_find is not None:
                    commands.append([name, "sudocmd_del", {}])
            else:
                ansible_module.fail_json(msg="Unkown state '%s'" % state)

        # Execute commands
        for name, command, args in commands:
            try:
                result = api_command(ansible_module, command, to_text(name),
                                     args)
                # Check if any changes were made by any command
                if command == 'sudocmd_del':
                    changed |= "Deleted" in result['summary']
                elif command == 'sudocmd_add':
                    changed |= "Added" in result['summary']
            except Exception as e:
                ansible_module.fail_json(msg="%s: %s: %s" % (command, name,
                                                             str(e)))

    except Exception as e:
        ansible_module.fail_json(msg=str(e))

    finally:
        temp_kdestroy(ccache_dir, ccache_name)

    # Done

    ansible_module.exit_json(changed=changed, **exit_args)


if __name__ == "__main__":
    main()

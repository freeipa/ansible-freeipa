#!/usr/bin/python
# -*- coding: utf-8 -*-

# Authors:
#   Thomas Woerner <twoerner@redhat.com>
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
module: ipapwpolicy
short description: Manage FreeIPA pwpolicies
description: Manage FreeIPA pwpolicies
options:
  ipaadmin_principal:
    description: The admin principal
    default: admin
  ipaadmin_password:
    description: The admin password
    required: false
  name:
    description: The group name
    required: false
    aliases: ["cn"]
  maxlife:
    description: Maximum password lifetime (in days)
    type: int
    required: false
    aliases: ["krbmaxpwdlife"]
  minlife:
    description: Minimum password lifetime (in hours)
    type: int
    required: false
    aliases: ["krbminpwdlife"]
  history:
    description: Password history size
    type: int
    required: false
    aliases: ["krbpwdhistorylength"]
  minclasses:
    description: Minimum number of character classes
    type: int
    required: false
    aliases: ["krbpwdmindiffchars"]
  minlength:
    description: Minimum length of password
    type: int
    required: false
    aliases: ["krbpwdminlength"]
  priority:
    description: Priority of the policy (higher number means lower priority)
    type: int
    required: false
    aliases: ["cospriority"]
  maxfail:
    description: Consecutive failures before lockout
    type: int
    required: false
    aliases: ["krbpwdmaxfailure"]
  failinterval:
    description: Period after which failure count will be reset (seconds)
    type: int
    required: false
    aliases: ["krbpwdfailurecountinterval"]
  lockouttime:
    description: Period for which lockout is enforced (seconds)
    type: int
    required: false
    aliases: ["krbpwdlockoutduration"]
  state:
    description: State to ensure
    default: present
    choices: ["present", "absent"]
author:
    - Thomas Woerner
"""

EXAMPLES = """
# Ensure pwpolicy is set for ops
- ipapwpolicy:
    ipaadmin_password: SomeADMINpassword
    name: ops
    minlife: 7
    maxlife: 49
    history: 5
    priority: 1
    lockouttime: 300
    minlength: 8
"""

RETURN = """
"""

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_text
from ansible.module_utils.ansible_freeipa_module import temp_kinit, \
    temp_kdestroy, valid_creds, api_connect, api_command, compare_args_ipa


def find_pwpolicy(module, name):
    _args = {
        "all": True,
        "cn": to_text(name),
    }

    _result = api_command(module, "pwpolicy_find", to_text(name), _args)

    if len(_result["result"]) > 1:
        module.fail_json(
            msg="There is more than one pwpolicy '%s'" % (name))
    elif len(_result["result"]) == 1:
        return _result["result"][0]
    else:
        return None


def gen_args(maxlife, minlife, history, minclasses, minlength, priority,
             maxfail, failinterval, lockouttime):
    _args = {}
    if maxlife is not None:
        _args["krbmaxpwdlife"] = maxlife
    if minlife is not None:
        _args["krbminpwdlife"] = minlife
    if history is not None:
        _args["krbpwdhistorylength"] = history
    if minclasses is not None:
        _args["krbpwdmindiffchars"] = minclasses
    if minlength is not None:
        _args["krbpwdminlength"] = minlength
    if priority is not None:
        _args["cospriority"] = priority
    if maxfail is not None:
        _args["krbpwdmaxfailure"] = maxfail
    if failinterval is not None:
        _args["krbpwdfailurecountinterval"] = failinterval
    if lockouttime is not None:
        _args["krbpwdlockoutduration"] = lockouttime

    return _args


def main():
    ansible_module = AnsibleModule(
        argument_spec=dict(
            # general
            ipaadmin_principal=dict(type="str", default="admin"),
            ipaadmin_password=dict(type="str", required=False, no_log=True),

            name=dict(type="list", aliases=["cn"], default=None,
                      required=False),
            # present

            maxlife=dict(type="int", aliases=["krbmaxpwdlife"], default=None),
            minlife=dict(type="int", aliases=["krbminpwdlife"], default=None),
            history=dict(type="int", aliases=["krbpwdhistorylength"],
                         default=None),
            minclasses=dict(type="int", aliases=["krbpwdmindiffchars"],
                            default=None),
            minlength=dict(type="int", aliases=["krbpwdminlength"],
                           default=None),
            priority=dict(type="int", aliases=["cospriority"], default=None),
            maxfail=dict(type="int", aliases=["krbpwdmaxfailure"],
                         default=None),
            failinterval=dict(type="int",
                              aliases=["krbpwdfailurecountinterval"],
                              default=None),
            lockouttime=dict(type="int", aliases=["krbpwdlockoutduration"],
                             default=None),
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
    maxlife = ansible_module.params.get("maxlife")
    minlife = ansible_module.params.get("minlife")
    history = ansible_module.params.get("history")
    minclasses = ansible_module.params.get("minclasses")
    minlength = ansible_module.params.get("minlength")
    priority = ansible_module.params.get("priority")
    maxfail = ansible_module.params.get("maxfail")
    failinterval = ansible_module.params.get("failinterval")
    lockouttime = ansible_module.params.get("lockouttime")

    # state
    state = ansible_module.params.get("state")

    # Check parameters

    if names is None:
        names = ["global_policy"]

    if state == "present":
        if len(names) != 1:
            ansible_module.fail_json(
                msg="Only one pwpolicy can be set at a time.")

    if state == "absent":
        if len(names) < 1:
            ansible_module.fail_json(msg="No name given.")
        if "global_policy" in names:
            ansible_module.fail_json(
                msg="'global_policy' can not be made absent.")
        invalid = ["maxlife", "minlife", "history", "minclasses",
                   "minlength", "priority", "maxfail", "failinterval",
                   "lockouttime"]
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
            # Try to find pwpolicy
            res_find = find_pwpolicy(ansible_module, name)

            # Create command
            if state == "present":
                # Generate args
                args = gen_args(maxlife, minlife, history, minclasses,
                                minlength, priority, maxfail, failinterval,
                                lockouttime)

                # Found the pwpolicy
                if res_find is not None:
                    # For all settings is args, check if there are
                    # different settings in the find result.
                    # If yes: modify
                    if not compare_args_ipa(ansible_module, args,
                                            res_find):
                        commands.append([name, "pwpolicy_mod", args])
                else:
                    commands.append([name, "pwpolicy_add", args])

            elif state == "absent":
                if res_find is not None:
                    commands.append([name, "pwpolicy_del", {}])

            else:
                ansible_module.fail_json(msg="Unkown state '%s'" % state)

        # Execute commands

        for name, command, args in commands:
            try:
                api_command(ansible_module, command, to_text(name), args)
                changed = True
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

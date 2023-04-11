# -*- coding: utf-8 -*-

# Authors:
#   Thomas Woerner <twoerner@redhat.com>
#   Rafael Guterres Jeffman <rjeffman@redhat.com>
#
# Copyright (C) 2019-2022 Red Hat
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
module: ipapwpolicy
short_description: Manage FreeIPA pwpolicies
description: Manage FreeIPA pwpolicies
extends_documentation_fragment:
  - ipamodule_base_docs
options:
  name:
    description: The group name
    type: list
    elements: str
    required: false
    aliases: ["cn"]
  maxlife:
    description: Maximum password lifetime (in days)
    type: str
    required: false
    aliases: ["krbmaxpwdlife"]
  minlife:
    description: Minimum password lifetime (in hours)
    type: str
    required: false
    aliases: ["krbminpwdlife"]
  history:
    description: Password history size
    type: str
    required: false
    aliases: ["krbpwdhistorylength"]
  minclasses:
    description: Minimum number of character classes
    type: str
    required: false
    aliases: ["krbpwdmindiffchars"]
  minlength:
    description: Minimum length of password
    type: str
    required: false
    aliases: ["krbpwdminlength"]
  priority:
    description: Priority of the policy (higher number means lower priority)
    type: str
    required: false
    aliases: ["cospriority"]
  maxfail:
    description: Consecutive failures before lockout
    type: str
    required: false
    aliases: ["krbpwdmaxfailure"]
  failinterval:
    description: Period after which failure count will be reset (seconds)
    type: str
    required: false
    aliases: ["krbpwdfailurecountinterval"]
  lockouttime:
    description: Period for which lockout is enforced (seconds)
    type: str
    required: false
    aliases: ["krbpwdlockoutduration"]
  maxrepeat:
    description: >
      Maximum number of same consecutive characters.
      Requires IPA 4.9+
    type: str
    required: false
    aliases: ["ipapwdmaxrepeat"]
  maxsequence:
    description: >
      The maximum length of monotonic character sequences (abcd).
      Requires IPA 4.9+
    type: str
    required: false
    aliases: ["ipapwdmaxsequence"]
  dictcheck:
    description: >
      Check if the password is a dictionary word.
      Requires IPA 4.9+
    type: str
    required: false
    aliases: ["ipapwdictcheck"]
  usercheck:
    description: >
      Check if the password contains the username.
      Requires IPA 4.9+
    type: str
    required: false
    aliases: ["ipapwdusercheck"]
  gracelimit:
    description: >
      Number of LDAP authentications allowed after expiration.
      Requires IPA 4.10.1+
    type: str
    required: false
    aliases: ["passwordgracelimit"]
  state:
    description: State to ensure
    type: str
    default: present
    choices: ["present", "absent"]
author:
  - Thomas Woerner (@t-woerner)
  - Rafael Guterres Jeffman (@rjeffman)
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

from ansible.module_utils.ansible_freeipa_module import \
    IPAAnsibleModule, compare_args_ipa, boolean


def find_pwpolicy(module, name):
    _args = {
        "all": True,
        "cn": name,
    }

    _result = module.ipa_command("pwpolicy_find", name, _args)

    if len(_result["result"]) > 1:
        module.fail_json(
            msg="There is more than one pwpolicy '%s'" % (name))
    elif len(_result["result"]) == 1:
        return _result["result"][0]

    return None


def gen_args(module,
             maxlife, minlife, history, minclasses, minlength, priority,
             maxfail, failinterval, lockouttime, maxrepeat, maxsequence,
             dictcheck, usercheck, gracelimit):
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
    if maxrepeat is not None:
        _args["ipapwdmaxrepeat"] = maxrepeat
    if maxsequence is not None:
        _args["ipapwdmaxsequence"] = maxsequence
    if dictcheck is not None:
        if module.ipa_check_version("<", "4.9.10"):
            # Allowed values: "TRUE", "FALSE", ""
            _args["ipapwddictcheck"] = "TRUE" if dictcheck is True else \
                "FALSE" if dictcheck is False else dictcheck
        else:
            _args["ipapwddictcheck"] = dictcheck
    if usercheck is not None:
        if module.ipa_check_version("<", "4.9.10"):
            # Allowed values: "TRUE", "FALSE", ""
            _args["ipapwdusercheck"] = "TRUE" if usercheck is True else \
                "FALSE" if usercheck is False else usercheck
        else:
            _args["ipapwdusercheck"] = usercheck
    if gracelimit is not None:
        _args["passwordgracelimit"] = gracelimit

    return _args


def check_supported_params(
    module, maxrepeat, maxsequence, dictcheck, usercheck, gracelimit
):
    # All password checking parameters were added by the same commit,
    # so we only need to test one of them.
    has_password_check = module.ipa_command_param_exists(
        "pwpolicy_add", "ipapwdmaxrepeat")
    # check if gracelimit is supported
    has_gracelimit = module.ipa_command_param_exists(
        "pwpolicy_add", "passwordgracelimit")

    # If needed, report unsupported password checking paramteres
    if (
        not has_password_check
        and any([maxrepeat, maxsequence, dictcheck, usercheck])
    ):
        module.fail_json(
            msg="Your IPA version does not support arguments: "
                "maxrepeat, maxsequence, dictcheck, usercheck.")

    if not has_gracelimit and gracelimit is not None:
        module.fail_json(
            msg="Your IPA version does not support 'gracelimit'.")


def main():
    ansible_module = IPAAnsibleModule(
        argument_spec=dict(
            # general
            name=dict(type="list", elements="str", aliases=["cn"],
                      default=None, required=False),
            # present

            maxlife=dict(type="str", aliases=["krbmaxpwdlife"], default=None),
            minlife=dict(type="str", aliases=["krbminpwdlife"], default=None),
            history=dict(type="str", aliases=["krbpwdhistorylength"],
                         default=None),
            minclasses=dict(type="str", aliases=["krbpwdmindiffchars"],
                            default=None),
            minlength=dict(type="str", aliases=["krbpwdminlength"],
                           default=None),
            priority=dict(type="str", aliases=["cospriority"], default=None),
            maxfail=dict(type="str", aliases=["krbpwdmaxfailure"],
                         default=None),
            failinterval=dict(type="str",
                              aliases=["krbpwdfailurecountinterval"],
                              default=None),
            lockouttime=dict(type="str", aliases=["krbpwdlockoutduration"],
                             default=None),
            maxrepeat=dict(type="str", aliases=["ipapwdmaxrepeat"],
                           default=None),
            maxsequence=dict(type="str", aliases=["ipapwdmaxsequence"],
                             default=None),
            dictcheck=dict(type="str", aliases=["ipapwdictcheck"],
                           default=None),
            usercheck=dict(type="str", aliases=["ipapwdusercheck"],
                           default=None),
            gracelimit=dict(type="str", aliases=["passwordgracelimit"],
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
    names = ansible_module.params_get("name")

    # present
    maxlife = ansible_module.params_get("maxlife")
    minlife = ansible_module.params_get("minlife")
    history = ansible_module.params_get("history")
    minclasses = ansible_module.params_get("minclasses")
    minlength = ansible_module.params_get("minlength")
    priority = ansible_module.params_get("priority")
    maxfail = ansible_module.params_get("maxfail")
    failinterval = ansible_module.params_get("failinterval")
    lockouttime = ansible_module.params_get("lockouttime")
    maxrepeat = ansible_module.params_get("maxrepeat")
    maxsequence = ansible_module.params_get("maxsequence")
    dictcheck = ansible_module.params_get("dictcheck")
    usercheck = ansible_module.params_get("usercheck")
    gracelimit = ansible_module.params_get("gracelimit")

    # state
    state = ansible_module.params_get("state")

    # Check parameters
    invalid = []

    if names is None:
        names = [u"global_policy"]

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
                   "lockouttime", "maxrepeat", "maxsequence", "dictcheck",
                   "usercheck", "gracelimit"]

    ansible_module.params_fail_used_invalid(invalid, state)

    # Ensure parameter values are valid and have proper type.
    def int_or_empty_param(value, param):
        if value is not None and value != "":
            try:
                value = int(value)
            except ValueError:
                ansible_module.fail_json(
                    msg="Invalid value '%s' for argument '%s'" % (value, param)
                )
        return value

    maxlife = int_or_empty_param(maxlife, "maxlife")
    minlife = int_or_empty_param(minlife, "minlife")
    history = int_or_empty_param(history, "history")
    minclasses = int_or_empty_param(minclasses, "minclasses")
    minlength = int_or_empty_param(minlength, "minlength")
    priority = int_or_empty_param(priority, "priority")
    maxfail = int_or_empty_param(maxfail, "maxfail")
    failinterval = int_or_empty_param(failinterval, "failinterval")
    lockouttime = int_or_empty_param(lockouttime, "lockouttime")
    maxrepeat = int_or_empty_param(maxrepeat, "maxrepeat")
    maxsequence = int_or_empty_param(maxsequence, "maxsequence")
    gracelimit = int_or_empty_param(gracelimit, "gracelimit")

    def bool_or_empty_param(value, param):  # pylint: disable=R1710
        if value is None or value == "":
            return value
        try:
            return boolean(value)
        except TypeError as terr:
            ansible_module.fail_json(msg="Param '%s': %s" % (param, str(terr)))

    dictcheck = bool_or_empty_param(dictcheck, "dictcheck")
    usercheck = bool_or_empty_param(usercheck, "usercheck")

    # Ensure gracelimit has proper limit.
    if gracelimit:
        if gracelimit < -1:
            ansible_module.fail_json(
                msg="'gracelimit' must be no less than -1")

    # Init

    changed = False
    exit_args = {}

    with ansible_module.ipa_connect():

        check_supported_params(
            ansible_module, maxrepeat, maxsequence, dictcheck, usercheck,
            gracelimit
        )

        commands = []

        for name in names:
            # Try to find pwpolicy
            res_find = find_pwpolicy(ansible_module, name)

            # Create command
            if state == "present":
                # Generate args
                args = gen_args(ansible_module,
                                maxlife, minlife, history, minclasses,
                                minlength, priority, maxfail, failinterval,
                                lockouttime, maxrepeat, maxsequence, dictcheck,
                                usercheck, gracelimit)

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

        changed = ansible_module.execute_ipa_commands(commands)

    # Done

    ansible_module.exit_json(changed=changed, **exit_args)


if __name__ == "__main__":
    main()

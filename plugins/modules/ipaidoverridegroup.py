# -*- coding: utf-8 -*-

# Authors:
#   Thomas Woerner <twoerner@redhat.com>
#
# Copyright (C) 2023 Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, exither version 3 of the License, or
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

# No rename support: 'ID overrides cannot be renamed'
# ipaserver/plugins/idviews.py:baseidoverride_mod:pre_callback

DOCUMENTATION = """
---
module: ipaidoverridegroup
short_description: Manage FreeIPA idoverridegroup
description: Manage FreeIPA idoverridegroups
extends_documentation_fragment:
  - ipamodule_base_docs
options:
  idview:
    description: The idoverridegroup idview string.
    type: str
    required: true
    aliases: ["idviewcn"]
  anchor:
    description: The list of anchors to override
    type: list
    elements: str
    required: true
    aliases: ["ipaanchoruuid"]
  description:
    description: Description
    type: str
    required: False
    aliases: ["desc"]
  name:
    description: Group name
    type: str
    required: False
    aliases: ["group_name", "cn"]
  gid:
    description: Group ID Number (int or "")
    type: str
    required: False
    aliases: ["gidnumber"]
  fallback_to_ldap:
    description: |
      Allow falling back to AD DC LDAP when resolving AD trusted objects.
      For two-way trusts only.
    required: False
    type: bool
  delete_continue:
    description: |
      Continuous mode. Don't stop on errors.
      Valid only if `state` is `absent`.
    required: false
    type: bool
    aliases: ["continue"]
  state:
    description: The state to ensure.
    choices: ["present", "absent"]
    default: present
    type: str
author:
  - Thomas Woerner (@t-woerner)
"""

EXAMPLES = """
# Ensure test group test_group is present in idview test_idview
- ipaidoverridegroup:
    ipaadmin_password: SomeADMINpassword
    idview: test_idview
    anchor: test_group

# Ensure test group test_group is present in idview test_idview with
# description
- ipaidoverridegroup:
    ipaadmin_password: SomeADMINpassword
    idview: test_idview
    anchor: test_group
    description: "test_group description"

# Ensure test group test_group is present in idview test_idview without
# description
- ipaidoverridegroup:
    ipaadmin_password: SomeADMINpassword
    idview: test_idview
    anchor: test_group
    description: ""

# Ensure test group test_group is present in idview test_idview with internal
# name test_123_group
- ipaidoverridegroup:
    ipaadmin_password: SomeADMINpassword
    idview: test_idview
    anchor: test_group
    name: test_123_group

# Ensure test group test_group is present in idview test_idview without
# internal name
- ipaidoverridegroup:
    ipaadmin_password: SomeADMINpassword
    idview: test_idview
    anchor: test_group
    name: ""

# Ensure test group test_group is present in idview test_idview with gid 20001
- ipaidoverridegroup:
    ipaadmin_password: SomeADMINpassword
    idview: test_idview
    anchor: test_group
    gid: 20001

# Ensure test group test_group is present in idview test_idview without gid
- ipaidoverridegroup:
    ipaadmin_password: SomeADMINpassword
    idview: test_idview
    anchor: test_group
    gid: ""

# Ensure test group test_group is absent in idview test_idview
- ipaidoverridegroup:
    ipaadmin_password: SomeADMINpassword
    idview: test_idview
    anchor: test_group
    continue: true
    state: absent
"""

RETURN = """
"""


from ansible.module_utils.ansible_freeipa_module import \
    IPAAnsibleModule, compare_args_ipa
from ansible.module_utils import six

if six.PY3:
    unicode = str


def find_idoverridegroup(module, idview, anchor):
    """Find if a idoverridegroup with the given name already exist."""
    try:
        _result = module.ipa_command("idoverridegroup_show", idview,
                                     {"ipaanchoruuid": anchor,
                                      "all": True})
    except Exception:  # pylint: disable=broad-except
        # An exception is raised if idoverridegroup anchor is not found.
        return None
    return _result["result"]


def gen_args(anchor, description, name, gid):
    # fallback_to_ldap is only a runtime tuning parameter
    _args = {}
    if anchor is not None:
        _args["ipaanchoruuid"] = anchor
    if description is not None:
        _args["description"] = description
    if name is not None:
        _args["cn"] = name
    if gid is not None:
        _args["gidnumber"] = gid
    return _args


def gen_args_runtime(fallback_to_ldap):
    _args = {}
    if fallback_to_ldap is not None:
        _args["fallback_to_ldap"] = fallback_to_ldap
    return _args


def merge_dicts(dict1, dict2):
    ret = dict1.copy()
    ret.update(dict2)
    return ret


def main():
    ansible_module = IPAAnsibleModule(
        argument_spec=dict(
            # general
            idview=dict(type="str", required=True, aliases=["idviewcn"]),
            anchor=dict(type="list", elements="str", required=True,
                        aliases=["ipaanchoruuid"]),

            # present
            description=dict(type="str", required=False, aliases=["desc"]),
            name=dict(type="str", required=False,
                      aliases=["group_name", "cn"]),
            gid=dict(type="str", required=False, aliases=["gidnumber"]),

            # runtime flags
            fallback_to_ldap=dict(type="bool", required=False),

            # absent
            delete_continue=dict(type="bool", required=False,
                                 aliases=['continue'], default=None),

            # No rename support: 'ID overrides cannot be renamed'
            # ipaserver/plugins/idviews.py:baseidoverride_mod:pre_callback

            # state
            state=dict(type="str", default="present",
                       choices=["present", "absent"]),
        ),
        supports_check_mode=True,
    )

    ansible_module._ansible_debug = True

    # Get parameters

    # general
    idview = ansible_module.params_get("idview")
    anchors = ansible_module.params_get("anchor")

    # present
    description = ansible_module.params_get("description")
    name = ansible_module.params_get("name")
    gid = ansible_module.params_get_with_type_cast("gid", int)

    # runtime flags
    fallback_to_ldap = ansible_module.params_get("fallback_to_ldap")

    # absent
    delete_continue = ansible_module.params_get("delete_continue")

    # state
    state = ansible_module.params_get("state")

    # Check parameters

    invalid = []

    if state == "present":
        if len(anchors) != 1:
            ansible_module.fail_json(
                msg="Only one idoverridegroup can be added at a time.")
        invalid = ["delete_continue"]

    if state == "absent":
        if len(anchors) < 1:
            ansible_module.fail_json(msg="No name given.")
        invalid = ["description", "name", "gid"]

    ansible_module.params_fail_used_invalid(invalid, state)

    # Init

    changed = False
    exit_args = {}

    # Connect to IPA API
    with ansible_module.ipa_connect():

        runtime_args = gen_args_runtime(fallback_to_ldap)
        commands = []
        for anchor in anchors:
            # Make sure idoverridegroup exists
            res_find = find_idoverridegroup(ansible_module, idview, anchor)

            # Create command
            if state == "present":

                # Generate args
                args = gen_args(anchor, description, name, gid)
                # fallback_to_ldap is only a runtime tuning parameter
                all_args = merge_dicts(args, runtime_args)

                # Found the idoverridegroup
                if res_find is not None:
                    # For idempotency: Remove empty sshpubkey list if
                    # there are no sshpubkey in the found entry.
                    if "ipasshpubkey" in args and \
                       len(args["ipasshpubkey"]) < 1 and \
                       "ipasshpubkey" not in res_find:
                        del args["ipasshpubkey"]
                    # For all settings is args, check if there are
                    # different settings in the find result.
                    # If yes: modify
                    if not compare_args_ipa(ansible_module, args,
                                            res_find):
                        commands.append([idview, "idoverridegroup_mod",
                                         all_args])
                else:
                    commands.append([idview, "idoverridegroup_add",
                                     all_args])

            elif state == "absent":
                if res_find is not None:
                    commands.append(
                        [idview, "idoverridegroup_del",
                         merge_dicts(
                             {
                                 "ipaanchoruuid": anchor,
                                 "continue": delete_continue or False
                             },
                             runtime_args
                         )]
                    )

            else:
                ansible_module.fail_json(msg="Unkown state '%s'" % state)

        # Execute commands

        changed = ansible_module.execute_ipa_commands(commands)

    # Done

    ansible_module.exit_json(changed=changed, **exit_args)


if __name__ == "__main__":
    main()

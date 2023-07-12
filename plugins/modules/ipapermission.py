# -*- coding: utf-8 -*-

# Authors:
#   Seth Kress <kresss@gmail.com>
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
module: ipapermission
short_description: Manage FreeIPA permission
description: Manage FreeIPA permission and permission members
extends_documentation_fragment:
  - ipamodule_base_docs
options:
  name:
    description: The permission name string.
    type: list
    elements: str
    required: true
    aliases: ["cn"]
  right:
    description: Rights to grant
    required: false
    choices: ["read", "search", "compare", "write", "add", "delete", "all"]
    type: list
    elements: str
    aliases: ["ipapermright"]
  attrs:
    description: All attributes to which the permission applies
    required: false
    type: list
    elements: str
  bindtype:
    description: Bind rule type
    required: false
    type: str
    choices: ["permission", "all", "anonymous", "self"]
    aliases: ["ipapermbindruletype"]
  subtree:
    description: Subtree to apply permissions to
    type: str
    required: false
    aliases: ["ipapermlocation"]
  extra_target_filter:
    description: Extra target filter
    required: false
    type: list
    elements: str
    aliases: ["filter", "extratargetfilter"]
  rawfilter:
    description: All target filters
    required: false
    type: list
    elements: str
    aliases: ["ipapermtargetfilter"]
  target:
    description: Optional DN to apply the permission to
    type: str
    required: false
    aliases: ["ipapermtarget"]
  targetto:
    description: Optional DN subtree where an entry can be moved to
    type: str
    required: false
    aliases: ["ipapermtargetto"]
  targetfrom:
    description: Optional DN subtree from where an entry can be moved
    type: str
    required: false
    aliases: ["ipapermtargetfrom"]
  memberof:
    description: Target members of a group (sets memberOf targetfilter)
    required: false
    type: list
    elements: str
  targetgroup:
    description: User group to apply permissions to (sets target)
    type: str
    required: false
    aliases: ["targetgroup"]
  object_type:
    description: Type of IPA object (sets subtree and objectClass targetfilter)
    type: str
    required: false
    aliases: ["type"]
  no_members:
    description: Suppress processing of membership
    required: false
    type: bool
  rename:
    description: Rename the permission object
    type: str
    required: false
    aliases: ["new_name"]
  action:
    description: Work on permission or member privilege level.
    type: str
    choices: ["permission", "member"]
    default: permission
    required: false
  state:
    description: The state to ensure.
    type: str
    choices: ["present", "absent", "renamed"]
    default: present
    required: false
author:
  - Seth Kress (@kresss)
  - Thomas Woerner (@t-woerner)
"""

EXAMPLES = """
# Ensure permission NAME is present
- ipapermission:
    name: manage-my-hostgroup
    right: all
    bindtype: permission
    object_type: host

# Ensure permission NAME is absent
- ipapermission:
    name: "Removed Permission Name"
    state: absent
"""

RETURN = """
"""


from ansible.module_utils.ansible_freeipa_module import \
    IPAAnsibleModule, compare_args_ipa


def find_permission(module, name):
    """Find if a permission with the given name already exist."""
    try:
        _result = module.ipa_command("permission_show", name, {"all": True})
    except Exception:  # pylint: disable=broad-except
        # An exception is raised if permission name is not found.
        return None
    return _result["result"]


def gen_args(right, attrs, bindtype, subtree,
             extra_target_filter, rawfilter, target,
             targetto, targetfrom, memberof, targetgroup,
             object_type, no_members, rename):
    _args = {}
    if right is not None:
        _args["ipapermright"] = right
    if attrs is not None:
        _args["attrs"] = attrs
    if bindtype is not None:
        _args["ipapermbindruletype"] = bindtype
    if subtree is not None:
        _args["ipapermlocation"] = subtree
    if extra_target_filter is not None:
        _args["extratargetfilter"] = extra_target_filter
    if rawfilter is not None:
        _args["ipapermtargetfilter"] = rawfilter
    if target is not None:
        _args["ipapermtarget"] = target
    if targetto is not None:
        _args["ipapermtargetto"] = targetto
    if targetfrom is not None:
        _args["ipapermtargetfrom"] = targetfrom
    if memberof is not None:
        _args["memberof"] = memberof
    if targetgroup is not None:
        _args["targetgroup"] = targetgroup
    if object_type is not None:
        _args["type"] = object_type
    if no_members is not None:
        _args["no_members"] = no_members
    if rename is not None:
        _args["rename"] = rename
    return _args


# pylint: disable=unused-argument
def result_handler(module, result, command, name, args, errors):
    # Get all errors
    # All "already a member" and "not a member" failures in the
    # result are ignored. All others are reported.
    for failed_item in result.get("failed", []):
        failed = result["failed"][failed_item]
        for member_type in failed:
            for member, failure in failed[member_type]:
                if "already a member" in failure \
                   or "not a member" in failure:
                    continue
                errors.append("%s: %s %s: %s" % (
                    command, member_type, member, failure))


def main():
    ansible_module = IPAAnsibleModule(
        argument_spec=dict(
            # general
            name=dict(type="list", elements="str", aliases=["cn"],
                      required=True),
            # present
            right=dict(type="list", elements="str", aliases=["ipapermright"],
                       default=None, required=False,
                       choices=["read", "search", "compare", "write", "add",
                                "delete", "all"]),
            attrs=dict(type="list", elements="str", default=None,
                       required=False),
            # Note: bindtype has a default of permission for Adds.
            bindtype=dict(type="str", aliases=["ipapermbindruletype"],
                          default=None, required=False, choices=["permission",
                          "all", "anonymous", "self"]),
            subtree=dict(type="str", aliases=["ipapermlocation"], default=None,
                         required=False),
            extra_target_filter=dict(type="list", elements="str",
                                     aliases=["filter", "extratargetfilter"],
                                     default=None, required=False),
            rawfilter=dict(type="list", elements="str",
                           aliases=["ipapermtargetfilter"],
                           default=None, required=False),
            target=dict(type="str", aliases=["ipapermtarget"], default=None,
                        required=False),
            targetto=dict(type="str", aliases=["ipapermtargetto"],
                          default=None, required=False),
            targetfrom=dict(type="str", aliases=["ipapermtargetfrom"],
                            default=None, required=False),
            memberof=dict(type="list", elements="str", default=None,
                          required=False),
            targetgroup=dict(type="str", default=None, required=False),
            object_type=dict(type="str", aliases=["type"], default=None,
                             required=False),
            no_members=dict(type="bool", default=None, required=False),
            rename=dict(type="str", default=None, required=False,
                        aliases=["new_name"]),
            action=dict(type="str", default="permission",
                        choices=["member", "permission"]),
            # state
            state=dict(type="str", default="present",
                       choices=["present", "absent", "renamed"]),
        ),
        supports_check_mode=True,
    )

    ansible_module._ansible_debug = True

    # Get parameters

    # general
    names = ansible_module.params_get("name")

    # present
    right = ansible_module.params_get("right")
    attrs = ansible_module.params_get("attrs")
    bindtype = ansible_module.params_get("bindtype")
    subtree = ansible_module.params_get("subtree")
    extra_target_filter = ansible_module.params_get("extra_target_filter")
    rawfilter = ansible_module.params_get("rawfilter")
    target = ansible_module.params_get("target")
    targetto = ansible_module.params_get("targetto")
    targetfrom = ansible_module.params_get("targetfrom")
    memberof = ansible_module.params_get("memberof")
    targetgroup = ansible_module.params_get("targetgroup")
    object_type = ansible_module.params_get("object_type")
    no_members = ansible_module.params_get("no_members")
    rename = ansible_module.params_get("rename")
    action = ansible_module.params_get("action")

    # state
    state = ansible_module.params_get("state")

    # Check parameters

    invalid = []

    if state == "present":
        if len(names) != 1:
            ansible_module.fail_json(
                msg="Only one permission can be added at a time.")
        if action == "member":
            invalid = ["bindtype", "target", "targetto", "targetfrom",
                       "subtree", "targetgroup", "object_type", "rename"]
        else:
            invalid = ["rename"]

    if state == "renamed":
        if len(names) != 1:
            ansible_module.fail_json(
                msg="Only one permission can be renamed at a time.")
        if action == "member":
            ansible_module.fail_json(
                msg="Member action can not be used with state 'renamed'")
        invalid = ["right", "attrs", "bindtype", "subtree",
                   "extra_target_filter", "rawfilter", "target", "targetto",
                   "targetfrom", "memberof", "targetgroup", "object_type",
                   "no_members"]

    if state == "absent":
        if len(names) < 1:
            ansible_module.fail_json(msg="No name given.")
        invalid = ["bindtype", "subtree", "target", "targetto",
                   "targetfrom", "targetgroup", "object_type",
                   "no_members", "rename"]
        if action != "member":
            invalid += ["right", "attrs", "memberof",
                        "extra_target_filter", "rawfilter"]

    ansible_module.params_fail_used_invalid(invalid, state, action)

    if bindtype == "self" and ansible_module.ipa_check_version("<", "4.8.7"):
        ansible_module.fail_json(
            msg="Bindtype 'self' is not supported by your IPA version.")

    if all([extra_target_filter, rawfilter]):
        ansible_module.fail_json(
            msg="Cannot specify target filter and extra target filter "
                "simultaneously.")

    # Init

    changed = False
    exit_args = {}

    # Connect to IPA API
    with ansible_module.ipa_connect():

        commands = []
        for name in names:
            # Make sure permission exists
            res_find = find_permission(ansible_module, name)

            # Create command
            if state == "present":
                # Generate args
                args = gen_args(right, attrs, bindtype, subtree,
                                extra_target_filter, rawfilter, target,
                                targetto, targetfrom, memberof, targetgroup,
                                object_type, no_members, rename)

                if action == "permission":
                    # Found the permission
                    if res_find is not None:
                        # For all settings is args, check if there are
                        # different settings in the find result.
                        # If yes: modify
                        if not compare_args_ipa(ansible_module, args,
                                                res_find):
                            commands.append([name, "permission_mod", args])
                    else:
                        commands.append([name, "permission_add", args])

                elif action == "member":
                    if res_find is None:
                        ansible_module.fail_json(
                            msg="No permission '%s'" % name)

                    member_attrs = {}
                    check_members = {
                        "attrs": attrs,
                        "memberof": memberof,
                        "ipapermright": right,
                        "ipapermtargetfilter": rawfilter,
                        "extratargetfilter": extra_target_filter,
                        # subtree member management is currently disabled.
                        # "ipapermlocation": subtree,
                    }

                    for _member, _member_change in check_members.items():
                        if _member_change is not None:
                            _res_list = res_find[_member]
                            # if running in a client context, data may be
                            # returned as a tuple instead of a list.
                            if isinstance(_res_list, tuple):
                                _res_list = list(_res_list)
                            _new_set = set(_res_list + _member_change)
                            if _new_set != set(_res_list):
                                member_attrs[_member] = list(_new_set)

                    if member_attrs:
                        commands.append([name, "permission_mod", member_attrs])

                else:
                    ansible_module.fail_json(
                        msg="Unknown action '%s'" % action)

            elif state == "renamed":
                if action == "permission":
                    # Generate args
                    # Note: Only valid arg for rename is rename.
                    args = gen_args(right, attrs, bindtype, subtree,
                                    extra_target_filter, rawfilter, target,
                                    targetto, targetfrom, memberof,
                                    targetgroup, object_type, no_members,
                                    rename)

                    # Found the permission
                    if res_find is not None:
                        # For all settings is args, check if there are
                        # different settings in the find result.
                        # If yes: modify
                        if not compare_args_ipa(ansible_module, args,
                                                res_find):
                            commands.append([name, "permission_mod", args])
                    else:
                        ansible_module.fail_json(
                            msg="Permission not found, cannot rename")
                else:
                    ansible_module.fail_json(
                        msg="Unknown action '%s'" % action)

            elif state == "absent":
                if action == "permission":
                    if res_find is not None:
                        commands.append([name, "permission_del", {}])

                elif action == "member":
                    if res_find is None:
                        ansible_module.fail_json(
                            msg="No permission '%s'" % name)

                    member_attrs = {}
                    check_members = {
                        "attrs": attrs,
                        "memberof": memberof,
                        "ipapermright": right,
                        "ipapermtargetfilter": rawfilter,
                        "extratargetfilter": extra_target_filter,
                        # subtree member management is currently disabled.
                        # "ipapermlocation": subtree,
                    }

                    for _member, _member_change in check_members.items():
                        if _member_change is not None:
                            _res_set = set(res_find[_member])
                            _new_set = _res_set - set(_member_change)
                            if _new_set != _res_set:
                                member_attrs[_member] = list(_new_set)

                    if member_attrs:
                        commands.append([name, "permission_mod", member_attrs])

            else:
                ansible_module.fail_json(msg="Unknown state '%s'" % state)

        # Execute commands

        changed = ansible_module.execute_ipa_commands(commands, result_handler)

    # Done

    ansible_module.exit_json(changed=changed, **exit_args)


if __name__ == "__main__":
    main()

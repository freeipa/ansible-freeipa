#!/usr/bin/python
# -*- coding: utf-8 -*-

# Authors:
#   Seth Kress <kresss@gmail.com>
#
# Copyright (C) 2020 Red Hat
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
module: ipapermission
short description: Manage FreeIPA permission
description: Manage FreeIPA permission and permission members
options:
  ipaadmin_principal:
    description: The admin principal.
    default: admin
  ipaadmin_password:
    description: The admin password.
    required: false
  name:
    description: The permission name string.
    required: true
    aliases: ["cn"]
  right:
    description: Rights to grant
    required: false
    choices: ["read", "search", "compare", "write", "add", "delete", "all"]
    type: list
    aliases: ["ipapermright"]
  attrs:
    description: All attributes to which the permission applies
    required: false
    type: list
  bindtype:
    description: Bind rule type
    required: false
    choices: ["permission", "all", "anonymous"]
    aliases: ["ipapermbindruletype"]
  subtree:
    description: Subtree to apply permissions to
    required: false
    aliases: ["ipapermlocation"]
  filter:
    description: Extra target filter
    required: false
    type: list
    aliases: ["extratargetfilter"]
  rawfilter:
    description: All target filters
    required: false
    type: list
    aliases: ["ipapermtargetfilter"]
  target:
    description: Optional DN to apply the permission to
    required: false
    aliases: ["ipapermtarget"]
  targetto:
    description: Optional DN subtree where an entry can be moved to
    required: false
    aliases: ["ipapermtargetto"]
  targetfrom:
    description: Optional DN subtree from where an entry can be moved
    required: false
    aliases: ["ipapermtargetfrom"]
  memberof:
    description: Target members of a group (sets memberOf targetfilter)
    required: false
    type: list
  targetgroup:
    description: User group to apply permissions to (sets target)
    required: false
    aliases: ["targetgroup"]
  object_type:
    description: Type of IPA object (sets subtree and objectClass targetfilter)
    required: false
    aliases: ["type"]
  no_members:
    description: Suppress processing of membership
    required: false
    type: bool
  rename:
    description: Rename the permission object
    required: false
  action:
    description: Work on permission or member privilege level.
    choices: ["permission", "member"]
    default: permission
    required: false
  state:
    description: The state to ensure.
    choices: ["present", "absent", "renamed"]
    default: present
    required: true
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


from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.ansible_freeipa_module import \
    temp_kinit, temp_kdestroy, valid_creds, api_connect, api_command, \
    compare_args_ipa, module_params_get, api_check_ipa_version
import six

if six.PY3:
    unicode = str


def find_permission(module, name):
    """Find if a permission with the given name already exist."""
    try:
        _result = api_command(module, "permission_show", name, {"all": True})
    except Exception:  # pylint: disable=broad-except
        # An exception is raised if permission name is not found.
        return None
    else:
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


def main():
    ansible_module = AnsibleModule(
        argument_spec=dict(
            # general
            ipaadmin_principal=dict(type="str", default="admin"),
            ipaadmin_password=dict(type="str", required=False, no_log=True),

            name=dict(type="list", aliases=["cn"],
                      default=None, required=True),
            # present
            right=dict(type="list", aliases=["ipapermright"], default=None,
                       required=False,
                       choices=["read", "search", "compare", "write", "add",
                                "delete", "all"]),
            attrs=dict(type="list", default=None, required=False),
            # Note: bindtype has a default of permission for Adds.
            bindtype=dict(type="str", aliases=["ipapermbindruletype"],
                          default=None, require=False, choices=["permission",
                          "all", "anonymous", "self"]),
            subtree=dict(type="str", aliases=["ipapermlocation"], default=None,
                         required=False),
            extra_target_filter=dict(type="list", aliases=["filter",
                                     "extratargetfilter"], default=None,
                                     required=False),
            rawfilter=dict(type="list", aliases=["ipapermtargetfilter"],
                           default=None, required=False),
            target=dict(type="str", aliases=["ipapermtarget"], default=None,
                        required=False),
            targetto=dict(type="str", aliases=["ipapermtargetto"],
                          default=None, required=False),
            targetfrom=dict(type="str", aliases=["ipapermtargetfrom"],
                            default=None, required=False),
            memberof=dict(type="list", default=None, required=False),
            targetgroup=dict(type="str", default=None, required=False),
            object_type=dict(type="str", aliases=["type"], default=None,
                             required=False),
            no_members=dict(type=bool, default=None, require=False),
            rename=dict(type="str", default=None, required=False),

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
    ipaadmin_principal = module_params_get(ansible_module,
                                           "ipaadmin_principal")
    ipaadmin_password = module_params_get(ansible_module, "ipaadmin_password")
    names = module_params_get(ansible_module, "name")

    # present
    right = module_params_get(ansible_module, "right")
    attrs = module_params_get(ansible_module, "attrs")
    bindtype = module_params_get(ansible_module, "bindtype")
    subtree = module_params_get(ansible_module, "subtree")
    extra_target_filter = module_params_get(ansible_module,
                                            "extra_target_filter")
    rawfilter = module_params_get(ansible_module, "rawfilter")
    target = module_params_get(ansible_module, "target")
    targetto = module_params_get(ansible_module, "targetto")
    targetfrom = module_params_get(ansible_module, "targetfrom")
    memberof = module_params_get(ansible_module, "memberof")
    targetgroup = module_params_get(ansible_module, "targetgroup")
    object_type = module_params_get(ansible_module, "object_type")
    no_members = module_params_get(ansible_module, "no_members")
    rename = module_params_get(ansible_module, "rename")
    action = module_params_get(ansible_module, "action")

    # state
    state = module_params_get(ansible_module, "state")

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

    for x in invalid:
        if vars()[x] is not None:
            ansible_module.fail_json(
                msg="Argument '%s' can not be used with action "
                "'%s' and state '%s'" % (x, action, state))

    if bindtype == "self" and api_check_ipa_version("<", "4.8.7"):
        ansible_module.fail_json(
            msg="Bindtype 'self' is not supported by your IPA version.")

    if all([extra_target_filter, rawfilter]):
        ansible_module.fail_json(
            msg="Cannot specify target filter and extra target filter "
                "simultaneously.")

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

        # Check mode exit
        if ansible_module.check_mode:
            ansible_module.exit_json(changed=len(commands) > 0, **exit_args)

        # Execute commands

        for name, command, args in commands:
            try:
                result = api_command(ansible_module, command, name,
                                     args)
                if "completed" in result:
                    if result["completed"] > 0:
                        changed = True
                else:
                    changed = True
            except Exception as e:
                ansible_module.fail_json(msg="%s: %s: %s" % (command, name,
                                                             str(e)))
            # Get all errors
            # All "already a member" and "not a member" failures in the
            # result are ignored. All others are reported.
            errors = []
            for failed_item in result.get("failed", []):
                failed = result["failed"][failed_item]
                for member_type in failed:
                    for member, failure in failed[member_type]:
                        if "already a member" in failure \
                           or "not a member" in failure:
                            continue
                        errors.append("%s: %s %s: %s" % (
                            command, member_type, member, failure))
            if len(errors) > 0:
                ansible_module.fail_json(msg=", ".join(errors))

    except Exception as e:
        ansible_module.fail_json(msg=str(e))

    finally:
        temp_kdestroy(ccache_dir, ccache_name)

    # Done

    ansible_module.exit_json(changed=changed, **exit_args)


if __name__ == "__main__":
    main()

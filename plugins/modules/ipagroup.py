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
module: ipagroup
short description: Manage FreeIPA groups
description: Manage FreeIPA groups
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
  description:
    description: The group description
    required: false
  gid:
    description: The GID
    required: false
    aliases: ["gidnumber"]
  nonposix:
    description: Create as a non-POSIX group
    required: false
    type: bool
  external:
    description: Allow adding external non-IPA members from trusted domains
    required: false
    type: bool
  posix:
    description:
      Create a non-POSIX group or change a non-POSIX to a posix group.
    required: false
    type: bool
  nomembers:
    description: Suppress processing of membership attributes
    required: false
    type: bool
  user:
    description: List of user names assigned to this group.
    required: false
    type: list
  group:
    description: List of group names assigned to this group.
    required: false
    type: list
  service:
    description:
    - List of service names assigned to this group.
    - Only usable with IPA versions 4.7 and up.
    required: false
    type: list
  membermanager_user:
    description:
    - List of member manager users assigned to this group.
    - Only usable with IPA versions 4.8.4 and up.
    required: false
    type: list
  membermanager_group:
    description:
    - List of member manager groups assigned to this group.
    - Only usable with IPA versions 4.8.4 and up.
    required: false
    type: list
  externalmember:
    description:
    - List of members of a trusted domain in DOM\\name or name@domain form.
    required: false
    type: list
    ailases: ["ipaexternalmember", "external_member"]
  action:
    description: Work on group or member level
    default: group
    choices: ["member", "group"]
  state:
    description: State to ensure
    default: present
    choices: ["present", "absent"]
author:
    - Thomas Woerner
"""

EXAMPLES = """
# Create group ops with gid 1234
- ipagroup:
    ipaadmin_password: SomeADMINpassword
    name: ops
    gidnumber: 1234

# Create group sysops
- ipagroup:
    ipaadmin_password: SomeADMINpassword
    name: sysops

# Create group appops
- ipagroup:
    ipaadmin_password: SomeADMINpassword
    name: appops

# Add user member pinky to group sysops
- ipagroup:
    ipaadmin_password: SomeADMINpassword
    name: sysops
    action: member
    user:
    - pinky

# Add user member brain to group sysops
- ipagroup:
    ipaadmin_password: SomeADMINpassword
    name: sysops
    action: member
    user:
    - brain

# Add group members sysops and appops to group sysops
- ipagroup:
    ipaadmin_password: SomeADMINpassword
    name: ops
    group:
    - sysops
    - appops

# Create a non-POSIX group
- ipagroup:
    ipaadmin_password: SomeADMINpassword
    name: nongroup
    nonposix: yes

# Turn a non-POSIX group into a POSIX group.
- ipagroup:
    ipaadmin_password: SomeADMINpassword
    name: nonposix
    posix: yes

# Create an external group and add members from a trust to it.
- ipagroup:
    ipaadmin_password: SomeADMINpassword
    name: extgroup
    external: yes
    externalmember:
    - WINIPA\\Web Users
    - WINIPA\\Developers

# Remove goups sysops, appops, ops and nongroup
- ipagroup:
    ipaadmin_password: SomeADMINpassword
    name: sysops,appops,ops, nongroup
    state: absent
"""

RETURN = """
"""

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.ansible_freeipa_module import temp_kinit, \
    temp_kdestroy, valid_creds, api_connect, api_command, compare_args_ipa, \
    api_check_param, module_params_get, gen_add_del_lists, api_check_command


def find_group(module, name):
    _args = {
        "all": True,
        "cn": name,
    }

    _result = api_command(module, "group_find", name, _args)

    if len(_result["result"]) > 1:
        module.fail_json(
            msg="There is more than one group '%s'" % (name))
    elif len(_result["result"]) == 1:
        return _result["result"][0]
    else:
        return None


def gen_args(description, gid, nomembers):
    _args = {}
    if description is not None:
        _args["description"] = description
    if gid is not None:
        _args["gidnumber"] = gid
    if nomembers is not None:
        _args["nomembers"] = nomembers

    return _args


def gen_member_args(user, group, service, externalmember):
    _args = {}
    if user is not None:
        _args["member_user"] = user
    if group is not None:
        _args["member_group"] = group
    if service is not None:
        _args["member_service"] = service
    if externalmember is not None:
        _args["member_external"] = externalmember

    return _args


def is_external_group(res_find):
    """Verify if the result group is an external group."""
    return res_find and 'ipaexternalgroup' in res_find['objectclass']


def is_posix_group(res_find):
    """Verify if the result group is an external group."""
    return res_find and 'posixgroup' in res_find['objectclass']


def check_objectclass_args(module, res_find, nonposix, posix, external):
    if is_posix_group(res_find):
        if (
            (posix is not None and posix is False)
            or nonposix
            or external
        ):
            module.fail_json(
                msg="Cannot change `POSIX` status of a group "
                    "to `non-POSIX` or `external`.")
    # Can't change an existing external group
    if is_external_group(res_find):
        if (
            posix
            or (nonposix is not None and nonposix is False)
            or (external is not None and external is False)
        ):
            module.fail_json(
                msg="Cannot change `external` status of group "
                    "to `POSIX` or `non-external`.")


def should_modify_group(module, res_find, args, nonposix, posix, external):
    if not compare_args_ipa(module, args, res_find):
        return True
    if any([posix, nonposix]):
        set_posix = posix or (nonposix is not None and not nonposix)
        if set_posix and not is_posix_group(res_find):
            return True
    if not is_external_group(res_find) and external:
        if not is_posix_group(res_find):
            return True
    return False


def main():
    ansible_module = AnsibleModule(
        argument_spec=dict(
            # general
            ipaadmin_principal=dict(type="str", default="admin"),
            ipaadmin_password=dict(type="str", required=False, no_log=True),

            name=dict(type="list", aliases=["cn"], default=None,
                      required=True),
            # present
            description=dict(type="str", default=None),
            gid=dict(type="int", aliases=["gidnumber"], default=None),
            nonposix=dict(required=False, type='bool', default=None),
            external=dict(required=False, type='bool', default=None),
            posix=dict(required=False, type='bool', default=None),
            nomembers=dict(required=False, type='bool', default=None),
            user=dict(required=False, type='list', default=None),
            group=dict(required=False, type='list', default=None),
            service=dict(required=False, type='list', default=None),
            membermanager_user=dict(required=False, type='list', default=None),
            membermanager_group=dict(required=False, type='list',
                                     default=None),
            externalmember=dict(required=False, type='list', default=None,
                                aliases=[
                                    "ipaexternalmember",
                                    "external_member"
                                ]),
            action=dict(type="str", default="group",
                        choices=["member", "group"]),
            # state
            state=dict(type="str", default="present",
                       choices=["present", "absent"]),
        ),
        mutually_exclusive=[['posix', 'nonposix']],
        supports_check_mode=True,
    )

    ansible_module._ansible_debug = True

    # Get parameters

    # general
    ipaadmin_principal = module_params_get(
        ansible_module,
        "ipaadmin_principal",
    )
    ipaadmin_password = module_params_get(ansible_module, "ipaadmin_password")
    names = module_params_get(ansible_module, "name")

    # present
    description = module_params_get(ansible_module, "description")
    gid = module_params_get(ansible_module, "gid")
    nonposix = module_params_get(ansible_module, "nonposix")
    external = module_params_get(ansible_module, "external")
    posix = module_params_get(ansible_module, "posix")
    nomembers = module_params_get(ansible_module, "nomembers")
    user = module_params_get(ansible_module, "user")
    group = module_params_get(ansible_module, "group")
    service = module_params_get(ansible_module, "service")
    membermanager_user = module_params_get(ansible_module,
                                           "membermanager_user")
    membermanager_group = module_params_get(ansible_module,
                                            "membermanager_group")
    externalmember = module_params_get(ansible_module, "externalmember")
    action = module_params_get(ansible_module, "action")
    # state
    state = module_params_get(ansible_module, "state")

    # Check parameters

    if state == "present":
        if len(names) != 1:
            ansible_module.fail_json(
                msg="Only one group can be added at a time.")
        if action == "member":
            invalid = ["description", "gid", "posix", "nonposix", "external",
                       "nomembers"]
            for x in invalid:
                if vars()[x] is not None:
                    ansible_module.fail_json(
                        msg="Argument '%s' can not be used with action "
                        "'%s'" % (x, action))

    if state == "absent":
        if len(names) < 1:
            ansible_module.fail_json(
                msg="No name given.")
        invalid = ["description", "gid", "posix", "nonposix", "external",
                   "nomembers"]
        if action == "group":
            invalid.extend(["user", "group", "service", "externalmember"])
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

        has_add_member_service = api_check_param("group_add_member", "service")
        if service is not None and not has_add_member_service:
            ansible_module.fail_json(
                msg="Managing a service as part of a group is not supported "
                "by your IPA version")

        has_add_membermanager = api_check_command("group_add_member_manager")
        if ((membermanager_user is not None or
             membermanager_group is not None) and not has_add_membermanager):
            ansible_module.fail_json(
                msg="Managing a membermanager user or group is not supported "
                "by your IPA version"
            )

        commands = []

        for name in names:
            # Make sure group exists
            res_find = find_group(ansible_module, name)

            # Create command
            if state == "present":
                # Can't change an existing posix group
                check_objectclass_args(ansible_module, res_find, nonposix,
                                       posix, external)

                # Generate args
                args = gen_args(description, gid, nomembers)

                if action == "group":
                    # Found the group
                    if res_find is not None:
                        # For all settings is args, check if there are
                        # different settings in the find result.
                        # If yes: modify
                        if should_modify_group(ansible_module, res_find, args,
                                               nonposix, posix, external):
                            if (
                                posix
                                or (nonposix is not None and not nonposix)
                            ):
                                args['posix'] = True
                            if external:
                                args['external'] = True
                            commands.append([name, "group_mod", args])
                    else:
                        if nonposix or (posix is not None and not posix):
                            args['nonposix'] = True
                        if external:
                            args['external'] = True
                        commands.append([name, "group_add", args])
                        # Set res_find dict for next step
                        res_find = {}

                    # if we just created/modified the group, update res_find
                    res_find.setdefault("objectclass", [])
                    if external and not is_external_group(res_find):
                        res_find["objectclass"].append("ipaexternalgroup")
                    if posix and not is_posix_group(res_find):
                        res_find["objectclass"].append("posixgroup")

                    member_args = gen_member_args(
                        user, group, service, externalmember
                    )
                    if not compare_args_ipa(ansible_module, member_args,
                                            res_find):
                        # Generate addition and removal lists
                        user_add, user_del = gen_add_del_lists(
                            user, res_find.get("member_user"))

                        group_add, group_del = gen_add_del_lists(
                            group, res_find.get("member_group"))

                        service_add, service_del = gen_add_del_lists(
                            service, res_find.get("member_service"))

                        (externalmember_add,
                         externalmember_del) = gen_add_del_lists(
                            externalmember, res_find.get("member_external"))

                        # setup member args for add/remove members.
                        add_member_args = {
                            "user": user_add,
                            "group": group_add,
                        }
                        del_member_args = {
                            "user": user_del,
                            "group": group_del,
                        }
                        if has_add_member_service:
                            add_member_args["service"] = service_add
                            del_member_args["service"] = service_del

                        if is_external_group(res_find):
                            add_member_args["ipaexternalmember"] = \
                                externalmember_add
                            del_member_args["ipaexternalmember"] = \
                                externalmember_del
                        elif externalmember or external:
                            ansible_module.fail_json(
                                msg="Cannot add external members to a "
                                    "non-external group."
                            )

                        # Add members
                        add_members = any([user_add, group_add,
                                           service_add, externalmember_add])
                        if add_members:
                            commands.append(
                                [name, "group_add_member", add_member_args]
                            )
                        # Remove members
                        remove_members = any([user_del, group_del,
                                              service_del, externalmember_del])
                        if remove_members:
                            commands.append(
                                [name, "group_remove_member", del_member_args]
                            )

                    membermanager_user_add, membermanager_user_del = \
                        gen_add_del_lists(
                            membermanager_user,
                            res_find.get("membermanager_user")
                        )

                    membermanager_group_add, membermanager_group_del = \
                        gen_add_del_lists(
                            membermanager_group,
                            res_find.get("membermanager_group")
                        )

                    if has_add_membermanager:
                        # Add membermanager users and groups
                        if len(membermanager_user_add) > 0 or \
                           len(membermanager_group_add) > 0:
                            commands.append(
                                [name, "group_add_member_manager",
                                 {
                                     "user": membermanager_user_add,
                                     "group": membermanager_group_add,
                                 }]
                            )
                        # Remove member manager
                        if len(membermanager_user_del) > 0 or \
                           len(membermanager_group_del) > 0:
                            commands.append(
                                [name, "group_remove_member_manager",
                                 {
                                     "user": membermanager_user_del,
                                     "group": membermanager_group_del,
                                 }]
                            )

                elif action == "member":
                    if res_find is None:
                        ansible_module.fail_json(msg="No group '%s'" % name)

                    add_member_args = {
                        "user": user,
                        "group": group,
                    }
                    if has_add_member_service:
                        add_member_args["service"] = service
                    if is_external_group(res_find):
                        add_member_args["ipaexternalmember"] = externalmember
                    elif externalmember:
                        ansible_module.fail_json(
                            msg="Cannot add external members to a "
                                "non-external group."
                        )

                    if any([user, group, service, externalmember]):
                        commands.append(
                            [name, "group_add_member", add_member_args]
                        )

                    if has_add_membermanager:
                        # Add membermanager users and groups
                        if membermanager_user is not None or \
                           membermanager_group is not None:
                            commands.append(
                                [name, "group_add_member_manager",
                                 {
                                     "user": membermanager_user,
                                     "group": membermanager_group,
                                 }]
                            )

            elif state == "absent":
                if action == "group":
                    if res_find is not None:
                        commands.append([name, "group_del", {}])

                elif action == "member":
                    if res_find is None:
                        ansible_module.fail_json(msg="No group '%s'" % name)

                    del_member_args = {
                        "user": user,
                        "group": group,
                    }
                    if has_add_member_service:
                        del_member_args["service"] = service
                    if is_external_group(res_find):
                        del_member_args["ipaexternalmember"] = externalmember
                    elif externalmember:
                        ansible_module.fail_json(
                            msg="Cannot add external members to a "
                                "non-external group."
                        )

                    if any([user, group, service, externalmember]):
                        commands.append(
                            [name, "group_remove_member", del_member_args]
                        )

                    if has_add_membermanager:
                        # Remove membermanager users and groups
                        if membermanager_user is not None or \
                           membermanager_group is not None:
                            commands.append(
                                [name, "group_remove_member_manager",
                                 {
                                     "user": membermanager_user,
                                     "group": membermanager_group,
                                 }]
                            )

            else:
                ansible_module.fail_json(msg="Unkown state '%s'" % state)

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

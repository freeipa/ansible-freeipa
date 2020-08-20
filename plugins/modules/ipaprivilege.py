#!/usr/bin/python
# -*- coding: utf-8 -*-

# Authors:
#   Rafael Guterres Jeffman <rjeffman@redhat.com>
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

"""ansible-freeipa module to manage FreeIPA privileges."""


ANSIBLE_METADATA = {
    "metadata_version": "1.0",
    "supported_by": "community",
    "status": ["preview"],
}

DOCUMENTATION = """
---
module: ipaprivilege
short description: Manage FreeIPA privilege
description: Manage FreeIPA privilege and privilege members
options:
  ipaadmin_principal:
    description: The admin principal.
    default: admin
  ipaadmin_password:
    description: The admin password.
    required: false
  name:
    description: The list of privilege name strings.
    required: true
    aliases: ["cn"]
  description:
    description: Privilege description
    required: false
  rename:
    description: Rename the privilege object.
    required: false
    aliases: ["new_name"]
  permission:
    description: Permissions to be added to the privilege.
    required: false
  action:
    description: Work on privilege or member level.
    choices: ["privilege", "member"]
    default: privilege
    required: false
  state:
    description: The state to ensure.
    choices: ["present", "absent", "renamed"]
    default: present
    required: true
"""

EXAMPLES = """
# Ensure privilege "Broad Privilege" is present
- ipaprivilege:
    ipaadmin_password: SomeADMINpassword
    name: Broad Privilege
    description: Broad Privilege

# Ensure privilege "Broad Privilege" has permissions set
- ipaprivilege:
    ipaadmin_password: SomeADMINpassword
    name: Broad Privilege
    permission:
    - "Write IPA Configuration"
    - "System: Write DNS Configuration"
    - "System: Update DNS Entries"
    action: member

# Ensure privilege member permission 'Write IPA Configuration' is absent
- ipaprivilege:
    ipaadmin_password: SomeADMINpassword
    name: Broad Privilege
    permission:
    - "Write IPA Configuration"
    action: member
    state: absent

# Rename privilege "Broad Privilege" to "DNS Special Privilege"
- ipaprivilege:
    ipaadmin_password: SomeADMINpassword
    name: Broad Privilege
    rename: DNS Special Privilege
    state: renamed

# Ensure privilege "DNS Special Privilege" is absent
- ipaprivilege:
    ipaadmin_password: SomeADMINpassword
    name: DNS Special Privilege
    state: absent
"""

RETURN = """
"""


from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.ansible_freeipa_module import \
    temp_kinit, temp_kdestroy, valid_creds, api_connect, api_command, \
    compare_args_ipa, module_params_get, gen_add_del_lists
import six

if six.PY3:
    unicode = str


def find_privilege(module, name):
    """Find if a privilege with the given name already exist."""
    try:
        _result = api_command(module, "privilege_show", name, {"all": True})
    except Exception:  # pylint: disable=broad-except
        # An exception is raised if privilege name is not found.
        return None
    else:
        return _result["result"]


def main():
    ansible_module = AnsibleModule(
        argument_spec=dict(
            # general
            ipaadmin_principal=dict(type="str", default="admin"),
            ipaadmin_password=dict(type="str", required=False, no_log=True),

            name=dict(type="list", aliases=["cn"],
                      default=None, required=True),
            # present
            description=dict(required=False, type='str', default=None),
            rename=dict(required=False, type='str', default=None,
                        aliases=["new_name"], ),
            permission=dict(required=False, type='list', default=None),
            action=dict(type="str", default="privilege",
                        choices=["member", "privilege"]),
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
    description = module_params_get(ansible_module, "description")
    permission = module_params_get(ansible_module, "permission")
    rename = module_params_get(ansible_module, "rename")
    action = module_params_get(ansible_module, "action")

    # state
    state = module_params_get(ansible_module, "state")

    # Check parameters
    invalid = []

    if state == "present":
        if len(names) != 1:
            ansible_module.fail_json(
                msg="Only one privilege be added at a time.")
        if action == "member":
            invalid = ["description"]

    if state == "absent":
        if len(names) < 1:
            ansible_module.fail_json(msg="No name given.")
        invalid = ["description", "rename"]
        if action == "privilege":
            invalid.append("permission")

    if state == "renamed":
        if len(names) != 1:
            ansible_module.fail_json(
                msg="Only one privilege be added at a time.")
        invalid = ["description", "permission"]
        if action != "privilege":
            ansible_module.fail_json(
                msg="Action '%s' can not be used with state '%s'"
                    % (action, state))

    for x in invalid:
        if vars()[x] is not None:
            ansible_module.fail_json(
                msg="Argument '%s' can not be used with action "
                "'%s' and state '%s'" % (x, action, state))

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
            # Make sure privilege exists
            res_find = find_privilege(ansible_module, name)

            # Create command
            if state == "present":

                args = {}
                if description:
                    args['description'] = description

                if action == "privilege":
                    # Found the privilege
                    if res_find is not None:
                        # For all settings is args, check if there are
                        # different settings in the find result.
                        # If yes: modify
                        if not compare_args_ipa(ansible_module, args,
                                                res_find):
                            commands.append([name, "privilege_mod", args])
                    else:
                        commands.append([name, "privilege_add", args])

                    member_args = {}
                    if permission:
                        member_args['permission'] = permission

                    if not compare_args_ipa(ansible_module, member_args,
                                            res_find):

                        # Generate addition and removal lists
                        permission_add, permission_del = gen_add_del_lists(
                                permission, res_find.get("member_permission"))

                        # Add members
                        if len(permission_add) > 0:
                            commands.append([name, "privilege_add_permission",
                                             {
                                                 "permission": permission_add,
                                             }])
                        # Remove members
                        if len(permission_del) > 0:
                            commands.append([
                                name,
                                "privilege_remove_permission",
                                {"permission": permission_del}
                            ])

                elif action == "member":
                    if res_find is None:
                        ansible_module.fail_json(
                            msg="No privilege '%s'" % name)

                    if permission is None:
                        ansible_module.fail_json(msg="No permission given")

                    commands.append([name, "privilege_add_permission",
                                     {"permission": permission}])

            elif state == "absent":
                if action == "privilege":
                    if res_find is not None:
                        commands.append([name, "privilege_del", {}])

                elif action == "member":
                    if res_find is None:
                        ansible_module.fail_json(
                            msg="No privilege '%s'" % name)

                    if permission is None:
                        ansible_module.fail_json(msg="No permission given")

                    commands.append([name, "privilege_remove_permission",
                                     {
                                         "permission": permission,
                                     }])

            elif state == "renamed":
                if not rename:
                    ansible_module.fail_json(msg="No rename value given.")

                if res_find is None:
                    ansible_module.fail_json(
                        msg="No privilege found to be renamed: '%s'" % (name))

                if name != rename:
                    commands.append(
                        [name, "privilege_mod", {"rename": rename}])

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
                ansible_module.fail_json(
                    msg="%s: %s: %s" % (command, name, str(e)))
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

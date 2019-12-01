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
module: ipavault
short description: Manage vaults and secret vaults.
description: Manage vaults and secret vaults. KRA service must be enabled.
options:
  ipaadmin_principal:
    description: The admin principal
    default: admin
  ipaadmin_password:
    description: The admin password
    required: false
  name:
    description: The vault name
    required: true
    aliases: ["cn"]
  description:
    description: The vault description
    required: false
  vault_public_key:
    description: Base64 encoded public key.
    required: false
    type: list
    aliases: ["ipavaultpublickey"]
  vault_salt:
    description: Vault salt.
    required: false
    type: list
    aliases: ["ipavaultsalt"]
  vault_password:
    description: password to be used on symmetric vault.
    required: false
    type: string
    aliases: ["ipavaultpassword"]
  vault_type:
    description: Vault types are based on security level.
    required: true
    default: symmetric
    choices: ["standard", "symmetric", "asymmetric"]
    aliases: ["ipavaulttype"]
  service:
    description: Any service can own one or more service vaults.
    required: false
    type: list
  username:
    description: Any user can own one or more user vaults.
    required: false
    type: string
    aliases: ["user"]
  shared:
    description: Vault is shared.
    required: false
    type: boolean
  vault_data:
    description: Data to be stored in the vault.
    required: false
    type: string
    aliases: ["ipavaultdata"]
  owners:
    description: Users that are owners of the container.
    required: false
    type: list
  users:
    description: Users that are member of the container.
    required: false
    type: list
  groups:
    description: Groups that are member of the container.
    required: false
    type: list
  action:
    description: Work on vault or member level.
    default: vault
    choices: ["vault", "member"]
  state:
    description: State to ensure
    default: present
    choices: ["present", "absent"]
author:
    - Rafael Jeffman
"""

EXAMPLES = """
# Ensure vault symvault is present
- ipavault:
    ipaadmin_password: MyPassword123
    name: symvault
    username: admin
    vault_password: MyVaultPassword123
    vault_salt: MTIzNDU2Nzg5MAo=
    vault_type: symmetric

# Ensure group ipausers is a vault member.
- ipavault:
    ipaadmin_password: MyPassword123
    name: symvault
    username: admin
    groups: ipausers
    action: member

# Ensure group ipausers is not a vault member.
- ipavault:
    ipaadmin_password: MyPassword123
    name: symvault
    username: admin
    groups: ipausers
    action: member
    state: absent

# Ensure vault users are present.
- ipavault:
    ipaadmin_password: MyPassword123
    name: symvault
    username: admin
    users:
    - user01
    - user02
    action: member

# Ensure vault users are absent.
- ipavault:
    ipaadmin_password: MyPassword123
    name: symvault
    username: admin
    users:
    - user01
    - user02
    action: member
    status: absent

# Ensure user owns vault.
- ipavault:
    ipaadmin_password: MyPassword123
    name: symvault
    username: admin
    action: member
    owners: user01

# Ensure user does not own vault.
- ipavault:
    ipaadmin_password: MyPassword123
    name: symvault
    username: admin
    owners: user01
    action: member
    status: absent

# Ensure data is archived to a symmetric vault
- ipavault:
    ipaadmin_password: MyPassword123
    name: symvault
    username: admin
    vault_password: MyVaultPassword123
    vault_data: >
      Data archived.
      More data archived.
    action: member

# Ensure vault symvault is absent
- ipavault:
    ipaadmin_password: MyPassword123
    name: symvault
    user: admin
    state: absent

# Ensure asymmetric vault is present.
- ipavault:
    ipaadmin_password: MyPassword123
    name: asymvault
    username: user01
    description: An asymmetric vault
    vault_type: asymmetric
    vault_public_key:
      LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlHZk1BMEdDU3FHU0liM0RRRUJBUVVBQTR
      HTkFEQ0JpUUtCZ1FDdGFudjRkK3ptSTZ0T3ova1RXdGowY3AxRAowUENoYy8vR0pJMTUzTi
      9CN3UrN0h3SXlRVlZoNUlXZG1UcCtkWXYzd09yeVpPbzYvbHN5eFJaZ2pZRDRwQ3VGCjlxM
      295VTFEMnFOZERYeGtSaFFETXBiUEVSWWlHbE1jbzdhN0hIVDk1bGNQbmhObVFkb3VGdHlV
      bFBUVS96V1kKZldYWTBOeU1UbUtoeFRseUV3SURBUUFCCi0tLS0tRU5EIFBVQkxJQyBLRVk
      tLS0tLQo=

# Ensure data is archived in an asymmetric vault
- ipavault:
    ipaadmin_password: MyPassword123
    name: asymvault
    username: admin
    vault_data: >
      Data archived.
      More data archived.
    action: member

# Ensure asymmetric vault is absent.
- ipavault:
    ipaadmin_password: MyPassword123
    name: asymvault
    username: user01
    vault_type: asymmetric
    state: absent
"""

RETURN = """
"""

import os
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.ansible_freeipa_module import temp_kinit, \
    temp_kdestroy, valid_creds, api_connect, api_command, \
    gen_add_del_lists, compare_args_ipa, module_params_get
from ipalib.errors import EmptyModlist


def find_vault(module, name, username, service, shared):
    _args = {
        "all": True,
        "cn": name,
    }

    if username is not None:
        _args['username'] = username
    elif service is not None:
        _args['service'] = service
    else:
        _args['shared'] = shared

    _result = api_command(module, "vault_find", name, _args)

    if len(_result["result"]) > 1:
        module.fail_json(
            msg="There is more than one vault '%s'" % (name))
    if len(_result["result"]) == 1:
        return _result["result"][0]

    return None


def gen_args(description, username, service, shared, vault_type, salt,
             public_key, vault_data):
    _args = {}

    if description is not None:
        _args['description'] = description
    if username is not None:
        _args['username'] = username
    if service is not None:
        _args['service'] = service
    if shared is not None:
        _args['shared'] = shared
    if vault_type is not None:
        _args['ipavaulttype'] = vault_type
    if salt is not None:
        _args['ipavaultsalt'] = salt
    if public_key is not None:
        _args['ipavaultpublickey'] = public_key
    if vault_data is not None:
        _args['data'] = vault_data.encode('utf-8')

    return _args


def gen_member_args(args, users, groups):
    _args = args.copy()

    for arg in ['ipavaulttype', 'description', 'ipavaultpublickey',
                'ipavaultsalt']:
        if arg in _args:
            del _args[arg]

    _args['user'] = users
    _args['group'] = groups

    return _args


def data_storage_args(args, data, password):
    _args = {}

    if 'username' in args:
        _args['username'] = args['username']
    if 'service' in args:
        _args['service'] = args['service']
    if 'shared' in args:
        _args['shared'] = args['shared']

    if password is not None:
        _args['password'] = password

    _args['data'] = data

    return _args


def check_parameters(module, state, action, description, username, service,
                     shared, users, groups, owners, ownergroups, vault_type,
                     salt, password, public_key, vault_data):
    invalid = []
    if state == "present":
        if action == "member":
            invalid = ['description', 'public_key', 'salt']

        for param in invalid:
            if vars()[param] is not None:
                module.fail_json(
                    msg="Argument '%s' can not be used with action '%s'" %
                    (param, action))

    elif state == "absent":
        invalid = ['description', 'salt']

        if action == "vault":
            invalid.extend(['users', 'groups', 'owners', 'ownergroups',
                            'password', 'public_key'])

        for arg in invalid:
            if vars()[arg] is not None:
                module.fail_json(
                    msg="Argument '%s' can not be used with action '%s'" %
                    (arg, state))


def check_encryption_params(module, state, vault_type, password, public_key,
                            vault_data, res_find):
    if state == "present":
        if vault_type == "symmetric":
            if password is None \
               and (vault_data is not None or res_find is None):
                module.fail_json(
                    msg="Vault password required for symmetric vault.")

        if vault_type == "asymmetric":
            if public_key is None and res_find is None:
                module.fail_json(
                    msg="Public Key required for asymmetric vault.")


def main():
    ansible_module = AnsibleModule(
        argument_spec=dict(
            # generalgroups
            ipaadmin_principal=dict(type="str", default="admin"),
            ipaadmin_password=dict(type="str", required=False, no_log=True),

            name=dict(type="list", aliases=["cn"], default=None,
                      required=True),

            # present

            description=dict(required=False, type="str", default=None),
            vault_type=dict(type="str", aliases=["ipavaulttype"],
                            default=None, required=False,
                            choices=["standard", "symmetric", "asymmetric"]),
            vault_public_key=dict(type="str", required=False, default=None,
                                  aliases=['ipavaultpublickey']),
            vault_salt=dict(type="str", required=False, default=None,
                            aliases=['ipavaultsalt']),
            username=dict(type="str", required=False, default=None,
                          aliases=['user']),
            service=dict(type="str", required=False, default=None),
            shared=dict(type="bool", required=False, default=None),

            users=dict(required=False, type='list', default=None),
            groups=dict(required=False, type='list', default=None),
            owners=dict(required=False, type='list', default=None),
            ownergroups=dict(required=False, type='list', default=None),

            vault_data=dict(type="str", required=False, default=None,
                            aliases=['ipavaultdata']),
            vault_password=dict(type="str", required=False, default=None,
                                no_log=True, aliases=['ipavaultpassword']),

            # state
            action=dict(type="str", default="vault",
                        choices=["vault", "data", "member"]),
            state=dict(type="str", default="present",
                       choices=["present", "absent"]),
        ),
        supports_check_mode=True,
        mutually_exclusive=[['username', 'service', 'shared']],
        required_one_of=[['username', 'service', 'shared']]
    )

    ansible_module._ansible_debug = True

    # general
    ipaadmin_principal = module_params_get(ansible_module,
                                           "ipaadmin_principal")
    ipaadmin_password = module_params_get(ansible_module, "ipaadmin_password")
    names = module_params_get(ansible_module, "name")

    # present
    description = module_params_get(ansible_module, "description")

    username = module_params_get(ansible_module, "username")
    service = module_params_get(ansible_module, "service")
    shared = module_params_get(ansible_module, "shared")

    users = module_params_get(ansible_module, "users")
    groups = module_params_get(ansible_module, "groups")
    owners = module_params_get(ansible_module, "owners")
    ownergroups = module_params_get(ansible_module, "ownergroups")

    vault_type = module_params_get(ansible_module, "vault_type")
    salt = module_params_get(ansible_module, "vault_salt")
    password = module_params_get(ansible_module, "vault_password")
    public_key = module_params_get(ansible_module, "vault_public_key")

    vault_data = module_params_get(ansible_module, "vault_data")

    action = module_params_get(ansible_module, "action")
    # state
    state = module_params_get(ansible_module, "state")

    # Check parameters

    if state == "present":
        if len(names) != 1:
            ansible_module.fail_json(
                msg="Only one vault can be added at a time.")

    elif state == "absent":
        if len(names) < 1:
            ansible_module.fail_json(msg="No name given.")

    else:
        ansible_module.fail_json(msg="Invalid state '%s'" % state)

    check_parameters(ansible_module, state, action, description, username,
                     service, shared, users, groups, owners, ownergroups,
                     vault_type, salt, password, public_key, vault_data)
    # Init

    changed = False
    exit_args = {}
    ccache_dir = None
    ccache_name = None
    try:
        if not valid_creds(ansible_module, ipaadmin_principal):
            ccache_dir, ccache_name = temp_kinit(ipaadmin_principal,
                                                 ipaadmin_password)

        api_connect(context='ansible-freeipa')

        commands = []

        for name in names:
            # Make sure vault exists
            res_find = find_vault(
                ansible_module, name, username, service, shared)

            # Generate args
            args = gen_args(description, username, service, shared, vault_type,
                            salt, public_key, vault_data)

            # Set default vault_type if needed.
            if vault_type is None and vault_data is not None:
                if res_find is not None:
                    res_vault_type = res_find.get('ipavaulttype')[0]
                    args['ipavaulttype'] = vault_type = res_vault_type
                else:
                    args['ipavaulttype'] = vault_type = "symmetric"

            # verify data encription args
            check_encryption_params(ansible_module, state, vault_type,
                                    password, public_key, vault_data, res_find)

            # Create command
            if state == "present":

                # Found the vault
                if action == "vault":
                    if res_find is not None:
                        # For all settings is args, check if there are
                        # different settings in the find result.
                        # If yes: modify
                        if not compare_args_ipa(ansible_module, args,
                                                res_find):
                            commands.append([name, "vault_mod_internal", args])
                    else:
                        if 'ipavaultsault' not in args:
                            args['ipavaultsalt'] = os.urandom(32)
                        commands.append([name, "vault_add_internal", args])
                        # archive empty data to set password
                        pwdargs = data_storage_args(
                            args, args.get('data', ''), password)
                        commands.append([name, "vault_archive", pwdargs])

                        # Set res_find to empty dict for next step  # noqa
                        res_find = {}

                    # Generate adittion and removal lists
                    user_add, user_del = \
                        gen_add_del_lists(users,
                                          res_find.get('member_user', []))
                    group_add, group_del = \
                        gen_add_del_lists(groups,
                                          res_find.get('member_group', []))
                    owner_add, owner_del = \
                        gen_add_del_lists(owners,
                                          res_find.get('owner_user', []))
                    ownergroups_add, ownergroups_del = \
                        gen_add_del_lists(ownergroups,
                                          res_find.get('owner_group', []))

                    # Add users and groups
                    if len(user_add) > 0 or len(group_add) > 0:
                        user_add_args = gen_member_args(args, user_add,
                                                        group_add)
                        commands.append([name, 'vault_add_member',
                                         user_add_args])

                    # Remove users and groups
                    if len(user_del) > 0 or len(group_del) > 0:
                        user_del_args = gen_member_args(args, user_del,
                                                        group_del)
                        commands.append([name, 'vault_remove_member',
                                         user_del_args])

                    # Add owner users and groups
                    if len(user_add) > 0 or len(group_add) > 0:
                        owner_add_args = gen_member_args(args, owner_add,
                                                         ownergroups_add)
                        commands.append([name, 'vault_add_owner',
                                         owner_add_args])

                    # Remove owner users and groups
                    if len(user_del) > 0 or len(group_del) > 0:
                        owner_del_args = gen_member_args(args, owner_del,
                                                         ownergroups_del)
                        commands.append([name, 'vault_remove_owner',
                                         owner_del_args])

                elif action in "member":
                    # Add users and groups
                    if users is not None or groups is not None:
                        user_args = gen_member_args(args, users, groups)
                        commands.append([name, 'vault_add_member', user_args])
                    if owners is not None or ownergroups is not None:
                        owner_args = gen_member_args(args, owners, ownergroups)
                        commands.append([name, 'vault_add_owner', owner_args])

                    if vault_data is not None:
                        data_args = data_storage_args(
                            args, args.get('data', ''), password)
                        commands.append([name, 'vault_archive', data_args])

            elif state == "absent":
                if 'ipavaulttype' in args:
                    del args['ipavaulttype']

                if action == "vault":
                    if res_find is not None:
                        commands.append([name, "vault_del", args])

                elif action == "member":
                    # remove users and groups
                    if users is not None or groups is not None:
                        user_args = gen_member_args(args, users, groups)
                        commands.append([name, 'vault_remove_member',
                                         user_args])

                    if owners is not None or ownergroups is not None:
                        owner_args = gen_member_args(args, owners, ownergroups)
                        commands.append([name, 'vault_remove_owner',
                                         owner_args])
                else:
                    ansible_module.fail_json(
                        msg="Invalid action '%s' for state '%s'" %
                        (action, state))
            else:
                ansible_module.fail_json(msg="Unkown state '%s'" % state)

        # Execute commands

        errors = []
        for name, command, args in commands:
            try:
                result = api_command(ansible_module, command, name, args)

                if command == 'vault_archive':
                    changed = 'Archived data into' in result['summary']
                else:
                    if "completed" in result:
                        if result["completed"] > 0:
                            changed = True
                    else:
                        changed = True
            except EmptyModlist:
                result = {}
            except Exception as exception:
                ansible_module.fail_json(
                    msg="%s: %s: %s" % (command, name, str(exception)))

            # Get all errors
            # All "already a member" and "not a member" failures in the
            # result are ignored. All others are reported.
            if "failed" in result and len(result["failed"]) > 0:
                for item in result["failed"]:
                    failed_item = result["failed"][item]
                    for member_type in failed_item:
                        for member, failure in failed_item[member_type]:
                            if "already a member" in failure \
                               or "not a member" in failure:
                                continue
                            errors.append("%s: %s %s: %s" % (
                                command, member_type, member, failure))
        if len(errors) > 0:
            ansible_module.fail_json(msg=", ".join(errors))

    except Exception as exception:
        ansible_module.fail_json(msg=str(exception))

    finally:
        temp_kdestroy(ccache_dir, ccache_name)

    # Done
    ansible_module.exit_json(changed=changed, **exit_args)


if __name__ == "__main__":
    main()

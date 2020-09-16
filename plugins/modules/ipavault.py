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
  public_key:
    description: Base64 encode public key.
    required: false
    type: string
    aliases: ["ipavaultpublickey", "vault_public_key"]
  public_key_file:
    description: Path to file with public key.
    required: false
    type: string
    aliases: ["vault_public_key_file"]
  private_key:
    description: Base64 encode private key.
    required: false
    type: string
    aliases: ["ipavaultprivatekey", "vault_private_key"]
  private_key_file:
    description: Path to file with private key.
    required: false
    type: string
    aliases: ["vault_private_key_file"]
  password:
    description: password to be used on symmetric vault.
    required: false
    type: string
    aliases: ["ipavaultpassword", "vault_password", "old_password"]
  password_file:
    description: file with password to be used on symmetric vault.
    required: false
    type: string
    aliases: ["vault_password_file", "old_password_file"]
  new_password:
    description: new password to be used on symmetric vault.
    required: false
    type: string
  new_password_file:
    description: file with new password to be used on symmetric vault.
    required: false
    type: string
  salt:
    description: Vault salt.
    required: false
    type: list
    aliases: ["ipavaultsalt", "vault_salt"]
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
  users:
    description: Users that are member of the vault.
    required: false
    type: list
  groups:
    description: Groups that are member of the vault.
    required: false
    type: list
  owners:
    description: Users that are owners of the vault.
    required: false
    type: list
  ownergroups:
    description: Groups that are owners of the vault.
    required: false
    type: list
  ownerservices:
    description: Services that are owners of the vault.
    required: false
    type: list
  services:
    description: Services that are member of the container.
    required: false
    type: list
  data:
    description: Data to be stored in the vault.
    required: false
    type: string
    aliases: ["ipavaultdata", "vault_data"]
  in:
    description: Path to file with data to be stored in the vault.
    required: false
    type: string
    aliases: ["datafile_in"]
  out:
    description: Path to file to store data retrieved from the vault.
    required: false
    type: string
    aliases: ["datafile_out"]
  action:
    description: Work on vault or member level.
    default: vault
    choices: ["vault", "member"]
  state:
    description: State to ensure
    default: present
    choices: ["present", "absent", "retrieved"]
author:
    - Rafael Jeffman
"""

EXAMPLES = """
# Ensure vault symvault is present
- ipavault:
    ipaadmin_password: SomeADMINpassword
    name: symvault
    username: admin
    vault_type: symmetric
    password: SomeVAULTpassword
    salt: MTIzNDU2Nzg5MAo=

# Ensure group ipausers is a vault member.
- ipavault:
    ipaadmin_password: SomeADMINpassword
    name: symvault
    username: admin
    groups: ipausers
    action: member

# Ensure group ipausers is not a vault member.
- ipavault:
    ipaadmin_password: SomeADMINpassword
    name: symvault
    username: admin
    groups: ipausers
    action: member
    state: absent

# Ensure vault users are present.
- ipavault:
    ipaadmin_password: SomeADMINpassword
    name: symvault
    username: admin
    users:
    - user01
    - user02
    action: member

# Ensure vault users are absent.
- ipavault:
    ipaadmin_password: SomeADMINpassword
    name: symvault
    username: admin
    users:
    - user01
    - user02
    action: member
    status: absent

# Ensure user owns vault.
- ipavault:
    ipaadmin_password: SomeADMINpassword
    name: symvault
    username: admin
    action: member
    owners: user01

# Ensure user does not own vault.
- ipavault:
    ipaadmin_password: SomeADMINpassword
    name: symvault
    username: admin
    owners: user01
    action: member
    status: absent

# Ensure data is archived to a symmetric vault
- ipavault:
    ipaadmin_password: SomeADMINpassword
    name: symvault
    username: admin
    password: SomeVAULTpassword
    data: >
      Data archived.
      More data archived.
    action: member

# Retrieve data archived from a symmetric vault
- ipavault:
    ipaadmin_password: SomeADMINpassword
    name: symvault
    username: admin
    password: SomeVAULTpassword
    state: retrieved
  register: result
- debug:
    msg: "{{ result.vault.data }}"

# Change password of a symmetric vault
- ipavault:
    ipaadmin_password: SomeADMINpassword
    name: symvault
    username: admin
    old_password: SomeVAULTpassword
    new_password: SomeNEWpassword

# Ensure vault symvault is absent
- ipavault:
    ipaadmin_password: SomeADMINpassword
    name: symvault
    user: admin
    state: absent

# Ensure asymmetric vault is present.
- ipavault:
    ipaadmin_password: SomeADMINpassword
    name: asymvault
    username: user01
    description: An asymmetric vault
    vault_type: asymmetric
    public_key: |
      LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlHZk1BMEdDU3FHU0liM0RRRUJBUVVBQTR
      HTkFEQ0JpUUtCZ1FDdGFudjRkK3ptSTZ0T3ova1RXdGowY3AxRAowUENoYy8vR0pJMTUzTi
      9CN3UrN0h3SXlRVlZoNUlXZG1UcCtkWXYzd09yeVpPbzYvbHN5eFJaZ2pZRDRwQ3VGCjlxM
      295VTFEMnFOZERYeGtSaFFETXBiUEVSWWlHbE1jbzdhN0hIVDk1bGNQbmhObVFkb3VGdHlV
      bFBUVS96V1kKZldYWTBOeU1UbUtoeFRseUV3SURBUUFCCi0tLS0tRU5EIFBVQkxJQyBLRVk
      tLS0tLQo=

# Ensure data is archived in an asymmetric vault
- ipavault:
    ipaadmin_password: SomeADMINpassword
    name: asymvault
    username: admin
    data: >
      Data archived.
      More data archived.
    action: member

# Retrive data archived in an asymmetric vault, using a private key file.
- ipavault:
    ipaadmin_password: SomeADMINpassword
    name: asymvault
    username: admin
    private_key_file: private.pem
    state: retrieved

# Ensure asymmetric vault is absent.
- ipavault:
    ipaadmin_password: SomeADMINpassword
    name: asymvault
    username: user01
    vault_type: asymmetric
    state: absent
"""

RETURN = """
vault:
  description: Vault dict with archived data.
  returned: If state is `retrieved`.
  type: dict
  options:
    data:
      description: The vault data.
      returned: always
      type: string
"""

import os
from base64 import b64decode
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
             password, password_file, public_key, public_key_file, vault_data,
             datafile_in, datafile_out):
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
        _args['ipavaultpublickey'] = b64decode(public_key.encode('utf-8'))
    if public_key_file is not None:
        with open(public_key_file, 'r') as keyfile:
            keydata = keyfile.read()
            _args['ipavaultpublickey'] = keydata.strip().encode('utf-8')

    return _args


def gen_member_args(args, users, groups, services):
    _args = args.copy()

    for arg in ['ipavaulttype', 'description', 'ipavaultpublickey',
                'ipavaultsalt']:
        if arg in _args:
            del _args[arg]

    if any([users, groups, services]):
        if users is not None:
            _args['user'] = users
        if groups is not None:
            _args['group'] = groups
        if services is not None:
            _args['services'] = services

        return _args

    return None


def data_storage_args(args, data, password, password_file, private_key,
                      private_key_file, datafile_in, datafile_out):
    _args = {}

    if 'username' in args:
        _args['username'] = args['username']
    if 'service' in args:
        _args['service'] = args['service']
    if 'shared' in args:
        _args['shared'] = args['shared']

    if password is not None:
        _args['password'] = password
    if password_file is not None:
        _args['password_file'] = password_file

    if private_key is not None:
        _args['private_key'] = private_key
    if private_key_file is not None:
        _args['private_key_file'] = private_key_file

    if datafile_in is not None:
        _args['in'] = datafile_in
    else:
        if data is None:
            _args['data'] = b''
        else:
            _args['data'] = data.encode('utf-8')

    if datafile_out is not None:
        _args['out'] = datafile_out

    if private_key_file is not None:
        _args['private_key_file'] = private_key_file

    return _args


def check_parameters(module, state, action, description, username, service,
                     shared, users, groups, services, owners, ownergroups,
                     ownerservices, vault_type, salt, password, password_file,
                     public_key, public_key_file, private_key,
                     private_key_file, vault_data, datafile_in, datafile_out,
                     new_password, new_password_file):
    invalid = []
    if state == "present":
        invalid = ['private_key', 'private_key_file', 'datafile_out']

        if all([password, password_file]) \
           or all([new_password, new_password_file]):
            module.fail_json(msg="Password specified multiple times.")

        if any([new_password, new_password_file]) \
           and not any([password, password_file]):
            module.fail_json(
                msg="Either `password` or `password_file` must be provided to "
                    "change symmetric vault password.")

        if action == "member":
            invalid.extend(['description'])

    elif state == "absent":
        invalid = ['description', 'salt', 'vault_type', 'private_key',
                   'private_key_file', 'datafile_in', 'datafile_out',
                   'vault_data', 'new_password', 'new_password_file']

        if action == "vault":
            invalid.extend(['users', 'groups', 'services', 'owners',
                            'ownergroups', 'ownerservices', 'password',
                            'password_file', 'public_key', 'public_key_file'])

    elif state == "retrieved":
        invalid = ['description', 'salt', 'datafile_in', 'users', 'groups',
                   'owners', 'ownergroups', 'public_key', 'public_key_file',
                   'vault_data', 'new_password', 'new_password_file']
        if action == 'member':
            module.fail_json(
                msg="State `retrieved` do not support action `member`.")

    for arg in invalid:
        if vars()[arg] is not None:
            module.fail_json(
                msg="Argument '%s' can not be used with state '%s', "
                    "action '%s'" % (arg, state, action))

    for arg in invalid:
        if vars()[arg] is not None:
            module.fail_json(
                msg="Argument '%s' can not be used with state '%s', "
                    "action '%s'" % (arg, state, action))


def check_encryption_params(module, state, action, vault_type, salt,
                            password, password_file, public_key,
                            public_key_file, private_key, private_key_file,
                            vault_data, datafile_in, datafile_out,
                            new_password, new_password_file, res_find):
    vault_type_invalid = []

    if vault_type is None and res_find is not None:
        vault_type = res_find['ipavaulttype']
        if isinstance(vault_type, (tuple, list)):
            vault_type = vault_type[0]

    if vault_type == "standard":
        vault_type_invalid = ['public_key', 'public_key_file', 'password',
                              'password_file', 'salt', 'new_password',
                              'new_password_file']

    if vault_type is None or vault_type == "symmetric":
        vault_type_invalid = ['public_key', 'public_key_file',
                              'private_key', 'private_key_file']

        if password is None and password_file is None and action != 'member':
            module.fail_json(
                msg="Symmetric vault requires password or password_file "
                    "to store data or change `salt`.")

        if any([new_password, new_password_file]) and res_find is None:
            module.fail_json(
                msg="Cannot modify password of inexistent vault.")

        if (
            salt is not None
            and not(
                any([password, password_file])
                and any([new_password, new_password_file])
            )
        ):
            module.fail_json(
                msg="Vault `salt` can only change when changing the password.")

    if vault_type == "asymmetric":
        vault_type_invalid = [
            'password', 'password_file', 'new_password', 'new_password_file'
        ]
        if not any([public_key, public_key_file]) and res_find is None:
            module.fail_json(
                msg="Assymmetric vault requires public_key "
                    "or public_key_file to store data.")

    for param in vault_type_invalid:
        if vars()[param] is not None:
            module.fail_json(
                msg="Argument '%s' cannot be used with vault type '%s'" %
                (param, vault_type or 'symmetric'))


def change_password(module, res_find, password, password_file, new_password,
                    new_password_file):
    """
    Change the password of a symmetric vault.

    To change the password of a vault, it is needed to retrieve the stored
    data with the current password, and store the data again, with the new
    password, forcing it to override the old one.
    """
    # verify parameters.
    if not any([new_password, new_password_file]):
        return []
    if res_find["ipavaulttype"][0] != "symmetric":
        module.fail_json(msg="Cannot change password of `%s` vault."
                             % res_find["ipavaulttype"])

    # prepare arguments to retrieve data.
    name = res_find["cn"][0]
    args = {}
    if password:
        args["password"] = password
    if password_file:
        args["password_file"] = password_file
    # retrieve current stored data
    result = api_command(module, 'vault_retrieve', name, args)

    # modify arguments to store data with new password.
    args = {"override_password": True, "data": result['result']['data']}
    if new_password:
        args["password"] = new_password
    if new_password_file:
        args["password_file"] = new_password_file
    # return the command to store data with the new password.
    return [(name, "vault_archive", args)]


def main():
    ansible_module = AnsibleModule(
        argument_spec=dict(
            # generalgroups
            ipaadmin_principal=dict(type="str", default="admin"),
            ipaadmin_password=dict(type="str", required=False, no_log=True),

            name=dict(type="list", aliases=["cn"], default=None,
                      required=True),

            description=dict(required=False, type="str", default=None),
            vault_type=dict(type="str", aliases=["ipavaulttype"],
                            default=None, required=False,
                            choices=["standard", "symmetric", "asymmetric"]),
            vault_public_key=dict(type="str", required=False, default=None,
                                  aliases=['ipavaultpublickey', 'public_key']),
            vault_public_key_file=dict(type="str", required=False,
                                       default=None,
                                       aliases=['public_key_file']),
            vault_private_key=dict(
                type="str", required=False, default=None, no_log=True,
                aliases=['ipavaultprivatekey', 'private_key']),
            vault_private_key_file=dict(type="str", required=False,
                                        default=None,
                                        aliases=['private_key_file']),
            vault_salt=dict(type="str", required=False, default=None,
                            aliases=['ipavaultsalt', 'salt']),
            username=dict(type="str", required=False, default=None,
                          aliases=['user']),
            service=dict(type="str", required=False, default=None),
            shared=dict(type="bool", required=False, default=None),

            users=dict(required=False, type='list', default=None),
            groups=dict(required=False, type='list', default=None),
            services=dict(required=False, type='list', default=None),
            owners=dict(required=False, type='list', default=None,
                        aliases=['ownerusers']),
            ownergroups=dict(required=False, type='list', default=None),
            ownerservices=dict(required=False, type='list', default=None),
            vault_data=dict(type="str", required=False, default=None,
                            no_log=True, aliases=['ipavaultdata', 'data']),
            datafile_in=dict(type="str", required=False, default=None,
                             aliases=['in']),
            datafile_out=dict(type="str", required=False, default=None,
                              aliases=['out']),
            vault_password=dict(type="str", required=False, default=None,
                                no_log=True,
                                aliases=['ipavaultpassword', 'password',
                                         "old_password"]),
            vault_password_file=dict(type="str", required=False, default=None,
                                     no_log=False,
                                     aliases=[
                                        'password_file', "old_password_file"
                                     ]),
            new_password=dict(type="str", required=False, default=None,
                              no_log=True),
            new_password_file=dict(type="str", required=False, default=None,
                                   no_log=False),
            # state
            action=dict(type="str", default="vault",
                        choices=["vault", "data", "member"]),
            state=dict(type="str", default="present",
                       choices=["present", "absent", "retrieved"]),
        ),
        supports_check_mode=True,
        mutually_exclusive=[['username', 'service', 'shared'],
                            ['datafile_in', 'vault_data'],
                            ['new_password', 'new_password_file'],
                            ['vault_password', 'vault_password_file'],
                            ['vault_public_key', 'vault_public_key_file']],
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
    services = module_params_get(ansible_module, "services")
    owners = module_params_get(ansible_module, "owners")
    ownergroups = module_params_get(ansible_module, "ownergroups")
    ownerservices = module_params_get(ansible_module, "ownerservices")

    vault_type = module_params_get(ansible_module, "vault_type")
    salt = module_params_get(ansible_module, "vault_salt")
    password = module_params_get(ansible_module, "vault_password")
    password_file = module_params_get(ansible_module, "vault_password_file")
    new_password = module_params_get(ansible_module, "new_password")
    new_password_file = module_params_get(ansible_module, "new_password_file")
    public_key = module_params_get(ansible_module, "vault_public_key")
    public_key_file = module_params_get(ansible_module,
                                        "vault_public_key_file")
    private_key = module_params_get(ansible_module, "vault_private_key")
    private_key_file = module_params_get(ansible_module,
                                         "vault_private_key_file")

    vault_data = module_params_get(ansible_module, "vault_data")

    datafile_in = module_params_get(ansible_module, "datafile_in")
    datafile_out = module_params_get(ansible_module, "datafile_out")

    action = module_params_get(ansible_module, "action")
    state = module_params_get(ansible_module, "state")

    # Check parameters

    if state == "present":
        if len(names) != 1:
            ansible_module.fail_json(
                msg="Only one vault can be added at a time.")

    elif state == "absent":
        if len(names) < 1:
            ansible_module.fail_json(msg="No name given.")

    elif state == "retrieved":
        if len(names) != 1:
            ansible_module.fail_json(
                msg="Only one vault can be retrieved at a time.")

    else:
        ansible_module.fail_json(msg="Invalid state '%s'" % state)

    check_parameters(ansible_module, state, action, description, username,
                     service, shared, users, groups, services, owners,
                     ownergroups, ownerservices, vault_type, salt, password,
                     password_file, public_key, public_key_file, private_key,
                     private_key_file, vault_data, datafile_in, datafile_out,
                     new_password, new_password_file)
    # Init

    changed = False
    exit_args = {}
    ccache_dir = None
    ccache_name = None
    try:
        if not valid_creds(ansible_module, ipaadmin_principal):
            ccache_dir, ccache_name = temp_kinit(ipaadmin_principal,
                                                 ipaadmin_password)
            # Need to set krb5 ccache name, due to context='ansible-freeipa'
            if ccache_name is not None:
                os.environ["KRB5CCNAME"] = ccache_name

        api_connect(context='ansible-freeipa')

        commands = []

        for name in names:
            # Make sure vault exists
            res_find = find_vault(
                ansible_module, name, username, service, shared)

            # Generate args
            args = gen_args(description, username, service, shared, vault_type,
                            salt, password, password_file, public_key,
                            public_key_file, vault_data, datafile_in,
                            datafile_out)
            pwdargs = None

            # Set default vault_type if needed.
            if vault_type is None and vault_data is not None:
                if res_find is not None:
                    res_vault_type = res_find.get('ipavaulttype')[0]
                    args['ipavaulttype'] = vault_type = res_vault_type
                else:
                    args['ipavaulttype'] = vault_type = u"symmetric"

            # Create command
            if state == "present":
                # verify data encription args
                check_encryption_params(
                    ansible_module, state, action, vault_type, salt, password,
                    password_file, public_key, public_key_file, private_key,
                    private_key_file, vault_data, datafile_in, datafile_out,
                    new_password, new_password_file, res_find)

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
                        if vault_type == 'symmetric' \
                           and 'ipavaultsalt' not in args:
                            args['ipavaultsalt'] = os.urandom(32)

                        commands.append([name, "vault_add_internal", args])

                        if vault_type != 'standard' and vault_data is None:
                            vault_data = ''

                        # Set res_find to empty dict for next steps
                        res_find = {}

                    # Generate adittion and removal lists
                    user_add, user_del = \
                        gen_add_del_lists(users,
                                          res_find.get('member_user', []))
                    group_add, group_del = \
                        gen_add_del_lists(groups,
                                          res_find.get('member_group', []))
                    service_add, service_del = \
                        gen_add_del_lists(services,
                                          res_find.get('member_service', []))

                    owner_add, owner_del = \
                        gen_add_del_lists(owners,
                                          res_find.get('owner_user', []))

                    ownergroups_add, ownergroups_del = \
                        gen_add_del_lists(ownergroups,
                                          res_find.get('owner_group', []))

                    ownerservice_add, ownerservice_del = \
                        gen_add_del_lists(ownerservices,
                                          res_find.get('owner_service', []))

                    # Add users and groups
                    user_add_args = gen_member_args(args, user_add,
                                                    group_add, service_add)
                    if user_add_args is not None:
                        commands.append(
                            [name, 'vault_add_member', user_add_args])

                    # Remove users and groups
                    user_del_args = gen_member_args(args, user_del,
                                                    group_del, service_del)
                    if user_del_args is not None:
                        commands.append(
                            [name, 'vault_remove_member', user_del_args])

                    # Add owner users and groups
                    owner_add_args = gen_member_args(
                        args, owner_add, ownergroups_add, ownerservice_add)
                    if owner_add_args is not None:
                        commands.append(
                            [name, 'vault_add_owner', owner_add_args])

                    # Remove owner users and groups
                    owner_del_args = gen_member_args(
                        args, owner_del, ownergroups_del, ownerservice_del)
                    if owner_del_args is not None:
                        commands.append(
                            [name, 'vault_remove_owner', owner_del_args])

                elif action in "member":
                    # Add users and groups
                    if any([users, groups, services]):
                        user_args = gen_member_args(args, users, groups,
                                                    services)
                        commands.append([name, 'vault_add_member', user_args])
                    if any([owners, ownergroups, ownerservices]):
                        owner_args = gen_member_args(args, owners, ownergroups,
                                                     ownerservices)
                        commands.append([name, 'vault_add_owner', owner_args])

                pwdargs = data_storage_args(
                    args, vault_data, password, password_file, private_key,
                    private_key_file, datafile_in, datafile_out)
                if any([vault_data, datafile_in]):
                    commands.append([name, "vault_archive", pwdargs])

                cmds = change_password(
                    ansible_module, res_find, password, password_file,
                    new_password, new_password_file)
                commands.extend(cmds)

            elif state == "retrieved":
                if res_find is None:
                    ansible_module.fail_json(
                        msg="Vault `%s` not found to retrieve data." % name)

                # verify data encription args
                check_encryption_params(
                    ansible_module, state, action, vault_type, salt, password,
                    password_file, public_key, public_key_file, private_key,
                    private_key_file, vault_data, datafile_in, datafile_out,
                    new_password, new_password_file, res_find)

                pwdargs = data_storage_args(
                    args, vault_data, password, password_file, private_key,
                    private_key_file, datafile_in, datafile_out)
                if 'data' in pwdargs:
                    del pwdargs['data']

                commands.append([name, "vault_retrieve", pwdargs])

            elif state == "absent":
                if 'ipavaulttype' in args:
                    del args['ipavaulttype']

                if action == "vault":
                    if res_find is not None:
                        commands.append([name, "vault_del", args])

                elif action == "member":
                    # remove users and groups
                    if any([users, groups, services]):
                        user_args = gen_member_args(
                            args, users, groups, services)
                        commands.append(
                            [name, 'vault_remove_member', user_args])

                    if any([owners, ownergroups, ownerservices]):
                        owner_args = gen_member_args(
                            args, owners, ownergroups, ownerservices)
                        commands.append(
                            [name, 'vault_remove_owner', owner_args])
                else:
                    ansible_module.fail_json(
                        msg="Invalid action '%s' for state '%s'" %
                        (action, state))
            else:
                ansible_module.fail_json(msg="Unknown state '%s'" % state)

        # Execute commands

        errors = []
        for name, command, args in commands:
            try:
                result = api_command(ansible_module, command, name, args)

                if command == 'vault_archive':
                    changed = 'Archived data into' in result['summary']
                elif command == 'vault_retrieve':
                    if 'result' not in result:
                        raise Exception("No result obtained.")
                    if "data" in result["result"]:
                        data_return = exit_args.setdefault("vault", {})
                        data_return["data"] = result["result"]["data"]
                    else:
                        if not datafile_out:
                            raise Exception("No data retrieved.")
                    changed = False
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

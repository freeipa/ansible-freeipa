# -*- coding: utf-8 -*-

# Authors:
#   Rafael Guterres Jeffman <rjeffman@redhat.com>
#   Thomas Woerner <twoerner@redhat.com>
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
module: ipavault
short_description: Manage vaults and secret vaults.
description: Manage vaults and secret vaults. KRA service must be enabled.
extends_documentation_fragment:
  - ipamodule_base_docs
options:
  name:
    description: The vault name
    type: list
    elements: str
    required: true
    aliases: ["cn"]
  description:
    description: The vault description
    type: str
    required: false
  vault_public_key:
    description: Base64 encode public key.
    required: false
    type: str
    aliases: ["ipavaultpublickey", "public_key", "new_public_key"]
  vault_public_key_file:
    description: Path to file with public key.
    required: false
    type: str
    aliases: ["public_key_file", "new_public_key_file"]
  private_key:
    description: Base64 encode private key.
    required: false
    type: str
    aliases: ["ipavaultprivatekey", "vault_private_key"]
  private_key_file:
    description: Path to file with private key.
    required: false
    type: str
    aliases: ["vault_private_key_file"]
  password:
    description: password to be used on symmetric vault.
    required: false
    type: str
    aliases: ["ipavaultpassword", "vault_password", "old_password"]
  password_file:
    description: file with password to be used on symmetric vault.
    required: false
    type: str
    aliases: ["vault_password_file", "old_password_file"]
  new_password:
    description: new password to be used on symmetric vault.
    required: false
    type: str
  new_password_file:
    description: file with new password to be used on symmetric vault.
    required: false
    type: str
  vault_salt:
    description: Vault salt.
    required: false
    type: str
    aliases: ["ipavaultsalt", "salt"]
  vault_type:
    description: Vault types are based on security level.
    type: str
    required: false
    choices: ["standard", "symmetric", "asymmetric"]
    aliases: ["ipavaulttype"]
  service:
    description: Any service can own one or more service vaults.
    required: false
    type: str
  username:
    description: Any user can own one or more user vaults.
    required: false
    type: str
    aliases: ["user"]
  shared:
    description: Vault is shared.
    required: false
    type: bool
  users:
    description: Users that are member of the vault.
    required: false
    type: list
    elements: str
  groups:
    description: Groups that are member of the vault.
    required: false
    type: list
    elements: str
  owners:
    description: Users that are owners of the vault.
    required: false
    type: list
    elements: str
    aliases: ["ownerusers"]
  ownergroups:
    description: Groups that are owners of the vault.
    required: false
    type: list
    elements: str
  ownerservices:
    description: Services that are owners of the vault.
    required: false
    type: list
    elements: str
  services:
    description: Services that are member of the container.
    required: false
    type: list
    elements: str
  data:
    description: Data to be stored in the vault.
    required: false
    type: str
    aliases: ["ipavaultdata", "vault_data"]
  in:
    description: Path to file with data to be stored in the vault.
    required: false
    type: str
    aliases: ["datafile_in"]
  out:
    description: Path to file to store data retrieved from the vault.
    required: false
    type: str
    aliases: ["datafile_out"]
  action:
    description: Work on vault or member level.
    type: str
    default: vault
    choices: ["vault", "data", "member"]
  state:
    description: State to ensure
    type: str
    default: present
    choices: ["present", "absent", "retrieved"]
author:
  - Rafael Guterres Jeffman (@rjeffman)
  - Thomas Woerner (@t-woerner)
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
  contains:
    data:
      description: The vault data.
      returned: always
      type: str
"""

import os
from base64 import b64decode
from ansible.module_utils._text import to_text
from ansible.module_utils.ansible_freeipa_module import IPAAnsibleModule, \
    gen_add_del_lists, compare_args_ipa, exit_raw_json, ipalib_errors


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

    _result = module.ipa_command("vault_find", name, _args)

    if len(_result["result"]) > 1:
        module.fail_json(
            msg="There is more than one vault '%s'" % (name))
    if len(_result["result"]) == 1:
        return _result["result"][0]

    return None


def gen_args(
        description, username, service, shared, vault_type, salt,
        public_key, public_key_file):
    _args = {}
    vault_type = vault_type or to_text("symmetric")

    _args['ipavaulttype'] = vault_type
    if description is not None:
        _args['description'] = description
    if username is not None:
        _args['username'] = username
    if service is not None:
        _args['service'] = service
    if shared is not None:
        _args['shared'] = shared

    if vault_type == "symmetric":
        if salt is not None:
            _args['ipavaultsalt'] = salt
        _args['ipavaultpublickey'] = None

    elif vault_type == "asymmetric":
        if public_key is not None:
            _args['ipavaultpublickey'] = b64decode(public_key.encode('utf-8'))
        if public_key_file is not None:
            with open(public_key_file, 'r') as keyfile:
                keydata = keyfile.read()
                _args['ipavaultpublickey'] = keydata.strip().encode('utf-8')
        _args['ipavaultsalt'] = None

    elif vault_type == "standard":
        _args['ipavaultsalt'] = None
        _args['ipavaultpublickey'] = None

    return _args


def gen_member_args(args, users, groups, services):
    remove = ['ipavaulttype', 'description', 'ipavaultpublickey',
              'ipavaultsalt']
    _args = {k: v for k, v in args.items() if k not in remove}

    if any([users, groups, services]):
        if users is not None:
            _args['user'] = users
        if groups is not None:
            _args['group'] = groups
        if services is not None:
            _args['services'] = services

        return _args

    return None


def data_storage_args(vault_type, args, data, password, password_file,
                      private_key, private_key_file, datafile_in,
                      datafile_out):
    remove = ['ipavaulttype', 'description', 'ipavaultpublickey',
              'ipavaultsalt']
    _args = {k: v for k, v in args.items() if k not in remove}

    if 'username' in args:
        _args['username'] = args['username']
    if 'service' in args:
        _args['service'] = args['service']
    if 'shared' in args:
        _args['shared'] = args['shared']

    if vault_type is None or vault_type == "symmetric":
        if password is not None:
            _args['password'] = password
        if password_file is not None:
            _args['password_file'] = password_file

    if vault_type == "asymmetric":
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

    return _args


def check_parameters(  # pylint: disable=unused-argument
        module, state, action, description, username, service, shared, users,
        groups, services, owners, ownergroups, ownerservices, vault_type, salt,
        password, password_file, public_key, public_key_file, private_key,
        private_key_file, vault_data, datafile_in, datafile_out, new_password,
        new_password_file):
    if module.params_get("ipaapi_context") == "server":
        module.fail_json(
            msg="Context 'server' for ipavault not yet supported."
        )

    invalid = []
    if state == "present":
        invalid = ['datafile_out']

        if all([password, password_file]) \
           or all([new_password, new_password_file]):
            module.fail_json(msg="Password specified multiple times.")

        if any([new_password, new_password_file]) \
           and not any([password, password_file]):
            module.fail_json(
                msg="Either `password` or `password_file` must be provided to "
                    "change symmetric vault password.")

        if action == "member":
            invalid.extend(['description', 'vault_type'])

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

    module.params_fail_used_invalid(invalid, state, action)


def check_encryption_params(  # pylint: disable=unused-argument
        module, state, action, vault_type, salt, password, password_file,
        public_key, public_key_file, private_key, private_key_file, vault_data,
        datafile_in, datafile_out, new_password, new_password_file, res_find):
    """Check parameters used for (de)vault data encryption."""
    vault_type_invalid = []

    existing_type = None
    if res_find:
        existing_type = res_find["ipavaulttype"][0]

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
            and not (
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

    valid_fields = []
    if existing_type == "symmetric":
        valid_fields = [
            'password', 'password_file', 'new_password', 'new_password_file',
            'salt'
        ]
    if existing_type == "asymmetric":
        valid_fields = [
            'public_key', 'public_key_file', 'private_key', 'private_key_file'
        ]

    check_fields = [f for f in vault_type_invalid if f not in valid_fields]

    for param in check_fields:
        if vars()[param] is not None:
            module.fail_json(
                msg="Argument '%s' cannot be used with vault type '%s'" %
                (param, vault_type or 'symmetric'))


def get_stored_data(module, res_find, args):
    """Retrieve data stored in the vault."""
    # prepare arguments to retrieve data.
    name = res_find["cn"][0]
    copy_args = []
    if res_find['ipavaulttype'][0] == "symmetric":
        copy_args = ["password", "password_file"]
    if res_find['ipavaulttype'][0] == "asymmetric":
        copy_args = ["private_key", "private_key_file"]

    pwdargs = {arg: args[arg] for arg in copy_args if arg in args}

    # retrieve vault stored data
    try:
        result = module.ipa_command('vault_retrieve', name, pwdargs)
    except ipalib_errors.NotFound:
        return None

    return result['result'].get('data')


def main():
    ansible_module = IPAAnsibleModule(
        argument_spec=dict(
            # generalgroups
            name=dict(type="list", elements="str", aliases=["cn"],
                      required=True),

            description=dict(required=False, type="str", default=None),
            vault_type=dict(type="str", aliases=["ipavaulttype"],
                            default=None, required=False,
                            choices=["standard", "symmetric", "asymmetric"]),
            vault_public_key=dict(type="str", required=False, default=None,
                                  aliases=['ipavaultpublickey', 'public_key',
                                           'new_public_key']),
            vault_public_key_file=dict(type="str", required=False,
                                       default=None,
                                       aliases=['public_key_file',
                                                'new_public_key_file']),
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

            users=dict(required=False, type="list", elements="str",
                       default=None),
            groups=dict(required=False, type="list", elements="str",
                        default=None),
            services=dict(required=False, type="list", elements="str",
                          default=None),
            owners=dict(required=False, type="list", elements="str",
                        default=None,
                        aliases=['ownerusers']),
            ownergroups=dict(required=False, type="list", elements="str",
                             default=None),
            ownerservices=dict(required=False, type="list", elements="str",
                               default=None),
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
    names = ansible_module.params_get("name")

    # present
    description = ansible_module.params_get("description")

    username = ansible_module.params_get("username")
    service = ansible_module.params_get("service")
    shared = ansible_module.params_get("shared")

    users = ansible_module.params_get("users")
    groups = ansible_module.params_get("groups")
    services = ansible_module.params_get("services")
    owners = ansible_module.params_get("owners")
    ownergroups = ansible_module.params_get("ownergroups")
    ownerservices = ansible_module.params_get("ownerservices")

    vault_type = ansible_module.params_get("vault_type")
    salt = ansible_module.params_get("vault_salt")
    password = ansible_module.params_get("vault_password")
    password_file = ansible_module.params_get("vault_password_file")
    new_password = ansible_module.params_get("new_password")
    new_password_file = ansible_module.params_get("new_password_file")
    public_key = ansible_module.params_get("vault_public_key")
    public_key_file = ansible_module.params_get("vault_public_key_file")
    private_key = ansible_module.params_get("vault_private_key")
    private_key_file = ansible_module.params_get("vault_private_key_file")

    vault_data = ansible_module.params_get("vault_data")

    datafile_in = ansible_module.params_get("datafile_in")
    datafile_out = ansible_module.params_get("datafile_out")

    action = ansible_module.params_get("action")
    state = ansible_module.params_get("state")

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

    with ansible_module.ipa_connect(context="client") as ccache_name:
        if ccache_name is not None:
            os.environ["KRB5CCNAME"] = ccache_name

        commands = []

        for name in names:
            # Make sure vault exists
            res_find = find_vault(
                ansible_module, name, username, service, shared)

            # Set default vault_type if needed.
            res_type = res_find.get('ipavaulttype')[0] if res_find else None
            if vault_type is None:
                vault_type = res_type if res_find is not None else u"symmetric"

            # Generate args
            args = gen_args(description, username, service, shared, vault_type,
                            salt, public_key, public_key_file)
            pwdargs = None

            # Create command
            if state == "present":
                # verify data encription args
                check_encryption_params(
                    ansible_module, state, action, vault_type, salt, password,
                    password_file, public_key, public_key_file, private_key,
                    private_key_file, vault_data, datafile_in, datafile_out,
                    new_password, new_password_file, res_find)

                change_passwd = any([
                    new_password, new_password_file,
                    (private_key or private_key_file) and
                    (public_key or public_key_file)
                ])
                if action == "vault":
                    # Found the vault
                    if res_find is not None:
                        arg_type = args.get("ipavaulttype")

                        modified = not compare_args_ipa(ansible_module,
                                                        args, res_find)

                        if arg_type != res_type or change_passwd:
                            stargs = data_storage_args(
                                res_type, args, vault_data, password,
                                password_file, private_key,
                                private_key_file, datafile_in,
                                datafile_out)
                            stored = get_stored_data(
                                ansible_module, res_find, stargs
                            )
                            if stored:
                                vault_data = \
                                    (stored or b"").decode("utf-8")

                            remove_attrs = {
                                "symmetric": ["private_key", "public_key"],
                                "asymmetric": ["password", "ipavaultsalt"],
                                "standard": [
                                    "private_key", "public_key",
                                    "password", "ipavaultsalt"
                                ],
                            }
                            for attr in remove_attrs.get(arg_type, []):
                                if attr in args:
                                    del args[attr]

                            if vault_type == 'symmetric':
                                if 'ipavaultsalt' not in args:
                                    args['ipavaultsalt'] = os.urandom(32)
                            else:
                                args['ipavaultsalt'] = b''

                        if modified:
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

                if any([vault_data, datafile_in]):
                    if change_passwd:
                        pwdargs = data_storage_args(
                            vault_type, args, vault_data, new_password,
                            new_password_file, private_key, private_key_file,
                            datafile_in, datafile_out)
                    else:
                        pwdargs = data_storage_args(
                            vault_type, args, vault_data, password,
                            password_file, private_key, private_key_file,
                            datafile_in, datafile_out)

                    pwdargs['override_password'] = True
                    pwdargs.pop("private_key", None)
                    pwdargs.pop("private_key_file", None)
                    commands.append([name, "vault_archive", pwdargs])

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
                    res_find["ipavaulttype"][0], args, vault_data, password,
                    password_file, private_key, private_key_file, datafile_in,
                    datafile_out)
                if 'data' in pwdargs:
                    del pwdargs['data']

                commands.append([name, "vault_retrieve", pwdargs])

            elif state == "absent":
                if 'ipavaulttype' in args:
                    del args['ipavaulttype']

                if action == "vault":
                    if res_find is not None:
                        remove = ['ipavaultsalt', 'ipavaultpublickey']
                        args = {
                            k: v for k, v in args.items() if k not in remove
                        }
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

        # Check mode exit
        if ansible_module.check_mode:
            ansible_module.exit_json(changed=len(commands) > 0, **exit_args)

        # Execute commands

        errors = []
        for name, command, args in commands:
            try:
                result = ansible_module.ipa_command(command, name, args)

                if command == 'vault_archive':
                    changed = 'Archived data into' in result['summary']
                elif command == 'vault_retrieve':
                    if 'result' not in result:
                        # pylint: disable=W0012,broad-exception-raised
                        raise Exception("No result obtained.")
                    if "data" in result["result"]:
                        data_return = exit_args.setdefault("vault", {})
                        data_return["data"] = result["result"]["data"]
                    else:
                        if not datafile_out:
                            # pylint: disable=W0012,broad-exception-raised
                            raise Exception("No data retrieved.")
                    changed = False
                else:
                    if "completed" in result:
                        if result["completed"] > 0:
                            changed = True
                    else:
                        changed = True
            except ipalib_errors.EmptyModlist:
                result = {}
            except Exception as exception:  # pylint: disable=broad-except
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

    # Done

    # exit_raw_json is a replacement for ansible_module.exit_json that
    # does not mask the output.
    exit_raw_json(ansible_module, changed=changed, **exit_args)


if __name__ == "__main__":
    main()

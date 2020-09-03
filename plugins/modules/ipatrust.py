#!/usr/bin/python
# -*- coding: utf-8 -*-

# Authors:
#   Rob Verduijn <rob.verduijn@gmail.com>
#
# Copyright (C) 2019 By Rob Verduijn
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

from ansible.module_utils.ansible_freeipa_module import temp_kinit, \
    temp_kdestroy, valid_creds, api_connect, api_command, module_params_get
from ansible.module_utils.basic import AnsibleModule
ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'supported_by': 'community',
                    'status': ['preview'],
                    }

DOCUMENTATION = """
---
module: ipatrust
short_description: Manage FreeIPA Domain Trusts.
description: Manage FreeIPA Domain Trusts.
options:
  realm:
    description:
    - Realm name
    required: true
  trust_type:
    description:
    - Trust type (ad for Active Directory, default)
    default: ad
    required: true
  admin:
    description:
    - Active Directory domain administrator
    required: false
  password:
    description:
    - Active Directory domain administrator's password
    required: false
  server:
    description:
    - Domain controller for the Active Directory domain (optional)
    required: false
  trust_secret:
    description:
    - Shared secret for the trust
    required: false
  base_id:
    description:
    - First Posix ID of the range reserved for the trusted domain
    required: false
  range_size:
    description:
    - Size of the ID range reserved for the trusted domain
  range_type:
    description:
    - Type of trusted domain ID range, one of ipa-ad-trust, ipa-ad-trust-posix
    default: ipa-ad-trust
    required: false
  two_way:
    description:
    - Establish bi-directional trust. By default trust is inbound one-way only.
    default: false
    required: false
    choices: ["true", "false"]
  external:
    description:
    - Establish external trust to a domain in another forest.
    - The trust is not transitive beyond the domain.
    default: false
    required: false
    choices: ["true", "false"]
  state:
    description: State to ensure
    default: present
    required: true
    choices: ["present", "absent"]

author:
    - Rob Verduijn
"""

EXAMPLES = """
# add ad-trust
- ipatrust:
    realm: ad.example.test
    trust_type: ad
    admin: Administrator
    password: Welcome2020!
    state: present

# delete ad-trust
- ipatrust:
    realm: ad.example.test
    state: absent
"""

RETURN = """
"""


def find_trust(module, realm):
    _args = {
        "all": True,
        "cn": realm,
    }

    _result = api_command(module, "trust_find", realm, _args)

    if len(_result["result"]) > 1:
        module.fail_json(msg="There is more than one realm '%s'" % (realm))
    elif len(_result["result"]) == 1:
        return _result["result"][0]
    else:
        return None


def del_trust(module, realm):
    _args = {}

    _result = api_command(module, "trust_del", realm, _args)
    if len(_result["result"]["failed"]) > 0:
        module.fail_json(
            msg="Trust deletion has failed for '%s'" % (realm))
    else:
        return None


def add_trust(module, realm, args):
    _args = args

    _result = api_command(module, "trust_add", realm, _args)

    if "cn" not in _result["result"]:
        module.fail_json(
            msg="Trust add has failed for '%s'" % (realm))
    else:
        return None


def gen_args(trust_type, admin, password, server, trust_secret, base_id,
             range_size, range_type, two_way, external):
    _args = {}
    if trust_type is not None:
        _args["trust_type"] = trust_type
    if admin is not None:
        _args["realm_admin"] = admin
    if password is not None:
        _args["realm_passwd"] = password
    if server is not None:
        _args["realm_server"] = server
    if trust_secret is not None:
        _args["trust_secret"] = trust_secret
    if base_id is not None:
        _args["base_id"] = base_id
    if range_size is not None:
        _args["range_size"] = range_size
    if two_way is not None:
        _args["bidirectional"] = two_way
    if external is not None:
        _args["external"] = external

    return _args


def main():
    ansible_module = AnsibleModule(
        argument_spec=dict(
            # general
            ipaadmin_principal=dict(type="str", default="admin"),
            ipaadmin_password=dict(type="str", required=False, no_log=True),
            realm=dict(type="str", default=None, required=True),
            # state
            state=dict(type="str", default="present",
                       choices=["present", "absent"]),
            # present
            trust_type=dict(type="str", default="ad", required=False),
            admin=dict(type="str", default=None, required=False),
            password=dict(type="str", default=None,
                          required=False, no_log=True),
            server=dict(type="str", default=None, required=False),
            trust_secret=dict(type="str", default=None,
                              required=False, no_log=True),
            base_id=dict(type="int", default=None, required=False),
            range_size=dict(type="int", default=200000, required=False),
            range_type=dict(type="str", default="ipa-ad-trust",
                            required=False, choices=["ipa-ad-trust-posix",
                                                     "ipa-ad-trust"]),
            two_way=dict(type="bool", default=False, required=False),
            external=dict(type="bool", default=False, required=False),
        ),
        mutually_exclusive=[["trust_secret", "admin"]],
        required_together=[["admin", "password"]],
        supports_check_mode=True
    )

    ansible_module._ansible_debug = True

    # general
    ipaadmin_principal = module_params_get(
        ansible_module, "ipaadmin_principal")
    ipaadmin_password = module_params_get(ansible_module, "ipaadmin_password")
    realm = module_params_get(ansible_module, "realm")

    # state
    state = module_params_get(ansible_module, "state")

    # trust
    trust_type = module_params_get(ansible_module, "trust_type")
    admin = module_params_get(ansible_module, "admin")
    password = module_params_get(ansible_module, "password")
    server = module_params_get(ansible_module, "server")
    trust_secret = module_params_get(ansible_module, "trust_secret")
    base_id = module_params_get(ansible_module, "base_id")
    range_size = module_params_get(ansible_module, "range_size")
    range_type = module_params_get(ansible_module, "range_type")
    two_way = module_params_get(ansible_module, "two_way")
    external = module_params_get(ansible_module, "external")

    changed = False
    exit_args = {}
    ccache_dir = None
    ccache_name = None
    try:
        if not valid_creds(ansible_module, ipaadmin_principal):
            ccache_dir, ccache_name = temp_kinit(
                ipaadmin_principal, ipaadmin_password)
        api_connect()
        res_find = find_trust(ansible_module, realm)

        if state == "absent":
            if res_find is not None:
                del_trust(ansible_module, realm)
                changed = True
        elif res_find is None:
            if admin is None and trust_secret is None:
                ansible_module.fail_json(
                    msg="one of admin or trust_secret is required when state "
                        "is present")
            else:
                args = gen_args(trust_type, admin, password, server,
                                trust_secret, base_id, range_size, range_type,
                                two_way, external)

                add_trust(ansible_module, realm, args)
                changed = True

    except Exception as e:
        ansible_module.fail_json(msg=str(e))

    finally:
        temp_kdestroy(ccache_dir, ccache_name)

    # Done

    ansible_module.exit_json(changed=changed, **exit_args)


if __name__ == "__main__":
    main()

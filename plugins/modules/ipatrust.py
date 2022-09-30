# -*- coding: utf-8 -*-

# Authors:
#   Rob Verduijn <rob.verduijn@gmail.com>
#   Thomas Woerner <twoerner@redhat.com>
#
# Copyright (C) 2019-2022 By Rob Verduijn
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

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'supported_by': 'community',
                    'status': ['preview'],
                    }

DOCUMENTATION = """
---
module: ipatrust
short_description: Manage FreeIPA Domain Trusts.
description: Manage FreeIPA Domain Trusts.
extends_documentation_fragment:
  - ipamodule_base_docs
options:
  realm:
    description:
    - Realm name
    type: str
    required: true
  trust_type:
    description:
    - Trust type (ad for Active Directory, default)
    type: str
    default: ad
    required: false
    choices: ["ad"]
  admin:
    description:
    - Active Directory domain administrator
    type: str
    required: false
  password:
    description:
    - Active Directory domain administrator's password
    type: str
    required: false
  server:
    description:
    - Domain controller for the Active Directory domain (optional)
    type: str
    required: false
  trust_secret:
    description:
    - Shared secret for the trust
    type: str
    required: false
  base_id:
    description:
    - First Posix ID of the range reserved for the trusted domain
    type: int
    required: false
  range_size:
    description:
    - Size of the ID range reserved for the trusted domain
    type: int
    default: 200000
  range_type:
    description:
    - Type of trusted domain ID range, one of ipa-ad-trust, ipa-ad-trust-posix
    type: str
    choices: ["ipa-ad-trust-posix", "ipa-ad-trust"]
    default: ipa-ad-trust
    required: false
  two_way:
    description:
    - Establish bi-directional trust. By default trust is inbound one-way only.
    type: bool
    default: false
    required: false
  external:
    description:
    - Establish external trust to a domain in another forest.
    - The trust is not transitive beyond the domain.
    type: bool
    default: false
    required: false
  state:
    description: State to ensure
    type: str
    default: present
    required: false
    choices: ["present", "absent"]

author:
  - Rob Verduijn (@RobVerduijn)
  - Thomas Woerner (@t-woerner)
"""

EXAMPLES = """
# add ad-trust
- ipatrust:
    ipaadmin_password: SomeADMINpassword
    realm: ad.example.test
    trust_type: ad
    admin: Administrator
    password: SomeW1Npassword
    state: present

# delete ad-trust
- ipatrust:
    ipaadmin_password: SomeADMINpassword
    realm: ad.example.test
    state: absent
"""

RETURN = """
"""


from ansible.module_utils.ansible_freeipa_module import \
    IPAAnsibleModule


def find_trust(module, realm):
    _args = {
        "all": True,
        "cn": realm,
    }

    _result = module.ipa_command("trust_find", realm, _args)

    if len(_result["result"]) > 1:
        module.fail_json(msg="There is more than one realm '%s'" % (realm))
    elif len(_result["result"]) == 1:
        return _result["result"][0]

    return None


def del_trust(module, realm):
    _args = {}

    _result = module.ipa_command("trust_del", realm, _args)
    if len(_result["result"]["failed"]) > 0:
        module.fail_json(
            msg="Trust deletion has failed for '%s'" % (realm))


def add_trust(module, realm, args):
    _args = args

    _result = module.ipa_command("trust_add", realm, _args)

    if "cn" not in _result["result"]:
        module.fail_json(
            msg="Trust add has failed for '%s'" % (realm))


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
    if range_type is not None:
        _args["range_type"] = range_type
    if two_way is not None:
        _args["bidirectional"] = two_way
    if external is not None:
        _args["external"] = external

    return _args


def main():
    ansible_module = IPAAnsibleModule(
        argument_spec=dict(
            # general
            realm=dict(type="str", required=True),
            # state
            state=dict(type="str", default="present",
                       choices=["present", "absent"]),
            # present
            trust_type=dict(type="str", default="ad", required=False,
                            choices=["ad"]),
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
    realm = ansible_module.params_get("realm")

    # state
    state = ansible_module.params_get("state")

    # trust
    trust_type = ansible_module.params_get("trust_type")
    admin = ansible_module.params_get("admin")
    password = ansible_module.params_get("password")
    server = ansible_module.params_get("server")
    trust_secret = ansible_module.params_get("trust_secret")
    base_id = ansible_module.params_get("base_id")
    range_size = ansible_module.params_get("range_size")
    range_type = ansible_module.params_get("range_type")
    two_way = ansible_module.params_get("two_way")
    external = ansible_module.params_get("external")

    changed = False
    exit_args = {}

    # Connect to IPA API
    with ansible_module.ipa_connect():

        res_find = find_trust(ansible_module, realm)

        if state == "absent":
            if res_find is not None:
                if not ansible_module.check_mode:
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

                if not ansible_module.check_mode:
                    add_trust(ansible_module, realm, args)
                changed = True

    # Done

    ansible_module.exit_json(changed=changed, **exit_args)


if __name__ == "__main__":
    main()

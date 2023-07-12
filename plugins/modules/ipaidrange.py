# -*- coding: utf-8 -*-

# Authors:
#   Rafael Guterres Jeffman <rjeffman@redhat.com>
#   Thomas Woerner <twoerner@redhat.com>
#
# Copyright (C) 2022 Red Hat
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
module: ipaidrange
short_description: Manage FreeIPA idrange
description: Manage FreeIPA idrange
extends_documentation_fragment:
  - ipamodule_base_docs
  - ipamodule_base_docs.delete_continue
options:
  name:
    description: The list of idrange name strings.
    type: list
    elements: str
    required: true
    aliases: ["cn"]
  base_id:
    description: First Posix ID of the range.
    type: int
    required: false
    aliases: ["ipabaseid"]
  range_size:
    description: Number of IDs in the range.
    type: int
    required: false
    aliases: ["ipaidrangesize"]
  rid_base:
    description: First RID of the corresponding RID range.
    type: int
    required: false
    aliases: ["ipabaserid"]
  secondary_rid_base:
    description: First RID of the secondary RID range.
    type: int
    required: false
    aliases: ["ipasecondarybaserid"]
  idrange_type:
    description: ID range type.
    type: str
    required: false
    choices: ["ipa-ad-trust", "ipa-ad-trust-posix", "ipa-local"]
    aliases: ["iparangetype"]
  dom_sid:
    description: Domain SID of the trusted domain.
    type: str
    required: false
    aliases: ["ipanttrusteddomainsid"]
  dom_name:
    description: |
      Domain name of the trusted domain. Can only be used when
      `ipaapi_context: server`.
    type: str
    required: false
    aliases: ["ipanttrusteddomainname"]
  auto_private_groups:
    description: Auto creation of private groups.
    type: str
    required: false
    choices: ["true", "false", "hybrid"]
    aliases: ["ipaautoprivategroups"]
  state:
    description: The state to ensure.
    type: str
    choices: ["present", "absent"]
    default: present
    required: false
author:
  - Rafael Guterres Jeffman (@rjeffman)
  - Thomas Woerner (@t-woerner)
"""

EXAMPLES = """
# Ensure local domain idrange is present
- ipaidrange:
    ipaadmin_password: SomeADMINpassword
    name: id_range
    base_id: 150000000
    range_size: 200000
    rid_base: 1000000
    secondary_rid_base: 200000000

# Ensure local domain idrange is absent
- ipaidrange:
    ipaadmin_password: SomeADMINpassword
    name: id_range
    state: absent

# Ensure AD-trust idrange is present
- ipaidrange:
    name: id_range
    base_id: 150000000
    range_size: 200000
    rid_base: 1000000
    idrange_type: ipa-ad-trust
    dom_sid: S-1-5-21-2870384104-3340008087-3140804251
    auto_private_groups: "false"

# Ensure AD-trust idrange is present, with range type ad-trust-posix,
# and using domain name
- ipaidrange:
    name: id_range
    base_id: 150000000
    range_size: 200000
    rid_base: 1000000
    idrange_type: ipa-ad-trust-posix
    dom_name: ad.ipa.test
    auto_private_groups: "hybrid"
"""

RETURN = """
"""


from ansible.module_utils.ansible_freeipa_module import \
    IPAAnsibleModule, compare_args_ipa, get_trusted_domain_sid_from_name
from ansible.module_utils import six

if six.PY3:
    unicode = str


def find_idrange(module, name):
    """Find if a idrange with the given name already exist."""
    try:
        _result = module.ipa_command("idrange_show", name, {"all": True})
    except Exception:  # pylint: disable=broad-except
        # An exception is raised if idrange name is not found.
        return None
    return _result["result"]


def gen_args(
    base_id, range_size, rid_base, secondary_rid_base, idrange_type, dom_sid,
    dom_name, auto_private_groups
):
    _args = {}
    # Integer parameters are stored as strings.
    # Converting them here allows the proper use of compare_args_ipa.
    if base_id is not None:
        _args["ipabaseid"] = base_id
    if range_size is not None:
        _args["ipaidrangesize"] = range_size
    if rid_base is not None:
        _args["ipabaserid"] = rid_base
    if secondary_rid_base is not None:
        _args["ipasecondarybaserid"] = secondary_rid_base
    if idrange_type is not None:
        _args["iparangetype"] = idrange_type
    if dom_name is not None:
        dom_sid = get_trusted_domain_sid_from_name(dom_name)
    if dom_sid is not None:
        _args["ipanttrusteddomainsid"] = dom_sid
    if auto_private_groups is not None:
        _args["ipaautoprivategroups"] = auto_private_groups
    return _args


def main():
    ansible_module = IPAAnsibleModule(
        argument_spec=dict(
            # general
            name=dict(type="list", elements="str", aliases=["cn"],
                      required=True),
            # present
            base_id=dict(required=False, type='int',
                         aliases=["ipabaseid"], default=None),
            range_size=dict(required=False, type='int',
                            aliases=["ipaidrangesize"], default=None),
            rid_base=dict(required=False, type='int',
                          aliases=["ipabaserid"], default=None),
            secondary_rid_base=dict(required=False, type='int', default=None,
                                    aliases=["ipasecondarybaserid"]),
            idrange_type=dict(required=False, aliases=["iparangetype"],
                              type="str", default=None,
                              choices=["ipa-ad-trust", "ipa-ad-trust-posix",
                                       "ipa-local"]),
            dom_sid=dict(required=False, type='str', default=None,
                         aliases=["ipanttrusteddomainsid"]),
            dom_name=dict(required=False, type='str', default=None,
                          aliases=["ipanttrusteddomainname"]),
            auto_private_groups=dict(required=False, type='str', default=None,
                                     aliases=["ipaautoprivategroups"],
                                     choices=['true', 'false', 'hybrid']),
            # state
            state=dict(type="str", default="present",
                       choices=["present", "absent"]),
        ),
        mutually_exclusive=[
            ["dom_sid", "secondary_rid_base"],
            ["dom_name", "secondary_rid_base"],
            ["dom_sid", "dom_name"],
        ],
        supports_check_mode=True,
        ipa_module_options=["delete_continue"],
    )

    ansible_module._ansible_debug = True

    # Get parameters

    # general
    names = ansible_module.params_get("name")
    delete_continue = ansible_module.params_get("delete_continue")

    # present
    base_id = ansible_module.params_get("base_id")
    range_size = ansible_module.params_get("range_size")
    rid_base = ansible_module.params_get("rid_base")
    secondary_rid_base = ansible_module.params_get("secondary_rid_base")
    idrange_type = ansible_module.params_get("idrange_type")
    dom_sid = ansible_module.params_get("dom_sid")
    dom_name = ansible_module.params_get("dom_name")
    auto_private_groups = \
        ansible_module.params_get_lowercase("auto_private_groups")

    # state
    state = ansible_module.params_get("state")

    # Check parameters

    invalid = []

    if state == "present":
        if len(names) != 1:
            ansible_module.fail_json(
                msg="Only one idrange can be added at a time.")

    if state == "absent":
        if len(names) < 1:
            ansible_module.fail_json(msg="No name given.")
        invalid = [
            "base_id", "range_size", "idrange_type", "dom_sid", "dom_name",
            "rid_base", "secondary_rid_base", "auto_private_groups"
        ]

    ansible_module.params_fail_used_invalid(invalid, state)

    # Init

    changed = False
    exit_args = {}

    range_types = {
        "Active Directory domain range": "ipa-ad-trust",
        "Active Directory trust range with POSIX attributes":
            "ipa-ad-trust-posix",
        "local domain range": "ipa-local",
    }

    # Connect to IPA API
    with ansible_module.ipa_connect():

        commands = []
        for name in names:
            # Make sure idrange exists
            res_find = find_idrange(ansible_module, name)

            # Create command
            if state == "present":

                # Generate args
                args = gen_args(
                    base_id, range_size, rid_base, secondary_rid_base,
                    idrange_type, dom_sid, dom_name, auto_private_groups
                )

                # Found the idrange
                if res_find is not None:
                    # For all settings is args, check if there are
                    # different settings in the find result.
                    # If yes: modify
                    if not compare_args_ipa(
                        ansible_module, args, res_find, ignore=["iparangetype"]
                    ):
                        res_type = range_types.get(
                            res_find.get("iparangetype")[0]
                        )
                        if res_type == "local_id_range":
                            ansible_module.fail_json(
                                "Cannot modify local IPA domain idrange."
                            )

                        arg_type = args.get("iparangetype")
                        if arg_type:
                            if arg_type != res_type:
                                ansible_module.fail_json(
                                    "Cannot modify idrange type."
                                )
                            del args["iparangetype"]
                        commands.append([name, "idrange_mod", args])
                else:
                    commands.append([name, "idrange_add", args])

            elif state == "absent":
                if res_find is not None:
                    commands.append([
                        name,
                        "idrange_del",
                        {"continue": delete_continue or False}
                    ])

            else:
                ansible_module.fail_json(msg="Unkown state '%s'" % state)

        # Execute commands

        changed = ansible_module.execute_ipa_commands(commands)

    # Done

    ansible_module.exit_json(changed=changed, **exit_args)


if __name__ == "__main__":
    main()

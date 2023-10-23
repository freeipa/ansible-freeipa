# -*- coding: utf-8 -*-

# Authors:
#   Thomas Woerner <twoerner@redhat.com>
#
# Copyright (C) 2023 Red Hat
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
module: ipaidview
short_description: Manage FreeIPA idview
description: Manage FreeIPA idview and idview host members
extends_documentation_fragment:
  - ipamodule_base_docs
options:
  name:
    description: The list of idview name strings.
    required: true
    type: list
    elements: str
    aliases: ["cn"]
  description:
    description: Description
    required: False
    type: str
    aliases: ["desc"]
  domain_resolution_order:
    description: |
      Colon-separated list of domains used for short name qualification
    required: False
    type: str
    aliases: ["ipadomainresolutionorder"]
  host:
    description: Hosts to apply the ID View to
    required: False
    type: list
    elements: str
    aliases: ["hosts"]
  rename:
    description: Rename the ID view object
    required: False
    type: str
    aliases: ["new_name"]
  delete_continue:
    description: |
      Continuous mode. Don't stop on errors.
      Valid only if `state` is `absent`.
    required: false
    type: bool
    aliases: ["continue"]
  action:
    description: Work on idview or member level.
    choices: ["idview", "member"]
    default: idview
    type: str
  state:
    description: The state to ensure.
    choices: ["present", "absent", "renamed"]
    default: present
    type: str
author:
  - Thomas Woerner (@t-woerner)
"""

EXAMPLES = """
# Ensure idview test_idview is present
- ipaidview:
    ipaadmin_password: SomeADMINpassword
    name: test_idview

# name: Ensure host testhost.example.com is applied to idview test_idview
- ipaidview:
    ipaadmin_password: SomeADMINpassword
    name: test_idview
    host: testhost.example.com
    action: member

# Ensure host testhost.example.com is not applied to idview test_idview
- ipaidview:
    ipaadmin_password: SomeADMINpassword
    name: test_idview
    host: testhost.example.com
    action: member
    state: absent

# Ensure idview "test_idview" is present with domain_resolution_order for
# "ad.example.com:ipa.example.com"
- ipaidview:
    ipaadmin_password: SomeADMINpassword
    name: test_idview
    domain_resolution_order: "ad.example.com:ipa.example.com"

# Ensure idview test_idview is absent
- ipaidview:
    ipaadmin_password: SomeADMINpassword
    name: test_idview
    state: absent
"""

RETURN = """
"""


from ansible.module_utils.ansible_freeipa_module import \
    IPAAnsibleModule, compare_args_ipa, gen_add_del_lists, gen_add_list, \
    gen_intersection_list, ipalib_errors
from ansible.module_utils import six

if six.PY3:
    unicode = str


def find_idview(module, name):
    """Find if a idview with the given name already exist."""
    try:
        _result = module.ipa_command("idview_show", name, {"all": True})
    except Exception:  # pylint: disable=broad-except
        # An exception is raised if idview name is not found.
        return None
    return _result["result"]


def valid_host(module, name):
    try:
        module.ipa_command("host_show", name, {})
    except ipalib_errors.NotFound:
        return False
    return True


def gen_args(description, domain_resolution_order):
    _args = {}
    if description is not None:
        _args["description"] = description
    if domain_resolution_order is not None:
        _args["ipadomainresolutionorder"] = domain_resolution_order
    return _args


def gen_member_args(host):
    _args = {}
    if host is not None:
        _args["host"] = host
    return _args


def main():
    ansible_module = IPAAnsibleModule(
        argument_spec=dict(
            # general
            name=dict(type="list", elements="str", required=True,
                      aliases=["cn"]),
            # present
            description=dict(type="str", required=False, aliases=["desc"]),
            domain_resolution_order=dict(type="str", required=False,
                                         aliases=["ipadomainresolutionorder"]),
            host=dict(type="list", elements="str", required=False,
                      aliases=["hosts"], default=None),
            rename=dict(type="str", required=False, aliases=["new_name"]),
            delete_continue=dict(type="bool", required=False,
                                 aliases=['continue'], default=None),
            # action
            action=dict(type="str", default="idview",
                        choices=["member", "idview"]),
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
    description = ansible_module.params_get("description")
    domain_resolution_order = ansible_module.params_get(
        "domain_resolution_order")
    host = ansible_module.params_get("host")
    rename = ansible_module.params_get("rename")

    action = ansible_module.params_get("action")

    # absent
    delete_continue = ansible_module.params_get("delete_continue")

    # state
    state = ansible_module.params_get("state")

    # Check parameters

    invalid = []

    if state == "present":
        if len(names) != 1:
            ansible_module.fail_json(
                msg="Only one idview can be added at a time.")
        invalid = ["delete_continue", "rename"]
        if action == "member":
            invalid += ["description", "domain_resolution_order"]

    if state == "renamed":
        if len(names) != 1:
            ansible_module.fail_json(
                msg="Only one idoverridegroup can be renamed at a time.")
        if not rename:
            ansible_module.fail_json(
                msg="Rename is required for state: renamed.")
        if action == "member":
            ansible_module.fail_json(
                msg="Action member can not be used with state: renamed.")
        invalid = ["description", "domain_resolution_order", "host",
                   "delete_continue"]

    if state == "absent":
        if len(names) < 1:
            ansible_module.fail_json(msg="No name given.")
        invalid = ["description", "domain_resolution_order", "rename"]
        if action == "idview":
            invalid += ["host"]

    ansible_module.params_fail_used_invalid(invalid, state, action)

    # Init

    changed = False
    exit_args = {}

    # Connect to IPA API
    with ansible_module.ipa_connect():

        commands = []
        for name in names:
            # Make sure idview exists
            res_find = find_idview(ansible_module, name)

            # add/del lists
            host_add, host_del = [], []

            # Create command
            if state == "present":

                # Generate args
                args = gen_args(description, domain_resolution_order)

                if action == "idview":
                    # Found the idview
                    if res_find is not None:
                        # For all settings is args, check if there are
                        # different settings in the find result.
                        # If yes: modify
                        if not compare_args_ipa(ansible_module, args,
                                                res_find):
                            commands.append([name, "idview_mod", args])
                    else:
                        commands.append([name, "idview_add", args])
                        res_find = {}

                    member_args = gen_member_args(host)
                    if not compare_args_ipa(ansible_module, member_args,
                                            res_find):

                        # Generate addition and removal lists
                        host_add, host_del = gen_add_del_lists(
                            host, res_find.get("appliedtohosts"))

                elif action == "member":
                    if res_find is None:
                        ansible_module.fail_json(
                            msg="No idview '%s'" % name)

                    # Reduce add lists for host
                    # to new entries only that are not in res_find.
                    if host is not None:
                        host_add = gen_add_list(
                            host, res_find.get("appliedtohosts"))

            elif state == "absent":
                if action == "idview":
                    if res_find is not None:
                        commands.append(
                            [name, "idview_del",
                             {"continue": delete_continue or False}]
                        )

                elif action == "member":
                    if res_find is None:
                        ansible_module.fail_json(
                            msg="No idview '%s'" % name)

                    # Reduce del lists of member_host
                    # to the entries only that are in res_find.
                    if host is not None:
                        host_del = gen_intersection_list(
                            host, res_find.get("appliedtohosts"))

            elif state == "renamed":
                if res_find is None:
                    ansible_module.fail_json(msg="No idview '%s'" % name)
                else:
                    commands.append([name, 'idview_mod', {"rename": rename}])

            else:
                ansible_module.fail_json(msg="Unkown state '%s'" % state)

            # Member management

            # Add members
            if host_add:
                for host in host_add:
                    if not valid_host(ansible_module, host):
                        ansible_module.fail_json("Invalid host '%s'" % host)
                commands.append([name, "idview_apply", {"host": host_add}])

            # Remove members
            if host_del:
                # idview_unapply does not have the idview name (cn) as an arg.
                # It is removing the host from any idview it is applied to.
                # But as we create the intersection with the list of hosts of
                # the idview, we emulate the correct behaviour. But this means
                # that there is no general idview_unapply like in the cli.
                commands.append([None, "idview_unapply", {"host": host_del}])

        # Execute commands

        changed = ansible_module.execute_ipa_commands(commands)

    # Done

    ansible_module.exit_json(changed=changed, **exit_args)


if __name__ == "__main__":
    main()

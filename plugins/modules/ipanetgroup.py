# -*- coding: utf-8 -*-

# Authors:
#   Denis Karpelevich <dkarpele@redhat.com>
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
module: ipanetgroup
short_description: NIS entities can be stored in netgroups.
description: |
  A netgroup is a group used for permission checking.
  It can contain both user and host values.
extends_documentation_fragment:
  - ipamodule_base_docs
  - ipamodule_base_docs.delete_continue
options:
  name:
    description: The list of netgroup name strings.
    required: true
    type: list
    elements: str
    aliases: ["cn"]
  description:
    description: Netgroup description
    required: false
    type: str
    aliases: ["desc"]
  nisdomain:
    description: NIS domain name
    required: false
    type: str
    aliases: ["nisdomainname"]
  nomembers:
    description: Suppress processing of membership attributes
    required: false
    type: bool
  user:
    description: List of user names assigned to this netgroup.
    required: false
    type: list
    elements: str
    aliases: ["users"]
  group:
    description: List of group names assigned to this netgroup.
    required: false
    type: list
    elements: str
    aliases: ["groups"]
  host:
    description: List of host names assigned to this netgroup.
    required: false
    type: list
    elements: str
    aliases: ["hosts"]
  hostgroup:
    description: List of host group names assigned to this netgroup.
    required: false
    type: list
    elements: str
    aliases: ["hostgroups"]
  netgroup:
    description: List of netgroup names assigned to this netgroup.
    required: false
    type: list
    elements: str
    aliases: ["netgroups"]
  action:
    description: Work on netgroup or member level
    required: false
    type: str
    default: netgroup
    choices: ["member", "netgroup"]
  state:
    description: The state to ensure.
    type: str
    choices: ["present", "absent"]
    default: present
author:
    - Denis Karpelevich (@dkarpele)
"""

EXAMPLES = """
- name: Ensure netgroup my_netgroup1 is present
  ipanetgroup:
    ipaadmin_password: SomeADMINpassword
    name: my_netgroup1
    description: My netgroup 1

- name: Ensure netgroup my_netgroup1 is absent
  ipanetgroup:
    ipaadmin_password: SomeADMINpassword
    name: my_netgroup1
    state: absent

- name: Ensure netgroup is present with user "user1"
  ipanetgroup:
    ipaadmin_password: SomeADMINpassword
    name: TestNetgroup1
    user: user1
    action: member

- name: Ensure netgroup user, "user1", is absent
  ipanetgroup:
    ipaadmin_password: SomeADMINpassword
    name: TestNetgroup1
    user: "user1"
    action: member
    state: absent

- name: Ensure netgroup is present with members
  ipanetgroup:
    ipaadmin_password: SomeADMINpassword
    name: TestNetgroup1
    user: user1,user2
    group: group1
    host: host1
    hostgroup: ipaservers
    netgroup: admins
    action: member

- name: Ensure 2 netgroups TestNetgroup1, admins are absent
  ipanetgroup:
    ipaadmin_password: SomeADMINpassword
    name:
    - TestNetgroup1
    - admins
    state: absent
"""

RETURN = """
"""


from ansible.module_utils.ansible_freeipa_module import \
    IPAAnsibleModule, compare_args_ipa, gen_add_del_lists, \
    gen_add_list, gen_intersection_list, ensure_fqdn


def find_netgroup(module, name):
    """Find if a netgroup with the given name already exist."""
    _args = {
        "all": True,
        "cn": name,
    }

    # `netgroup_find` is used here instead of `netgroup_show` to workaround
    # FreeIPA bug https://pagure.io/freeipa/issue/9284.
    # `ipa netgroup-show hostgroup` shows hostgroup - it's a bug.
    # `ipa netgroup-find hostgroup` doesn't show hostgroup - it's correct.
    _result = module.ipa_command("netgroup_find", name, _args)

    if len(_result["result"]) > 1:
        module.fail_json(
            msg="There is more than one netgroup '%s'" % name)
    elif len(_result["result"]) == 1:
        return _result["result"][0]

    return None


def gen_args(description, nisdomain, nomembers):
    _args = {}
    if description is not None:
        _args["description"] = description
    if nisdomain is not None:
        _args["nisdomainname"] = nisdomain
    if nomembers is not None:
        _args["nomembers"] = nomembers

    return _args


def gen_member_args(user, group, host, hostgroup, netgroup):
    _args = {}
    if user is not None:
        _args["memberuser_user"] = user
    if group is not None:
        _args["memberuser_group"] = group
    if host is not None:
        _args["memberhost_host"] = host
    if hostgroup is not None:
        _args["memberhost_hostgroup"] = hostgroup
    if netgroup is not None:
        _args["member_netgroup"] = netgroup

    return _args


def main():
    ansible_module = IPAAnsibleModule(
        argument_spec=dict(
            # general
            name=dict(type="list", elements="str", aliases=["cn"],
                      required=True),
            # present
            description=dict(required=False, type='str',
                             aliases=["desc"], default=None),
            nisdomain=dict(required=False, type='str',
                           aliases=["nisdomainname"], default=None),
            nomembers=dict(required=False, type='bool', default=None),
            user=dict(required=False, type='list', elements="str",
                      aliases=["users"], default=None),
            group=dict(required=False, type='list', elements="str",
                       aliases=["groups"], default=None),
            host=dict(required=False, type='list', elements="str",
                      aliases=["hosts"], default=None),
            hostgroup=dict(required=False, type='list', elements="str",
                           aliases=["hostgroups"], default=None),
            netgroup=dict(required=False, type='list', elements="str",
                          aliases=["netgroups"], default=None),
            action=dict(required=False, type="str", default="netgroup",
                        choices=["member", "netgroup"]),
            # state
            state=dict(type="str", default="present",
                       choices=["present", "absent"]),
        ),
        supports_check_mode=True,
        ipa_module_options=["delete_continue"],
    )

    ansible_module._ansible_debug = True

    # Get parameters

    # general
    names = ansible_module.params_get("name")

    # present
    description = ansible_module.params_get("description")
    nisdomain = ansible_module.params_get("nisdomain")
    nomembers = ansible_module.params_get("nomembers")
    user = ansible_module.params_get_lowercase("user")
    group = ansible_module.params_get_lowercase("group")
    host = ansible_module.params_get_lowercase("host")
    hostgroup = ansible_module.params_get_lowercase("hostgroup")
    netgroup = ansible_module.params_get_lowercase("netgroup")
    action = ansible_module.params_get("action")

    # state
    state = ansible_module.params_get("state")

    # Check parameters

    invalid = []

    if state == "present":
        if len(names) != 1:
            ansible_module.fail_json(
                msg="Only one netgroup can be added at a time.")
        if action == "member":
            invalid = ["description", "nisdomain", "nomembers"]

    if state == "absent":
        if len(names) < 1:
            ansible_module.fail_json(msg="No name given.")
        if len(names) != 1 and action == "member":
            ansible_module.fail_json(msg="Members can be removed only from one"
                                         " netgroup at a time.")
        invalid = ["description", "nisdomain", "nomembers"]
        if action == "netgroup":
            invalid.extend(["user", "group", "host", "hostgroup", "netgroup"])

    ansible_module.params_fail_used_invalid(invalid, state)

    # Init

    exit_args = {}

    # Connect to IPA API
    with ansible_module.ipa_connect():
        # Ensure fqdn host names, use default domain for simple names
        if host is not None:
            default_domain = ansible_module.ipa_get_domain()
            host = [ensure_fqdn(_host, default_domain).lower()
                    for _host in host]

        commands = []
        for name in names:
            # Make sure netgroup exists
            res_find = find_netgroup(ansible_module, name)

            user_add, user_del = [], []
            group_add, group_del = [], []
            host_add, host_del = [], []
            hostgroup_add, hostgroup_del = [], []
            netgroup_add, netgroup_del = [], []

            # Create command
            if state == "present":
                # Generate args
                args = gen_args(description, nisdomain, nomembers)

                if action == "netgroup":
                    # Found the netgroup
                    if res_find is not None:
                        # For all settings is args, check if there are
                        # different settings in the find result.
                        # If yes: modify
                        if not compare_args_ipa(ansible_module, args,
                                                res_find):
                            commands.append([name, "netgroup_mod", args])
                    else:
                        commands.append([name, "netgroup_add", args])
                        res_find = {}

                    member_args = gen_member_args(
                        user, group, host, hostgroup, netgroup
                    )
                    if not compare_args_ipa(ansible_module, member_args,
                                            res_find):
                        # Generate addition and removal lists
                        user_add, user_del = gen_add_del_lists(
                            user, res_find.get("memberuser_user"))

                        group_add, group_del = gen_add_del_lists(
                            group, res_find.get("memberuser_group"))

                        host_add, host_del = gen_add_del_lists(
                            host, res_find.get("memberhost_host"))

                        hostgroup_add, hostgroup_del = gen_add_del_lists(
                            hostgroup, res_find.get("memberhost_hostgroup"))

                        netgroup_add, netgroup_del = gen_add_del_lists(
                            netgroup, res_find.get("member_netgroup"))

                elif action == "member":
                    if res_find is None:
                        ansible_module.fail_json(msg="No netgroup '%s'" % name)

                    # Reduce add lists for memberuser_user, memberuser_group,
                    # member_service and member_external to new entries
                    # only that are not in res_find.
                    user_add = gen_add_list(
                        user, res_find.get("memberuser_user"))
                    group_add = gen_add_list(
                        group, res_find.get("memberuser_group"))
                    host_add = gen_add_list(
                        host, res_find.get("memberhost_host"))
                    hostgroup_add = gen_add_list(
                        hostgroup, res_find.get("memberhost_hostgroup"))
                    netgroup_add = gen_add_list(
                        netgroup, res_find.get("member_netgroup"))

            elif state == "absent":
                if action == "netgroup":
                    if res_find is not None:
                        commands.append([name, "netgroup_del", {}])

                elif action == "member":
                    if res_find is None:
                        ansible_module.fail_json(msg="No netgroup '%s'" % name)
                    user_del = gen_intersection_list(
                        user, res_find.get("memberuser_user"))
                    group_del = gen_intersection_list(
                        group, res_find.get("memberuser_group"))
                    host_del = gen_intersection_list(
                        host, res_find.get("memberhost_host"))
                    hostgroup_del = gen_intersection_list(
                        hostgroup, res_find.get("memberhost_hostgroup"))
                    netgroup_del = gen_intersection_list(
                        netgroup, res_find.get("member_netgroup"))

            else:
                ansible_module.fail_json(msg="Unknown state '%s'" % state)

            # manage members
            # setup member args for add/remove members.
            add_member_args = {
                "user": user_add,
                "group": group_add,
                "host": host_add,
                "hostgroup": hostgroup_add,
                "netgroup": netgroup_add
            }

            del_member_args = {
                "user": user_del,
                "group": group_del,
                "host": host_del,
                "hostgroup": hostgroup_del,
                "netgroup": netgroup_del
            }

            # Add members
            add_members = any([user_add, group_add, host_add,
                               hostgroup_add, netgroup_add])
            if add_members:
                commands.append(
                    [name, "netgroup_add_member", add_member_args]
                )
            # Remove members
            remove_members = any([user_del, group_del, host_del,
                                  hostgroup_del, netgroup_del])
            if remove_members:
                commands.append(
                    [name, "netgroup_remove_member", del_member_args]
                )
        # Execute commands

        changed = ansible_module.execute_ipa_commands(
            commands, fail_on_member_errors=True)

    # Done

    ansible_module.exit_json(changed=changed, **exit_args)


if __name__ == "__main__":
    main()

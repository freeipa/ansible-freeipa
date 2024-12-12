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
module: ipasudorule
short_description: Manage FreeIPA sudo rules
description: Manage FreeIPA sudo rules
extends_documentation_fragment:
  - ipamodule_base_docs
options:
  name:
    description: The sudorule name
    type: list
    elements: str
    required: false
    aliases: ["cn"]
  sudorules:
    description: The list of sudorule dicts.
    type: list
    elements: dict
    suboptions:
      name:
        description: The sudorule name
        type: list
        elements: str
        required: true
        aliases: ["cn"]
      description:
        description: The sudorule description
        type: str
        required: false
      user:
        description: List of users assigned to the sudo rule.
        type: list
        elements: str
        required: false
      usercategory:
        description: User category the sudo rule applies to
        type: str
        required: false
        choices: ["all", ""]
        aliases: ["usercat"]
      group:
        description: List of user groups assigned to the sudo rule.
        type: list
        elements: str
        required: false
      runasgroupcategory:
        description: RunAs Group category applied to the sudo rule.
        type: str
        required: false
        choices: ["all", ""]
        aliases: ["runasgroupcat"]
      runasusercategory:
        description: RunAs User category applied to the sudorule.
        type: str
        required: false
        choices: ["all", ""]
        aliases: ["runasusercat"]
      nomembers:
        description: Suppress processing of membership attributes
        required: false
        type: bool
      host:
        description: List of host names assigned to this sudorule.
        required: false
        type: list
        elements: str
      hostgroup:
        description: List of host groups assigned to this sudorule.
        required: false
        type: list
        elements: str
      hostcategory:
        description: Host category the sudo rule applies to.
        type: str
        required: false
        choices: ["all", ""]
        aliases: ["hostcat"]
      allow_sudocmd:
        description: List of allowed sudocmds assigned to this sudorule.
        required: false
        type: list
        elements: str
      allow_sudocmdgroup:
        description: List of allowed sudocmd groups assigned to this sudorule.
        required: false
        type: list
        elements: str
      deny_sudocmd:
        description: List of denied sudocmds assigned to this sudorule.
        required: false
        type: list
        elements: str
      deny_sudocmdgroup:
        description: List of denied sudocmd groups assigned to this sudorule.
        required: false
        type: list
        elements: str
      cmdcategory:
        description: Command category the sudo rule applies to
        type: str
        required: false
        choices: ["all", ""]
        aliases: ["cmdcat"]
      order:
        description: Order to apply this rule.
        required: false
        type: int
        aliases: ["sudoorder"]
      sudooption:
        description: List of sudo options.
        required: false
        type: list
        elements: str
        aliases: ["options"]
      runasuser:
        description: List of users for Sudo to execute as.
        required: false
        type: list
        elements: str
      runasuser_group:
        description: List of groups for Sudo to execute as.
        required: false
        type: list
        elements: str
      runasgroup:
        description: List of groups for Sudo to execute as.
        required: false
        type: list
        elements: str
      hostmask:
        description: Host masks of allowed hosts.
        required: false
        type: list
        elements: str
  description:
    description: The sudorule description
    type: str
    required: false
  user:
    description: List of users assigned to the sudo rule.
    type: list
    elements: str
    required: false
  usercategory:
    description: User category the sudo rule applies to
    type: str
    required: false
    choices: ["all", ""]
    aliases: ["usercat"]
  group:
    description: List of user groups assigned to the sudo rule.
    type: list
    elements: str
    required: false
  runasgroupcategory:
    description: RunAs Group category applied to the sudo rule.
    type: str
    required: false
    choices: ["all", ""]
    aliases: ["runasgroupcat"]
  runasusercategory:
    description: RunAs User category applied to the sudorule.
    type: str
    required: false
    choices: ["all", ""]
    aliases: ["runasusercat"]
  nomembers:
    description: Suppress processing of membership attributes
    required: false
    type: bool
  host:
    description: List of host names assigned to this sudorule.
    required: false
    type: list
    elements: str
  hostgroup:
    description: List of host groups assigned to this sudorule.
    required: false
    type: list
    elements: str
  hostcategory:
    description: Host category the sudo rule applies to.
    type: str
    required: false
    choices: ["all", ""]
    aliases: ["hostcat"]
  allow_sudocmd:
    description: List of allowed sudocmds assigned to this sudorule.
    required: false
    type: list
    elements: str
  allow_sudocmdgroup:
    description: List of allowed sudocmd groups assigned to this sudorule.
    required: false
    type: list
    elements: str
  deny_sudocmd:
    description: List of denied sudocmds assigned to this sudorule.
    required: false
    type: list
    elements: str
  deny_sudocmdgroup:
    description: List of denied sudocmd groups assigned to this sudorule.
    required: false
    type: list
    elements: str
  cmdcategory:
    description: Command category the sudo rule applies to
    type: str
    required: false
    choices: ["all", ""]
    aliases: ["cmdcat"]
  order:
    description: Order to apply this rule.
    required: false
    type: int
    aliases: ["sudoorder"]
  sudooption:
    description: List of sudo options.
    required: false
    type: list
    elements: str
    aliases: ["options"]
  runasuser:
    description: List of users for Sudo to execute as.
    required: false
    type: list
    elements: str
  runasuser_group:
    description: List of groups for Sudo to execute as.
    required: false
    type: list
    elements: str
  runasgroup:
    description: List of groups for Sudo to execute as.
    required: false
    type: list
    elements: str
  hostmask:
    description: Host masks of allowed hosts.
    required: false
    type: list
    elements: str
  action:
    description: Work on sudorule or member level
    type: str
    default: sudorule
    choices: ["member", "sudorule"]
  state:
    description: State to ensure
    type: str
    default: present
    choices: ["present", "absent", "enabled", "disabled"]
author:
  - Rafael Guterres Jeffman (@rjeffman)
  - Thomas Woerner (@t-woerner)
"""

EXAMPLES = """
# Ensure Sudo Rule tesrule1 is present
- ipasudorule:
    ipaadmin_password: SomeADMINpassword
    name: testrule1

# Ensure sudocmd is present in Sudo Rule
- ipasudorule:
    ipaadmin_password: pass1234
    name: testrule1
    allow_sudocmd:
      - /sbin/ifconfig
      - /usr/bin/vim
    action: member
    state: absent

# Ensure host server is present in Sudo Rule
- ipasudorule:
    ipaadmin_password: SomeADMINpassword
    name: testrule1
    host: server
    action: member

# Ensure hostgroup cluster is present in Sudo Rule
- ipasudorule:
    ipaadmin_password: SomeADMINpassword
    name: testrule1
    hostgroup: cluster
    action: member

# Ensure sudo rule for usercategory "all" is enabled
- ipasudorule:
    ipaadmin_password: SomeADMINpassword
    name: allusers
    usercategory: all
    state: enabled

# Ensure sudo rule for hostcategory "all" is enabled
- ipasudorule:
    ipaadmin_password: SomeADMINpassword
    name: allhosts
    hostcategory: all
    state: enabled

# Ensure sudo rule applies for hosts with hostmasks
- ipasudorule:
    ipaadmin_password: SomeADMINpassword
    name: testrule1
    hostmask:
    - 192.168.122.1/24
    - 192.168.120.1/24

# Ensure sudorule 'runasuser' has 'ipasuers' group as runas users.
- ipasudorule:
    ipaadmin_password: SomeADMINpassword
    name: testrule1
    runasuser_group: ipausers
    action: member

# Ensure Sudo Rule tesrule1 is absent
- ipasudorule:
    ipaadmin_password: SomeADMINpassword
    name: testrule1
    state: absent

# Ensure multiple Sudo Rules are present using batch mode.
- ipasudorule:
    ipaadmin_password: SomeADMINpassword
    sudorules:
      - name: testrule1
        hostmask:
          - 192.168.122.1/24
      - name: testrule2
        hostcategory: all
"""

RETURN = """
"""

from ansible.module_utils.ansible_freeipa_module import \
    IPAAnsibleModule, compare_args_ipa, gen_add_del_lists, gen_add_list, \
    gen_intersection_list, api_get_domain, ensure_fqdn, netaddr, to_text, \
    ipalib_errors, convert_param_value_to_lowercase, EntryFactory


def find_sudorule(module, name):
    _args = {
        "all": True,
    }

    try:
        _result = module.ipa_command("sudorule_show", name, _args)
    except ipalib_errors.NotFound:
        return None
    return _result["result"]


def gen_args(entry):
    """Generate args for sudorule."""
    _args = {}

    if entry.description is not None:
        _args['description'] = entry.description
    if entry.usercategory is not None:
        _args['usercategory'] = entry.usercategory
    if entry.hostcategory is not None:
        _args['hostcategory'] = entry.hostcategory
    if entry.cmdcategory is not None:
        _args['cmdcategory'] = entry.cmdcategory
    if entry.runasusercategory is not None:
        _args['ipasudorunasusercategory'] = entry.runasusercategory
    if entry.runasgroupcategory is not None:
        _args['ipasudorunasgroupcategory'] = entry.runasgroupcategory
    if entry.order is not None:
        _args['sudoorder'] = entry.order
    if entry.nomembers is not None:
        _args['nomembers'] = entry.nomembers

    return _args


def init_ansible_module():
    """Initialize IPAAnsibleModule object for sudorule."""
    sudorule_spec = dict(
        description=dict(required=False, type="str", default=None),
        usercategory=dict(required=False, type="str", default=None,
                          choices=["all", ""], aliases=['usercat']),
        hostcategory=dict(required=False, type="str", default=None,
                          choices=["all", ""], aliases=['hostcat']),
        nomembers=dict(required=False, type='bool', default=None),
        host=dict(required=False, type='list', elements="str",
                  default=None),
        hostgroup=dict(required=False, type='list', elements="str",
                       default=None),
        hostmask=dict(required=False, type='list', elements="str",
                      default=None),
        user=dict(required=False, type='list', elements="str",
                  default=None),
        group=dict(required=False, type='list', elements="str",
                   default=None),
        allow_sudocmd=dict(required=False, type="list", elements="str",
                           default=None),
        deny_sudocmd=dict(required=False, type="list", elements="str",
                          default=None),
        allow_sudocmdgroup=dict(required=False, type="list",
                                elements="str", default=None),
        deny_sudocmdgroup=dict(required=False, type="list", elements="str",
                               default=None),
        cmdcategory=dict(required=False, type="str", default=None,
                         choices=["all", ""], aliases=['cmdcat']),
        runasusercategory=dict(required=False, type="str", default=None,
                               choices=["all", ""],
                               aliases=['runasusercat']),
        runasgroupcategory=dict(required=False, type="str", default=None,
                                choices=["all", ""],
                                aliases=['runasgroupcat']),
        runasuser=dict(required=False, type="list", elements="str",
                       default=None),
        runasgroup=dict(required=False, type="list", elements="str",
                        default=None),
        runasuser_group=dict(required=False, type="list", elements="str",
                             default=None),
        order=dict(type="int", required=False, aliases=['sudoorder']),
        sudooption=dict(required=False, type='list', elements="str",
                        default=None, aliases=["options"]),
    )

    ansible_module = IPAAnsibleModule(
        argument_spec=dict(
            # general
            name=dict(type="list", elements="str", aliases=["cn"],
                      required=False),
            sudorules=dict(
                type="list",
                defalut=None,
                options=dict(
                    # name of the sudorule
                    name=dict(type="str", required=True, aliases=["cn"]),
                    # sudorule specific parameters
                    **sudorule_spec
                ),
                elements='dict',
                required=False,
            ),
            # action
            action=dict(type="str", default="sudorule",
                        choices=["member", "sudorule"]),
            # state
            state=dict(type="str", default="present",
                       choices=["present", "absent",
                                "enabled", "disabled"]),
            # Specific parameters for simple use case
            **sudorule_spec
        ),
        mutually_exclusive=[["name", "sudorules"]],
        required_one_of=[["name", "sudorules"]],
        supports_check_mode=True,
    )

    ansible_module._ansible_debug = True
    return ansible_module


def convert_list_of_hostmask(hostmasks):
    """Ensure all hostmasks is hostmask_list is a CIDR value."""
    return [
        to_text(netaddr.IPNetwork(mask).cidr)
        for mask in (
            hostmasks if isinstance(hostmasks, (list, tuple))
            else [hostmasks]
        )
    ]


def convert_list_of_hostnames(hostnames):
    """Ensure all hostnames in hostnames are lowercase FQDN."""
    return list(
        set(
            ensure_fqdn(value.lower(), api_get_domain())
            for value in (
                hostnames if isinstance(hostnames, (list, tuple))
                else [hostnames]
            )
        )
    )


def validate_entry(module, entry, state, action):
    """Ensure entry object is valid."""
    if state == "present" and action == "sudorule":
        # Ensure the entry is valid for state:present, action:sudorule.
        if entry.hostcategory == 'all' and any([entry.host, entry.hostgroup]):
            module.fail_json(
                msg="Hosts cannot be added when host category='all'"
            )
        if entry.usercategory == 'all' and any([entry.user, entry.group]):
            module.fail_json(
                msg="Users cannot be added when user category='all'"
            )
        if entry.cmdcategory == 'all' \
           and any([entry.allow_sudocmd, entry.allow_sudocmdgroup]):
            module.fail_json(
                msg="Commands cannot be added when command category='all'"
            )
    return entry


def main():
    ansible_module = init_ansible_module()
    # Get parameters
    # general
    names = ansible_module.params_get("name")
    # sudorules = ansible_module.params_get("sudorules")
    # action
    action = ansible_module.params_get("action")
    # state
    state = ansible_module.params_get("state")

    # Check parameters
    invalid = []

    if state == "present":
        if names is not None and len(names) != 1:
            ansible_module.fail_json(
                msg="Only one sudorule can be added at a time using 'name'.")
        if action == "member":
            invalid = ["description", "usercategory", "hostcategory",
                       "cmdcategory", "runasusercategory",
                       "runasgroupcategory", "order", "nomembers"]

    elif state == "absent":
        invalid = ["description", "usercategory", "hostcategory",
                   "cmdcategory", "runasusercategory",
                   "runasgroupcategory", "nomembers", "order"]
        if action == "sudorule":
            invalid.extend(["host", "hostgroup", "hostmask", "user", "group",
                            "runasuser", "runasgroup", "allow_sudocmd",
                            "allow_sudocmdgroup", "deny_sudocmd",
                            "deny_sudocmdgroup", "sudooption",
                            "runasuser_group"])

    elif state in ["enabled", "disabled"]:
        if action == "member":
            ansible_module.fail_json(
                msg="Action member can not be used with states enabled and "
                "disabled")
        invalid = ["description", "usercategory", "hostcategory",
                   "cmdcategory", "runasusercategory", "runasgroupcategory",
                   "nomembers", "nomembers", "host", "hostgroup", "hostmask",
                   "user", "group", "allow_sudocmd", "allow_sudocmdgroup",
                   "deny_sudocmd", "deny_sudocmdgroup", "runasuser",
                   "runasgroup", "order", "sudooption", "runasuser_group"]
    else:
        ansible_module.fail_json(msg="Invalid state '%s'" % state)

    # Init
    changed = False
    exit_args = {}

    # Factory parameters
    params = {
        "name": {},
        "description": {},
        "cmdcategory": {},
        "usercategory": {},
        "hostcategory": {},
        "runasusercategory": {},
        "runasgroupcategory": {},
        "host": {"convert": [convert_list_of_hostnames]},
        "hostgroup": {"convert": [convert_param_value_to_lowercase]},
        "hostmask": {"convert": [convert_list_of_hostmask]},
        "user": {"convert": [convert_param_value_to_lowercase]},
        "group": {"convert": [convert_param_value_to_lowercase]},
        "allow_sudocmd": {},
        "allow_sudocmdgroup": {"convert": [convert_param_value_to_lowercase]},
        "deny_sudocmd": {},
        "deny_sudocmdgroup": {"convert": [convert_param_value_to_lowercase]},
        "sudooption": {},
        "order": {},
        "runasuser": {"convert": [convert_param_value_to_lowercase]},
        "runasuser_group": {"convert": [convert_param_value_to_lowercase]},
        "runasgroup": {"convert": [convert_param_value_to_lowercase]},
        "nomembers": {},
    }

    # Connect to IPA API
    with ansible_module.ipa_connect():
        commands = []

        # Creating factory after connect as host conversion
        # requires 'api_get_domain()' to be available
        entry_factory = EntryFactory(
            ansible_module,
            invalid,
            "sudorules",
            params,
            validate_entry=validate_entry,
            state=state,
            action=action,
        )

        for entry in entry_factory:
            host_add, host_del = [], []
            user_add, user_del = [], []
            group_add, group_del = [], []
            hostgroup_add, hostgroup_del = [], []
            hostmask_add, hostmask_del = [], []
            allow_cmd_add, allow_cmd_del = [], []
            allow_cmdgroup_add, allow_cmdgroup_del = [], []
            deny_cmd_add, deny_cmd_del = [], []
            deny_cmdgroup_add, deny_cmdgroup_del = [], []
            sudooption_add, sudooption_del = [], []
            runasuser_add, runasuser_del = [], []
            runasuser_group_add, runasuser_group_del = [], []
            runasgroup_add, runasgroup_del = [], []

            # Try to retrieve sudorule
            res_find = find_sudorule(ansible_module, entry.name)

            # Fail if sudorule must exist but is not found
            if (
                (state in ["enabled", "disabled"] or action == "member")
                and res_find is None
            ):
                ansible_module.fail_json(msg="No sudorule '%s'" % entry.name)

            # Create command
            if state == "present":
                # Generate args
                args = gen_args(entry)
                if action == "sudorule":
                    # Found the sudorule
                    if res_find is not None:
                        # Remove empty usercategory, hostcategory,
                        # cmdcaterory, runasusercategory and hostcategory
                        # from args if "" and if the category is not in the
                        # sudorule. The empty string is used to reset the
                        # category.
                        if (
                            "usercategory" in args
                            and args["usercategory"] == ""
                            and "usercategory" not in res_find
                        ):
                            del args["usercategory"]
                        if (
                            "hostcategory" in args
                            and args["hostcategory"] == ""
                            and "hostcategory" not in res_find
                        ):
                            del args["hostcategory"]
                        if (
                            "cmdcategory" in args
                            and args["cmdcategory"] == ""
                            and "cmdcategory" not in res_find
                        ):
                            del args["cmdcategory"]
                        if (
                            "ipasudorunasusercategory" in args
                            and args["ipasudorunasusercategory"] == ""
                            and "ipasudorunasusercategory" not in res_find
                        ):
                            del args["ipasudorunasusercategory"]
                        if (
                            "ipasudorunasgroupcategory" in args
                            and args["ipasudorunasgroupcategory"] == ""
                            and "ipasudorunasgroupcategory" not in res_find
                        ):
                            del args["ipasudorunasgroupcategory"]

                        # For all settings is args, check if there are
                        # different settings in the find result.
                        # If yes: modify
                        if not compare_args_ipa(ansible_module, args,
                                                res_find):
                            commands.append([entry.name, "sudorule_mod", args])
                    else:
                        commands.append([entry.name, "sudorule_add", args])
                        # Set res_find to empty dict for next step
                        res_find = {}

                    # Generate addition and removal lists
                    host_add, host_del = gen_add_del_lists(
                        entry.host, (
                            list(res_find.get('memberhost_host', []))
                            + list(res_find.get('externalhost', []))
                        )
                    )

                    hostgroup_add, hostgroup_del = gen_add_del_lists(
                        entry.hostgroup,
                        res_find.get('memberhost_hostgroup', [])
                    )

                    hostmask_add, hostmask_del = gen_add_del_lists(
                        entry.hostmask, res_find.get('hostmask', []))

                    user_add, user_del = gen_add_del_lists(
                        entry.user, (
                            list(res_find.get('memberuser_user', []))
                            + list(res_find.get('externaluser', []))
                        )
                    )

                    group_add, group_del = gen_add_del_lists(
                        entry.group, res_find.get('memberuser_group', []))

                    allow_cmd_add, allow_cmd_del = gen_add_del_lists(
                        entry.allow_sudocmd,
                        res_find.get('memberallowcmd_sudocmd', []))

                    allow_cmdgroup_add, allow_cmdgroup_del = gen_add_del_lists(
                        entry.allow_sudocmdgroup,
                        res_find.get('memberallowcmd_sudocmdgroup', []))

                    deny_cmd_add, deny_cmd_del = gen_add_del_lists(
                        entry.deny_sudocmd,
                        res_find.get('memberdenycmd_sudocmd', []))

                    deny_cmdgroup_add, deny_cmdgroup_del = gen_add_del_lists(
                        entry.deny_sudocmdgroup,
                        res_find.get('memberdenycmd_sudocmdgroup', []))

                    sudooption_add, sudooption_del = gen_add_del_lists(
                        entry.sudooption, res_find.get('ipasudoopt', []))

                    # runasuser attribute can be used with both IPA and
                    # non-IPA (external) users. IPA will handle the correct
                    # attribute to properly store data, so we need to compare
                    # the provided list against both users and external
                    # users list.
                    runasuser_add, runasuser_del = gen_add_del_lists(
                        entry.runasuser, (
                            list(res_find.get('ipasudorunas_user', []))
                            + list(res_find.get('ipasudorunasextuser', []))
                        )
                    )
                    runasuser_group_add, runasuser_group_del = (
                        gen_add_del_lists(
                            entry.runasuser_group,
                            res_find.get('ipasudorunas_group', [])
                        )
                    )

                    # runasgroup attribute can be used with both IPA and
                    # non-IPA (external) groups. IPA will handle the correct
                    # attribute to properly store data, so we need to compare
                    # the provided list against both groups and external
                    # groups list.
                    runasgroup_add, runasgroup_del = gen_add_del_lists(
                        entry.runasgroup,
                        (
                            list(res_find.get('ipasudorunasgroup_group', []))
                            + list(res_find.get('ipasudorunasextgroup', []))
                        )
                    )

                elif action == "member":
                    # Generate add lists for host, hostgroup, user, group,
                    # allow_sudocmd, allow_sudocmdgroup, deny_sudocmd,
                    # deny_sudocmdgroup, sudooption, runasuser, runasgroup
                    # and res_find to only try to add the items that not in
                    # the sudorule already
                    if entry.host is not None:
                        host_add = gen_add_list(
                            entry.host, (
                                list(res_find.get("memberhost_host", []))
                                + list(res_find.get("externalhost", []))
                            )
                        )
                    if entry.hostgroup is not None:
                        hostgroup_add = gen_add_list(
                            entry.hostgroup,
                            res_find.get("memberhost_hostgroup")
                        )
                    if entry.hostmask is not None:
                        hostmask_add = gen_add_list(
                            entry.hostmask, res_find.get("hostmask"))
                    if entry.user is not None:
                        user_add = gen_add_list(
                            entry.user, (
                                list(res_find.get('memberuser_user', []))
                                + list(res_find.get('externaluser', []))
                            )
                        )
                    if entry.group is not None:
                        group_add = gen_add_list(
                            entry.group, res_find.get("memberuser_group"))
                    if entry.allow_sudocmd is not None:
                        allow_cmd_add = gen_add_list(
                            entry.allow_sudocmd,
                            res_find.get("memberallowcmd_sudocmd")
                        )
                    if entry.allow_sudocmdgroup is not None:
                        allow_cmdgroup_add = gen_add_list(
                            entry.allow_sudocmdgroup,
                            res_find.get("memberallowcmd_sudocmdgroup")
                        )
                    if entry.deny_sudocmd is not None:
                        deny_cmd_add = gen_add_list(
                            entry.deny_sudocmd,
                            res_find.get("memberdenycmd_sudocmd")
                        )
                    if entry.deny_sudocmdgroup is not None:
                        deny_cmdgroup_add = gen_add_list(
                            entry.deny_sudocmdgroup,
                            res_find.get("memberdenycmd_sudocmdgroup")
                        )
                    if entry.sudooption is not None:
                        sudooption_add = gen_add_list(
                            entry.sudooption, res_find.get("ipasudoopt"))
                    # runasuser attribute can be used with both IPA and
                    # non-IPA (external) users, so we need to compare
                    # the provided list against both users and external
                    # users list.
                    if entry.runasuser is not None:
                        runasuser_add = gen_add_list(
                            entry.runasuser,
                            (list(res_find.get('ipasudorunas_user', []))
                             + list(res_find.get('ipasudorunasextuser', [])))
                        )
                    if entry.runasuser_group is not None:
                        runasuser_group_add = gen_add_list(
                            entry.runasuser_group,
                            res_find.get('ipasudorunas_group', [])
                        )
                    # runasgroup attribute can be used with both IPA and
                    # non-IPA (external) groups, so we need to compare
                    # the provided list against both users and external
                    # groups list.
                    if entry.runasgroup is not None:
                        runasgroup_add = gen_add_list(
                            entry.runasgroup,
                            (list(res_find.get("ipasudorunasgroup_group", []))
                             + list(res_find.get("ipasudorunasextgroup", [])))
                        )

            elif state == "absent":
                if action == "sudorule":
                    if res_find is not None:
                        commands.append([entry.name, "sudorule_del", {}])

                elif action == "member":
                    # Generate intersection lists for host, hostgroup, user,
                    # group, allow_sudocmd, allow_sudocmdgroup, deny_sudocmd
                    # deny_sudocmdgroup, sudooption, runasuser, runasgroup
                    # and res_find to only try to remove the items that are
                    # in sudorule
                    if entry.host is not None:
                        host_del = gen_intersection_list(
                            entry.host, (
                                list(res_find.get("memberhost_host", []))
                                + list(res_find.get("externalhost", []))
                            )
                        )

                    if entry.hostgroup is not None:
                        hostgroup_del = gen_intersection_list(
                            entry.hostgroup,
                            res_find.get("memberhost_hostgroup")
                        )

                    if entry.hostmask is not None:
                        hostmask_del = gen_intersection_list(
                            entry.hostmask, res_find.get("hostmask"))

                    if entry.user is not None:
                        user_del = gen_intersection_list(
                            entry.user, (
                                list(res_find.get('memberuser_user', []))
                                + list(res_find.get('externaluser', []))
                            )
                        )

                    if entry.group is not None:
                        group_del = gen_intersection_list(
                            entry.group, res_find.get("memberuser_group"))

                    if entry.allow_sudocmd is not None:
                        allow_cmd_del = gen_intersection_list(
                            entry.allow_sudocmd,
                            res_find.get("memberallowcmd_sudocmd")
                        )
                    if entry.allow_sudocmdgroup is not None:
                        allow_cmdgroup_del = gen_intersection_list(
                            entry.allow_sudocmdgroup,
                            res_find.get("memberallowcmd_sudocmdgroup")
                        )
                    if entry.deny_sudocmd is not None:
                        deny_cmd_del = gen_intersection_list(
                            entry.deny_sudocmd,
                            res_find.get("memberdenycmd_sudocmd")
                        )
                    if entry.deny_sudocmdgroup is not None:
                        deny_cmdgroup_del = gen_intersection_list(
                            entry.deny_sudocmdgroup,
                            res_find.get("memberdenycmd_sudocmdgroup")
                        )
                    if entry.sudooption is not None:
                        sudooption_del = gen_intersection_list(
                            entry.sudooption, res_find.get("ipasudoopt"))
                    # runasuser attribute can be used with both IPA and
                    # non-IPA (external) users, so we need to compare
                    # the provided list against both users and external
                    # users list.
                    if entry.runasuser is not None:
                        runasuser_del = gen_intersection_list(
                            entry.runasuser, (
                                list(res_find.get('ipasudorunas_user', []))
                                + list(res_find.get('ipasudorunasextuser', []))
                            )
                        )
                    if entry.runasuser_group is not None:
                        runasuser_group_del = gen_intersection_list(
                            entry.runasuser_group,
                            res_find.get('ipasudorunas_group', [])
                        )
                    # runasgroup attribute can be used with both IPA and
                    # non-IPA (external) groups, so we need to compare
                    # the provided list against both groups and external
                    # groups list.
                    if entry.runasgroup is not None:
                        runasgroup_del = gen_intersection_list(
                            entry.runasgroup,
                            (
                                list(res_find.get(
                                    "ipasudorunasgroup_group", []))
                                + list(res_find.get(
                                    "ipasudorunasextgroup", []))
                            )
                        )

            elif state == "enabled":
                # sudorule_enable is not failing on an enabled sudorule
                # Therefore it is needed to have a look at the ipaenabledflag
                # in res_find.
                # FreeIPA 4.9.10+ and 4.10 use proper mapping for
                # boolean values, so we need to convert it to str
                # for comparison.
                # See: https://github.com/freeipa/freeipa/pull/6294
                enabled_flag = str(res_find.get("ipaenabledflag", [False])[0])
                if enabled_flag.upper() != "TRUE":
                    commands.append([entry.name, "sudorule_enable", {}])

            elif state == "disabled":
                # sudorule_disable is not failing on an disabled sudorule
                # Therefore it is needed to have a look at the ipaenabledflag
                # in res_find.
                # FreeIPA 4.9.10+ and 4.10 use proper mapping for
                # boolean values, so we need to convert it to str
                # for comparison.
                # See: https://github.com/freeipa/freeipa/pull/6294
                enabled_flag = str(res_find.get("ipaenabledflag", [False])[0])
                if enabled_flag.upper() != "FALSE":
                    commands.append([entry.name, "sudorule_disable", {}])

            else:
                ansible_module.fail_json(msg="Unkown state '%s'" % state)

            # Manage members.
            # Manage hosts and hostgroups
            if any([host_add, hostgroup_add, hostmask_add]):
                params = {"host": host_add, "hostgroup": hostgroup_add}
                # An empty Hostmask cannot be used, or IPA API will fail.
                if hostmask_add:
                    params["hostmask"] = hostmask_add
                commands.append([entry.name, "sudorule_add_host", params])

            if any([host_del, hostgroup_del, hostmask_del]):
                params = {"host": host_del, "hostgroup": hostgroup_del}
                # An empty Hostmask cannot be used, or IPA API will fail.
                if hostmask_del:
                    params["hostmask"] = hostmask_del
                commands.append([entry.name, "sudorule_remove_host", params])

            # Manage users and groups
            if user_add or group_add:
                commands.append([
                    entry.name, "sudorule_add_user",
                    {"user": user_add, "group": group_add}
                ])
            if user_del or group_del:
                commands.append([
                    entry.name, "sudorule_remove_user",
                    {"user": user_del, "group": group_del}
                ])

            # Manage commands allowed
            if allow_cmd_add or allow_cmdgroup_add:
                commands.append([
                    entry.name, "sudorule_add_allow_command",
                    {
                        "sudocmd": allow_cmd_add,
                        "sudocmdgroup": allow_cmdgroup_add,
                    }
                ])
            if allow_cmd_del or allow_cmdgroup_del:
                commands.append([
                    entry.name, "sudorule_remove_allow_command",
                    {
                        "sudocmd": allow_cmd_del,
                        "sudocmdgroup": allow_cmdgroup_del
                    }
                ])
            # Manage commands denied
            if deny_cmd_add or deny_cmdgroup_add:
                commands.append([
                    entry.name, "sudorule_add_deny_command",
                    {
                        "sudocmd": deny_cmd_add,
                        "sudocmdgroup": deny_cmdgroup_add,
                    }
                ])
            if deny_cmd_del or deny_cmdgroup_del:
                commands.append([
                    entry.name, "sudorule_remove_deny_command",
                    {
                        "sudocmd": deny_cmd_del,
                        "sudocmdgroup": deny_cmdgroup_del
                    }
                ])
            # Manage RunAS users
            if runasuser_add or runasuser_group_add:
                # Can't use empty lists with command "sudorule_add_runasuser".
                _args = {}
                if runasuser_add:
                    _args["user"] = runasuser_add
                if runasuser_group_add:
                    _args["group"] = runasuser_group_add
                commands.append([entry.name, "sudorule_add_runasuser", _args])
            if runasuser_del or runasuser_group_del:
                commands.append([
                    entry.name,
                    "sudorule_remove_runasuser",
                    {"user": runasuser_del, "group": runasuser_group_del}
                ])

            # Manage RunAS Groups
            if runasgroup_add:
                commands.append([
                    entry.name, "sudorule_add_runasgroup",
                    {"group": runasgroup_add}
                ])
            if runasgroup_del:
                commands.append([
                    entry.name, "sudorule_remove_runasgroup",
                    {"group": runasgroup_del}
                ])
            # Manage sudo options
            if sudooption_add:
                for option in sudooption_add:
                    commands.append([
                        entry.name, "sudorule_add_option",
                        {"ipasudoopt": option}
                    ])
            if sudooption_del:
                for option in sudooption_del:
                    commands.append([
                        entry.name, "sudorule_remove_option",
                        {"ipasudoopt": option}
                    ])

        # Execute commands

        changed = ansible_module.execute_ipa_commands(
            commands, batch=True, fail_on_member_errors=True)

    # Done

    ansible_module.exit_json(changed=changed, **exit_args)


if __name__ == "__main__":
    main()

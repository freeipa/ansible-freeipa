# -*- coding: utf-8 -*-

# Authors:
#   Chris Procter <cprocter@redhat.com>
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


DOCUMENTATION = '''
---
module: ipadnsforwardzone
author:
  - Chris Procter (@chr15p)
  - Thomas Woerner (@t-woerner)
short_description: Manage FreeIPA DNS Forwarder Zones
description:
  - Add and delete an IPA DNS Forwarder Zones using IPA API
extends_documentation_fragment:
  - ipamodule_base_docs
options:
  name:
    description:
    - The DNS zone name which needs to be managed.
    type: list
    elements: str
    required: true
    aliases: ["cn"]
  action:
    description: |
      Work on dnsforwardzone or member level. It can be one of `member` or
      `dnsforwardzone`.
    type: str
    default: "dnsforwardzone"
    choices: ["member", "dnsforwardzone"]
  state:
    description: State to ensure
    type: str
    required: false
    default: present
    choices: ["present", "absent", "enabled", "disabled"]
  forwarders:
    description:
    - List of the DNS servers to forward to
    type: list
    elements: dict
    aliases: ["idnsforwarders"]
    suboptions:
      ip_address:
        description: Forwarder IP address (either IPv4 or IPv6).
        required: true
        type: str
      port:
        description: Forwarder port.
        required: false
        type: int
  forwardpolicy:
    description: Per-zone conditional forwarding policy
    type: str
    required: false
    choices: ["only", "first", "none"]
    aliases: ["idnsforwardpolicy", "forward_policy"]
  skip_overlap_check:
    description:
    - Force DNS zone creation even if it will overlap with an existing zone.
    type: bool
    required: false
  permission:
    description:
    - Allow DNS Forward Zone to be managed.
    required: false
    type: bool
    aliases: ["managedby"]
'''

EXAMPLES = '''
# Ensure dns zone is present
- ipadnsforwardzone:
    ipaadmin_password: SomeADMINpassword
    state: present
    name: example.com
    forwarders:
    - ip_address: 8.8.8.8
    - ip_address: 4.4.4.4
    forwardpolicy: first
    skip_overlap_check: true

# Ensure dns zone is present, with forwarder on non-default port
- ipadnsforwardzone:
    ipaadmin_password: SomeADMINpassword
    state: present
    name: example.com
    forwarders:
    - ip_address: 8.8.8.8
      port: 8053
    forwardpolicy: first
    skip_overlap_check: true

# Ensure that dns zone is removed
- ipadnsforwardzone:
    ipaadmin_password: SomeADMINpassword
    name: example.com
    state: absent
'''

RETURN = '''
'''


from ansible.module_utils._text import to_text
from ansible.module_utils.ansible_freeipa_module import \
    IPAAnsibleModule, compare_args_ipa


def find_dnsforwardzone(module, name):
    _args = {
        "all": True,
        "idnsname": name
    }
    _result = module.ipa_command("dnsforwardzone_find", name, _args)

    if len(_result["result"]) > 1:
        module.fail_json(
            msg="There is more than one dnsforwardzone '%s'" % (name))
    elif len(_result["result"]) == 1:
        return _result["result"][0]

    return None


def gen_args(forwarders, forwardpolicy, skip_overlap_check):
    _args = {}

    if forwarders is not None:
        _args["idnsforwarders"] = forwarders
    if forwardpolicy is not None:
        _args["idnsforwardpolicy"] = forwardpolicy
    if skip_overlap_check is not None:
        _args["skip_overlap_check"] = skip_overlap_check

    return _args


def forwarder_list(forwarders):
    """Convert the forwarder dict into a list compatible with IPA API."""
    if forwarders is None:
        return None
    fwd_list = []
    for forwarder in forwarders:
        if forwarder.get('port', None) is not None:
            formatter = "{ip_address} port {port}"
        else:
            formatter = "{ip_address}"
        fwd_list.append(to_text(formatter.format(**forwarder)))
    return fwd_list


def fix_resource_data_types(resource):
    """Fix resource data types."""
    # When running in client context, some data might
    # not come as a list, so we need to fix it before
    # applying any modifications to it.
    forwarders = resource["idnsforwarders"]
    if isinstance(forwarders, str):
        forwarders = [forwarders]
    elif isinstance(forwarders, tuple):
        forwarders = list(forwarders)
    resource["idnsforwarders"] = forwarders


def main():
    ansible_module = IPAAnsibleModule(
        argument_spec=dict(
            # general
            name=dict(type="list", elements="str", aliases=["cn"],
                      required=True),
            forwarders=dict(type="list", default=None, required=False,
                            aliases=["idnsforwarders"], elements='dict',
                            options=dict(
                                 ip_address=dict(type='str', required=True),
                                 port=dict(type='int', required=False,
                                           default=None),
                            )),
            forwardpolicy=dict(type='str',
                               aliases=["idnsforwardpolicy", "forward_policy"],
                               required=False,
                               choices=['only', 'first', 'none']),
            skip_overlap_check=dict(type='bool', required=False),
            permission=dict(type='bool', required=False,
                            aliases=['managedby']),
            action=dict(type="str", default="dnsforwardzone",
                        choices=["member", "dnsforwardzone"]),
            # state
            state=dict(type='str', default='present',
                       choices=['present', 'absent', 'enabled', 'disabled']),
        ),
        supports_check_mode=True,
    )

    ansible_module._ansible_debug = True

    # Get parameters
    names = ansible_module.params_get("name")
    action = ansible_module.params_get("action")
    forwarders = forwarder_list(
        ansible_module.params_get("forwarders"))
    forwardpolicy = ansible_module.params_get("forwardpolicy")
    skip_overlap_check = ansible_module.params_get("skip_overlap_check")
    permission = ansible_module.params_get("permission")
    state = ansible_module.params_get("state")

    if state == 'present' and len(names) != 1:
        ansible_module.fail_json(
            msg="Only one dnsforwardzone can be added at a time.")
    if state == 'absent' and len(names) < 1:
        ansible_module.fail_json(msg="No name given.")

    # absent stae means delete if the action is NOT member but update if it is
    # if action is member then update an exisiting resource
    # and if action is not member then create a resource
    if state == "absent" and action == "dnsforwardzone":
        operation = "del"
    elif action == "member":
        operation = "update"
    else:
        operation = "add"

    invalid = []
    if state in ["enabled", "disabled"]:
        if action == "member":
            ansible_module.fail_json(
                msg="Action `member` cannot be used with state `%s`"
                    % (state))
        invalid = [
            "forwarders", "forwardpolicy", "skip_overlap_check", "permission"
        ]
        wants_enable = state == "enabled"

    if operation == "del":
        invalid = [
            "forwarders", "forwardpolicy", "skip_overlap_check", "permission"
        ]

    ansible_module.params_fail_used_invalid(invalid, state, action)

    changed = False
    exit_args = {}
    args = {}
    is_enabled = "IGNORE"

    # Connect to IPA API
    with ansible_module.ipa_connect():

        # we need to determine 3 variables
        # args = the values we want to change/set
        # command = the ipa api command to call del, add, or mod
        # is_enabled = is the current resource enabled (True)
        #             disabled (False) and do we care (IGNORE)

        for name in names:
            commands = []
            command = None

            # Make sure forwardzone exists
            existing_resource = find_dnsforwardzone(ansible_module, name)

            # validate parameters
            if state == 'present':
                if existing_resource is None and not forwarders:
                    ansible_module.fail_json(msg='No forwarders specified.')

            if existing_resource is None:
                if operation == "add":
                    # does not exist but should be present
                    # determine args
                    args = gen_args(forwarders, forwardpolicy,
                                    skip_overlap_check)
                    # set command
                    command = "dnsforwardzone_add"
                    # enabled or disabled?

                elif operation == "update":
                    # does not exist and is updating
                    # trying to update something that doesn't exist, so error
                    ansible_module.fail_json(
                        msg="dnsforwardzone '%s' not found." % (name))

                elif operation == "del":
                    # there's nothnig to do.
                    continue

            else:   # existing_resource is not None
                fix_resource_data_types(existing_resource)
                if state != "absent":
                    if forwarders:
                        forwarders = list(
                            set(existing_resource["idnsforwarders"]
                                + forwarders))
                else:
                    if forwarders:
                        forwarders = list(
                            set(existing_resource["idnsforwarders"])
                            - set(forwarders))

                if operation == "add":
                    # exists and should be present, has it changed?
                    # determine args
                    args = gen_args(
                        forwarders, forwardpolicy, skip_overlap_check)
                    if 'skip_overlap_check' in args:
                        del args['skip_overlap_check']

                    # set command
                    if not compare_args_ipa(
                            ansible_module, args, existing_resource):
                        command = "dnsforwardzone_mod"

                elif operation == "del":
                    # exists but should be absent
                    # set command
                    command = "dnsforwardzone_del"
                    args = {}

                elif operation == "update":
                    # exists and is updating
                    # calculate the new forwarders and mod
                    args = gen_args(
                        forwarders, forwardpolicy, skip_overlap_check)
                    if "skip_overlap_check" in args:
                        del args['skip_overlap_check']

                    # command
                    if not compare_args_ipa(
                            ansible_module, args, existing_resource):
                        command = "dnsforwardzone_mod"

            if state in ['enabled', 'disabled']:
                if existing_resource is not None:
                    # FreeIPA 4.9.10+ and 4.10 use proper mapping for
                    # boolean values, so we need to convert it to str
                    # for comparison.
                    # See: https://github.com/freeipa/freeipa/pull/6294
                    is_enabled = (
                        str(existing_resource["idnszoneactive"][0]).upper()
                    )
                else:
                    ansible_module.fail_json(
                        msg="dnsforwardzone '%s' not found." % (name))

            # does the enabled state match what we want (if we care)
            if is_enabled != "IGNORE":
                if wants_enable and is_enabled != "TRUE":
                    commands.append([name, "dnsforwardzone_enable", {}])
                elif not wants_enable and is_enabled != "FALSE":
                    commands.append([name, "dnsforwardzone_disable", {}])

            # if command is set...
            if command is not None:
                commands.append([name, command, args])

            if permission is not None:
                if existing_resource is None:
                    managedby = None
                else:
                    managedby = existing_resource.get('managedby', None)
                if permission and managedby is None:
                    commands.append(
                        [name, 'dnsforwardzone_add_permission', {}]
                    )
                elif not permission and managedby is not None:
                    commands.append(
                        [name, 'dnsforwardzone_remove_permission', {}]
                    )

            # Check mode exit
            if ansible_module.check_mode:
                ansible_module.exit_json(changed=len(commands) > 0,
                                         **exit_args)

            # Execute commands
            for _name, command, args in commands:
                ansible_module.ipa_command(command, _name, args)
                changed = True

    # Done
    ansible_module.exit_json(changed=changed, dnsforwardzone=exit_args)


if __name__ == "__main__":
    main()

#!/usr/bin/python
# -*- coding: utf-8 -*-

# Authors:
#   Chris Procter <cprocter@redhat.com>
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


DOCUMENTATION = '''
---
module: ipa_dnsforwardzone
author: chris procter
short_description: Manage FreeIPA DNS Forwarder Zones
description:
- Add and delete an IPA DNS Forwarder Zones using IPA API
options:
  ipaadmin_principal:
    description: The admin principal
    default: admin
  ipaadmin_password:
    description: The admin password
    required: false
  name:
    description:
    - The DNS zone name which needs to be managed.
    required: true
    aliases: ["cn"]
  state:
    description: State to ensure
    required: false
    default: present
    choices: ["present", "absent", "enabled", "disabled"]
  forwarders:
    description:
    - List of the DNS servers to forward to
    required: true
    type: list
    aliases: ["idnsforwarders"]
  forwardpolicy:
    description: Per-zone conditional forwarding policy
    required: false
    default: only
    choices: ["only", "first", "none"]
    aliases: ["idnsforwarders"]
  skip_overlap_check:
    description:
    - Force DNS zone creation even if it will overlap with an existing zone.
    required: false
    default: false
'''

EXAMPLES = '''
# Ensure dns zone is present
- ipadnsforwardzone:
    ipaadmin_password: MyPassword123
    state: present
    name: example.com
    forwarders:
    - 8.8.8.8
    - 4.4.4.4
    forwardpolicy: first
    skip_overlap_check: true

# Ensure that dns zone is removed
- ipadnsforwardzone:
    ipaadmin_password: MyPassword123
    name: example.com
    state: absent
'''

RETURN = '''
'''


from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.ansible_freeipa_module import temp_kinit, \
    temp_kdestroy, valid_creds, api_connect, api_command, compare_args_ipa, \
    module_params_get


def find_dnsforwardzone(module, name):
    _args = {
        "all": True,
        "idnsname": name
    }
    _result = api_command(module, "dnsforwardzone_find", name, _args)

    if len(_result["result"]) > 1:
        module.fail_json(
            msg="There is more than one dnsforwardzone '%s'" % (name))
    elif len(_result["result"]) == 1:
        return _result["result"][0]
    else:
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


def main():
    ansible_module = AnsibleModule(
        argument_spec=dict(
            # general
            ipaadmin_principal=dict(type="str", default="admin"),
            ipaadmin_password=dict(type="str", required=False, no_log=True),
            name=dict(type="str", aliases=["cn"], default=None,
                      required=True),
            forwarders=dict(type='list', aliases=["idnsforwarders"],
                            required=False),
            forwardpolicy=dict(type='str', aliases=["idnsforwardpolicy"],
                               required=False,
                               choices=['only', 'first', 'none']),
            skip_overlap_check=dict(type='bool', required=False),
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
    ipaadmin_principal = module_params_get(ansible_module,
                                           "ipaadmin_principal")
    ipaadmin_password = module_params_get(ansible_module,
                                          "ipaadmin_password")
    name = module_params_get(ansible_module, "name")
    action = module_params_get(ansible_module, "action")
    forwarders = module_params_get(ansible_module, "forwarders")
    forwardpolicy = module_params_get(ansible_module, "forwardpolicy")
    skip_overlap_check = module_params_get(ansible_module,
                                           "skip_overlap_check")
    state = module_params_get(ansible_module, "state")

    # absent stae means delete if the action is NOT member but update if it is
    # if action is member then update an exisiting resource
    # and if action is not member then create a resource
    if state == "absent" and action == "dnsforwardzone":
        operation = "del"
    elif action == "member":
        operation = "update"
    else:
        operation = "add"

    if state == "disabled":
        wants_enable = False
    else:
        wants_enable = True

    if operation == "del":
        invalid = ["forwarders", "forwardpolicy", "skip_overlap_check"]
        for x in invalid:
            if vars()[x] is not None:
                ansible_module.fail_json(
                    msg="Argument '%s' can not be used with action "
                    "'%s'" % (x, action))

    changed = False
    exit_args = {}
    args = {}
    ccache_dir = None
    ccache_name = None
    is_enabled = "IGNORE"
    try:
        # we need to determine 3 variables
        # args = the values we want to change/set
        # command = the ipa api command to call del, add, or mod
        # is_enabled = is the current resource enabled (True)
        #             disabled (False) and do we care (IGNORE)

        if not valid_creds(ansible_module, ipaadmin_principal):
            ccache_dir, ccache_name = temp_kinit(ipaadmin_principal,
                                                 ipaadmin_password)
        api_connect()

        # Make sure forwardzone exists
        existing_resource = find_dnsforwardzone(ansible_module, name)

        if existing_resource is None and operation == "update":
            # does not exist and is updating
            # trying to update something that doesn't exist, so error
            ansible_module.fail_json(msg="""dnsforwardzone '%s' is not
                                                     valid""" % (name))
        elif existing_resource is None and operation == "del":
            # does not exists and should be absent
            # set command
            command = None
            # enabled or disabled?
            is_enabled = "IGNORE"
        elif existing_resource is not None and operation == "del":
            # exists but should be absent
            # set command
            command = "dnsforwardzone_del"
            # enabled or disabled?
            is_enabled = "IGNORE"
        elif forwarders is None:
            # forwarders are not defined its not a delete, update state?
            # set command
            command = None
            # enabled or disabled?
            if existing_resource is not None:
                is_enabled = existing_resource["idnszoneactive"][0]
            else:
                is_enabled = "IGNORE"
        elif existing_resource is not None and operation == "update":
            # exists and is updating
            # calculate the new forwarders and mod
            # determine args
            if state != "absent":
                forwarders = list(set(existing_resource["idnsforwarders"]
                                      + forwarders))
            else:
                forwarders = list(set(existing_resource["idnsforwarders"])
                                  - set(forwarders))
            args = gen_args(forwarders, forwardpolicy,
                            skip_overlap_check)
            if skip_overlap_check is not None:
                del args['skip_overlap_check']

            # command
            if not compare_args_ipa(ansible_module, args, existing_resource):
                command = "dnsforwardzone_mod"
            else:
                command = None

            # enabled or disabled?
            is_enabled = existing_resource["idnszoneactive"][0]

        elif existing_resource is None and operation == "add":
            # does not exist but should be present
            # determine args
            args = gen_args(forwarders, forwardpolicy,
                            skip_overlap_check)
            # set command
            command = "dnsforwardzone_add"
            # enabled or disabled?
            is_enabled = "TRUE"

        elif existing_resource is not None and operation == "add":
            # exists and should be present, has it changed?
            # determine args
            args = gen_args(forwarders, forwardpolicy, skip_overlap_check)
            if skip_overlap_check is not None:
                del args['skip_overlap_check']

            # set command
            if not compare_args_ipa(ansible_module, args, existing_resource):
                command = "dnsforwardzone_mod"
            else:
                command = None

            # enabled or disabled?
            is_enabled = existing_resource["idnszoneactive"][0]

        # if command is set then run it with the args
        if command is not None:
            api_command(ansible_module, command, name, args)
            changed = True

        # does the enabled state match what we want (if we care)
        if is_enabled != "IGNORE":
            if wants_enable and is_enabled != "TRUE":
                api_command(ansible_module, "dnsforwardzone_enable",
                            name, {})
                changed = True
            elif not wants_enable and is_enabled != "FALSE":
                api_command(ansible_module, "dnsforwardzone_disable",
                            name, {})
                changed = True

    except Exception as e:
        ansible_module.fail_json(msg=str(e))

    finally:
        temp_kdestroy(ccache_dir, ccache_name)

    # Done
    ansible_module.exit_json(changed=changed, dnsforwardzone=exit_args)


if __name__ == "__main__":
    main()

#!/usr/bin/python
# -*- coding: utf-8 -*-
# Authors:
#   Chris Procter <cprocter@redhat.com>
#
# Copyright (C) 2021 Red Hat
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
module: ipaautomountmap
author: Chris Procter
short_description: Manage FreeIPA autommount map
description:
- Add, delete, and modify an IPA automount map
options:
  ipaadmin_principal:
    description: The admin principal.
    default: admin
  ipaadmin_password:
    description: The admin password.
    required: false
  automountlocation:
    description: automount location map is anchored to
    choices: ["location", "automountlocationcn"]
    required: True
  name:
    description: automount map to be managed.
    choices: ["mapname", "map", "automountmapname"]
    required: True
  desc:
    description: description of automount map.
    choices: ["description"]
    required: false
  state:
    description: State to ensure
    required: false
    default: present
    choices: ["present", "absent"]
'''

EXAMPLES = '''
  - name: ensure map named auto.DMZ in location DMZ is present
    ipaautomountmap:
      ipaadmin_password: SomeADMINpassword
      name: auto.DMZ
      location: DMZ
      desc: "this is a map for servers in the DMZ"

  - name: remove a map named auto.DMZ in location DMZ if it exists
    ipaautomountmap:
      ipaadmin_password: SomeADMINpassword
      name: auto.DMZ
      location: DMZ
      state: absent
'''

RETURN = '''
'''

from ansible.module_utils.ansible_freeipa_module import (
    IPAAnsibleModule, compare_args_ipa
)


class AutomountMap(IPAAnsibleModule):

    def __init__(self, *args, **kwargs):
        # pylint: disable=super-with-arguments
        super(AutomountMap, self).__init__(*args, **kwargs)
        self.commands = []

    def get_automountmap(self, location, name):
        try:
            response = self.ipa_command(
                "automountmap_show",
                location,
                {"automountmapname": name, "all": True}
            )
        except Exception:  # pylint: disable=broad-except
            return None
        else:
            return response["result"]

    def check_ipa_params(self):
        invalid = []
        name = self.params_get("name")
        state = self.params_get("state")
        if state == "present":
            if len(name) != 1:
                self.fail_json(msg="Exactly one name must be provided for"
                                   " 'state: present'.")
        if state == "absent":
            if len(name) == 0:
                self.fail_json(msg="At least one 'name' must be provided for"
                                   " 'state: absent'")
            invalid = ["desc"]

        self.params_fail_used_invalid(invalid, state)

    def get_args(self, mapname, desc):  # pylint: disable=no-self-use
        # automountmapname is required for all automountmap operations.
        if not mapname:
            self.fail_json(msg="automountmapname cannot be None or empty.")
        _args = {"automountmapname": mapname}
        # An empty string is valid and will clear the attribute.
        if desc is not None:
            _args["description"] = desc
        return _args

    def define_ipa_commands(self):
        name = self.params_get("name")
        state = self.params_get("state")
        location = self.params_get("location")
        desc = self.params_get("desc")

        for mapname in name:
            automountmap = self.get_automountmap(location, mapname)

            if state == "present":
                args = self.get_args(mapname, desc)
                if automountmap is None:
                    self.commands.append([location, "automountmap_add", args])
                else:
                    if not compare_args_ipa(self, args, automountmap):
                        self.commands.append(
                            [location, "automountmap_mod", args]
                        )

            if state == "absent":
                if automountmap is not None:
                    self.commands.append([
                        location,
                        "automountmap_del",
                        {"automountmapname": [mapname]}
                    ])


def main():
    ipa_module = AutomountMap(
        argument_spec=dict(
            state=dict(type='str',
                       default='present',
                       choices=['present', 'absent']
                       ),
            location=dict(type="str",
                          aliases=["automountlocation", "automountlocationcn"],
                          default=None,
                          required=True
                          ),
            name=dict(type="list",
                      aliases=["mapname", "map", "automountmapname"],
                      default=None,
                      required=True
                      ),
            desc=dict(type="str",
                      aliases=["description"],
                      required=False,
                      default=None
                      ),
        ),
    )
    changed = False
    ipaapi_context = ipa_module.params_get("ipaapi_context")
    with ipa_module.ipa_connect(context=ipaapi_context):
        ipa_module.check_ipa_params()
        ipa_module.define_ipa_commands()
        changed = ipa_module.execute_ipa_commands(ipa_module.commands)
    ipa_module.exit_json(changed=changed)


if __name__ == "__main__":
    main()

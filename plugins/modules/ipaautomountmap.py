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

ANSIBLE_METADATA = {
    "metadata_version": "1.0",
    "supported_by": "community",
    "status": ["preview"],
}


DOCUMENTATION = '''
---
module: ipaautomountmap
author: chris procter
short_description: Manage FreeIPA autommount map
description:
- Add, delete, and modify an IPA automount map
options:
  ipaadmin_principal:
    description: The admin principal
    default: admin
  ipaadmin_password:
    description: The admin password
    required: false
  automountlocation:
    description: automount location map is anchored to
    choices: ["location", "automountlocationcn"]
    required: True
  name:
    description: automount map to be managed
    choices: ["mapname", "map", "automountmapname"]
    required: True
  desc:
    description: description of automount map
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

from ansible.module_utils.ansible_freeipa_module import FreeIPABaseModule


class AutomountMap(FreeIPABaseModule):

    ipa_param_mapping = {
        "automountmapname": "name",
    }

    def get_map(self, location, name):
        response = dict()
        try:
            response = self.api_command("automountmap_show",
                                        location,
                                        {"automountmapname": name})
        except Exception:
            pass

        return response.get("result", None)

    def check_ipa_params(self):

        if self.ipa_params.state == "present":
            if len(self.ipa_params.name) != 1:
                self.fail_json(msg="Exactly one name must be provided \
                                for state=present.")
        else:
            if len(self.ipa_params.name) == 0 :
                self.fail_json(msg="At least one name must be provided \
                                when state=absent.")

    def define_ipa_commands(self):
        args = self.get_ipa_command_args()

        if self.ipa_params.state == "present":
            automountmap = self.get_map(self.ipa_params.location,
                                        self.ipa_params.name[0])
            args['automountmapname'] = self.ipa_params.name[0]
            if automountmap is None:
                # does not exist and is wanted
                self.add_ipa_command(
                    "automountmap_add",
                    name=self.ipa_params.location,
                    args=args
                )
            else:
                # exists and is wanted, check for changes
                if self.ipa_params.desc != \
                        automountmap.get('description', [None])[0]:
                    args['description'] = self.ipa_params.desc
                    self.add_ipa_command(
                        "automountmap_mod",
                        name=self.ipa_params.location,
                        args=args
                    )
        else:
            # exists and is not wanted (i.e. self.ipa_params.state == "absent")
            to_del = [x for x in self.ipa_params.name
                      if self.get_map(self.ipa_params.location, x) is not None]

            if len(to_del) > 0:
                self.add_ipa_command(
                    "automountmap_del",
                    name=self.ipa_params.location,
                    args={"automountmapname": to_del}
                )


def main():
    ipa_module = AutomountMap(
        argument_spec=dict(
            ipaadmin_principal=dict(type="str",
                                    default="admin"
                                    ),
            ipaadmin_password=dict(type="str",
                                   required=False,
                                   no_log=True
                                   ),
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
    ipa_module.ipa_run()


if __name__ == "__main__":
    main()

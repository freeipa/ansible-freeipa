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
module: ipa_automountmap
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
  location:
    description: automount location map is in
    required: True
    choices: ["automountlocationcn"]
  mapname:
    description: automount map to be managed
    choices: ["cn", "name", "map", "automountmapname"],
    required: True
  desc:
    choices: ["description"],
    required: false
  state:
    description: State to ensure
    required: false
    default: present
    choices: ["present", "absent"]
'''

EXAMPLES = '''
  - name: ensure map named auto.DMZ in location DMZ is created
    ipaautomountmap:
      ipaadmin_password: password01
      name: auto.DMZ
      location: DMZ
      desc: "this is a map for servers in the DMZ"

  - name: remove a map named auto.DMZ in location DMZ if it exists
    ipaautomountmap:
      ipaadmin_password: password01
      name: auto.DMZ
      location: DMZ
      state: absent
'''

RETURN = '''
'''

from ansible.module_utils.ansible_freeipa_module import FreeIPABaseModule


class AutomountLocation(FreeIPABaseModule):

    ipa_param_mapping = {
        "automountmapname": "mapname",
    }

    def get_map(self, location, args):
        response = dict()
        try:
            # if the location doesn't exists this throws an error
            # rather than just returning nothing
            response = self.api_command("automountmap_find",
                                        location,
                                        args)
        except Exception:
            pass

        if response.get("count", 0) == 1:
            self.map = response["result"][0]
        else:
            self.map = None
        return self.map

    @property
    def location_name(self):
        return self.ipa_params.location

    def define_ipa_commands(self):
        args = self.get_ipa_command_args()
        self.get_map(self.location_name, args)

        if not self.map and self.ipa_params.state == "present":
            # does not exist and is wanted
            self.add_ipa_command(
                "automountmap_add",
                name=self.location_name,
                args=args
            )
        elif self.map is not None and self.ipa_params.state == "present":
            # exists and is wanted, check for changes
            if self.ipa_params.desc != self.map.get('description', [None])[0]:
                args['description'] = self.ipa_params.desc
                self.add_ipa_command(
                    "automountmap_mod",
                    name=self.location_name,
                    args=args
                )
        elif self.map and self.ipa_params.state == "absent":
            # exists and is not wanted
            self.add_ipa_command(
                "automountmap_del",
                name=self.location_name,
                args=args
            )


def main():
    ipa_module = AutomountLocation(
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
                          aliases=["automountlocationcn"],
                          default=None,
                          required=True
                          ),
            mapname=dict(type="str",
                         aliases=["cn", "name", "map", "automountmapname"],
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

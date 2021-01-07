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
module: ipa_automountlocation
author: chris procter
short_description: Manage FreeIPA autommount locations
description:
- Add and delete an IPA automount location
options:
  ipaadmin_principal:
    description: The admin principal
    default: admin
  ipaadmin_password:
    description: The admin password
    required: false
  name:
    description: The automount location to be managed
    required: true
    aliases: ["cn","location"]
  state:
    description: State to ensure
    required: false
    default: present
    choices: ["present", "absent"]
'''

EXAMPLES = '''
  - name: ensure a automount location named DMZ exists
    ipaautomountlocation:
      ipaadmin_password: password01
      name: DMZ
      state: present

  - name: remove an automount location named DMZ if it exists
    ipaautomountlocation:
      ipaadmin_password: password01
      name: DMZ
      state: absent
'''

RETURN = '''
'''

from ansible.module_utils.ansible_freeipa_module import FreeIPABaseModule


class AutomountLocation(FreeIPABaseModule):

    ipa_param_mapping = {}

    def get_location(self, location):
        response = self.api_command("automountlocation_find",
                                    location,
                                    args={"cn": location})

        if response["count"] == 1:
            self.location = response["result"][0]
        else:
            self.location = None
        return self.location

    @property
    def location_name(self):
        return self.ipa_params.name

    def define_ipa_commands(self):
        self.get_location(self.location_name)

        if not self.location and self.ipa_params.state == "present":
            # does not exist and is wanted
            self.add_ipa_command(
                "automountlocation_add",
                name=self.location_name,
                args=None,
            )
        elif self.location and self.ipa_params.state == "absent":
            # exists and is not wanted
            self.add_ipa_command(
                "automountlocation_del",
                name=self.location_name,
                args=None,
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
            name=dict(type="str",
                      aliases=["cn", "location"],
                      default=None,
                      required=True
                      ),
        ),
    )
    ipa_module.ipa_run()


if __name__ == "__main__":
    main()

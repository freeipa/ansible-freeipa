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
    choices: ["map", "automountmapname"],
    required: True
  key:
    description: automount key to be managed
    required: true,
    choicesr: ["name", "automountkey" ]
  info:
    description: Mount information for the key
    required: true when state is 'present'
    choices: ["information","automountinformation"]
  state:
    description: State to ensure
    required: false
    default: present
    choices: ["present", "absent"]
'''

EXAMPLES = '''
  - name: create key TestKey
    ipaautomountkey:
      ipaadmin_password: password01
      locationcn: TestLocation
      mapname: TestMap
      key: TestKey
      info: 192.168.122.1:/exports
      state: present

  - name: ensure key TestKey is absent
    ipaautomountkey:
      ipaadmin_password: password01
      location: TestLocation
      mapname: TestMap
      key: TestKey
      state: absent
'''

RETURN = '''
'''


from ansible.module_utils.ansible_freeipa_module import FreeIPABaseModule


class AutomountLocation(FreeIPABaseModule):

    ipa_param_mapping = {
        'automountkey': "key",
        'automountmapautomountmapname': "mapname",
    }

    def get_key(self, name, args):
        response = dict()
        try:
            response = self.api_command("automountkey_find", name, args)
        except Exception:
            pass

        if response.get("count", 0) == 1:
            self.key = response["result"][0]
        else:
            self.key = None
        return self.key

    def check_ipa_params(self):
        if not self.ipa_params.info and self.ipa_params.state == "present":
            self.fail_json(msg="Value required for argument 'info'")

    @property
    def location_name(self):
        return self.ipa_params.location

    @property
    def automountinformation(self):
        return self.key.get('automountinformation', [None])[0]

    def define_ipa_commands(self):
        args = self.get_ipa_command_args()
        self.get_key(self.location_name, args)

        if not self.key and self.ipa_params.state == "present":
            # does not exist and is wanted
            args["automountinformation"] = self.ipa_params.info
            self.add_ipa_command(
                "automountkey_add",
                name=self.location_name,
                args=args
            )
        elif self.key is not None and self.ipa_params.state == "present":
            # exists and is wanted, check for changes
            if self.ipa_params.info != self.automountinformation:
                args["newautomountinformation"] = self.ipa_params.info
                self.add_ipa_command(
                    "automountkey_mod",
                    name=self.location_name,
                    args=args
                )
        elif self.key and self.ipa_params.state == "absent":
            # exists and is not wanted
            self.add_ipa_command(
                "automountkey_del",
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
                         aliases=["map", "automountmapname"],
                         default=None,
                         required=True
                         ),
            key=dict(type="str",
                     required=True,
                     aliases=["name", "automountkey"]
                     ),
            info=dict(type="str",
                      aliases=["information", "automountinformation"]
                      ),
        ),
    )
    ipa_module.ipa_run()


if __name__ == "__main__":
    main()

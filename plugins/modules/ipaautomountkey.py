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
module: ipaautomountkey
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
    required: False
  location:
    description: automount location map is in
    required: True
    choices: ["automountlocationcn", "automountlocation"]
  mapname:
    description: automount map to be managed
    choices: ["map", "automountmapname", "automountmap"]
    required: True
  key:
    description: automount key to be managed
    required: True
    choices: ["name", "automountkey"]
  newkey:
    description: key to change to if state=rename
    required: True
    choices: ["newname", "newautomountkey"]
  info:
    description: Mount information for the key
    required: True
    choices: ["information", "newinfo", "automountinformation"]
  state:
    description: State to ensure
    required: False
    default: present
    choices: ["present", "absent", "rename"]
'''

EXAMPLES = '''
  - name: create key TestKey
    ipaautomountkey:
      ipaadmin_password: SomeADMINpassword
      locationcn: TestLocation
      mapname: TestMap
      key: TestKey
      info: 192.168.122.1:/exports
      state: present

  - name: ensure key TestKey is absent
    ipaautomountkey:
      ipaadmin_password: SomeADMINpassword
      location: TestLocation
      mapname: TestMap
      key: TestKey
      state: absent
'''

RETURN = '''
'''

from ansible.module_utils.ansible_freeipa_module import (
    FreeIPABaseModule, ipalib_errors
)


class AutomountKey(FreeIPABaseModule):

    ipa_param_mapping = {
        'automountkey': "key",
        'automountmapautomountmapname': "mapname",
    }

    def get_key(self, location, mapname, keyname):
        resp = dict()
        try:
            resp = self.api_command("automountkey_show",
                                    location,
                                    {"automountmapautomountmapname": mapname,
                                     "automountkey": keyname})
        except ipalib_errors.NotFound:
            pass

        return resp.get("result", None)

    def check_ipa_params(self):
        if not self.ipa_params.info and self.ipa_params.state == "present":
            self.fail_json(msg="Value required for argument 'info'")

        if self.ipa_params.state == "rename" and \
           self.ipa_params.newname is None:
            self.fail_json(msg="newname is required if state = 'rename'")

    def define_ipa_commands(self):
        args = self.get_ipa_command_args()
        key = self.get_key(self.ipa_params.location,
                           self.ipa_params.mapname,
                           self.ipa_params.key)

        if self.ipa_params.state == "present":
            if key is None:
                # does not exist and is wanted
                args["automountinformation"] = self.ipa_params.info
                self.add_ipa_command(
                    "automountkey_add",
                    name=self.ipa_params.location,
                    args=args
                )
            elif key is not None:
                # exists and is wanted, check for changes
                if self.ipa_params.info != \
                        key.get('automountinformation', [None])[0]:
                    args["newautomountinformation"] = self.ipa_params.info
                    self.add_ipa_command(
                        "automountkey_mod",
                        name=self.ipa_params.location,
                        args=args
                    )
        elif self.ipa_params.state == "rename":
            if key is not None:
                newkey = self.get_key(self.ipa_params.location,
                                      self.ipa_params.mapname,
                                      self.ipa_params.newname)

                args["rename"] = self.ipa_params.newname
                if newkey is None:
                    self.add_ipa_command(
                        "automountkey_mod",
                        name=self.ipa_params.location,
                        args=args
                    )
        else:
            # if key exists and self.ipa_params.state == "absent":
            if key is not None:
                self.add_ipa_command(
                    "automountkey_del",
                    name=self.ipa_params.location,
                    args=args
                )


def main():
    ipa_module = AutomountKey(
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
                       choices=['present', 'absent', 'rename']
                       ),
            location=dict(type="str",
                          aliases=["automountlocationcn", "automountlocation"],
                          default=None,
                          required=True
                          ),
            newname=dict(type="str",
                         aliases=["newkey", "new_name",
                                  "new_key", "newautomountkey"],
                         default=None,
                         required=False
                         ),
            mapname=dict(type="str",
                         aliases=["map", "automountmapname", "automountmap"],
                         default=None,
                         required=True
                         ),
            key=dict(type="str",
                     required=True,
                     aliases=["name", "automountkey"]
                     ),
            info=dict(type="str",
                      aliases=["information", "newinfo",
                               "automountinformation"]
                      ),
        ),
    )
    ipa_module.ipa_run()


if __name__ == "__main__":
    main()

#!/usr/bin/python
# -*- coding: utf-8 -*-

# Authors:
#   Chris Procter <cprocter@redhat.com>
#   Thomas Woerner <twoerner@redhat.com>
#
# Copyright (C) 2021-2022 Red Hat
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
module: ipaautomountkey
author:
  - Chris Procter (@chr15p))
  - Thomas Woerner (@t-woerner)
short_description: Manage FreeIPA autommount map
description:
- Add, delete, and modify an IPA automount map
extends_documentation_fragment:
  - ipamodule_base_docs
options:
  location:
    description: automount location map is in
    type: str
    required: True
    aliases: ["automountlocationcn", "automountlocation"]
  mapname:
    description: automount map to be managed
    type: str
    aliases: ["map", "automountmapname", "automountmap"]
    required: True
  key:
    description: automount key to be managed
    type: str
    required: True
    aliases: ["name", "automountkey"]
  rename:
    description: key to change to if state is 'renamed'
    type: str
    required: False
    aliases: ["new_name", "newautomountkey"]
  info:
    description: Mount information for the key
    type: str
    required: False
    aliases: ["information", "automountinformation"]
  state:
    description: State to ensure
    type: str
    required: False
    default: present
    choices: ["present", "absent", "renamed"]
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
    IPAAnsibleModule, ipalib_errors
)


class AutomountKey(IPAAnsibleModule):

    def __init__(self, *args, **kwargs):
        # pylint: disable=super-with-arguments
        super(AutomountKey, self).__init__(*args, **kwargs)
        self.commands = []

    def get_key(self, location, mapname, key):
        try:
            args = {
                "automountmapautomountmapname": mapname,
                "automountkey": key,
                "all": True,
            }
            resp = self.ipa_command("automountkey_show", location, args)
        except ipalib_errors.NotFound:
            return None
        return resp.get("result")

    def check_ipa_params(self):
        invalid = []
        state = self.params_get("state")
        if state == "present":
            invalid = ["rename"]
            if not self.params_get("info"):
                self.fail_json(msg="Value required for argument 'info'")

        if state == "rename":
            invalid = ["info"]
            if not self.params_get("rename"):
                self.fail_json(msg="Value required for argument 'renamed'")

        if state == "absent":
            invalid = ["info", "rename"]

        self.params_fail_used_invalid(invalid, state)

    @staticmethod
    def get_args(mapname, key, info, rename):
        _args = {}
        if mapname:
            _args["automountmapautomountmapname"] = mapname
        if key:
            _args["automountkey"] = key
        if info:
            _args["automountinformation"] = info
        if rename:
            _args["rename"] = rename
        return _args

    def define_ipa_commands(self):
        state = self.params_get("state")
        location = self.params_get("location")
        mapname = self.params_get("mapname")
        key = self.params_get("key")
        info = self.params_get("info")
        rename = self.params_get("rename")

        args = self.get_args(mapname, key, info, rename)

        res_find = self.get_key(location, mapname, key)

        if state == "present":
            if res_find is None:
                # does not exist and is wanted
                self.commands.append([location, "automountkey_add", args])
            else:
                # exists and is wanted, check for changes
                if info not in res_find.get("automountinformation"):
                    self.commands.append([location, "automountkey_mod", args])

        if state == "renamed":
            if res_find is None:
                self.fail_json(
                    msg=(
                        "Cannot rename inexistent key: '%s', '%s', '%s'"
                        % (location, mapname, key)
                    )
                )
            self.commands.append([location, "automountkey_mod", args])

        if state == "absent":
            # if key exists and self.ipa_params.state == "absent":
            if res_find is not None:
                self.commands.append([location, "automountkey_del", args])


def main():
    ipa_module = AutomountKey(
        argument_spec=dict(
            state=dict(
                type='str',
                choices=['present', 'absent', 'renamed'],
                required=False,
                default='present',
            ),
            location=dict(
                type="str",
                aliases=["automountlocationcn", "automountlocation"],
                required=True,
            ),
            rename=dict(
                type="str",
                aliases=["new_name", "newautomountkey"],
                required=False,
            ),
            mapname=dict(
                type="str",
                aliases=["map", "automountmapname", "automountmap"],
                required=True,
            ),
            key=dict(
                type="str",
                aliases=["name", "automountkey"],
                required=True,
                no_log=False,
            ),
            info=dict(
                type="str",
                aliases=["information", "automountinformation"],
                required=False,
            ),
        ),
    )
    ipaapi_context = ipa_module.params_get("ipaapi_context")
    with ipa_module.ipa_connect(context=ipaapi_context):
        ipa_module.check_ipa_params()
        ipa_module.define_ipa_commands()
        changed = ipa_module.execute_ipa_commands(ipa_module.commands)
    ipa_module.exit_json(changed=changed)


if __name__ == "__main__":
    main()

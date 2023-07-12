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
module: ipaautomountmap
author:
  - Chris Procter (@chr15p)
  - Thomas Woerner (@t-woerner)
  - Rafael Jeffman (@rjeffman)
short_description: Manage FreeIPA autommount map
description:
- Add, delete, and modify an IPA automount map
extends_documentation_fragment:
  - ipamodule_base_docs
options:
  automountlocation:
    description: automount location map is anchored to
    type: str
    aliases: ["location", "automountlocationcn"]
    required: True
  name:
    description: automount map to be managed.
    type: list
    elements: str
    aliases: ["mapname", "map", "automountmapname"]
    required: True
  desc:
    description: description of automount map.
    type: str
    aliases: ["description"]
    required: false
  parentmap:
    description: |
      Parent map of the indirect map. Can only be used when creating
      new maps.
    type: str
    required: false
  mount:
    description: Indirect map mount point, relative to parent map.
    type: str
    required: false
  state:
    description: State to ensure
    type: str
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

  - name: ensure indirect map exists
    ipaautomountmap:
      ipaadmin_password: SomeADMINpassword
      name: auto.INDIRECT
      location: DMZ
      parentmap: auto.DMZ
      mount: indirect

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
        return response["result"]

    def get_indirect_map_keys(self, location, name):
        """Check if 'name' is an indirect map for 'parentmap'."""
        try:
            maps = self.ipa_command("automountmap_find", location, {})
        except Exception:  # pylint: disable=broad-except
            return []

        result = []
        for check_map in maps.get("result", []):
            _mapname = check_map['automountmapname'][0]
            keys = self.ipa_command(
                "automountkey_find",
                location,
                {
                    "automountmapautomountmapname": _mapname,
                    "all": True
                }
            )
            cmp_value = (
                name if _mapname == "auto.master" else "ldap:{0}".format(name)
            )
            result.extend([
                (location, _mapname, key.get("automountkey")[0])
                for key in keys.get("result", [])
                for mount_info in key.get("automountinformation", [])
                if cmp_value in mount_info
            ])
        return result

    def check_ipa_params(self):
        invalid = []
        name = self.params_get("name")
        state = self.params_get("state")
        if state == "present":
            if len(name) != 1:
                self.fail_json(msg="Exactly one name must be provided for"
                                   " 'state: present'.")
            mount = self.params_get("mount") or False
            parentmap = self.params_get("parentmap")
            if parentmap:
                if not mount:
                    self.fail_json(
                        msg="Must provide 'mount' parameter for indirect map."
                    )
                elif parentmap != "auto.master" and mount[0] == "/":
                    self.fail_json(
                        msg="mount point is relative to parent map, "
                            "cannot begin with '/'"
                    )
        if state == "absent":
            if len(name) == 0:
                self.fail_json(msg="At least one 'name' must be provided for"
                                   " 'state: absent'")
            invalid = ["desc", "parentmap", "mount"]

        self.params_fail_used_invalid(invalid, state)

    def get_args(self, mapname, desc, parentmap, mount):
        # automountmapname is required for all automountmap operations.
        if not mapname:
            self.fail_json(msg="automountmapname cannot be None or empty.")
        _args = {"automountmapname": mapname}
        # An empty string is valid and will clear the attribute.
        if desc is not None:
            _args["description"] = desc
        # indirect map attributes
        if parentmap is not None:
            _args["parentmap"] = parentmap
        if mount is not None:
            _args["key"] = mount
        return _args

    def define_ipa_commands(self):
        name = self.params_get("name")
        state = self.params_get("state")
        location = self.params_get("location")
        desc = self.params_get("desc")
        mount = self.params_get("mount")
        parentmap = self.params_get("parentmap")

        for mapname in name:
            automountmap = self.get_automountmap(location, mapname)

            is_indirect_map = any([parentmap, mount])

            if state == "present":
                args = self.get_args(mapname, desc, parentmap, mount)
                if automountmap is None:
                    if is_indirect_map:
                        if (
                            parentmap and
                            self.get_automountmap(location, parentmap) is None
                        ):
                            self.fail_json(msg="Parent map does not exist.")
                        self.commands.append(
                            [location, "automountmap_add_indirect", args]
                        )
                    else:
                        self.commands.append(
                            [location, "automountmap_add", args]
                        )
                else:
                    has_changes = not compare_args_ipa(
                        self, args, automountmap, ['parentmap', 'key']
                    )
                    if is_indirect_map:
                        map_config = (
                            location, parentmap or "auto.master", mount
                        )
                        indirects = self.get_indirect_map_keys(
                            location, mapname
                        )
                        if map_config not in indirects or has_changes:
                            self.fail_json(
                                msg="Indirect maps can only be created, "
                                    "not modified."
                            )
                    elif has_changes:
                        self.commands.append(
                            [location, "automountmap_mod", args]
                        )

            elif state == "absent":
                def find_keys(parent_loc, parent_map, parent_key):
                    return self.ipa_command(
                        "automountkey_show",
                        parent_loc,
                        {
                            "automountmapautomountmapname": parent_map,
                            "automountkey": parent_key,
                        }
                    ).get("result")

                if automountmap is not None:
                    indirects = self.get_indirect_map_keys(location, mapname)
                    # Remove indirect map configurations for this map
                    self.commands.extend([
                        (
                            ploc,
                            "automountkey_del",
                            {
                                "automountmapautomountmapname": pmap,
                                "automountkey": pkey,
                            }
                        )
                        for ploc, pmap, pkey in indirects
                        if find_keys(ploc, pmap, pkey)
                    ])
                    # Remove map
                    self.commands.append([
                        location,
                        "automountmap_del",
                        {"automountmapname": [mapname]}
                    ])

            # ensure commands are unique and automountkey commands are
            # executed first in the list
            def hashable_dict(dictionaire):
                return tuple(
                    (k, tuple(v) if isinstance(v, (list, tuple)) else v)
                    for k, v in dictionaire.items()
                )

            cmds = [
                (name, cmd, hashable_dict(args))
                for name, cmd, args in self.commands
            ]
            self.commands = [
                (name, cmd, dict(args))
                for name, cmd, args in
                sorted(set(cmds), key=lambda cmd: cmd[1])
            ]


def main():
    ipa_module = AutomountMap(
        argument_spec=dict(
            state=dict(type='str',
                       default='present',
                       choices=['present', 'absent']
                       ),
            location=dict(type="str",
                          aliases=["automountlocation", "automountlocationcn"],
                          required=True
                          ),
            name=dict(type="list", elements="str",
                      aliases=["mapname", "map", "automountmapname"],
                      required=True
                      ),
            desc=dict(type="str",
                      aliases=["description"],
                      required=False,
                      default=None
                      ),
            parentmap=dict(
                type="str", required=False, default=None
            ),
            mount=dict(type="str", required=False, default=None),
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

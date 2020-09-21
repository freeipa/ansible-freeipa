#!/usr/bin/python
# -*- coding: utf-8 -*-

# Authors:
#   Thomas Woerner <twoerner@redhat.com>
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

DOCUMENTATION = """
---
module: ipatopologysegment
short description: Manage FreeIPA topology segments
description: Manage FreeIPA topology segments
options:
  ipaadmin_principal:
    description: The admin principal
    default: admin
  ipaadmin_password:
    description: The admin password
    required: false
  suffix:
    description: Topology suffix
    required: true
    choices: ["domain", "ca", "domain+ca"]
  name:
    description: Topology segment name, unique identifier.
    required: false
    aliases: ["cn"]
  left:
    description: Left replication node - an IPA server
    aliases: ["leftnode"]
  right:
    description: Right replication node - an IPA server
    aliases: ["rightnode"]
  direction:
    description: The direction a segment will be reinitialized
    required: false
    choices: ["left-to-right", "right-to-left"]
  state:
    description: State to ensure
    default: present
    choices: ["present", "absent", "enabled", "disabled", "reinitialized",
              "checked" ]
author:
    - Thomas Woerner
"""

EXAMPLES = """
- ipatopologysegment:
    suffix: domain
    left: ipaserver.test.local
    right: ipareplica1.test.local
    state: present

- ipatopologysegment:
    suffix: domain
    name: ipaserver.test.local-to-replica1.test.local
    state: absent

- ipatopologysegment:
    suffix: domain
    left: ipaserver.test.local
    right: ipareplica1.test.local
    state: absent

- ipatopologysegment:
    suffix: ca
    name: ipaserver.test.local-to-replica1.test.local
    direction: left-to-right
    state: reinitialized

- ipatopologysegment:
    suffix: domain+ca
    left: ipaserver.test.local
    right: ipareplica1.test.local
    state: absent

- ipatopologysegment:
    suffix: domain+ca
    left: ipaserver.test.local
    right: ipareplica1.test.local
    state: checked
"""

RETURN = """
found:
  description: List of found segments
  returned: if state is checked
  type: list
not-found:
  description: List of not found segments
  returned: if state is checked
  type: list
"""

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_text
from ansible.module_utils.ansible_freeipa_module import temp_kinit, \
    temp_kdestroy, valid_creds, api_connect, api_command


def find_left_right(module, suffix, left, right):
    _args = {
        "iparepltoposegmentleftnode": to_text(left),
        "iparepltoposegmentrightnode": to_text(right),
    }
    _result = api_command(module, "topologysegment_find",
                          to_text(suffix), _args)
    if len(_result["result"]) > 1:
        module.fail_json(
            msg="Combination of left node '%s' and right node '%s' is "
            "not unique for suffix '%s'" % (left, right, suffix))
    elif len(_result["result"]) == 1:
        return _result["result"][0]
    else:
        return None


def find_cn(module, suffix, name):
    _args = {
        "cn": to_text(name),
    }
    _result = api_command(module, "topologysegment_find",
                          to_text(suffix), _args)
    if len(_result["result"]) > 1:
        module.fail_json(
            msg="CN '%s' is not unique for suffix '%s'" % (name, suffix))
    elif len(_result["result"]) == 1:
        return _result["result"][0]
    else:
        return None


def find_left_right_cn(module, suffix, left, right, name):
    if left is not None and right is not None:
        left_right = find_left_right(module, suffix, left, right)
        if left_right is not None:
            if name is not None and \
               left_right["cn"][0] != to_text(name):
                module.fail_json(
                    msg="Left and right nodes do not match "
                    "given name name (cn) '%s'" % name)
            return left_right
        # else: Nothing to change
    elif name is not None:
        cn = find_cn(module, suffix, name)
        if cn is not None:
            return cn
        # else: Nothing to change
    else:
        module.fail_json(
            msg="Either left and right or name need to be set.")
    return None


def main():
    ansible_module = AnsibleModule(
        argument_spec=dict(
            ipaadmin_principal=dict(type="str", default="admin"),
            ipaadmin_password=dict(type="str", required=False, no_log=True),
            suffix=dict(choices=["domain", "ca", "domain+ca"], required=True),
            name=dict(type="str", aliases=["cn"], default=None),
            left=dict(type="str", aliases=["leftnode"], default=None),
            right=dict(type="str", aliases=["rightnode"], default=None),
            direction=dict(type="str", default=None,
                           choices=["left-to-right", "right-to-left"]),
            state=dict(type="str", default="present",
                       choices=["present", "absent", "enabled", "disabled",
                                "reinitialized", "checked"]),
        ),
        supports_check_mode=True,
    )

    ansible_module._ansible_debug = True

    # Get parameters

    ipaadmin_principal = ansible_module.params.get("ipaadmin_principal")
    ipaadmin_password = ansible_module.params.get("ipaadmin_password")
    suffixes = ansible_module.params.get("suffix")
    name = ansible_module.params.get("name")
    left = ansible_module.params.get("left")
    right = ansible_module.params.get("right")
    direction = ansible_module.params.get("direction")
    state = ansible_module.params.get("state")

    # Check parameters

    if state != "reinitialized" and direction is not None:
        ansible_module.fail_json(
            msg="Direction is not supported in this mode.")

    # Init

    changed = False
    exit_args = {}
    ccache_dir = None
    ccache_name = None
    try:
        if not valid_creds(ansible_module, ipaadmin_principal):
            ccache_dir, ccache_name = temp_kinit(ipaadmin_principal,
                                                 ipaadmin_password)
        api_connect()

        commands = []

        for suffix in suffixes.split("+"):
            # Create command
            if state in ["present", "enabled"]:
                # Make sure topology segment exists

                if left is None or right is None:
                    ansible_module.fail_json(
                        msg="Left and right need to be set.")
                args = {
                    "iparepltoposegmentleftnode": to_text(left),
                    "iparepltoposegmentrightnode": to_text(right),
                }
                if name is not None:
                    args["cn"] = to_text(name)

                res_left_right = find_left_right(ansible_module, suffix,
                                                 left, right)
                if res_left_right is not None:
                    if name is not None and \
                       res_left_right["cn"][0] != to_text(name):
                        ansible_module.fail_json(
                            msg="Left and right nodes already used with "
                            "different name (cn) '%s'" % res_left_right["cn"])

                    # Left and right nodes and also the name can not be
                    # changed
                    for key in ["iparepltoposegmentleftnode",
                                "iparepltoposegmentrightnode"]:
                        if key in args:
                            del args[key]
                    if len(args) > 1:
                        # cn needs to be in args always
                        commands.append(["topologysegment_mod", args, suffix])
                    # else: Nothing to change
                else:
                    if name is None:
                        args["cn"] = to_text("%s-to-%s" % (left, right))
                    commands.append(["topologysegment_add", args, suffix])

            elif state in ["absent", "disabled"]:
                # Make sure topology segment does not exist

                res_find = find_left_right_cn(ansible_module, suffix,
                                              left, right, name)
                if res_find is not None:
                    # Found either given name or found name from left and right
                    # node
                    args = {
                        "cn": res_find["cn"][0]
                    }
                    commands.append(["topologysegment_del", args, suffix])

            elif state == "checked":
                # Check if topology segment does exists

                res_find = find_left_right_cn(ansible_module, suffix,
                                              left, right, name)
                if res_find is not None:
                    # Found either given name or found name from left and right
                    # node
                    exit_args.setdefault("found", []).append(suffix)
                else:
                    # Not found
                    exit_args.setdefault("not-found", []).append(suffix)

            elif state == "reinitialized":
                # Reinitialize segment

                if direction not in ["left-to-right", "right-to-left"]:
                    ansible_module.fail_json(msg="Unknown direction '%s'" %
                                             direction)

                res_find = find_left_right_cn(ansible_module, suffix,
                                              left, right, name)
                if res_find is not None:
                    # Found either given name or found name from left and right
                    # node
                    args = {
                        "cn": res_find["cn"][0]
                    }
                    if direction == "left-to-right":
                        args["left"] = True
                    elif direction == "right-to-left":
                        args["right"] = True

                    commands.append(["topologysegment_reinitialize", args,
                                     suffix])
                else:
                    params = []
                    if name is not None:
                        params.append("name=%s" % name)
                    if left is not None:
                        params.append("left=%s" % left)
                    if right is not None:
                        params.append("right=%s" % right)
                    ansible_module.fail_json(
                        msg="No entry '%s' for suffix '%s'" %
                        (",".join(params), suffix))

            else:
                ansible_module.fail_json(msg="Unkown state '%s'" % state)

        # Execute command

        for command, args, _suffix in commands:
            api_command(ansible_module, command, to_text(_suffix), args)
            changed = True

    except Exception as e:
        ansible_module.fail_json(msg=str(e))

    finally:
        temp_kdestroy(ccache_dir, ccache_name)

    # Done

    ansible_module.exit_json(changed=changed, **exit_args)


if __name__ == "__main__":
    main()

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
module: ipatopologysuffix
short description: Verify FreeIPA topology suffix
description: Verify FreeIPA topology suffix
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
    choices: ["domain", "ca"]
  state:
    description: State to ensure
    default: verified
    choices: ["verified"]
author:
    - Thomas Woerner
"""

EXAMPLES = """
- ipatopologysuffix:
    suffix: domain
    state: verified
"""

RETURN = """
"""

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_text
from ansible.module_utils.ansible_freeipa_module import execute_api_command


def main():
    ansible_module = AnsibleModule(
        argument_spec=dict(
            ipaadmin_principal=dict(type="str", default="admin"),
            ipaadmin_password=dict(type="str", required=False, no_log=True),
            suffix=dict(choices=["domain", "ca"], required=True),
            state=dict(type="str", default="verified",
                       choices=["verified"]),
        ),
        supports_check_mode=True,
    )

    ansible_module._ansible_debug = True

    # Get parameters

    ipaadmin_principal = ansible_module.params.get("ipaadmin_principal")
    ipaadmin_password = ansible_module.params.get("ipaadmin_password")
    suffix = ansible_module.params.get("suffix")
    state = ansible_module.params.get("state")

    # Check parameters

    # Init

    # Create command

    if state in ["verified"]:
        command = "topologysuffix_verify"
        args = {}
    else:
        ansible_module.fail_json(msg="Unkown state '%s'" % state)

    # Execute command

    execute_api_command(ansible_module, ipaadmin_principal, ipaadmin_password,
                        command, to_text(suffix), args)

    # Done

    ansible_module.exit_json(changed=True)


if __name__ == "__main__":
    main()

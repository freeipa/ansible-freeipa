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
module: ipahost
short description: Manage FreeIPA hosts
description: Manage FreeIPA hosts
options:
  ipaadmin_principal:
    description: The admin principal
    default: admin
  ipaadmin_password:
    description: The admin password
    required: false
  name:
    description: The full qualified domain name.
    aliases: ["fqdn"]
    required: true
  description:
    description: The host description
    required: false
  locality:
    description: Host locality (e.g. "Baltimore, MD")
    required: false
  location:
    description: Host location (e.g. "Lab 2")
    aliases: ["ns_host_location"]
    required: false
  platform:
    description: Host hardware platform (e.g. "Lenovo T61")
    aliases: ["ns_hardware_platform"]
    required: false
  os:
    description: Host operating system and version (e.g. "Fedora 9")
    aliases: ["ns_os_version"]
    required: false
  password:
    description: Password used in bulk enrollment
    aliases: ["user_password", "userpassword"]
    required: false
  random:
    description:
      Initiate the generation of a random password to be used in bulk
      enrollment
    aliases: ["random_password"]
    required: false
  mac_address:
    description: List of hardware MAC addresses.
    type: list
    aliases: ["macaddress"]
    required: false
  force:
    description: Force host name even if not in DNS
    required: false
  reverse:
    description: Reverse DNS detection
    default: true
    required: false
  ip_address:
    description: The host IP address
    aliases: ["ipaddress"]
    required: false
  update_dns:
    description: Update DNS entries
    required: false
  update_password:
    description:
      Set password for a host in present state only on creation or always
    default: 'always'
    choices: ["always", "on_create"]
  state:
    description: State to ensure
    default: present
    choices: ["present", "absent",
              "disabled"]
author:
    - Thomas Woerner
"""

EXAMPLES = """
# Ensure host is present
- ipahost:
    ipaadmin_password: MyPassword123
    name: host01.example.com
    description: Example host
    ip_address: 192.168.0.123
    locality: Lab
    ns_host_location: Lab
    ns_os_version: CentOS 7
    ns_hardware_platform: Lenovo T61
    mac_address:
    - "08:00:27:E3:B1:2D"
    - "52:54:00:BD:97:1E"
    state: present

# Ensure host is present without DNS
- ipahost:
    ipaadmin_password: MyPassword123
    name: host02.example.com
    description: Example host
    force: yes

# Initiate generation of a random password for the host
- ipahost:
    ipaadmin_password: MyPassword123
    name: host01.example.com
    description: Example host
    ip_address: 192.168.0.123
    random: yes

# Ensure host is disabled
- ipahost:
    ipaadmin_password: MyPassword123
    name: host01.example.com
    update_dns: yes
    state: disabled

# Ensure host is absent
- ipahost:
    ipaadmin_password: password1
    name: host01.example.com
    state: absent
"""

RETURN = """
"""

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_text
from ansible.module_utils.ansible_freeipa_module import temp_kinit, \
    temp_kdestroy, valid_creds, api_connect, api_command, compare_args_ipa


def find_host(module, name):
    _args = {
        "all": True,
        "fqdn": to_text(name),
    }

    _result = api_command(module, "host_find", to_text(name), _args)

    if len(_result["result"]) > 1:
        module.fail_json(
            msg="There is more than one host '%s'" % (name))
    elif len(_result["result"]) == 1:
        return _result["result"][0]
    else:
        return None


def show_host(module, name):
    _result = api_command(module, "host_show", to_text(name), {})
    return _result["result"]


def gen_args(description, force, locality, location, platform, os, password,
             random, mac_address, ip_address, update_dns, reverse):
    _args = {}
    if description is not None:
        _args["description"] = description
    if force is not None:
        _args["force"] = force
    if locality is not None:
        _args["l"] = locality
    if location is not None:
        _args["nshostlocation"] = location
    if platform is not None:
        _args["nshardwareplatform"] = platform
    if os is not None:
        _args["nsosversion"] = os
    if password is not None:
        _args["userpassword"] = password
    if random is not None:
        _args["random"] = random
    if mac_address is not None:
        _args["macaddress"] = mac_address
    if ip_address is not None:
        _args["ip_address"] = ip_address
    if update_dns is not None:
        _args["updatedns"] = update_dns
    if reverse is not None:
        _args["no_reverse"] = not reverse

    return _args


def main():
    ansible_module = AnsibleModule(
        argument_spec=dict(
            # general
            ipaadmin_principal=dict(type="str", default="admin"),
            ipaadmin_password=dict(type="str", no_log=True),

            name=dict(type="list", aliases=["fqdn"], default=None,
                      required=True),
            # present
            description=dict(type="str", default=None),
            locality=dict(type="str", default=None),
            location=dict(type="str", aliases=["ns_host_location"],
                          default=None),
            platform=dict(type="str", aliases=["ns_hardware_platform"],
                          default=None),
            os=dict(type="str", aliases=["ns_os_version"], default=None),
            password=dict(type="str",
                          aliases=["user_password", "userpassword"],
                          default=None, no_log=True),
            random=dict(type="bool", aliases=["random_password"],
                        default=None),
            # certificate (usercertificate)
            mac_address=dict(type="list", aliases=["macaddress"],
                             default=None),
            # sshpubkey=dict(type="str", aliases=["ipasshpubkey"],
            #                default=None),
            # class
            # auth_ind
            # requires_pre_auth
            # ok_as_delegate
            # ok_to_auth_as_delegate
            force=dict(type='bool', default=None),
            reverse=dict(type='bool', default=True),
            ip_address=dict(type="str", aliases=["ipaddress"],
                            default=None),
            # no_members

            # for update:
            # krbprincipalname
            update_dns=dict(type="bool", aliases=["updatedns"],
                            default=None),
            update_password=dict(type='str', default=None,
                                 choices=['always', 'on_create']),
            # absent
            # continue

            # disabled

            # state
            state=dict(type="str", default="present",
                       choices=["present", "absent", "disabled"]),
        ),
        supports_check_mode=True,
    )

    ansible_module._ansible_debug = True

    # Get parameters

    # general
    ipaadmin_principal = ansible_module.params.get("ipaadmin_principal")
    ipaadmin_password = ansible_module.params.get("ipaadmin_password")
    names = ansible_module.params.get("name")

    # present
    description = ansible_module.params.get("description")
    locality = ansible_module.params.get("locality")
    location = ansible_module.params.get("location")
    platform = ansible_module.params.get("platform")
    os = ansible_module.params.get("os")
    password = ansible_module.params.get("password")
    random = ansible_module.params.get("random")
    mac_address = ansible_module.params.get("mac_address")
    force = ansible_module.params.get("force")
    reverse = ansible_module.params.get("reverse")
    ip_address = ansible_module.params.get("ip_address")
    update_dns = ansible_module.params.get("update_dns")
    update_password = ansible_module.params.get("update_password")
    # absent
    # disabled
    # state
    state = ansible_module.params.get("state")

    # Check parameters

    if state == "present":
        if len(names) != 1:
            ansible_module.fail_json(
                msg="Only one host can be added at a time.")

    if state == "absent":
        if len(names) < 1:
            ansible_module.fail_json(
                msg="No name given.")
        for x in ["description", "password", "random", "mac_address",
                  "force", "ip_address", "update_password"]:
            if vars()[x] is not None:
                ansible_module.fail_json(
                    msg="Argument '%s' can not be used with state '%s'" %
                    (x, state))

    if update_password is None:
        update_password = "always"

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

        for name in names:
            # Make sure host exists
            res_find = find_host(ansible_module, name)

            # Create command
            if state == "present":
                # Generate args
                args = gen_args(
                    description, force, locality, location, platform, os,
                    password, random, mac_address, ip_address, update_dns,
                    reverse)

                # Found the host
                if res_find is not None:
                    # Ignore password with update_password == on_create
                    if update_password == "on_create" and \
                       "userpassword" in args:
                        del args["userpassword"]

                    # Ignore force, ip_address and no_reverse for mod
                    for x in ["force", "ip_address", "no_reverse"]:
                        if x in args:
                            del args[x]

                    # For all settings is args, check if there are
                    # different settings in the find result.
                    # If yes: modify
                    if not compare_args_ipa(ansible_module, args, res_find):
                        commands.append([name, "host_mod", args])
                else:
                    commands.append([name, "host_add", args])

            elif state == "absent":
                if res_find is not None:
                    commands.append([name, "host_del", {}])

            elif state == "disabled":
                if res_find is not None:
                    res_show = show_host(ansible_module, name)
                    if res_show["has_keytab"]:
                        commands.append([name, "host_disable", {}])
                else:
                    raise ValueError("No host '%s'" % name)

            else:
                ansible_module.fail_json(msg="Unkown state '%s'" % state)

        # Execute commands
        for name, command, args in commands:
            try:
                api_command(ansible_module, command, to_text(name), args)
                changed = True
            except Exception as e:
                ansible_module.fail_json(msg="%s: %s: %s" % (command, name,
                                                             str(e)))

    except Exception as e:
        ansible_module.fail_json(msg=str(e))

    finally:
        temp_kdestroy(ccache_dir, ccache_name)

    # Done

    ansible_module.exit_json(changed=changed, **exit_args)


if __name__ == "__main__":
    main()

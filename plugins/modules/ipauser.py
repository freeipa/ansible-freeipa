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
module: ipauser
short description: Manage FreeIPA users
description: Manage FreeIPA users
options:
  ipaadmin_principal:
    description: The admin principal
    default: admin
  ipaadmin_password:
    description: The admin password
    required: false
  name:
    description: The list of users (internally uid).
    required: false
  first:
    description: The first name
    required: false
    aliases: ["givenname"]
  last:
    description: The last name
    required: false
  fullname:
    description: The full name
    required: false
    aliases: ["cn"]
  displayname:
    description: The display name
    required: false
  homedir:
    description: The home directory
    required: false
  shell:
    description: The login shell
    required: false
    aliases: ["loginshell"]
  email:
    description: List of email addresses
    required: false
  principalname:
    description: The kerberos principal
    required: false
    aliases: ["krbprincipalname"]
  passwordexpiration:
    description:
    - The kerberos password expiration date
    - (possible formats: YYYYMMddHHmmssZ, YYYY-MM-ddTHH:mm:ssZ,
    - YYYY-MM-ddTHH:mmZ, YYYY-MM-ddZ, YYYY-MM-dd HH:mm:ssZ,
    - YYYY-MM-dd HH:mmZ) The trailing 'Z' can be skipped.
    required: false
    aliases: ["krbpasswordexpiration"]
  password:
    description: The user password
    required: false
  uid:
    description: The UID
    required: false
    aliases: ["uidnumber"]
  gid:
    description: The GID
    required: false
    aliases: ["gidnumber"]
  phone:
    description: List of telephone numbers
    required: false
    aliases: ["telephonenumber"]
  title:
    description: The job title
    required: false
  #sshpubkey:
  #  description: List of SSH public keys
  #  required: false
  #  aliases: ["ipasshpubkey"]
  # ..
  update_password:
    description:
      Set password for a user in present state only on creation or always
    default: 'always'
    choices: ["always", "on_create"]
  preserve:
    description: Delete a user, keeping the entry available for future use
    required: false
  state:
    description: State to ensure
    default: present
    choices: ["present", "absent",
              "enabled", "disabled",
              "unlocked", "undeleted"]
author:
    - Thomas Woerner
"""

EXAMPLES = """
# Create user pinky
- ipauser:
    ipaadmin_password: MyPassword123
    name: pinky
    first: pinky
    last: Acme
    uid: 10001
    gid: 100
    phone: "+555123457"
    email: pinky@acme.com
    passwordexpiration: "2023-01-19 23:59:59"
    password: "no-brain"
    update_password: on_create

# Create user brain
- ipauser:
    ipaadmin_password: MyPassword123
    name: brain
    first: brain
    last: Acme

# Delete user pinky, but preserved
- ipauser:
    ipaadmin_password: MyPassword123
    name: pinky
    preserve: yes
    state: absent

# Undelete user pinky
- ipauser:
    ipaadmin_password: MyPassword123
    name: pinky
    state: undeleted

# Disable user pinky
- ipauser:
    ipaadmin_password: MyPassword123
    name: pinky,brain
    state: disabled

# Enable user pinky and brain
- ipauser:
    ipaadmin_password: MyPassword123
    name: pinky,brain
    state: enabled

# Remove user pinky and brain
- ipauser:
    ipaadmin_password: MyPassword123
    name: pinky,brain
    state: disabled
"""

RETURN = """
"""

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_text
from ansible.module_utils.ansible_freeipa_module import temp_kinit, \
    temp_kdestroy, valid_creds, api_connect, api_command, date_format, \
    compare_args_ipa


def find_user(module, name, preserved=False):
    _args = {
        "all": True,
        "uid": to_text(name),
    }
    if preserved:
        _args["preserved"] = preserved

    _result = api_command(module, "user_find", to_text(name), _args)

    if len(_result["result"]) > 1:
        module.fail_json(
            msg="There is more than one user '%s'" % (name))
    elif len(_result["result"]) == 1:
        return _result["result"][0]
    else:
        return None


def gen_args(first, last, fullname, displayname, homedir, shell, emails,
             principalname, passwordexpiration, password, uid, gid,
             phones, title, sshpubkey):
    _args = {}
    if first is not None:
        _args["givenname"] = first
    if last is not None:
        _args["sn"] = last
    if fullname is not None:
        _args["cn"] = fullname
    if displayname is not None:
        _args["displayname"] = displayname
    if homedir is not None:
        _args["homedirectory"] = homedir
    if shell is not None:
        _args["loginshell"] = shell
    if emails is not None and len(emails) > 0:
        _args["mail"] = emails
    if principalname is not None:
        _args["krbprincipalname"] = principalname
    if passwordexpiration is not None:
        _args["krbpasswordexpiration"] = passwordexpiration
    if password is not None:
        _args["userpassword"] = password
    if uid is not None:
        _args["uidnumber"] = str(uid)
    if gid is not None:
        _args["gidnumber"] = str(gid)
    if phones is not None and len(phones) > 0:
        _args["telephonenumber"] = phones
    if title is not None:
        _args["title"] = title
    if sshpubkey is not None:
        _args["ipasshpubkey"] = sshpubkey

    return _args


def main():
    ansible_module = AnsibleModule(
        argument_spec=dict(
            # general
            ipaadmin_principal=dict(type="str", default="admin"),
            ipaadmin_password=dict(type="str", required=False, no_log=True),

            name=dict(type="list", aliases=["login"], default=None,
                      required=True),
            # present
            first=dict(type="str", aliases=["givenname"], default=None),
            last=dict(type="str", default=None),
            fullname=dict(type="str", aliases=["cn"], default=None),
            displayname=dict(type="str", default=None),
            homedir=dict(type="str", default=None),
            shell=dict(type="str", aliases=["loginshell"], default=None),
            email=dict(type="list", default=None),
            principalname=dict(type="str", aliases=["krbprincipalname"],
                               default=None),
            passwordexpiration=dict(type="str",
                                    aliases=["krbpasswordexpiration"],
                                    default=None),
            password=dict(type="str", default=None, no_log=True),
            uid=dict(type="int", aliases=["uidnumber"], default=None),
            gid=dict(type="int", aliases=["gidnumber"], default=None),
            phone=dict(type="list", aliases=["telephonenumber"], default=None),
            title=dict(type="str", default=None),
            # sshpubkey=dict(type="list", aliases=["ipasshpubkey"],
            #                default=None),
            update_password=dict(type='str', default=None,
                                 choices=['always', 'on_create']),
            # deleted
            preserve=dict(required=False, type='bool', default=None),
            # state
            state=dict(type="str", default="present",
                       choices=["present", "absent", "enabled", "disabled",
                                "unlocked", "undeleted"]),
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
    first = ansible_module.params.get("first")
    last = ansible_module.params.get("last")
    fullname = ansible_module.params.get("fullname")
    displayname = ansible_module.params.get("displayname")
    homedir = ansible_module.params.get("homedir")
    shell = ansible_module.params.get("shell")
    emails = ansible_module.params.get("email")
    principalname = ansible_module.params.get("principalname")
    passwordexpiration = ansible_module.params.get("passwordexpiration")
    if passwordexpiration is not None:
        if passwordexpiration[:-1] != "Z":
            passwordexpiration = "%sZ" % passwordexpiration
        passwordexpiration = date_format(passwordexpiration)
    password = ansible_module.params.get("password")
    uid = ansible_module.params.get("uid")
    gid = ansible_module.params.get("gid")
    phones = ansible_module.params.get("phone")
    title = ansible_module.params.get("title")
    sshpubkey = ansible_module.params.get("sshpubkey")
    update_password = ansible_module.params.get("update_password")
    # deleted
    preserve = ansible_module.params.get("preserve")
    # state
    state = ansible_module.params.get("state")

    # Check parameters

    if state == "present":
        if len(names) != 1:
            ansible_module.fail_json(
                msg="Only one user can be added at a time.")
        if first is None:
            ansible_module.fail_json(msg="First name is needed")
        if last is None:
            ansible_module.fail_json(msg="Last name is needed")

    if state == "absent":
        if len(names) < 1:
            ansible_module.fail_json(
                msg="No name given.")
        for x in ["first", "last", "fullname", "displayname", "homedir",
                  "shell", "emails", "principalname", "passwordexpiration",
                  "password", "uid", "gid", "phones", "title", "sshpubkey",
                  "update_password"]:
            if vars()[x] is not None:
                ansible_module.fail_json(
                    msg="Argument '%s' can not be used with state '%s'" %
                    (x, state))
    else:
        if preserve is not None:
            ansible_module.fail_json(
                msg="Preserve is only possible for state=absent")

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
            # Make sure user exists
            res_find = find_user(ansible_module, name)
            # Also search for preserved user
            res_find_preserved = find_user(ansible_module, name,
                                           preserved=True)

            # Create command
            if state == "present":
                # Generate args
                args = gen_args(
                    first, last, fullname, displayname, homedir, shell, emails,
                    principalname, passwordexpiration, password, uid, gid,
                    phones, title, sshpubkey)

                # Also check preserved users
                if res_find is None and res_find_preserved is not None:
                    res_find = res_find_preserved

                # Found the user
                if res_find is not None:
                    # Ignore password with update_password == on_create
                    if update_password == "on_create" and \
                       "userpassword" in args:
                        del args["userpassword"]

                    # For all settings is args, check if there are
                    # different settings in the find result.
                    # If yes: modify
                    if not compare_args_ipa(ansible_module, args, res_find):
                        commands.append([name, "user_mod", args])
                else:
                    commands.append([name, "user_add", args])

            elif state == "absent":
                # Also check preserved users
                if res_find is None and res_find_preserved is not None:
                    res_find = res_find_preserved

                if res_find is not None:
                    args = {}
                    if preserve is not None:
                        args["preserve"] = preserve
                    commands.append([name, "user_del", args])

            elif state == "undeleted":
                if res_find_preserved is not None:
                    commands.append([name, "user_undel", {}])
                else:
                    raise ValueError("No preserved user '%s'" % name)

            elif state == "enabled":
                if res_find is not None:
                    if res_find["nsaccountlock"]:
                        commands.append([name, "user_enable", {}])
                else:
                    raise ValueError("No disabled user '%s'" % name)

            elif state == "disabled":
                if res_find is not None:
                    if not res_find["nsaccountlock"]:
                        commands.append([name, "user_disable", {}])
                else:
                    raise ValueError("No user '%s'" % name)

            elif state == "unlocked":
                if res_find is not None:
                    commands.append([name, "user_unlock", {}])

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

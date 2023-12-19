# -*- coding: utf-8 -*-

# Authors:
#   Thomas Woerner <twoerner@redhat.com>
#
# Copyright (C) 2023 Red Hat
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

# No rename support: 'ID overrides cannot be renamed'
# ipaserver/plugins/idviews.py:baseidoverride_mod:pre_callback

DOCUMENTATION = """
---
module: ipaidoverrideuser
short_description: Manage FreeIPA idoverrideuser
description: Manage FreeIPA idoverrideuser and idoverrideuser members
extends_documentation_fragment:
  - ipamodule_base_docs
options:
  idview:
    description: The idoverrideuser idview string.
    type: str
    required: true
    aliases: ["idviewcn"]
  anchor:
    description: The list of anchors to override
    type: list
    elements: str
    required: true
    aliases: ["ipaanchoruuid"]
  description:
    description: Description
    type: str
    required: False
    aliases: ["desc"]
  name:
    description: The user (internally uid)
    type: str
    required: False
    aliases: ["login"]
  uid:
    description: User ID Number (int or "")
    type: str
    required: False
    aliases: ["uidnumber"]
  gecos:
    description: GECOS
    required: False
    type: str
  gidnumber:
    description: Group ID Number (int or "")
    required: False
    type: str
  homedir:
    description: Home directory
    type: str
    required: False
    aliases: ["homedirectory"]
  shell:
    description: Login shell
    type: str
    required: False
    aliases: ["loginshell"]
  sshpubkey:
    description: List of SSH public keys
    type: list
    element: str
    required: False
    aliases: ["ipasshpubkey"]
  certificate:
    description: List of Base-64 encoded user certificates
    type: list
    elements: str
    required: False
    aliases: ["usercertificate"]
  fallback_to_ldap:
    description: |
      Allow falling back to AD DC LDAP when resolving AD trusted objects.
      For two-way trusts only.
    required: False
    type: bool
  delete_continue:
    description: |
      Continuous mode. Don't stop on errors.
      Valid only if `state` is `absent`.
    required: false
    type: bool
    aliases: ["continue"]
  nomembers:
    description: |
      Suppress processing of membership attributes.
      Valid only if `state` is `absent`.
    type: str
    required: False
    aliases: ["no_members"]
  action:
    description: Work on idoverrideuser or member level.
    choices: ["idoverrideuser", "member"]
    default: idoverrideuser
    type: str
  state:
    description: The state to ensure.
    choices: ["present", "absent"]
    default: present
    type: str
author:
  - Thomas Woerner (@t-woerner)
"""

EXAMPLES = """
# Ensure test user test_user is present in idview test_idview
- ipaidoverrideuser:
    ipaadmin_password: SomeADMINpassword
    idview: test_idview
    anchor: test_user

# Ensure test user test_user is present in idview test_idview with description
- ipaidoverrideuser:
    ipaadmin_password: SomeADMINpassword
    idview: test_idview
    anchor: test_user
    description: "test_user description"

# Ensure test user test_user is present in idview test_idview without
# description
- ipaidoverrideuser:
    ipaadmin_password: SomeADMINpassword
    idview: test_idview
    anchor: test_user
    description: ""

# Ensure test user test_user is present in idview test_idview with internal
# name test_123_user
- ipaidoverrideuser:
    ipaadmin_password: SomeADMINpassword
    idview: test_idview
    anchor: test_user
    name: test_123_user

# Ensure test user test_user is present in idview test_idview without internal
# name
- ipaidoverrideuser:
    ipaadmin_password: SomeADMINpassword
    idview: test_idview
    anchor: test_user
    name: ""

# Ensure test user test_user is present in idview test_idview with uid 20001
- ipaidoverrideuser:
    ipaadmin_password: SomeADMINpassword
    idview: test_idview
    anchor: test_user
    uid: 20001

# Ensure test user test_user is present in idview test_idview without uid
- ipaidoverrideuser:
    ipaadmin_password: SomeADMINpassword
    idview: test_idview
    anchor: test_user
    uid: ""

# Ensure test user test_user is present in idview test_idview with gecos
# "Gecos Test"
- ipaidoverrideuser:
    ipaadmin_password: SomeADMINpassword
    idview: test_idview
    anchor: test_user
    gecos: Gecos Test

# Ensure test user test_user is present in idview test_idview without gecos
- ipaidoverrideuser:
    ipaadmin_password: SomeADMINpassword
    idview: test_idview
    anchor: test_user
    gecos: ""

# Ensure test user test_user is present in idview test_idview with gidnumber
# 20001
- ipaidoverrideuser:
    ipaadmin_password: SomeADMINpassword
    idview: test_idview
    anchor: test_user
    gidnumber: 20001

# Ensure test user test_user is present in idview test_idview without
# gidnumber
- ipaidoverrideuser:
    ipaadmin_password: SomeADMINpassword
    idview: test_idview
    anchor: test_user
    gidnumber: ""

# Ensure test user test_user is present in idview test_idview with homedir
# /Users
- ipaidoverrideuser:
    ipaadmin_password: SomeADMINpassword
    idview: test_idview
    anchor: test_user
    homedir: /Users

# Ensure test user test_user is present in idview test_idview without homedir
- ipaidoverrideuser:
    ipaadmin_password: SomeADMINpassword
    idview: test_idview
    anchor: test_user
    homedir: ""

# Ensure test user test_user is present in idview test_idview with shell
# /bin/someshell
- ipaidoverrideuser:
    ipaadmin_password: SomeADMINpassword
    idview: test_idview
    anchor: test_user
    shell: /bin/someshell

# Ensure test user test_user is present in idview test_idview without shell
- ipaidoverrideuser:
    ipaadmin_password: SomeADMINpassword
    idview: test_idview
    anchor: test_user
    shell: ""

# Ensure test user test_user is present in idview test_idview with sshpubkey
- ipaidoverrideuser:
    ipaadmin_password: SomeADMINpassword
    idview: test_idview
    anchor: test_user
    sshpubkey:
    - ssh-rsa AAAAB3NzaC1yc2EAAADAQABAAABgQCqmVDpEX5gnSjKuv97Ay ...

# Ensure test user test_user is present in idview test_idview without
# sshpubkey
- ipaidoverrideuser:
    ipaadmin_password: SomeADMINpassword
    idview: test_idview
    anchor: test_user
    sshpubkey: []

# Ensure test user test_user is present in idview test_idview with 1
# certificate
- ipaidoverrideuser:
    ipaadmin_password: SomeADMINpassword
    idview: test_idview
    anchor: test_user
    certificate:
    - "{{ lookup('file', 'cert1.b64', rstrip=False) }}"

# Ensure test user test_user is present in idview test_idview with 3
# certificate members
- ipaidoverrideuser:
    ipaadmin_password: SomeADMINpassword
    idview: test_idview
    anchor: test_user
    certificate:
    - "{{ lookup('file', 'cert1.b64', rstrip=False) }}"
    - "{{ lookup('file', 'cert2.b64', rstrip=False) }}"
    - "{{ lookup('file', 'cert3.b64', rstrip=False) }}"
    action: member

# Ensure test user test_user is present in idview test_idview without
# 2 certificate members
- ipaidoverrideuser:
    ipaadmin_password: SomeADMINpassword
    idview: test_idview
    anchor: test_user
    certificate:
    - "{{ lookup('file', 'cert2.b64', rstrip=False) }}"
    - "{{ lookup('file', 'cert3.b64', rstrip=False) }}"
    action: member
    state: absent

# Ensure test user test_user is present in idview test_idview without
# certificates
- ipaidoverrideuser:
    ipaadmin_password: SomeADMINpassword
    idview: test_idview
    anchor: test_user
    certificate: []

# Ensure test user test_user is absent in idview test_idview
- ipaidoverrideuser:
    ipaadmin_password: SomeADMINpassword
    idview: test_idview
    anchor: test_user
    continue: true
    state: absent
"""

RETURN = """
"""


from ansible.module_utils.ansible_freeipa_module import \
    IPAAnsibleModule, compare_args_ipa, gen_add_del_lists, gen_add_list, \
    gen_intersection_list, encode_certificate
from ansible.module_utils import six

if six.PY3:
    unicode = str


def find_idoverrideuser(module, idview, anchor):
    """Find if a idoverrideuser with the given name already exist."""
    try:
        _result = module.ipa_command("idoverrideuser_show", idview,
                                     {"ipaanchoruuid": anchor,
                                      "all": True})
    except Exception:  # pylint: disable=broad-except
        # An exception is raised if idoverrideuser anchor is not found.
        return None

    _res = _result["result"]
    certs = _res.get("usercertificate")
    if certs is not None:
        _res["usercertificate"] = [encode_certificate(cert) for cert in certs]
    return _res


def gen_args(anchor, description, name, uid, gecos, gidnumber, homedir, shell,
             sshpubkey):
    # fallback_to_ldap and nomembers are only runtime tuning parameters
    _args = {}
    if anchor is not None:
        _args["ipaanchoruuid"] = anchor
    if description is not None:
        _args["description"] = description
    if name is not None:
        _args["uid"] = name
    if uid is not None:
        _args["uidnumber"] = uid
    if gecos is not None:
        _args["gecos"] = gecos
    if gidnumber is not None:
        _args["gidnumber"] = gidnumber
    if homedir is not None:
        _args["homedirectory"] = homedir
    if shell is not None:
        _args["loginshell"] = shell
    if sshpubkey is not None:
        _args["ipasshpubkey"] = sshpubkey
    return _args


def gen_args_runtime(fallback_to_ldap, nomembers):
    _args = {}
    if fallback_to_ldap is not None:
        _args["fallback_to_ldap"] = fallback_to_ldap
    if nomembers is not None:
        _args["no_members"] = nomembers
    return _args


def gen_member_args(certificate):
    _args = {}
    if certificate is not None:
        _args["usercertificate"] = certificate
    return _args


def merge_dicts(dict1, dict2):
    ret = dict1.copy()
    ret.update(dict2)
    return ret


def main():
    ansible_module = IPAAnsibleModule(
        argument_spec=dict(
            # general
            idview=dict(type="str", required=True, aliases=["idviewcn"]),
            anchor=dict(type="list", elements="str", required=True,
                        aliases=["ipaanchoruuid"]),

            # present
            description=dict(type="str", required=False, aliases=["desc"]),
            name=dict(type="str", required=False, aliases=["login"]),
            uid=dict(type="str", required=False, aliases=["uidnumber"]),
            gecos=dict(type="str", required=False),
            gidnumber=dict(type="str", required=False),
            homedir=dict(type="str", required=False,
                         aliases=["homedirectory"]),
            shell=dict(type="str", required=False, aliases=["loginshell"]),
            sshpubkey=dict(type="list", elements="str", required=False,
                           aliases=["ipasshpubkey"]),
            certificate=dict(type="list", elements="str", required=False,
                             aliases=["usercertificate"]),
            fallback_to_ldap=dict(type="bool", required=False),
            nomembers=dict(type="bool", required=False,
                           aliases=["no_members"]),

            # absent
            delete_continue=dict(type="bool", required=False,
                                 aliases=['continue'], default=None),

            # No rename support: 'ID overrides cannot be renamed'
            # ipaserver/plugins/idviews.py:baseidoverride_mod:pre_callback

            # action
            action=dict(type="str", default="idoverrideuser",
                        choices=["member", "idoverrideuser"]),
            # state
            state=dict(type="str", default="present",
                       choices=["present", "absent"]),
        ),
        supports_check_mode=True,
    )

    ansible_module._ansible_debug = True

    # Get parameters

    # general
    idview = ansible_module.params_get("idview")
    anchors = ansible_module.params_get("anchor")

    # present
    description = ansible_module.params_get("description")
    name = ansible_module.params_get("name")
    uid = ansible_module.params_get_with_type_cast("uid", int)
    gecos = ansible_module.params_get("gecos")
    gidnumber = ansible_module.params_get_with_type_cast("gidnumber", int)
    homedir = ansible_module.params_get("homedir")
    shell = ansible_module.params_get("shell")
    sshpubkey = ansible_module.params_get("sshpubkey")
    certificate = ansible_module.params_get("certificate")
    fallback_to_ldap = ansible_module.params_get("fallback_to_ldap")
    nomembers = ansible_module.params_get("nomembers")
    action = ansible_module.params_get("action")

    # absent
    delete_continue = ansible_module.params_get("delete_continue")

    # state
    state = ansible_module.params_get("state")

    # Check parameters

    invalid = []

    if state == "present":
        if len(anchors) != 1:
            ansible_module.fail_json(
                msg="Only one idoverrideuser can be added at a time.")
        invalid = ["delete_continue"]
        if action == "member":
            invalid += ["description", "name", "uid", "gecos", "gidnumber",
                        "homedir", "shell", "sshpubkey"]

    if state == "absent":
        if len(anchors) < 1:
            ansible_module.fail_json(msg="No name given.")
        invalid = ["description", "name", "uid", "gecos", "gidnumber",
                   "homedir", "shell", "sshpubkey", "nomembers"]
        if action == "idoverrideuser":
            invalid += ["certificate"]

    ansible_module.params_fail_used_invalid(invalid, state, action)

    if certificate is not None:
        certificate = [cert.strip() for cert in certificate]

    # Init

    changed = False
    exit_args = {}

    # Connect to IPA API
    with ansible_module.ipa_connect():

        runtime_args = gen_args_runtime(fallback_to_ldap, nomembers)
        commands = []
        for anchor in anchors:
            # Make sure idoverrideuser exists
            res_find = find_idoverrideuser(ansible_module, idview, anchor)

            # add/del lists
            certificate_add, certificate_del = [], []

            # Create command
            if state == "present":

                # Generate args
                args = gen_args(anchor, description, name, uid, gecos,
                                gidnumber, homedir, shell, sshpubkey)
                # fallback_to_ldap and nomembers are only runtime tuning
                # parameters
                all_args = merge_dicts(args, runtime_args)

                if action == "idoverrideuser":
                    # Found the idoverrideuser
                    if res_find is not None:
                        # For idempotency: Remove empty sshpubkey list if
                        # there are no sshpubkey in the found entry.
                        if "ipasshpubkey" in args and \
                           len(args["ipasshpubkey"]) < 1 and \
                           "ipasshpubkey" not in res_find:
                            del args["ipasshpubkey"]
                        # For all settings is args, check if there are
                        # different settings in the find result.
                        # If yes: modify
                        if not compare_args_ipa(ansible_module, args,
                                                res_find):
                            commands.append([idview, "idoverrideuser_mod",
                                             all_args])
                    else:
                        commands.append([idview, "idoverrideuser_add",
                                         all_args])
                        res_find = {}

                    member_args = gen_member_args(certificate)
                    if not compare_args_ipa(ansible_module, member_args,
                                            res_find):

                        # Generate addition and removal lists
                        certificate_add, certificate_del = gen_add_del_lists(
                            certificate, res_find.get("usercertificate"))

                elif action == "member":
                    if res_find is None:
                        ansible_module.fail_json(
                            msg="No idoverrideuser '%s' in idview '%s'" %
                            (anchor, idview))

                    # Reduce add lists for certificate
                    # to new entries only that are not in res_find.
                    if certificate is not None:
                        certificate_add = gen_add_list(
                            certificate, res_find.get("usercertificate"))

            elif state == "absent":
                if action == "idoverrideuser":
                    if res_find is not None:
                        commands.append(
                            [idview, "idoverrideuser_del",
                             merge_dicts(
                                 {
                                     "ipaanchoruuid": anchor,
                                     "continue": delete_continue or False
                                 },
                                 runtime_args
                             )]
                        )

                elif action == "member":
                    if res_find is None:
                        ansible_module.fail_json(
                            msg="No idoverrideuser '%s' in idview '%s'" %
                            (anchor, idview))

                    # Reduce del lists of member_host and member_hostgroup,
                    # to the entries only that are in res_find.
                    if certificate is not None:
                        certificate_del = gen_intersection_list(
                            certificate, res_find.get("usercertificate"))

            else:
                ansible_module.fail_json(msg="Unkown state '%s'" % state)

            # Member management

            # Add members
            if certificate_add:
                commands.append([idview, "idoverrideuser_add_cert",
                                 merge_dicts(
                                     {
                                         "ipaanchoruuid": anchor,
                                         "usercertificate": certificate_add
                                     },
                                     runtime_args
                                 )])

            # Remove members

            if certificate_del:
                commands.append([idview, "idoverrideuser_remove_cert",
                                 merge_dicts(
                                     {
                                         "ipaanchoruuid": anchor,
                                         "usercertificate": certificate_del
                                     },
                                     runtime_args
                                 )])

        # Execute commands

        changed = ansible_module.execute_ipa_commands(commands)

    # Done

    ansible_module.exit_json(changed=changed, **exit_args)


if __name__ == "__main__":
    main()

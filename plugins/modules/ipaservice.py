# -*- coding: utf-8 -*-

# Authors:
#   Rafael Guterres Jeffman <rjeffman@redhat.com>
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

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

ANSIBLE_METADATA = {
    "metadata_version": "1.0",
    "supported_by": "community",
    "status": ["preview"],
}


DOCUMENTATION = """
---
module: ipaservice
short_description: Manage FreeIPA service
description: Manage FreeIPA service
extends_documentation_fragment:
  - ipamodule_base_docs
options:
  name:
    description: The service to manage
    required: true
    aliases: ["service"]
  certificate:
    description: Base-64 encoded service certificate.
    required: false
    type: list
    aliases: ["usercertificate"]
  pac_type:
    description: Supported PAC type.
    required: false
    choices: ["MS-PAC", "PAD", "NONE", ""]
    type: list
    aliases: ["pac_type", "ipakrbauthzdata"]
  auth_ind:
    description: Defines a whitelist for Authentication Indicators.
    required: false
    choices: ["otp", "radius", "pkinit", "hardened", ""]
    aliases: ["krbprincipalauthind"]
  skip_host_check:
    description: Skip checking if host object exists.
    required: False
    type: bool
  force:
    description: Force principal name even if host is not in DNS.
    required: False
    type: bool
  requires_pre_auth:
    description: Pre-authentication is required for the service.
    required: false
    type: bool
    default: False
    aliases: ["ipakrbrequirespreauth"]
  ok_as_delegate:
    description: Client credentials may be delegated to the service.
    required: false
    type: bool
    default: False
    aliases: ["ipakrbokasdelegate"]
  ok_to_auth_as_delegate:
    description: Allow service to authenticate on behalf of a client.
    required: false
    type: bool
    default: False
    aliases: ["ipakrboktoauthasdelegate"]
  principal:
    description: List of principal aliases for the service.
    required: false
    type: list
    aliases: ["krbprincipalname"]
  smb:
    description: Add a SMB service.
    required: false
    type: bool
  netbiosname:
    description: NETBIOS name for the SMB service.
    required: false
    type: str
  host:
    description: Host that can manage the service.
    required: false
    type: list
    aliases: ["managedby_host"]
  allow_create_keytab_user:
    description: Users allowed to create a keytab of this host.
    required: false
    type: list
    aliases: ["ipaallowedtoperform_write_keys_user"]
  allow_create_keytab_group:
    description: Groups allowed to create a keytab of this host.
    required: false
    type: list
    aliases: ["ipaallowedtoperform_write_keys_group"]
  allow_create_keytab_host:
    description: Hosts allowed to create a keytab of this host.
    required: false
    type: list
    aliases: ["ipaallowedtoperform_write_keys_host"]
  allow_create_keytab_hostgroup:
    description: Host group allowed to create a keytab of this host.
    required: false
    type: list
    aliases: ["ipaallowedtoperform_write_keys_hostgroup"]
  allow_retrieve_keytab_user:
    description: User allowed to retrieve a keytab of this host.
    required: false
    type: list
    aliases: ["ipaallowedtoperform_read_keys_user"]
  allow_retrieve_keytab_group:
    description: Groups allowed to retrieve a keytab of this host.
    required: false
    type: list
    aliases: ["ipaallowedtoperform_read_keys_group"]
  allow_retrieve_keytab_host:
    description: Hosts allowed to retrieve a keytab of this host.
    required: false
    type: list
    aliases: ["ipaallowedtoperform_read_keys_host"]
  allow_retrieve_keytab_hostgroup:
    description: Host groups allowed to retrieve a keytab of this host.
    required: false
    type: list
    aliases: ["ipaallowedtoperform_read_keys_hostgroup"]
  continue:
    description:
      Continuous mode. Don't stop on errors. Valid only if `state` is `absent`.
    required: false
    default: True
    type: bool
  action:
    description: Work on service or member level
    default: service
    choices: ["member", "service"]
  state:
    description: State to ensure
    default: present
    choices: ["present", "absent", "disabled"]
author:
    - Rafael Jeffman
"""

EXAMPLES = """
  # Ensure service is present
  - ipaservice:
      ipaadmin_password: SomeADMINpassword
      name: HTTP/www.example.com
      pac_type:
        - MS-PAC
        - PAD
      auth_ind: otp
      skip_host_check: true
      force: false
      requires_pre_auth: true
      ok_as_delegate: false
      ok_to_auth_as_delegate: false

  # Ensure service is absent
  - ipaservice:
      ipaadmin_password: SomeADMINpassword
      name: HTTP/www.example.com
      state: absent

  # Ensure service member certificate is present.
  - ipaservice:
      ipaadmin_password: SomeADMINpassword
      name: HTTP/www.example.com
      certificate:
        - >
          MIIC/zCCAeegAwIBAgIUMNHIbn+hhrOVew/2WbkteisV29QwDQYJKoZIhvcNAQELBQAw
          DzENMAsGA1UEAwwEdGVzdDAeFw0yMDAyMDQxNDQxMDhaFw0zMDAyMDExNDQxMDhaMA8x
          DTALBgNVBAMMBHRlc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC+XVVG
          FYpHVkcDfVnNInE1Y/pFciegdzqTjMwUWlRL4Zt3u96GhaMLRbtk+OfEkzLUAhWBOwEr
          aELJzMLJOMvjYF3C+TiGO7dStFLikZmccuSsSIXjnzIPwBXa8KvgRVRyGLoVvGbLJvmj
          fMXp0nIToTx/i74KF9S++WEes9H5ErJ99CDhLKFgq0amnvsgparYXhypHaRLnikn0vQI
          Nt55YoEd1s4KrvEcD2VdZkIMPbLRu2zFvMprF3cjQQG4LT9ggfEXNIPZ1nQWAnAsu7OJ
          EkNF+E4Mkmpcxj9aGUVt5bsq1D+Tzj3GsidSX0nSNcZ2JltXRnL/5v63g5cZyE+nAgMB
          AAGjUzBRMB0GA1UdDgQWBBRV0j7JYukuH/r/t9+QeNlRLXDlEDAfBgNVHSMEGDAWgBRV
          0j7JYukuH/r/t9+QeNlRLXDlEDAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUA
          A4IBAQCgVy1+1kNwHs5y1Zp0WjMWGCJC6/zw7FDG4OW5r2GJiCXZYdJ0UonY9ZtoVLJP
          rp2/DAv1m5DtnDhBYqicuPgLzEkOS1KdTi20Otm/J4yxLLrZC5W4x0XOeSVPXOJuQWfw
          Q5pPvKkn6WxYUYkGwIt1OH2nSMngkbami3CbSmKZOCpgQIiSlQeDJ8oGjWFMLDymYSHo
          VOIXHwNoooyEiaio3693l6noobyGv49zyCVLVR1DC7i6RJ186ql0av+D4vPoiF5mX7+s
          KC2E8xEj9uKQ5GTWRh59VnRBVC/SiMJ/H78tJnBAvoBwXxSEvj8Z3Kjm/BQqZfv4IBsA
          5yqV7MVq
      action: member
      state: present

  # Ensure principal host/test.example.com present in service.
  - ipaservice:
      ipaadmin_password: SomeADMINpassword
      name: HTTP/www.example.com
      principal:
        - host/test.example.com
      action: member

  # Ensure host can manage service.
  - ipaservice:
      ipaadmin_password: SomeADMINpassword
      name: HTTP/www.example.com
      host:
      - host1.example.com
      - host2.example.com
      action: member
"""

RETURN = """
"""

from ansible.module_utils.ansible_freeipa_module import \
    IPAAnsibleModule, compare_args_ipa, encode_certificate, \
    gen_add_del_lists, gen_add_list, gen_intersection_list, ipalib_errors, \
    api_get_realm, to_text


def find_service(module, name):
    _args = {
        "all": True,
    }

    try:
        _result = module.ipa_command("service_show", name, _args)
    except ipalib_errors.NotFound:
        return None

    if "result" in _result:
        _res = _result["result"]
        certs = _res.get("usercertificate")
        if certs is not None:
            _res["usercertificate"] = [encode_certificate(cert) for
                                       cert in certs]
        return _res

    return None


def gen_args(pac_type, auth_ind, skip_host_check, force, requires_pre_auth,
             ok_as_delegate, ok_to_auth_as_delegate):
    _args = {}

    if pac_type is not None:
        _args['ipakrbauthzdata'] = pac_type
    if auth_ind is not None:
        _args['krbprincipalauthind'] = auth_ind
    if skip_host_check is not None:
        _args['skip_host_check'] = (skip_host_check)
    if force is not None:
        _args['force'] = (force)
    if requires_pre_auth is not None:
        _args['ipakrbrequirespreauth'] = (requires_pre_auth)
    if ok_as_delegate is not None:
        _args['ipakrbokasdelegate'] = (ok_as_delegate)
    if ok_to_auth_as_delegate is not None:
        _args['ipakrboktoauthasdelegate'] = (ok_to_auth_as_delegate)

    return _args


def gen_args_smb(netbiosname, ok_as_delegate, ok_to_auth_as_delegate):
    _args = {}

    if netbiosname is not None:
        _args['ipantflatname'] = netbiosname
    if ok_as_delegate is not None:
        _args['ipakrbokasdelegate'] = (ok_as_delegate)
    if ok_to_auth_as_delegate is not None:
        _args['ipakrboktoauthasdelegate'] = (ok_to_auth_as_delegate)

    return _args


def check_parameters(module, state, action, names):
    # invalid parameters for everything but state 'present', action 'service'.
    invalid = ['pac_type', 'auth_ind', 'skip_host_check',
               'force', 'requires_pre_auth', 'ok_as_delegate',
               'ok_to_auth_as_delegate', 'smb', 'netbiosname']

    # invalid parameters when not handling service members.
    invalid_not_member = \
        ['principal', 'certificate', 'host', 'allow_create_keytab_user',
         'allow_create_keytab_group', 'allow_create_keytab_host',
         'allow_create_keytab_hostgroup', 'allow_retrieve_keytab_user',
         'allow_retrieve_keytab_group', 'allow_retrieve_keytab_host',
         'allow_retrieve_keytab_hostgroup']

    if state == 'present':
        if len(names) != 1:
            module.fail_json(msg="Only one service can be added at a time.")

        if action == 'service':
            invalid = ['delete_continue']

            if (
                not module.params_get('smb')
                and module.params_get('netbiosname')
            ):
                module.fail_json(
                    msg="Argument 'netbiosname' can not be used without "
                        "SMB service.")
        else:
            invalid.append('delete_continue')

    elif state == 'absent':
        if len(names) < 1:
            module.fail_json(msg="No name given.")

        if action == "service":
            invalid.extend(invalid_not_member)
        else:
            invalid.extend('delete_continue')

    elif state == 'disabled':
        invalid.extend(invalid_not_member)
        invalid.append('delete_continue')
        if action != "service":
            module.fail_json(
                msg="Invalid action '%s' for state '%s'" % (action, state))

    else:
        module.fail_json(msg="Invalid state '%s'" % (state))

    module.params_fail_used_invalid(invalid, state, action)


def init_ansible_module():
    ansible_module = IPAAnsibleModule(
        argument_spec=dict(
            # general
            name=dict(type="list", aliases=["service"], default=None,
                      required=True),
            # service attributesstr
            certificate=dict(type="list", aliases=['usercertificate'],
                             default=None, required=False),
            principal=dict(type="list", aliases=["krbprincipalname"],
                           default=None),
            smb=dict(type="bool", required=False),
            netbiosname=dict(type="str", required=False),
            pac_type=dict(type="list", aliases=["ipakrbauthzdata"],
                          choices=["MS-PAC", "PAD", "NONE", ""]),
            auth_ind=dict(type="list",
                          aliases=["krbprincipalauthind"],
                          choices=["otp", "radius", "pkinit", "hardened", ""]),
            skip_host_check=dict(type="bool"),
            force=dict(type="bool"),
            requires_pre_auth=dict(
                type="bool", aliases=["ipakrbrequirespreauth"]),
            ok_as_delegate=dict(type="bool", aliases=["ipakrbokasdelegate"]),
            ok_to_auth_as_delegate=dict(type="bool",
                                        aliases=["ipakrboktoauthasdelegate"]),
            host=dict(type="list", aliases=["managedby_host"], required=False),
            allow_create_keytab_user=dict(
                type="list", required=False,
                aliases=['ipaallowedtoperform_write_keys_user']),
            allow_retrieve_keytab_user=dict(
                type="list", required=False,
                aliases=['ipaallowedtoperform_read_keys_user']),
            allow_create_keytab_group=dict(
                type="list", required=False,
                aliases=['ipaallowedtoperform_write_keys_group']),
            allow_retrieve_keytab_group=dict(
                type="list", required=False,
                aliases=['ipaallowedtoperform_read_keys_group']),
            allow_create_keytab_host=dict(
                type="list", required=False,
                aliases=['ipaallowedtoperform_write_keys_host']),
            allow_retrieve_keytab_host=dict(
                type="list", required=False,
                aliases=['ipaallowedtoperform_read_keys_host']),
            allow_create_keytab_hostgroup=dict(
                type="list", required=False,
                aliases=['ipaallowedtoperform_write_keys_hostgroup']),
            allow_retrieve_keytab_hostgroup=dict(
                type="list", required=False,
                aliases=['ipaallowedtoperform_read_keys_hostgroup']),
            delete_continue=dict(type="bool", required=False,
                                 aliases=['continue']),
            # action
            action=dict(type="str", default="service",
                        choices=["member", "service"]),
            # state
            state=dict(type="str", default="present",
                       choices=["present", "absent", "disabled"]),
        ),
        supports_check_mode=True,
    )

    ansible_module._ansible_debug = True

    return ansible_module


def main():
    ansible_module = init_ansible_module()

    # Get parameters

    # general
    names = ansible_module.params_get("name")

    # service attributes
    principal = ansible_module.params_get("principal")
    certificate = ansible_module.params_get("certificate")
    pac_type = ansible_module.params_get("pac_type", allow_empty_string=True)
    auth_ind = ansible_module.params_get("auth_ind", allow_empty_string=True)
    skip_host_check = ansible_module.params_get("skip_host_check")
    force = ansible_module.params_get("force")
    requires_pre_auth = ansible_module.params_get("requires_pre_auth")
    ok_as_delegate = ansible_module.params_get("ok_as_delegate")
    ok_to_auth_as_delegate = ansible_module.params_get(
        "ok_to_auth_as_delegate")

    smb = ansible_module.params_get("smb")
    netbiosname = ansible_module.params_get("netbiosname")

    host = ansible_module.params_get("host")

    delete_continue = ansible_module.params_get("delete_continue")

    # action
    action = ansible_module.params_get("action")
    # state
    state = ansible_module.params_get("state")

    # check parameters
    check_parameters(ansible_module, state, action, names)

    # Init

    changed = False
    exit_args = {}

    # Connect to IPA API
    with ansible_module.ipa_connect():

        has_skip_host_check = ansible_module.ipa_command_param_exists(
            "service_add", "skip_host_check")
        if skip_host_check and not has_skip_host_check:
            ansible_module.fail_json(
                msg="Skipping host check is not supported by your IPA version")

        commands = []
        keytab_members = ["user", "group", "host", "hostgroup"]

        for name in names:
            res_find = find_service(ansible_module, name)
            res_principals = []

            keytab = {
                "retrieve": {
                    "allow": {k: [] for k in keytab_members},
                    "disallow": {k: [] for k in keytab_members},
                },
                "create": {
                    "allow": {k: [] for k in keytab_members},
                    "disallow": {k: [] for k in keytab_members},
                },
            }
            certificate_add, certificate_del = [], []
            host_add, host_del = [], []
            principal_add, principal_del = [], []

            if principal and res_find:
                # When comparing principals to the existing ones,
                # the REALM is needded, and are added here for those
                # that do not have it.
                principal = [
                    p if "@" in p
                    else "%s@%s" % (p, api_get_realm())
                    for p in principal
                ]
                principal = list(set(principal))

                # Create list of existing principal aliases as strings
                # to compare with provided ones.
                canonicalname = {
                    to_text(p)
                    for p in res_find.get("krbcanonicalname", [])
                }
                res_principals = [
                    to_text(elem)
                    for elem in res_find.get("krbprincipalname", [])
                ]
                res_principals = list(set(res_principals) - canonicalname)

            if state == "present":
                if action == "service":
                    args = gen_args(
                        pac_type, auth_ind, skip_host_check, force,
                        requires_pre_auth, ok_as_delegate,
                        ok_to_auth_as_delegate)
                    if not has_skip_host_check and 'skip_host_check' in args:
                        del args['skip_host_check']

                    if smb:
                        if res_find is None:
                            _name = "cifs/" + name
                            res_find = find_service(ansible_module, _name)
                            if res_find is None:
                                _args = gen_args_smb(
                                    netbiosname, ok_as_delegate,
                                    ok_to_auth_as_delegate)
                                commands.append(
                                    [name, 'service_add_smb', _args])
                                res_find = {}
                            # service_add_smb will prefix 'name' with
                            # "cifs/", so we will need to change it here,
                            # so that service_mod, if called later, works.
                            name = _name

                    if res_find is None:
                        commands.append([name, 'service_add', args])
                        # Use an empty res_find to manage members
                        res_find = {}

                    else:
                        for remove in ['skip_host_check', 'force']:
                            if remove in args:
                                del args[remove]

                        if (
                            "ipakrbauthzdata" in args
                            and (
                                args.get("ipakrbauthzdata", [""]) ==
                                res_find.get("ipakrbauthzdata", [""])
                            )
                        ):
                            del args["ipakrbauthzdata"]

                        if (
                            "krbprincipalauthind" in args
                            and (
                                args.get("krbprincipalauthind", [""]) ==
                                res_find.get("krbprincipalauthind", [""])
                            )
                        ):
                            del args["krbprincipalauthind"]

                        if not compare_args_ipa(ansible_module, args,
                                                res_find):
                            commands.append([name, "service_mod", args])

                    # Manage members
                    certificate_add, certificate_del = gen_add_del_lists(
                        certificate, res_find.get("usercertificate"))

                    host_add, host_del = gen_add_del_lists(
                        host, res_find.get('managedby_host'))

                    principal_add, principal_del = gen_add_del_lists(
                        principal, res_principals)

                elif action == "member":
                    if res_find is None:
                        ansible_module.fail_json(msg="No service '%s'" % name)

                    certificate_add = gen_add_list(
                        certificate, res_find.get("usercertificate"))

                    host_add = gen_add_list(
                        host, res_find.get('managedby_host'))

                    principal_add = gen_add_list(principal, res_principals)

                # get keytab management lists for any 'action'.
                for perm in ["create", "retrieve"]:
                    oper = "write" if perm == "create" else "read"
                    for key in ["user", "group", "host", "hostgroup"]:
                        add_list, del_list = (
                            gen_add_del_lists(
                                ansible_module.params_get(
                                    "allow_%s_keytab_%s" % (perm, key)
                                ),
                                res_find.get(
                                    'ipaallowedtoperform_%s_keys_%s'
                                    % (oper, key)
                                )
                            )
                        )
                        keytab[perm]["allow"][key] = add_list
                        # Only remove members if action is 'service'
                        if action == "service":
                            keytab[perm]["disallow"][key] = del_list

            elif state == "absent":
                if action == "service":
                    if res_find is not None:
                        args = {'continue': delete_continue}
                        commands.append([name, 'service_del', args])

                elif action == "member":
                    if res_find is None:
                        ansible_module.fail_json(msg="No service '%s'" % name)

                    principal_del = gen_intersection_list(
                        principal, res_principals)

                    certificate_del = gen_intersection_list(
                        certificate, res_find.get("usercertificate"))

                    host_del = gen_intersection_list(
                        host, res_find.get("managedby_host"))

                    for perm in ["create", "retrieve"]:
                        oper = "write" if perm == "create" else "read"
                        for key in ["user", "group", "host", "hostgroup"]:
                            res_param = (
                                'ipaallowedtoperform_%s_keys_%s'
                                % (oper, key)
                            )
                            module_params = ansible_module.params_get(
                                "allow_%s_keytab_%s" % (perm, key)
                            )
                            existing = res_find.get(res_param)
                            del_list = (
                                gen_intersection_list(module_params, existing)
                            )
                            keytab[perm]["disallow"][key] = del_list

            elif state == "disabled":
                if action == "service":
                    if res_find is not None:
                        has_cert = bool(res_find.get('usercertificate'))
                        has_keytab = res_find.get('has_keytab', False)
                        if has_cert or has_keytab:
                            commands.append([name, 'service_disable', {}])
                else:
                    ansible_module.fail_json(
                        msg="Invalid action '%s' for state '%s'" %
                        (action, state))
                # Members are not managed when disabling service.
                # Continue with next 'name'.
                continue
            else:
                ansible_module.fail_json(msg="Unkown state '%s'" % state)

            # Manage members
            if principal_add:
                commands.append([name, "service_add_principal",
                                 {"krbprincipalname": principal_add}])
            if principal_del:
                commands.append([name, "service_remove_principal",
                                 {"krbprincipalname": principal_del}])

            if certificate_add:
                commands.append([name, "service_add_cert",
                                 {"usercertificate": certificate_add}])
            if certificate_del:
                commands.append([name, "service_remove_cert",
                                 {"usercertificate": certificate_del}])

            if host_add:
                commands.append([name, "service_add_host",
                                 {"host": host_add}])
            if host_del:
                commands.append([name, "service_remove_host",
                                 {"host": host_del}])

            # manage keytab permissions.
            for perm in ["create", "retrieve"]:
                for mode in ["allow", "disallow"]:
                    for key in ["user", "group", "host", "hostgroup"]:
                        if keytab[perm][mode][key]:
                            commands.append([
                                name,
                                "service_%s_%s_keytab" % (mode, perm),
                                keytab[perm][mode]
                            ])
                            break

        # Check mode exit
        if ansible_module.check_mode:
            ansible_module.exit_json(changed=len(commands) > 0, **exit_args)

        # Execute commands
        changed = ansible_module.execute_ipa_commands(
            commands, fail_on_member_errors=True)

    # Done
    ansible_module.exit_json(changed=changed, **exit_args)


if __name__ == "__main__":
    main()

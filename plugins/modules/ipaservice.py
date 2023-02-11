# -*- coding: utf-8 -*-

# Authors:
#   Rafael Guterres Jeffman <rjeffman@redhat.com>
#   Thomas Woerner <twoerner@redhat.com>
#
# Copyright (C) 2019-2022 Red Hat
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
    type: list
    elements: str
    required: true
    aliases: ["service"]
  certificate:
    description: Base-64 encoded service certificate.
    required: false
    type: list
    elements: str
    aliases: ["usercertificate"]
  pac_type:
    description: Supported PAC type.
    required: false
    choices: ["MS-PAC", "PAD", "NONE", ""]
    type: list
    elements: str
    aliases: ["pac_type", "ipakrbauthzdata"]
  auth_ind:
    description: Defines an allow list for Authentication Indicators.
    type: list
    elements: str
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
    aliases: ["ipakrbrequirespreauth"]
  ok_as_delegate:
    description: Client credentials may be delegated to the service.
    required: false
    type: bool
    aliases: ["ipakrbokasdelegate"]
  ok_to_auth_as_delegate:
    description: Allow service to authenticate on behalf of a client.
    required: false
    type: bool
    aliases: ["ipakrboktoauthasdelegate"]
  principal:
    description: List of principal aliases for the service.
    required: false
    type: list
    elements: str
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
    elements: str
    aliases: ["managedby_host"]
  allow_create_keytab_user:
    description: Users allowed to create a keytab of this host.
    required: false
    type: list
    elements: str
    aliases: ["ipaallowedtoperform_write_keys_user"]
  allow_create_keytab_group:
    description: Groups allowed to create a keytab of this host.
    required: false
    type: list
    elements: str
    aliases: ["ipaallowedtoperform_write_keys_group"]
  allow_create_keytab_host:
    description: Hosts allowed to create a keytab of this host.
    required: false
    type: list
    elements: str
    aliases: ["ipaallowedtoperform_write_keys_host"]
  allow_create_keytab_hostgroup:
    description: Host group allowed to create a keytab of this host.
    required: false
    type: list
    elements: str
    aliases: ["ipaallowedtoperform_write_keys_hostgroup"]
  allow_retrieve_keytab_user:
    description: User allowed to retrieve a keytab of this host.
    required: false
    type: list
    elements: str
    aliases: ["ipaallowedtoperform_read_keys_user"]
  allow_retrieve_keytab_group:
    description: Groups allowed to retrieve a keytab of this host.
    required: false
    type: list
    elements: str
    aliases: ["ipaallowedtoperform_read_keys_group"]
  allow_retrieve_keytab_host:
    description: Hosts allowed to retrieve a keytab of this host.
    required: false
    type: list
    elements: str
    aliases: ["ipaallowedtoperform_read_keys_host"]
  allow_retrieve_keytab_hostgroup:
    description: Host groups allowed to retrieve a keytab of this host.
    required: false
    type: list
    elements: str
    aliases: ["ipaallowedtoperform_read_keys_hostgroup"]
  delete_continue:
    description:
      Continuous mode. Don't stop on errors. Valid only if `state` is `absent`.
    required: false
    type: bool
    aliases: ["continue"]
  action:
    description: Work on service or member level
    type: str
    default: service
    choices: ["member", "service"]
  state:
    description: State to ensure
    type: str
    default: present
    choices: ["present", "absent", "disabled"]
author:
  - Rafael Guterres Jeffman (@rjeffman)
  - Thomas Woerner (@t-woerner)
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
    ipalib_errors, api_get_realm, to_text, \
    gen_member_manage_commands, create_ipa_mapping, ipa_api_map, \
    transform_lowercase, transform_service_principal


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
        # Remove principal host from list of managedby_host, as it is not
        # part of object member attributes.
        hosts = [
            x for x in _res.get("managedby_host", [])
            if x not in str(_res.get("krbprincipalname"))
        ]
        _res["managedby_host"] = hosts
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
            name=dict(type="list", elements="str", aliases=["service"],
                      required=True),
            # service attributesstr
            certificate=dict(type="list", elements="str",
                             aliases=['usercertificate'],
                             default=None, required=False),
            principal=dict(type="list", elements="str",
                           aliases=["krbprincipalname"], default=None),
            smb=dict(type="bool", required=False),
            netbiosname=dict(type="str", required=False),
            pac_type=dict(type="list", elements="str",
                          aliases=["ipakrbauthzdata"],
                          choices=["MS-PAC", "PAD", "NONE", ""]),
            auth_ind=dict(type="list", elements="str",
                          aliases=["krbprincipalauthind"],
                          choices=["otp", "radius", "pkinit", "hardened", ""]),
            skip_host_check=dict(type="bool"),
            force=dict(type="bool"),
            requires_pre_auth=dict(
                type="bool", aliases=["ipakrbrequirespreauth"]),
            ok_as_delegate=dict(type="bool", aliases=["ipakrbokasdelegate"]),
            ok_to_auth_as_delegate=dict(type="bool",
                                        aliases=["ipakrboktoauthasdelegate"]),
            host=dict(type="list", elements="str", aliases=["managedby_host"],
                      required=False),
            allow_create_keytab_user=dict(
                type="list", elements="str", required=False, no_log=False,
                aliases=['ipaallowedtoperform_write_keys_user']),
            allow_retrieve_keytab_user=dict(
                type="list", elements="str", required=False, no_log=False,
                aliases=['ipaallowedtoperform_read_keys_user']),
            allow_create_keytab_group=dict(
                type="list", elements="str", required=False, no_log=False,
                aliases=['ipaallowedtoperform_write_keys_group']),
            allow_retrieve_keytab_group=dict(
                type="list", elements="str", required=False, no_log=False,
                aliases=['ipaallowedtoperform_read_keys_group']),
            allow_create_keytab_host=dict(
                type="list", elements="str", required=False, no_log=False,
                aliases=['ipaallowedtoperform_write_keys_host']),
            allow_retrieve_keytab_host=dict(
                type="list", elements="str", required=False, no_log=False,
                aliases=['ipaallowedtoperform_read_keys_host']),
            allow_create_keytab_hostgroup=dict(
                type="list", elements="str", required=False, no_log=False,
                aliases=['ipaallowedtoperform_write_keys_hostgroup']),
            allow_retrieve_keytab_hostgroup=dict(
                type="list", elements="str", required=False, no_log=False,
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

        for name in names:
            if "@" not in name:
                name = name + "@" + api_get_realm()

            res_find = find_service(ansible_module, name)
            res_principals = []

            if principal and res_find:
                # When comparing principals to the existing ones,
                # the REALM is needded, and are added here for those
                # that do not have it.
                # principal = [
                #     p if "@" in p
                #     else "%s@%s" % (p, api_get_realm())
                #     for p in principal
                # ]
                # principal = list(set(principal))

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
                                smb_host = name.split("@")[0]
                                _args = gen_args_smb(
                                    netbiosname, ok_as_delegate,
                                    ok_to_auth_as_delegate)
                                commands.append(
                                    [smb_host, 'service_add_smb', _args])
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

                elif action == "member":
                    if res_find is None:
                        ansible_module.fail_json(msg="No service '%s'" % name)

            elif state == "absent":
                if action == "service":
                    if res_find is not None:
                        args = {'continue': delete_continue}
                        commands.append([name, 'service_del', args])

                elif action == "member":
                    if res_find is None:
                        ansible_module.fail_json(msg="No service '%s'" % name)

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
            commands.extend(
                gen_member_manage_commands(
                    ansible_module,
                    # Use the computed principals instead of res_find one.
                    {"krbprincipalname": res_principals},
                    name,
                    "service_add_principal", "service_remove_principal",
                    create_ipa_mapping(
                        ipa_api_map(
                            "krbprincipalname",
                            "principal",
                            "krbprincipalname",
                            transform={
                                "principal": transform_service_principal
                            }
                        )
                    )
                    # ipa_params=dict(
                    #     krbprincipalname=dict(
                    #         param="principal",
                    #         ldap="krbprincipalname",
                    #         values=principal,
                    #     )
                    # )
                )
            )

            commands.extend(
                gen_member_manage_commands(
                    ansible_module, res_find, name,
                    "service_add_cert", "service_remove_cert",
                    create_ipa_mapping(
                        ipa_api_map(
                            "usercertificate",
                            "certificate",
                            "usercertificate",
                        )
                    )
                )
            )

            commands.extend(
                gen_member_manage_commands(
                    ansible_module, res_find, name,
                    "service_add_host", "service_remove_host",
                    create_ipa_mapping(
                        ipa_api_map(
                            "host", "host", "managedby_host",
                            transform={"host": transform_lowercase},
                        )
                    )
                )
            )

            # manage keytab permissions.
            for oper, perm in {"write": "create", "read": "retrieve"}.items():
                for key in ["user", "group", "host", "hostgroup"]:
                    # module
                    mod_param = "allow_%s_keytab_%s" % (perm, key)
                    # LDAP
                    ldap_param = 'ipaallowedtoperform_%s_keys_%s' % (oper, key)
                    commands.extend(
                        gen_member_manage_commands(
                            ansible_module, res_find, name,
                            "service_allow_%s_keytab" % perm,
                            "service_disallow_%s_keytab" % perm,
                            create_ipa_mapping(
                                ipa_api_map(
                                    key, mod_param, ldap_param,
                                    transform={mod_param: transform_lowercase}
                                ),
                            ),
                        )
                    )

        # Execute commands
        changed = ansible_module.execute_ipa_commands(
            commands, fail_on_member_errors=True)

    # Done
    ansible_module.exit_json(changed=changed, **exit_args)


if __name__ == "__main__":
    main()

#!/usr/bin/python
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

ANSIBLE_METADATA = {
    "metadata_version": "1.0",
    "supported_by": "community",
    "status": ["preview"],
}


DOCUMENTATION = """
---
module: ipaservice
short description: Manage FreeIPA service
description: Manage FreeIPA service
options:
  ipaadmin_principal:
    description: The admin principal
    default: admin
  ipaadmin_password:
    description: The admin password
    required: false
  name:
    description: The service to manage
    required: true
    aliases: ["service"]
  certificate:
    description: Base-64 encoded service certificate.
    required: false
    type: list
    aliases=['usercertificate']
  pac_type:
    description: Supported PAC type.
    required: false
    choices: ["MS-PAC", "PAD", "NONE"]
    type: list
    aliases: ["pac_type", "ipakrbauthzdata"]
  auth_ind:
    description: Defines a whitelist for Authentication Indicators.
    required: false
    choices: ["otp", "radius", "pkinit", "hardened"]
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
  ok_to_auth_as_delegate: Allow service to authenticate on behalf of a client.
    description: .
    required: false
    type: bool
    default: False
    aliases:["ipakrboktoauthasdelegate"]
  principal:
    description: List of principal aliases for the service.
    required: false
    type: list
    aliases: ["krbprincipalname"]
  host:
    description: Host that can manage the service.
    required: false
    type: list
    aliases: ["managedby_host"]
  allow_create_keytab_user:
    descrption: Users allowed to create a keytab of this host.
    required: false
    type: list
    aliases: ["ipaallowedtoperform_write_keys_user"]
  allow_create_keytab_group:
    descrption: Groups allowed to create a keytab of this host.
    required: false
    type: list
    aliases: ["ipaallowedtoperform_write_keys_group"]
  allow_create_keytab_host:
    descrption: Hosts allowed to create a keytab of this host.
    required: false
    type: list
    aliases: ["ipaallowedtoperform_write_keys_host"]
  allow_create_keytab_hostgroup:
    descrption: Host group allowed to create a keytab of this host.
    required: false
    type: list
    aliases: ["ipaallowedtoperform_write_keys_hostgroup"]
  allow_retrieve_keytab_user:
    descrption: User allowed to retrieve a keytab of this host.
    required: false
    type: list
    aliases: ["ipaallowedtoperform_read_keys_user"]
  allow_retrieve_keytab_group:
    descrption: Groups allowed to retrieve a keytab of this host.
    required: false
    type: list
    aliases: ["ipaallowedtoperform_read_keys_group"]
  allow_retrieve_keytab_host:
    descrption: Hosts allowed to retrieve a keytab of this host.
    required: false
    type: list
    aliases: ["ipaallowedtoperform_read_keys_host"]
  allow_retrieve_keytab_hostgroup:
    descrption: Host groups allowed to retrieve a keytab of this host.
    required: false
    type: list
    aliases: ["ipaallowedtoperform_read_keys_hostgroup"]
  action:
    description: Work on service or member level
    default: service
    choices: ["member", "service"]
  state:
    description: State to ensure
    default: present
    choices: ["present", "absent", "enabled", "disabled"]
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
        - MIIC/zCCAeegAwIBAgIUMNHIbn+hhrOVew/2WbkteisV29QwDQYJKoZIhvcNAQELBQAw
        DzENMAsGA1UEAwwEdGVzdDAeFw0yMDAyMDQxNDQxMDhaFw0zMDAyMDExNDQxMDhaMA8xDT
        ALBgNVBAMMBHRlc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC+XVVGFYpH
        VkcDfVnNInE1Y/pFciegdzqTjMwUWlRL4Zt3u96GhaMLRbtk+OfEkzLUAhWBOwEraELJzM
        LJOMvjYF3C+TiGO7dStFLikZmccuSsSIXjnzIPwBXa8KvgRVRyGLoVvGbLJvmjfMXp0nIT
        oTx/i74KF9S++WEes9H5ErJ99CDhLKFgq0amnvsgparYXhypHaRLnikn0vQINt55YoEd1s
        4KrvEcD2VdZkIMPbLRu2zFvMprF3cjQQG4LT9ggfEXNIPZ1nQWAnAsu7OJEkNF+E4Mkmpc
        xj9aGUVt5bsq1D+Tzj3GsidSX0nSNcZ2JltXRnL/5v63g5cZyE+nAgMBAAGjUzBRMB0GA1
        UdDgQWBBRV0j7JYukuH/r/t9+QeNlRLXDlEDAfBgNVHSMEGDAWgBRV0j7JYukuH/r/t9+Q
        eNlRLXDlEDAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQCgVy1+1kNwHs
        5y1Zp0WjMWGCJC6/zw7FDG4OW5r2GJiCXZYdJ0UonY9ZtoVLJPrp2/DAv1m5DtnDhBYqic
        uPgLzEkOS1KdTi20Otm/J4yxLLrZC5W4x0XOeSVPXOJuQWfwQ5pPvKkn6WxYUYkGwIt1OH
        2nSMngkbami3CbSmKZOCpgQIiSlQeDJ8oGjWFMLDymYSHoVOIXHwNoooyEiaio3693l6no
        obyGv49zyCVLVR1DC7i6RJ186ql0av+D4vPoiF5mX7+sKC2E8xEj9uKQ5GTWRh59VnRBVC
        /SiMJ/H78tJnBAvoBwXxSEvj8Z3Kjm/BQqZfv4IBsA5yqV7MVq
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

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.ansible_freeipa_module import temp_kinit, \
    temp_kdestroy, valid_creds, api_connect, api_command, compare_args_ipa, \
    encode_certificate, gen_add_del_lists, module_params_get, to_text, \
    api_check_param


def find_service(module, name):
    _args = {
        "all": True,
    }

    _result = api_command(module, "service_find", to_text(name), _args)

    if len(_result["result"]) > 1:
        module.fail_json(
            msg="There is more than one service '%s'" % (name))
    elif len(_result["result"]) == 1:
        _res = _result["result"][0]
        certs = _res.get("usercertificate")
        if certs is not None:
            _res["usercertificate"] = [encode_certificate(cert) for
                                       cert in certs]
        return _res
    else:
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


def check_parameters(module, state, action, names, parameters):
    assert isinstance(parameters, dict)

    # invalid parameters for everything but state 'present', action 'service'.
    invalid = ['pac_type', 'auth_ind', 'skip_host_check',
               'force', 'requires_pre_auth', 'ok_as_delegate',
               'ok_to_auth_as_delegate']

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
            invalid = []

    elif state == 'absent':
        if len(names) < 1:
            module.fail_json(msg="No name given.")

        if action == "service":
            invalid.extend(invalid_not_member)

    elif state == 'disabled':
        invalid.extend(invalid_not_member)
        if action != "service":
            module.fail_json(
                msg="Invalid action '%s' for state '%s'" % (action, state))

    else:
        module.fail_json(msg="Invalid state '%s'" % (state))

    for _invalid in invalid:
        if parameters[_invalid] is not None:
            module.fail_json(
                msg="Argument '%s' can not be used with state '%s'" %
                (_invalid, state))


def init_ansible_module():
    ansible_module = AnsibleModule(
        argument_spec=dict(
            # general
            ipaadmin_principal=dict(type="str", default="admin"),
            ipaadmin_password=dict(type="str", required=False, no_log=True),

            name=dict(type="list", aliases=["service"], default=None,
                      required=True),
            # service attributesstr
            certificate=dict(type="list", aliases=['usercertificate'],
                             default=None, required=False),
            principal=dict(type="list", aliases=["krbprincipalname"],
                           default=None),
            pac_type=dict(type="list", aliases=["ipakrbauthzdata"],
                          choices=["MS-PAC", "PAD", "NONE"]),
            auth_ind=dict(type="str",
                          aliases=["krbprincipalauthind"],
                          choices=["otp", "radius", "pkinit", "hardened"]),
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
            # action
            action=dict(type="str", default="service",
                        choices=["member", "service"]),
            # state
            state=dict(type="str", default="present",
                       choices=["present", "absent",
                                "enabled", "disabled"]),
        ),
        supports_check_mode=True,
    )

    ansible_module._ansible_debug = True

    return ansible_module


def main():
    ansible_module = init_ansible_module()

    # Get parameters

    # general
    ipaadmin_principal = module_params_get(ansible_module,
                                           "ipaadmin_principal")
    ipaadmin_password = module_params_get(ansible_module, "ipaadmin_password")
    names = module_params_get(ansible_module, "name")

    # service attributes
    principal = module_params_get(ansible_module, "principal")
    certificate = module_params_get(ansible_module, "certificate")
    pac_type = module_params_get(ansible_module, "pac_type")
    auth_ind = module_params_get(ansible_module, "auth_ind")
    skip_host_check = module_params_get(ansible_module, "skip_host_check")
    force = module_params_get(ansible_module, "force")
    requires_pre_auth = module_params_get(ansible_module, "requires_pre_auth")
    ok_as_delegate = module_params_get(ansible_module, "ok_as_delegate")
    ok_to_auth_as_delegate = module_params_get(ansible_module,
                                               "ok_to_auth_as_delegate")

    host = module_params_get(ansible_module, "host")

    allow_create_keytab_user = module_params_get(
        ansible_module, "allow_create_keytab_user")
    allow_create_keytab_group = module_params_get(
        ansible_module, "allow_create_keytab_group")
    allow_create_keytab_host = module_params_get(
        ansible_module, "allow_create_keytab_host")
    allow_create_keytab_hostgroup = module_params_get(
        ansible_module, "allow_create_keytab_hostgroup")

    allow_retrieve_keytab_user = module_params_get(
        ansible_module, "allow_retrieve_keytab_user")
    allow_retrieve_keytab_group = module_params_get(
        ansible_module, "allow_retrieve_keytab_group")
    allow_retrieve_keytab_host = module_params_get(
        ansible_module, "allow_create_keytab_host")
    allow_retrieve_keytab_hostgroup = module_params_get(
        ansible_module, "allow_retrieve_keytab_hostgroup")

    # action
    action = module_params_get(ansible_module, "action")
    # state
    state = module_params_get(ansible_module, "state")

    # check parameters
    check_parameters(ansible_module, state, action, names, vars())

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

        has_skip_host_check = api_check_param(
            "service_add", "skip_host_check")
        if skip_host_check and not has_skip_host_check:
            ansible_module.fail_json(
                msg="Skipping host check is not supported by your IPA version")

        commands = []

        for name in names:
            res_find = find_service(ansible_module, name)

            if state == "present":
                if action == "service":
                    args = gen_args(
                        pac_type, auth_ind, skip_host_check, force,
                        requires_pre_auth, ok_as_delegate,
                        ok_to_auth_as_delegate)
                    if not has_skip_host_check and 'skip_host_check' in args:
                        del args['skip_host_check']

                    if res_find is None:
                        commands.append([name, 'service_add', args])

                        certificate_add = certificate or []
                        certificate_del = []
                        host_add = host or []
                        host_del = []
                        principal_add = principal or []
                        principal_del = []
                        allow_create_keytab_user_add = \
                            allow_create_keytab_user or []
                        allow_create_keytab_user_del = []
                        allow_create_keytab_group_add = \
                            allow_create_keytab_group or []
                        allow_create_keytab_group_del = []
                        allow_create_keytab_host_add = \
                            allow_create_keytab_host or []
                        allow_create_keytab_host_del = []
                        allow_create_keytab_hostgroup_add = \
                            allow_create_keytab_hostgroup or []
                        allow_create_keytab_hostgroup_del = []
                        allow_retrieve_keytab_user_add = \
                            allow_retrieve_keytab_user or []
                        allow_retrieve_keytab_user_del = []
                        allow_retrieve_keytab_group_add = \
                            allow_retrieve_keytab_group or []
                        allow_retrieve_keytab_group_del = []
                        allow_retrieve_keytab_host_add = \
                            allow_retrieve_keytab_host or []
                        allow_retrieve_keytab_host_del = []
                        allow_retrieve_keytab_hostgroup_add = \
                            allow_retrieve_keytab_hostgroup or []
                        allow_retrieve_keytab_hostgroup_del = []

                    else:
                        for remove in ['skip_host_check', 'force']:
                            if remove in args:
                                del args[remove]

                        if not compare_args_ipa(ansible_module, args,
                                                res_find):
                            commands.append([name, "service_mod", args])

                        certificate_add, certificate_del = gen_add_del_lists(
                            certificate, res_find.get("usercertificate"))

                        host_add, host_del = gen_add_del_lists(
                            host, res_find.get('managedby_host', []))

                        principal_add, principal_del = gen_add_del_lists(
                            principal, res_find.get("principal"))

                        (allow_create_keytab_user_add,
                         allow_create_keytab_user_del) = \
                            gen_add_del_lists(
                                allow_create_keytab_user, res_find.get(
                                    'ipaallowedtoperform_write_keys_user',
                                    []))
                        (allow_retrieve_keytab_user_add,
                         allow_retrieve_keytab_user_del) = \
                            gen_add_del_lists(
                                allow_retrieve_keytab_user, res_find.get(
                                    'ipaallowedtoperform_read_keys_user',
                                    []))
                        (allow_create_keytab_group_add,
                         allow_create_keytab_group_del) = \
                            gen_add_del_lists(
                                allow_create_keytab_group, res_find.get(
                                    'ipaallowedtoperform_write_keys_group',
                                    []))
                        (allow_retrieve_keytab_group_add,
                         allow_retrieve_keytab_group_del) = \
                            gen_add_del_lists(
                                allow_retrieve_keytab_group,
                                res_find.get(
                                    'ipaallowedtoperform_read_keys_group',
                                    []))
                        (allow_create_keytab_host_add,
                         allow_create_keytab_host_del) = \
                            gen_add_del_lists(
                                allow_create_keytab_host,
                                res_find.get(
                                    'ipaallowedtoperform_write_keys_host',
                                    []))
                        (allow_retrieve_keytab_host_add,
                         allow_retrieve_keytab_host_del) = \
                            gen_add_del_lists(
                                allow_retrieve_keytab_host,
                                res_find.get(
                                    'ipaallowedtoperform_read_keys_host',
                                    []))
                        (allow_create_keytab_hostgroup_add,
                         allow_create_keytab_hostgroup_del) = \
                            gen_add_del_lists(
                                allow_create_keytab_hostgroup,
                                res_find.get(
                                    'ipaallowedtoperform_write_keys_hostgroup',
                                    []))
                        (allow_retrieve_keytab_hostgroup_add,
                         allow_retrieve_keytab_hostgroup_del) = \
                            gen_add_del_lists(
                                allow_retrieve_keytab_hostgroup,
                                res_find.get(
                                    'ipaallowedtoperform_read_keys_hostgroup',
                                    []))

                elif action == "member":
                    if res_find is None:
                        ansible_module.fail_json(msg="No service '%s'" % name)

                    existing = res_find.get('usercertificate', [])
                    if certificate is None:
                        certificate_add = []
                    else:
                        certificate_add = [c for c in certificate
                                           if c not in existing]
                    certificate_del = []
                    host_add = host or []
                    host_del = []
                    principal_add = principal or []
                    principal_del = []

                    allow_create_keytab_user_add = \
                        allow_create_keytab_user or []
                    allow_create_keytab_user_del = []
                    allow_create_keytab_group_add = \
                        allow_create_keytab_group or []
                    allow_create_keytab_group_del = []
                    allow_create_keytab_host_add = \
                        allow_create_keytab_host or []
                    allow_create_keytab_host_del = []
                    allow_create_keytab_hostgroup_add = \
                        allow_create_keytab_hostgroup or []
                    allow_create_keytab_hostgroup_del = []
                    allow_retrieve_keytab_user_add = \
                        allow_retrieve_keytab_user or []
                    allow_retrieve_keytab_user_del = []
                    allow_retrieve_keytab_group_add = \
                        allow_retrieve_keytab_group or []
                    allow_retrieve_keytab_group_del = []
                    allow_retrieve_keytab_host_add = \
                        allow_retrieve_keytab_host or []
                    allow_retrieve_keytab_host_del = []
                    allow_retrieve_keytab_hostgroup_add = \
                        allow_retrieve_keytab_hostgroup or []
                    allow_retrieve_keytab_hostgroup_del = []

                # Add principals
                for _principal in principal_add:
                    commands.append([name, "service_add_principal",
                                     {
                                         "krbprincipalname":
                                         _principal,
                                     }])

                # Remove principals
                for _principal in principal_del:
                    commands.append([name, "service_remove_principal",
                                     {
                                         "krbprincipalname":
                                         _principal,
                                     }])

                for _certificate in certificate_add:
                    commands.append([name, "service_add_cert",
                                     {
                                         "usercertificate":
                                         _certificate,
                                     }])
                # Remove certificates
                for _certificate in certificate_del:
                    commands.append([name, "service_remove_cert",
                                     {
                                         "usercertificate":
                                         _certificate,
                                     }])

                # Add hosts.
                if host is not None and len(host) > 0 and len(host_add) > 0:
                    commands.append([name, "service_add_host",
                                     {"host": host_add}])
                # Remove hosts
                if host is not None and len(host) > 0 and len(host_del) > 0:
                    commands.append([name, "service_remove_host",
                                     {"host": host_del}])

                # Allow create keytab
                if len(allow_create_keytab_user_add) > 0 or \
                   len(allow_create_keytab_group_add) > 0 or \
                   len(allow_create_keytab_host_add) > 0 or \
                   len(allow_create_keytab_hostgroup_add) > 0:
                    commands.append(
                        [name, "service_allow_create_keytab",
                         {'user': allow_create_keytab_user_add,
                          'group': allow_create_keytab_group_add,
                          'host': allow_create_keytab_host_add,
                          'hostgroup': allow_create_keytab_hostgroup_add
                          }])

                # Disallow create keytab
                if len(allow_create_keytab_user_del) > 0 or \
                   len(allow_create_keytab_group_del) > 0 or \
                   len(allow_create_keytab_host_del) > 0 or \
                   len(allow_create_keytab_hostgroup_del) > 0:
                    commands.append(
                        [name, "service_disallow_create_keytab",
                         {'user': allow_create_keytab_user_del,
                          'group': allow_create_keytab_group_del,
                          'host': allow_create_keytab_host_del,
                          'hostgroup': allow_create_keytab_hostgroup_del
                          }])

                # Allow retrieve keytab
                if len(allow_retrieve_keytab_user_add) > 0 or \
                   len(allow_retrieve_keytab_group_add) > 0 or \
                   len(allow_retrieve_keytab_hostgroup_add) > 0 or \
                   len(allow_retrieve_keytab_hostgroup_add) > 0:
                    commands.append(
                        [name, "service_allow_retrieve_keytab",
                         {'user': allow_retrieve_keytab_user_add,
                          'group': allow_retrieve_keytab_group_add,
                          'host': allow_retrieve_keytab_host_add,
                          'hostgroup': allow_retrieve_keytab_hostgroup_add
                          }])

                # Disllow retrieve keytab
                if len(allow_retrieve_keytab_user_del) > 0 or \
                   len(allow_retrieve_keytab_group_del) > 0 or \
                   len(allow_retrieve_keytab_host_del) > 0 or \
                   len(allow_retrieve_keytab_hostgroup_del) > 0:
                    commands.append(
                        [name, "service_disallow_retrieve_keytab",
                         {'user': allow_retrieve_keytab_user_del,
                          'group': allow_retrieve_keytab_group_del,
                          'host': allow_retrieve_keytab_host_del,
                          'hostgroup': allow_retrieve_keytab_hostgroup_del
                          }])

            elif state == "absent":
                if action == "service":
                    if res_find is not None:
                        commands.append([name, 'service_del', {}])

                elif action == "member":
                    if res_find is None:
                        ansible_module.fail_json(msg="No service '%s'" % name)

                    # Remove principals
                    if principal is not None:
                        for _principal in principal:
                            commands.append([name, "service_remove_principal",
                                             {
                                                 "krbprincipalname":
                                                 _principal,
                                             }])
                    # Remove certificates
                    if certificate is not None:
                        existing = res_find.get('usercertificate', [])
                        for _certificate in certificate:
                            if _certificate in existing:
                                commands.append([name, "service_remove_cert",
                                                 {
                                                     "usercertificate":
                                                     _certificate,
                                                 }])

                    # Add hosts
                    if host is not None:
                        commands.append(
                            [name, "service_remove_host", {"host": host}])

                    # Allow create keytab
                    if allow_create_keytab_user is not None or \
                       allow_create_keytab_group is not None or \
                       allow_create_keytab_host is not None or \
                       allow_create_keytab_hostgroup is not None:
                        commands.append(
                            [name, "service_disallow_create_keytab",
                             {'user': allow_create_keytab_user,
                              'group': allow_create_keytab_group,
                              'host': allow_create_keytab_host,
                              'hostgroup': allow_create_keytab_hostgroup
                              }])

                    # Allow retriev keytab
                    if allow_retrieve_keytab_user is not None or \
                       allow_retrieve_keytab_group is not None or \
                       allow_retrieve_keytab_host is not None or \
                       allow_retrieve_keytab_hostgroup is not None:
                        commands.append(
                            [name, "service_disallow_retrieve_keytab",
                             {'user': allow_retrieve_keytab_user,
                              'group': allow_retrieve_keytab_group,
                              'host': allow_retrieve_keytab_host,
                              'hostgroup': allow_retrieve_keytab_hostgroup
                              }])

            elif state == "disabled":
                if action == "service":
                    if res_find is not None and \
                       len(res_find.get('usercertificate', [])) > 0:
                        commands.append([name, 'service_disable', {}])
                else:
                    ansible_module.fail_json(
                        msg="Invalid action '%s' for state '%s'" %
                        (action, state))
            else:
                ansible_module.fail_json(msg="Unkown state '%s'" % state)

        # Execute commands
        errors = []
        for name, command, args in commands:
            try:
                result = api_command(ansible_module, command, name, args)

                if "completed" in result:
                    if result["completed"] > 0:
                        changed = True
                else:
                    changed = True
            except Exception as ex:
                ansible_module.fail_json(msg="%s: %s: %s" % (command, name,
                                                             str(ex)))
            # Get all errors
            # All "already a member" and "not a member" failures in the
            # result are ignored. All others are reported.
            if "failed" in result and len(result["failed"]) > 0:
                for item in result["failed"]:
                    failed_item = result["failed"][item]
                    for member_type in failed_item:
                        for member, failure in failed_item[member_type]:
                            if "already a member" in failure \
                               or "not a member" in failure:
                                continue
                            errors.append("%s: %s %s: %s" % (
                                command, member_type, member, failure))
        if len(errors) > 0:
            ansible_module.fail_json(msg=", ".join(errors))

    except Exception as ex:
        ansible_module.fail_json(msg=str(ex))

    finally:
        temp_kdestroy(ccache_dir, ccache_name)

    # Done
    ansible_module.exit_json(changed=changed, **exit_args)


if __name__ == "__main__":
    main()

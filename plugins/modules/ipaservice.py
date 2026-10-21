# -*- coding: utf-8 -*-

# Authors:
#   Denis Karpelevich <dkarpele@redhat.com>
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
    required: false
    aliases: ["service"]
  services:
    description: The list of service dicts.
    type: list
    elements: dict
    suboptions:
      name:
        description: The service to manage
        type: str
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
        choices: ["otp", "radius", "pkinit", "hardened", "idp", "passkey", ""]
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
          Continuous mode. Don't stop on errors.
          Valid only if `state` is `absent`.
        required: false
        type: bool
        aliases: ["continue"]
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
    choices: ["otp", "radius", "pkinit", "hardened", "idp", "passkey", ""]
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
  query_param:
    description:
    - The fields to query with state=query.
    - Can be `ALL`, `BASE`, `PKEY_ONLY` or a list of specific field names.
    required: false
    type: list
    elements: str
  action:
    description: Work on service or member level
    type: str
    default: service
    choices: ["member", "service"]
  state:
    description: State to ensure
    type: str
    default: present
    choices: ["present", "absent", "disabled", "query"]
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

  # Ensure multiple services are present.
  - ipaservice:
      ipaadmin_password: SomeADMINpassword
      services:
      - name: HTTP/www.example.com
        host:
        - host1.example.com
      - name: HTTP/www.service.com

  # Ensure multiple services are present
  - ipaservice:
      ipaadmin_password: SomeADMINpassword
      services:
      - name: HTTP/www.example.com
        principal:
        - host/host1.example.com
      - name: mysvc/www.example.com
        pac_type: NONE
        ok_as_delegate: yes
        ok_to_auth_as_delegate: yes
      - name: HTTP/www.example.com
        allow_create_keytab_user:
        - user01
        - user02
        allow_create_keytab_group:
        - group01
        - group02
        allow_create_keytab_host:
        - host1.example.com
        - host2.example.com
        allow_create_keytab_hostgroup:
        - hostgroup01
        - hostgroup02
      - name: mysvc/host2.example.com
        auth_ind: otp,radius

  # Ensure service host members are present
  - ipaservice:
      ipaadmin_password: SomeADMINpassword
      services:
      - name: HTTP/www1.example.com
        host: host1.example.com
      - name: HTTP/www2.example.com
        host: host2.example.com
      action: member

  # Query base fields of a service
  - ipaservice:
      ipaadmin_password: SomeADMINpassword
      name: HTTP/www.example.com
      state: query
    register: result

  # Query specific fields of a service
  - ipaservice:
      ipaadmin_password: SomeADMINpassword
      name: HTTP/www.example.com
      query_param:
      - principal
      - host
      - certificate
      state: query
    register: result

  # Query all fields of a service
  - ipaservice:
      ipaadmin_password: SomeADMINpassword
      name: HTTP/www.example.com
      query_param: ALL
      state: query
    register: result

  # Query only the names of all services
  - ipaservice:
      ipaadmin_password: SomeADMINpassword
      query_param: PKEY_ONLY
      state: query
    register: result
"""

RETURN = """
"""

from ansible.module_utils.ansible_freeipa_module import \
    IPAAnsibleModule, compare_args_ipa, encode_certificate, \
    gen_member_add_del_lists, ipalib_errors, \
    api_get_realm, to_text, convert_input_certificates
from ansible.module_utils import six
if six.PY3:
    unicode = str


def service_show(module, name):
    _args = {
        "all": True,
    }

    try:
        _result = module.ipa_command("service_show", name, _args).get(
            "result")
    except ipalib_errors.NotFound:
        return None

    if _result is not None:
        certs = _result.get("usercertificate")
        if certs is not None:
            _result["usercertificate"] = [
                encode_certificate(cert) for cert in certs]
    return _result


def service_find(module, name):
    _args = {"all": True}

    try:
        if name:
            _args["krbcanonicalname"] = name
        _result = module.ipa_command_no_name(
            "service_find", _args).get("result")
        if _result and name:
            _result = _result[0]
    except ipalib_errors.NotFound:
        return None

    return _result


def query_convert_result(module, res):
    _res = {}
    for key in res:
        try:
            if key == "krbprincipalname":
                _res[key] = [to_text(x) for x in (res.get(key) or [])]
            elif key == "usercertificate":
                _res[key] = [
                    encode_certificate(x) for x in (res.get(key) or [])
                ]
            elif key in ["ipakrbrequirespreauth", "ipakrbokasdelegate",
                         "ipakrboktoauthasdelegate"]:
                _res[key] = bool(res[key])
            elif isinstance(res[key], (list, tuple)):
                if len(res[key]) == 1:
                    _res[key] = to_text(res[key][0])
                else:
                    _res[key] = [to_text(x) for x in res[key]]
            else:
                _res[key] = to_text(res[key])
        except (TypeError, ValueError) as e:
            module.fail_json(
                msg="Failed to convert query result for '%s': %s"
                % (key, str(e)))
    return _res


def gen_args_smb(netbiosname, ok_as_delegate, ok_to_auth_as_delegate):
    _args = {}

    if netbiosname is not None:
        _args['ipantflatname'] = netbiosname
    if ok_as_delegate is not None:
        _args['ipakrbokasdelegate'] = ok_as_delegate
    if ok_to_auth_as_delegate is not None:
        _args['ipakrboktoauthasdelegate'] = ok_to_auth_as_delegate

    return _args


def check_parameters(module, state, action, service_params):
    # invalid parameters for everything but state 'present', action
    # 'service'.
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
        if action == 'service':
            invalid = ['delete_continue']

            if (
                not service_params.get('smb')
                and service_params.get('netbiosname')
            ):
                module.fail_json(
                    msg="Argument 'netbiosname' can not be used without "
                        "SMB service.")
        else:
            invalid.append('delete_continue')

    elif state == 'absent':
        if action == "service":
            invalid.extend(invalid_not_member)
        else:
            invalid.append('delete_continue')

    elif state == 'disabled':
        invalid.extend(invalid_not_member)
        invalid.append('delete_continue')
        if action != "service":
            module.fail_json(
                msg="Invalid action '%s' for state '%s'" % (action, state))

    elif state == 'query':
        module.fail_json(
            msg="check_parameters can not be used with action query.")

    else:
        module.fail_json(msg="Invalid state '%s'" % (state))

    invalid.append('query_param')

    module.params_fail_used_invalid(invalid, state, action, service_params,
                                    PARAM_MAPPING)


def check_authind(module, auth_ind):
    _invalid = module.ipa_command_invalid_param_choices(
        "service_add", "krbprincipalauthind", auth_ind)
    if _invalid:
        module.fail_json(
            msg="The use of krbprincipalauthind '%s' is not supported "
            "by your IPA version" % "','".join(_invalid))


# Read-only attributes reported by the FreeIPA API, but not part of the
# module parameters, and operation-only flags that are never stored as
# entry attributes.
PARAM_MAPPING = {
    # Read-only system fields
    "dn": {"return_only": True},
    "objectclass": {"return_only": True},
    "ipauniqueid": {"return_only": True},
    "has_keytab": {"return_only": True},

    # Query-only: name is the primary key
    "name": {"api_name": "krbcanonicalname", "gen_args": False},

    # Writable params (used in gen_args)
    "pac_type": {"api_name": "ipakrbauthzdata",
                 "allow_empty_list_item": True},
    "auth_ind": {"api_name": "krbprincipalauthind",
                 "allow_empty_list_item": True},
    "requires_pre_auth": {"api_name": "ipakrbrequirespreauth",
                          "type": "bool"},
    "ok_as_delegate": {"api_name": "ipakrbokasdelegate", "type": "bool"},
    "ok_to_auth_as_delegate": {"api_name": "ipakrboktoauthasdelegate",
                               "type": "bool"},

    # Operation-only flags, not stored attributes. skip_host_check and
    # force are real service_add/service_mod command parameters (they
    # must stay in gen_args so they reach service_add; they are
    # stripped from args again before service_mod, which doesn't
    # accept them), while smb and delete_continue are never sent via
    # the generic args path at all.
    "skip_host_check": {"query": False},
    "force": {"query": False},
    "smb": {"gen_args": False, "query": False},
    "delete_continue": {"gen_args": False, "query": False},

    # Real attribute, but only ever sent via the dedicated SMB service
    # creation args (gen_args_smb)
    "netbiosname": {"api_name": "ipantflatname", "gen_args": False},

    # Query-only: members handled via separate member commands
    "principal": {"api_name": "krbprincipalname", "gen_args": False,
                  "member": True},
    "certificate": {"api_name": "usercertificate", "gen_args": False,
                    "member": True},
    "host": {"api_name": "managedby_host", "gen_args": False,
             "member": True},
    "allow_create_keytab_user": {
        "api_name": "ipaallowedtoperform_write_keys_user",
        "gen_args": False, "member": True},
    "allow_create_keytab_group": {
        "api_name": "ipaallowedtoperform_write_keys_group",
        "gen_args": False, "member": True},
    "allow_create_keytab_host": {
        "api_name": "ipaallowedtoperform_write_keys_host",
        "gen_args": False, "member": True},
    "allow_create_keytab_hostgroup": {
        "api_name": "ipaallowedtoperform_write_keys_hostgroup",
        "gen_args": False, "member": True},
    "allow_retrieve_keytab_user": {
        "api_name": "ipaallowedtoperform_read_keys_user",
        "gen_args": False, "member": True},
    "allow_retrieve_keytab_group": {
        "api_name": "ipaallowedtoperform_read_keys_group",
        "gen_args": False, "member": True},
    "allow_retrieve_keytab_host": {
        "api_name": "ipaallowedtoperform_read_keys_host",
        "gen_args": False, "member": True},
    "allow_retrieve_keytab_hostgroup": {
        "api_name": "ipaallowedtoperform_read_keys_hostgroup",
        "gen_args": False, "member": True},

    # Module-level params (not per-item, checked via self.params)
    "query_param": {"module_param": True},
}

QUERY_FIELDS = {
    "prefix": "services",
    "primary_key": "krbcanonicalname",
    "base": ["name", "principal", "pac_type", "auth_ind", "host"]
}


def init_ansible_module():
    service_spec = dict(
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
                      choices=["otp", "radius", "pkinit", "hardened", "idp",
                               "passkey", ""]),
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
    )

    query_param_settings = IPAAnsibleModule.build_query_param_settings(
        PARAM_MAPPING, QUERY_FIELDS)

    ansible_module = IPAAnsibleModule(
        argument_spec=dict(
            # general
            name=dict(type="list", elements="str", aliases=["service"],
                      default=None, required=False),
            services=dict(type="list",
                          default=None,
                          options=dict(
                              # Here name is a simple string
                              name=dict(type="str", required=True,
                                        aliases=["service"]),
                              # Add service specific parameters
                              **service_spec
                          ),
                          elements='dict',
                          required=False),
            # query
            query_param=dict(
                type="list", elements="str", default=None,
                choices=["ALL", "BASE", "PKEY_ONLY"]
                + query_param_settings["ALL"],
                required=False
            ),
            # action
            action=dict(type="str", default="service",
                        choices=["member", "service"]),
            # state
            state=dict(type="str", default="present",
                       choices=["present", "absent", "disabled", "query"]),

            # Add service specific parameters for simple use case
            **service_spec
        ),
        mutually_exclusive=[["name", "services"]],
        # Required one of [["name", "services"]] has been removed as there
        # is an extra test below and it is not working with state=query
        supports_check_mode=True,
    )

    ansible_module._ansible_debug = True

    return ansible_module, query_param_settings


def main():
    ansible_module, query_param_settings = init_ansible_module()

    # Get parameters

    # general
    names = ansible_module.params_get("name")
    services = ansible_module.params_get("services")

    # query
    query_param = ansible_module.params_get("query_param")

    # action
    action = ansible_module.params_get("action")
    # state
    state = ansible_module.params_get("state")

    # check parameters
    if state != "query":
        if (names is None or len(names) < 1) and \
           (services is None or len(services) < 1):
            ansible_module.fail_json(msg="At least one name or services is "
                                         "required")
    else:
        if action == "member":
            ansible_module.fail_json(
                msg="Query is not possible with action=member")
        if services is not None:
            ansible_module.fail_json(
                msg="services can not be used with state=query, "
                "use name instead")

    # Use services if names is None
    if services is not None:
        names = services

    # Init

    changed = False
    exit_args = {}

    # Connect to IPA API
    with ansible_module.ipa_connect():

        ansible_module.tm_warn("state: %s" % repr(state))

        if state == "query":
            exit_args = ansible_module.execute_query(
                names, query_param, service_find, query_param_settings,
                convert_result=lambda res: query_convert_result(
                    ansible_module, res)
            )

            ansible_module.exit_json(changed=False, service=exit_args)

        ansible_module.tm_warn("state: %s" % repr(state))

        has_skip_host_check = ansible_module.ipa_command_param_exists(
            "service_add", "skip_host_check")

        commands = []
        keytab_members = ["user", "group", "host", "hostgroup"]
        service_set = set()

        for service in names:
            if isinstance(service, dict):
                name = service.get("name")
                if name in service_set:
                    ansible_module.fail_json(
                        msg="service '%s' is used more than once" % name)
                service_set.add(name)

                service_params = IPAAnsibleModule.extract_params_from_entry(
                    service, PARAM_MAPPING)

            elif (
                isinstance(
                    service, (str, unicode)  # pylint: disable=W0012,E0606
                )
            ):
                name = service
                service_params = IPAAnsibleModule.extract_params(
                    ansible_module, PARAM_MAPPING)
            else:
                ansible_module.fail_json(msg="Service '%s' is not valid" %
                                         repr(service))
                # Never reached, just added to make pylint happy
                name = None
                service_params = {}

            check_parameters(ansible_module, state, action, service_params)

            service_params["certificate"] = convert_input_certificates(
                ansible_module, service_params.get("certificate"), state)

            auth_ind = service_params.get("auth_ind")
            check_authind(ansible_module, auth_ind)

            skip_host_check = service_params.get("skip_host_check")
            if skip_host_check and not has_skip_host_check:
                ansible_module.fail_json(
                    msg="Skipping host check is not supported by your IPA "
                        "version")

            res_find = service_show(ansible_module, name)
            principal = service_params.get("principal")

            if principal and res_find:
                # When comparing principals to the existing ones,
                # the REALM is needded, and are added here for those
                # that do not have it.
                service_params["principal"] = list(set(
                    p if "@" in p else "%s@%s" % (p, api_get_realm())
                    for p in principal
                ))

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

            if state == "present":
                if action == "service":
                    args = IPAAnsibleModule.gen_args_from_mapping(
                        PARAM_MAPPING, service_params)
                    if not has_skip_host_check and 'skip_host_check' in args:
                        del args['skip_host_check']

                    if service_params.get("smb"):
                        if res_find is None:
                            _name = "cifs/" + name
                            res_find = service_show(ansible_module, _name)
                            if res_find is None:
                                _args = gen_args_smb(
                                    service_params.get("netbiosname"),
                                    service_params.get("ok_as_delegate"),
                                    service_params.get(
                                        "ok_to_auth_as_delegate"))
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

                elif action == "member":
                    if res_find is None:
                        ansible_module.fail_json(msg="No service '%s'" % name)

            elif state == "absent":
                if action == "service":
                    if res_find is not None:
                        args = {}
                        delete_continue = service_params.get(
                            "delete_continue")
                        if delete_continue is not None:
                            args['continue'] = delete_continue
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

            # Compute member add/del lists for principal, certificate,
            # host and the keytab permission members.
            member_lists = gen_member_add_del_lists(
                PARAM_MAPPING, service_params, res_find or {}, action, state)
            principal_add, principal_del = member_lists.get(
                "principal", ([], []))
            certificate_add, certificate_del = member_lists.get(
                "certificate", ([], []))
            host_add, host_del = member_lists.get("host", ([], []))

            # Principals are not returned as utf8 for IPA using
            # python2 using service_show, therefore we need to
            # convert the principals that we should remove.
            principal_del = [to_text(x) for x in principal_del]

            # Remove the canonical principal from principal_del. It can
            # never be added or removed via service_add_principal /
            # service_remove_principal, and a full sync of the requested
            # principal list against the existing krbprincipalname
            # aliases (which include the canonical name) would otherwise
            # flag it for removal whenever it is not repeated in
            # `principal`.
            if state == "present" and res_find:
                canonical_principals = {
                    to_text(p)
                    for p in res_find.get("krbcanonicalname", [])
                }
                principal_del = [
                    p for p in principal_del if p not in canonical_principals
                ]

            # manage keytab permissions.
            for perm in ["create", "retrieve"]:
                for key in keytab_members:
                    add_list, del_list = member_lists.get(
                        "allow_%s_keytab_%s" % (perm, key), ([], []))
                    keytab[perm]["allow"][key] = add_list
                    keytab[perm]["disallow"][key] = del_list

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
                    for key in keytab_members:
                        if keytab[perm][mode][key]:
                            commands.append([
                                name,
                                "service_%s_%s_keytab" % (mode, perm),
                                keytab[perm][mode]
                            ])
                            break

        del service_set

        # Check mode exit
        if ansible_module.check_mode:
            ansible_module.exit_json(changed=len(commands) > 0, **exit_args)

        ansible_module.tm_warn("commands: %s" % repr(commands))

        # Execute commands
        changed = ansible_module.execute_ipa_commands(
            commands, batch=True, keeponly=[], fail_on_member_errors=True)

    # Done
    ansible_module.exit_json(changed=changed, **exit_args)


if __name__ == "__main__":
    main()

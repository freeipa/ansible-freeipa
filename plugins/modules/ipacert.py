#!/usr/bin/python
# -*- coding: utf-8 -*-

# Authors:
#   Sam Morris <sam@robots.org.uk>
#   Rafael Guterres Jeffman <rjeffman@redhat.com>
#
# Copyright (C) 2021 Red Hat
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
module: ipacert
short description: Manage FreeIPA certificates
description: Manage FreeIPA certificates
extends_documentation_fragment:
  - ipamodule_base_docs
options:
  csr:
    description: |
      X509 certificate signing request, in RFC 7468 PEM encoding.
      Only available if `state: requested`, required if `csr_file` is not
      provided.
    type: str
  csr_file:
    description: |
      Path to file with X509 certificate signing request, in RFC 7468 PEM
      encoding. Only available if `state: requested`, required if `csr_file`
      is not provided.
    type: str
  principal:
    description: |
      Host/service/user principal for the certificate.
      Required if `state: requested`. Only available if `state: requested`.
    type: str
  add:
    description: |
      Automatically add the principal if it doesn't exist (service
      principals only). Only available if `state: requested`.
    type: bool
    aliases: ["add_principal"]
    required: false
  ca:
    description: Name of the issuing certificate authority.
    type: str
    required: false
  serial_number:
    description: |
      Certificate serial number. Cannot be used with `state: requested`.
      Required for all states, except `requested`.
    type: int
  profile:
    description: Certificate Profile to use.
    type: str
    aliases: ["profile_id"]
    required: false
  revocation_reason:
    description: |
      Reason for revoking the certificate. Use one of the reason strings,
      or the corresponding value: "unspecified" (0), "keyCompromise" (1),
      "cACompromise" (2), "affiliationChanged" (3), "superseded" (4),
      "cessationOfOperation" (5), "certificateHold" (6), "removeFromCRL" (8),
      "privilegeWithdrawn" (9), "aACompromise" (10).
      Use only if `state: revoked`. Required if `state: revoked`.
    type: raw
    aliases: ['reason']
  certificate_out:
    description: |
      Write certificate (chain if `chain` is set) to this file, on the target
      node.. Use only when `state` is `requested` or `retrieved`.
    type: str
    required: false
  state:
    description: |
      The state to ensure. `held` is the same as revoke with reason
      "certificateHold" (6). `released` is the same as `cert-revoke-hold`
      on IPA CLI, releasing the hold status of a certificate.
    choices: ["requested", "held", "released", "revoked", "retrieved"]
    required: true
    type: str
author:
authors:
  - Sam Morris (@yrro)
  - Rafael Guterres Jeffman (@rjeffman)
"""

EXAMPLES = """
- name: Request a certificate for a web server
  ipacert:
    ipaadmin_password: SomeADMINpassword
    state: requested
    csr: |
      -----BEGIN CERTIFICATE REQUEST-----
      MIGYMEwCAQAwGTEXMBUGA1UEAwwOZnJlZWlwYSBydWxlcyEwKjAFBgMrZXADIQBs
      HlqIr4b/XNK+K8QLJKIzfvuNK0buBhLz3LAzY7QDEqAAMAUGAytlcANBAF4oSCbA
      5aIPukCidnZJdr491G4LBE+URecYXsPknwYb+V+ONnf5ycZHyaFv+jkUBFGFeDgU
      SYaXm/gF8cDYjQI=
      -----END CERTIFICATE REQUEST-----
    principal: HTTP/www.example.com
  register: cert

- name: Request certificate for a user, with an appropriate profile.
  ipacert:
    ipaadmin_password: SomeADMINpassword
    csr: |
      -----BEGIN CERTIFICATE REQUEST-----
      MIIBejCB5AIBADAQMQ4wDAYDVQQDDAVwaW5reTCBnzANBgkqhkiG9w0BAQEFAAOB
      jQAwgYkCgYEA7uChccy1Is1FTM0SF23WPYW472E3ozeLh2kzhKR9Ni6FLmeEGgu7
      /hicR1VwvXHYkNwI1tpW9LqxRVvgr6vheqHySljrBcoRfshfYvKejp03l2327Bfq
      BNxXqLcHylNEyg8SH0u63bWyxtgoDBfdZwdGAhYuJ+g4ev79J5eYoB0CAwEAAaAr
      MCkGCSqGSIb3DQEJDjEcMBowGAYHKoZIzlYIAQQNDAtoZWxsbyB3b3JsZDANBgkq
      hkiG9w0BAQsFAAOBgQADCi5BHDv1mrBFDWqYytFpQ1mrvr/mdax3AYXxNL2UEV8j
      AqZAFTEnJXL/u1eVQtI1yotqxakyUBN4XZBP2CBgJRO93Mtry8cgvU1sPdU8Mavx
      5gSnlP74Hio2ziscWWydlxpYxFx0gkKvu+0nyIpz954SVYwQ2wwk5FRqZnxI5w==
      -----END CERTIFICATE REQUEST-----
    principal: pinky
    profile_id: IECUserRoles
    state: requested

- name: Temporarily hold a certificate
  ipacert:
    ipaadmin_password: SomeADMINpassword
    serial_number: 12345
    state: held

- name: Remove a certificate hold
  ipacert:
    ipaadmin_password: SomeADMINpassword
    state: released
    serial_number: 12345

- name: Permanently revoke a certificate issued by a lightweight sub-CA
  ipacert:
    ipaadmin_password: SomeADMINpassword
    state: revoked
    ca: vpn-ca
    serial_number: 0x98765
    reason: keyCompromise

- name: Retrieve a certificate
  ipacert:
    ipaadmin_password: SomeADMINpassword
    serial_number: 12345
    state: retrieved
  register: cert_retrieved
"""

RETURN = """
certificate:
  description: Certificate fields and data.
  returned: |
    if `state` is `requested` or `retrived` and `certificate_out`
    is not defined.
  type: dict
  contains:
    certificate:
      description: |
        Issued X509 certificate in PEM encoding. Will include certificate
        chain if `chain: true` is used.
      type: list
      elements: str
      returned: always
    issuer:
      description: X509 distinguished name of issuer.
      type: str
      sample: CN=Certificate Authority,O=EXAMPLE.COM
      returned: always
    serial_number:
      description: Serial number of the issued certificate.
      type: int
      sample: 902156300
      returned: always
    valid_not_after:
      description: |
        Time when issued certificate ceases to be valid,
        in GeneralizedTime format (YYYYMMDDHHMMSSZ).
      type: str
      returned: always
    valid_not_before:
      description: |
        Time when issued certificate becomes valid, in
        GeneralizedTime format (YYYYMMDDHHMMSSZ).
      type: str
      returned: always
    subject:
      description: X509 distinguished name of certificate subject.
      type: str
      sample: CN=www.example.com,O=EXAMPLE.COM
      returned: always
    san_dnsname:
      description: X509 Subject Alternative Name.
      type: list
      elements: str
      sample: ['www.example.com', 'other.example.com']
      returned: |
        when DNSNames are present in the Subject Alternative Name
        extension of the issued certificate.
    revoked:
      description: Revoked status of the certificate.
      type: bool
      returned: always
    owner_user:
      description: The username that owns the certificate.
      type: str
      returned: when `state` is `retrieved`
    owner_host:
      description: The host that owns the certificate.
      type: str
      returned: when `state` is `retrieved`
    owner_service:
      description: The service that owns the certificate.
      type: str
      returned: when `state` is `retrieved`
"""

import base64
import time
import ssl

from ansible.module_utils import six
from ansible.module_utils._text import to_text
from ansible.module_utils.ansible_freeipa_module import (
    IPAAnsibleModule, certificate_loader, write_certificate_list,
)

if six.PY3:
    unicode = str

# Reasons are defined in RFC 5280 sec. 5.3.1; removeFromCRL is not present in
# this list; run the module with state=released instead.
REVOCATION_REASONS = {
    'unspecified': 0,
    'keyCompromise': 1,
    'cACompromise': 2,
    'affiliationChanged': 3,
    'superseded': 4,
    'cessationOfOperation': 5,
    'certificateHold': 6,
    'removeFromCRL': 8,
    'privilegeWithdrawn': 9,
    'aACompromise': 10,
}


def gen_args(
    module, principal=None, add_principal=None, ca=None, chain=None,
    profile=None, certificate_out=None, reason=None
):
    args = {}
    if principal is not None:
        args['principal'] = principal
    if add_principal is not None:
        args['add'] = add_principal
    if ca is not None:
        args['cacn'] = ca
    if profile is not None:
        args['profile_id'] = profile
    if certificate_out is not None:
        args['out'] = certificate_out
    if chain:
        args['chain'] = True
    if ca:
        args['cacn'] = ca
    if reason is not None:
        args['revocation_reason'] = get_revocation_reason(module, reason)
    return args


def get_revocation_reason(module, reason):
    """Ensure revocation reasion is a valid integer code."""
    reason_int = -1

    try:
        reason_int = int(reason)
    except ValueError:
        reason_int = REVOCATION_REASONS.get(reason, -1)

    if reason_int not in REVOCATION_REASONS.values():
        module.fail_json(msg="Invalid revocation reason: %s" % reason)

    return reason_int


def parse_cert_timestamp(dt):
    """Ensure time is in GeneralizedTime format (YYYYMMDDHHMMSSZ)."""
    return time.strftime(
        "%Y%m%d%H%M%SZ",
        time.strptime(dt, "%a %b %d %H:%M:%S %Y UTC")
    )


def result_handler(_module, result, _command, _name, _args, exit_args, chain):
    """Split certificate into fields."""
    if chain:
        exit_args['certificate'] = [
            ssl.DER_cert_to_PEM_cert(c)
            for c in result['result'].get('certificate_chain', [])
        ]
    else:
        exit_args['certificate'] = [
            ssl.DER_cert_to_PEM_cert(
                base64.b64decode(result['result']['certificate'])
            )
        ]

    exit_args['san_dnsname'] = [
        str(dnsname)
        for dnsname in result['result'].get('san_dnsname', [])
    ]

    exit_args.update({
        key: result['result'][key]
        for key in [
            'issuer', 'subject', 'serial_number',
            'revoked', 'revocation_reason'
        ]
        if key in result['result']
    })
    exit_args.update({
        key: result['result'][key][0]
        for key in ['owner_user', 'owner_host', 'owner_service']
        if key in result['result']
    })

    exit_args.update({
        key: parse_cert_timestamp(result['result'][key])
        for key in ['valid_not_after', 'valid_not_before']
        if key in result['result']
    })


def do_cert_request(
    module, csr, principal, add_principal=None, ca=None, profile=None,
    chain=None, certificate_out=None
):
    """Request a certificate."""
    args = gen_args(
        module, principal=principal, ca=ca, chain=chain,
        add_principal=add_principal, profile=profile,
    )
    exit_args = {}
    commands = [[to_text(csr), "cert_request", args]]
    changed = module.execute_ipa_commands(
        commands,
        result_handler=result_handler,
        exit_args=exit_args,
        chain=chain
    )

    if certificate_out is not None:
        certs = (
            certificate_loader(cert.encode("utf-8"))
            for cert in exit_args['certificate']
        )
        write_certificate_list(certs, certificate_out)
        exit_args = {}

    return changed, exit_args


def do_cert_revoke(ansible_module, serial_number, reason=None, ca=None):
    """Revoke a certificate."""
    _ign, cert = do_cert_retrieve(ansible_module, serial_number, ca)
    if not cert or cert.get('revoked', False):
        return False, cert

    args = gen_args(ansible_module, ca=ca, reason=reason)

    commands = [[serial_number, "cert_revoke", args]]
    changed = ansible_module.execute_ipa_commands(commands)

    return changed, cert


def do_cert_release(ansible_module, serial_number, ca=None):
    """Release hold on certificate."""
    _ign, cert = do_cert_retrieve(ansible_module, serial_number, ca)
    revoked = cert.get('revoked', True)
    reason = cert.get('revocation_reason', -1)
    if cert and not revoked:
        return False, cert

    if revoked and reason != 6:  # can only release held certificates
        ansible_module.fail_json(
            msg="Cannot release hold on certificate revoked with"
                " reason: %d" % reason
        )
    args = gen_args(ansible_module, ca=ca)

    commands = [[serial_number, "cert_remove_hold", args]]
    changed = ansible_module.execute_ipa_commands(commands)

    return changed, cert


def do_cert_retrieve(
    module, serial_number, ca=None, chain=None, outfile=None
):
    """Retrieve a certificate with 'cert-show'."""
    args = gen_args(module, ca=ca, chain=chain, certificate_out=outfile)
    exit_args = {}
    commands = [[serial_number, "cert_show", args]]
    module.execute_ipa_commands(
        commands,
        result_handler=result_handler,
        exit_args=exit_args,
        chain=chain,
    )
    if outfile is not None:
        exit_args = {}

    return False, exit_args


def main():
    ansible_module = IPAAnsibleModule(
        argument_spec=dict(
            # requested
            csr=dict(type="str"),
            csr_file=dict(type="str"),
            principal=dict(type="str"),
            add_principal=dict(type="bool", required=False, aliases=["add"]),
            profile_id=dict(type="str", aliases=["profile"], required=False),
            # revoked
            revocation_reason=dict(type="raw", aliases=["reason"]),
            # general
            serial_number=dict(type="int"),
            ca=dict(type="str"),
            chain=dict(type="bool", required=False),
            certificate_out=dict(type="str", required=False),
            # state
            state=dict(
                type="str",
                required=True,
                choices=[
                    "requested", "held", "released", "revoked", "retrieved"
                ]
            ),
        ),
        mutually_exclusive=[["csr", "csr_file"]],
        required_if=[
            ('state', 'requested', ['principal']),
            ('state', 'retrieved', ['serial_number']),
            ('state', 'held', ['serial_number']),
            ('state', 'released', ['serial_number']),
            ('state', 'revoked', ['serial_number', 'revocation_reason']),
        ],
        supports_check_mode=False,
    )

    ansible_module._ansible_debug = True

    # Get parameters

    # requested
    csr = ansible_module.params_get("csr")
    csr_file = ansible_module.params_get("csr_file")
    principal = ansible_module.params_get("principal")
    add_principal = ansible_module.params_get("add_principal")
    profile = ansible_module.params_get("profile_id")

    # revoked
    reason = ansible_module.params_get("revocation_reason")

    # general
    serial_number = ansible_module.params.get("serial_number")
    ca = ansible_module.params_get("ca")
    chain = ansible_module.params_get("chain")
    certificate_out = ansible_module.params_get("certificate_out")

    # state
    state = ansible_module.params_get("state")

    # Check parameters

    if ansible_module.params_get("ipaapi_context") == "server":
        ansible_module.fail_json(
            msg="Context 'server' for ipacert is not yet supported."
        )

    invalid = []
    if state == "requested":
        invalid = ["serial_number", "revocation_reason"]
        if csr is None and csr_file is None:
            ansible_module.fail_json(
                msg="Required 'csr' or 'csr_file' with 'state: requested'.")
    else:
        invalid = [
            "csr", "principal", "add_principal", "profile"
            "certificate_out"
        ]
        if state in ["released", "held"]:
            invalid.extend(["revocation_reason", "certificate_out", "chain"])
        if state == "retrieved":
            invalid.append("revocation_reason")
        if state == "revoked":
            invalid.extend(["certificate_out", "chain"])
        elif state == "held":
            reason = 6  # certificateHold

    ansible_module.params_fail_used_invalid(invalid, state)

    # Init

    changed = False
    exit_args = {}

    # Connect to IPA API
    # If executed on 'server' contexot, cert plugin uses the IPA RA agent
    # TLS client certificate/key, which users are not able to access,
    # resulting in a 'permission denied' exception when attempting to connect
    # the CA service. Therefore 'client' context in forced for this module.
    with ansible_module.ipa_connect(context="client"):

        if state == "requested":
            if csr_file is not None:
                with open(csr_file, "rt") as csr_in:
                    csr = "".join(csr_in.readlines())
            changed, exit_args = do_cert_request(
                ansible_module,
                csr,
                principal,
                add_principal,
                ca,
                profile,
                chain,
                certificate_out
            )

        elif state in ("held", "revoked"):
            changed, exit_args = do_cert_revoke(
                ansible_module, serial_number, reason, ca)

        elif state == "released":
            changed, exit_args = do_cert_release(
                ansible_module, serial_number, ca)

        elif state == "retrieved":
            changed, exit_args = do_cert_retrieve(
                ansible_module, serial_number, ca, chain, certificate_out)

    # Done

    ansible_module.exit_json(changed=changed, certificate=exit_args)


if __name__ == "__main__":
    main()

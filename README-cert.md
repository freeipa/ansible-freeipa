Cert module
============

Description
-----------

The cert module makes it possible to request, revoke and retrieve SSL certificates for hosts, services and users.

Features
--------

* Certificate request
* Certificate hold/release
* Certificate revocation
* Certificate retrieval


Supported FreeIPA Versions
--------------------------

FreeIPA versions 4.4.0 and up are supported by the ipacert module.


Requirements
------------

**Controller**
* Ansible version: 2.13+
* Some tool to generate a certificate signing request (CSR) might be needed, like `openssl`.

**Node**
* Supported FreeIPA version (see above)


Usage
=====

Example inventory file

```ini
[ipaserver]
ipaserver.test.local
```

Example playbook to request a new certificate for a service:

```yaml
---
- name: Certificate request
  hosts: ipaserver

  tasks:
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
```

Example playbook to revoke an existing certificate:

```yaml
---
- name: Revoke certificate
  hosts: ipaserver

  tasks:
  - name Revoke a certificate
    ipacert:
      ipaadmin_password: SomeADMINpassword
      serial_number: 123456789
      reason: 5
      state: revoked
```

When revoking a certificate a mnemonic can also be used to set the revocation reason:

```yaml
---
- name: Revoke certificate
  hosts: ipaserver

  tasks:
  - name Revoke a certificate
    ipacert:
      ipaadmin_password: SomeADMINpassword
      serial_number: 123456789
      reason: cessationOfOperation
      state: revoked
```

Example to hold a certificate (alias for revoking a certificate with reason `certificateHold (6)`):

```yaml
---
- name: Hold a certificate
  hosts: ipaserver

  tasks:
  - name: Hold certificate
    ipacert:
      ipaadmin_password: SomeADMINpassword
      serial_number: 0xAB1234
      state: held
```

Example playbook to release hold of certificate (may be used with any revoked certificates, despite of the rovoke reason):

```yaml
---
- name: Release hold
  hosts: ipaserver

  tasks:
  - name: Take a revoked certificate off hold
    ipacert:
      ipaadmin_password: SomeADMINpassword
      serial_number: 0xAB1234
      state: released
```

Example playbook to retrieve a certificate and save it to a file in the target node:

```yaml
---
- name: Retriev certificate
  hosts: ipaserver

  tasks:
  - name: Retrieve a certificate and save it to file 'cert.pem'
    ipacert:
      ipaadmin_password: SomeADMINpassword
      certificate_out: cert.pem
      state: retrieved
```


ipacert
-------

Variable | Description | Required
-------- | ----------- | --------
`ipaadmin_principal` | The admin principal is a string and defaults to `admin` | no
`ipaadmin_password` | The admin password is a string and is required if there is no admin ticket available on the node | no
`ipaapi_context` | The context in which the module will execute. Executing in a server context is preferred. If not provided context will be determined by the execution environment. Valid values are `server` and `client`. | no
`ipaapi_ldap_cache` | Use LDAP cache for IPA connection. The bool setting defaults to yes. (bool) | no
`csr` | X509 certificate signing request, in PEM format. | yes, if `state: requested`
`principal` | Host/service/user principal for the certificate. | yes, if `state: requested`
`add` \| `add_principal` | Automatically add the principal if it doesn't exist (service principals only). (bool) | no
`profile_id` \| `profile` | Certificate Profile to use | no
`ca` | Name of the issuing certificate authority. | no
`chain` | Include certificate chain in output. (bool) | no
`serial_number` | Certificate serial number. (int) | yes, if `state` is `retrieved`, `held`, `released` or `revoked`.
`revocation_reason` \| `reason` | Reason for revoking the certificate. Use one of the reason strings, or the corresponding value: "unspecified" (0), "keyCompromise" (1), "cACompromise" (2), "affiliationChanged" (3), "superseded" (4), "cessationOfOperation" (5), "certificateHold" (6), "removeFromCRL" (8), "privilegeWithdrawn" (9), "aACompromise" (10) | yes, if `state: revoked`
`certificate_out` | Write certificate (chain if `chain` is set) to this file, on the target node. | no
`state` | The state to ensure. It can be one of `requested`, `held`, `released`, `revoked`, or `retrieved`. `held` is the same as revoke with reason "certificateHold" (6). `released` is the same as `cert-revoke-hold` on IPA CLI, releasing the hold status of a certificate. | yes


Return Values
=============

Values are returned only if `state` is `requested` or `retrieved` and if `certificate_out` is not defined.

Variable | Description | Returned When
-------- | ----------- | -------------
`certificate` | Certificate fields and data. (dict) <br>Options: | if `state` is `requested` or `retrieved` and if `certificate_out` is not defined
&nbsp; | `certificate` - Issued X509 certificate in PEM encoding. Will include certificate chain if `chain: true`. (list) | always 
&nbsp; | `san_dnsname` - X509 Subject Alternative Name. | When DNSNames are present in the Subject Alternative Name extension of the issued certificate.
&nbsp; | `issuer` - X509 distinguished name of issuer. | always
&nbsp; | `subject` - X509 distinguished name of certificate subject. | always
&nbsp; | `serial_number` - Serial number of the issued certificate. (int) | always
&nbsp; | `revoked` - Revoked status of the certificate. (bool) | if certificate was revoked
&nbsp; | `owner_user` - The username that owns the certificate. | if `state: retrieved` and certificate is owned by a user
&nbsp; | `owner_host` - The host that owns the certificate. | if `state: retrieved` and certificate is owned by a host
&nbsp; | `owner_service` - The service that owns the certificate. | if `state: retrieved` and certificate is owned by a service
&nbsp; | `valid_not_before` - Time when issued certificate becomes valid, in GeneralizedTime format (YYYYMMDDHHMMSSZ) | always
&nbsp; | `valid_not_after` - Time when issued certificate ceases to be valid, in GeneralizedTime format (YYYYMMDDHHMMSSZ) | always


Authors
=======

Sam Morris
Rafael Jeffman

Service module
==============

Description
-----------

The service module allows to ensure presence and absence of services.


Features
--------

* Service management


Supported FreeIPA Versions
--------------------------

FreeIPA versions 4.4.0 and up are supported by the ipaservice module.

Some variables are only supported on newer versions of FreeIPA. Check `Variables` section for details.


Requirements
------------

**Controller**
* Ansible version: 2.13+

**Node**
* Supported FReeIPA version (see above)


Usage
=====

Example inventory file

```ini
[ipaserver]
ipaserver.test.local
```


Example playbook to make sure service is present:

```yaml
---
- name: Playbook to manage IPA service.
  hosts: ipaserver
  become: true
  gather_facts: false

  tasks:
  # Ensure service is present
  - ipaservice:
      ipaadmin_password: SomeADMINpassword
      name: HTTP/www.example.com
      certificate: |
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
      pac_type: PAD
      auth_ind: otp
      requires_pre_auth: false
      ok_as_delegate: false
      ok_to_auth_as_delegate: false
      skip_host_check: true
      force: true
```


Example playbook to make sure service is absent:

```yaml
---
- name: Playbook to manage IPA service.
  hosts: ipaserver
  become: true
  gather_facts: false

  tasks:
  # Ensure service is present
  - ipaservice:
      ipaadmin_password: SomeADMINpassword
      name: HTTP/www.example.com
      state: absent
```


Example playbook to make sure service is disabled:

```yaml
---
- name: Playbook to manage IPA service.
  hosts: ipaserver
  become: true
  gather_facts: false

  tasks:
  # Ensure service is present
  - ipaservice:
      ipaadmin_password: SomeADMINpassword
      name: HTTP/www.example.com
      state: disabled
```

Example playbook to add a service even if the host object does not exist, but only if it does have a DNS entry:

```yaml
---
- name: Playbook to manage IPA service.
  hosts: ipaserver
  become: true
  gather_facts: false

  tasks:
  # Ensure service is present
  - ipaservice:
      ipaadmin_password: SomeADMINpassword
      name: HTTP/www.example.com
      skip_host_check: true
      force: false
```

Example playbook to add a service if it does have a DNS entry, but host object exits:

```yaml
---
- name: Playbook to manage IPA service.
  hosts: ipaserver
  become: true
  gather_facts: false

  tasks:
  # Ensure service is present
  - ipaservice:
      ipaadmin_password: SomeADMINpassword
      name: HTTP/www.example.com
      skip_host_check: false
      force: true
```

Example playbook to ensure service has a certificate:

```yaml
---
- name: Playbook to manage IPA service.
  hosts: ipaserver
  become: true
  gather_facts: false

  tasks:
  # Ensure service member certificate is present.
  - ipaservice:
      ipaadmin_password: SomeADMINpassword
      name: HTTP/www.example.com
      certificate: |
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
```

Example playbook to add a principal to the service:

```yaml
---
- name: Playbook to manage IPA service.
  hosts: ipaserver
  become: true
  gather_facts: false

  tasks:
    # Principal host/principal.example.com present in service.
    - ipaservice:
        ipaadmin_password: SomeADMINpassword
        name: HTTP/www.example.com
        principal: host/principal.example.com
        action: member
```

Example playbook to enable a host to manage service:

```yaml
---
- name: Playbook to manage IPA service.
  hosts: ipaserver
  become: true
  gather_facts: false

  tasks:
    # Ensure host can manage service, again.
    - ipaservice:
        ipaadmin_password: SomeADMINpassword
        name: HTTP/www.example.com
        host: host1.example.com
        action: member
```

Example playbook to allow users, groups, hosts or hostgroups to create a keytab of this service:

```yaml
---
- name: Playbook to manage IPA service.
  hosts: ipaserver
  become: true
  gather_facts: false

  tasks:
    # Allow users, groups, hosts or host groups to create a keytab of this service.
    - ipaservice:
        ipaadmin_password: SomeADMINpassword
        name: HTTP/www.example.com
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
        action: member
```

Example playbook to allow users, groups, hosts or hostgroups to retrieve a keytab of this service:

```yaml
---
- name: Playbook to manage IPA service.
  hosts: ipaserver
  become: true
  gather_facts: false

  tasks:
    # Allow users, groups, hosts or host groups to retrieve a keytab of this service.
    - ipaservice:
        ipaadmin_password: SomeADMINpassword
        name: HTTP/www.example.com
        allow_retrieve_keytab_user:
        - user01
        - user02
        allow_retrieve_keytab_group:
        - group01
        - group02
        allow_retrieve_keytab_host:
        - "{{ host1_fqdn }}"
        - "{{ host2_fqdn }}"
        allow_retrieve_keytab_hostgroup:
        - hostgroup01
        - hostgroup02
        action: member
```


Variables
---------

Variable | Description | Required
-------- | ----------- | --------
`ipaadmin_principal` | The admin principal is a string and defaults to `admin` | no
`ipaadmin_password` | The admin password is a string and is required if there is no admin ticket available on the node | no
`ipaapi_context` | The context in which the module will execute. Executing in a server context is preferred. If not provided context will be determined by the execution environment. Valid values are `server` and `client`. | no
`ipaapi_ldap_cache` | Use LDAP cache for IPA connection. The bool setting defaults to yes. (bool) | no
`name` \| `service` | The list of service name strings. | yes
`certificate` \| `usercertificate` | Base-64 encoded service certificate. | no
`pac_type` \| `ipakrbauthzdata` | Supported PAC type. It can be one of `MS-PAC`, `PAD`, or `NONE`. Use empty string to reset pac_type to the initial value. | no
`auth_ind` \| `krbprincipalauthind` | Defines an allow list for Authentication Indicators. It can be any of `otp`, `radius`, `pkinit`, `hardened`, `idp` or `""`.  An additional check ensures that only types can be used that are supported by the IPA version. Use empty string to reset auth_ind to the initial value. | no
`requires_pre_auth` \| `ipakrbrequirespreauth` | Pre-authentication is required for the service. Default to true. (bool) | no
`ok_as_delegate` \|  `ipakrbokasdelegate` | Client credentials may be delegated to the service. Default to false. (bool) | no
`ok_to_auth_as_delegate` \|  `ipakrboktoauthasdelegate` | The service is allowed to authenticate on behalf of a client. Default to false. (bool) | no
`skip_host_check` | Force service to be created even when host object does not exist to manage it. Only usable with IPA versions 4.7.0 and up. Default to false. (bool)| no
`force` | Force principal name even if host not in DNS. Default to false. (bool) | no
`host` \| `managedby_host`| Hosts that can manage the service. | no
`principal` \| `krbprincipalname` | List of principal aliases for the service. | no
`allow_create_keytab_user` \| `ipaallowedtoperform_write_keys_user` | Users allowed to create a keytab of this host. | no
`allow_create_keytab_group` \| `ipaallowedtoperform_write_keys_group`| Groups allowed to create a keytab of this host. | no
`allow_create_keytab_host` \| `ipaallowedtoperform_write_keys_host`| Hosts allowed to create a keytab of this host. | no
`allow_create_keytab_hostgroup` \| `ipaallowedtoperform_write_keys_group`| Host groups allowed to create a keytab of this host. | no
`allow_retrieve_keytab_user` \| `ipaallowedtoperform_read_keys_user` | Users allowed to retrieve a keytab of this host. | no
`allow_retrieve_keytab_group` \| `ipaallowedtoperform_read_keys_group` | Groups allowed to retrieve a keytab of this host. | no
`allow_retrieve_keytab_host` \| `ipaallowedtoperform_read_keys_host` | Hosts allowed to retrieve a keytab from of host. | no
`allow_retrieve_keytab_hostgroup` \| `ipaallowedtoperform_read_keys_hostgroup` | Host groups allowed to retrieve a keytab of this host. | no
`continue` | Continuous mode: don't stop on errors. Valid only if `state` is `absent`. Default: `no` (bool) | no
`smb` | Service is an SMB service. If set, `cifs/` will be prefixed to the service name if needed. | no
`netbiosname` | NETBIOS name for the SMB service. Only with `smb: yes`. | no
`action` | Work on service or member level. It can be on of `member` or `service` and defaults to `service`. | no
`state` | The state to ensure. It can be one of `present`, `absent`, or `disabled`, default: `present`. | no


Authors
=======

Rafael Jeffman

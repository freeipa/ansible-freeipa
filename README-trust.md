Trust module
============

Description
-----------

The trust module allows to ensure presence and absence of a domain trust.

Features
--------

* Trust management

Supported FreeIPA Versions
--------------------------

FreeIPA versions 4.4.0 and up are supported by the ipatrust module.

Requirements
------------

**Controller**

* Ansible version: 2.13+

**Node**

* Supported FreeIPA version (see above)
* samba-4
* ipa-server-trust-ad

Usage
=====

Example inventory file

```ini
[ipaserver]
ipaserver.test.local
```

Example playbook to ensure a one-way trust is present:
Omitting the two_way option implies the default of one-way

```yaml
---
- name: Playbook to ensure a one-way trust is present
  hosts: ipaserver
  become: true

  tasks:
  - name: ensure the one-way trust present
    ipatrust:
      realm: ad.example.test
      admin: Administrator
      password: secret_password
      state: present
```

Example playbook to ensure a two-way trust is present using a shared-secret:

```yaml
---
- name: Playbook to ensure a two-way trust is present
  hosts: ipaserver
  become: true

  tasks:
  - name: ensure the two-way trust is present
    ipatrust:
      realm: ad.example.test
      trust_secret: my_share_Secret
      two_way: True
      state: present
```

Example playbook to ensure a trust is absent:

```yaml
---
- name: Playbook to ensure a trust is absent
  hosts: ipaserver
  become: true

  tasks:
  - name: ensure the trust is absent
    ipatrust:
      realm: ad.example.test
      state: absent
```

This will only delete the ipa-side of the trust and it does NOT delete the id-range that matches the trust,

Variables
=========

Variable | Description | Required
-------- | ----------- | --------
`ipaadmin_principal` | The admin principal is a string and defaults to `admin` | no
`ipaadmin_password` | The admin password is a string and is required if there is no admin ticket available on the node | no
`ipaapi_context` | The context in which the module will execute. Executing in a server context is preferred. If not provided context will be determined by the execution environment. Valid values are `server` and `client`. | no
`ipaapi_ldap_cache` | Use LDAP cache for IPA connection. The bool setting defaults to yes. (bool) | no
`realm` | The realm name string. | yes
`admin` | Active Directory domain administrator string. | no
`password` | Active Directory domain administrator's password string. | no
`server` | Domain controller for the Active Directory domain string. | no
`trust_secret` | Shared secret for the trust string. | no
`trust_type` | Trust type. Currently, only 'ad' for Active Directory is supported. | no
`base_id` | First posix id for the trusted domain integer. | no
`range_size` | Size of the ID range reserved for the trusted domain integer. | no
`range_type` | Type of trusted domain ID range, It can be one of `ipa-ad-trust` or `ipa-ad-trust-posix`and defaults to `ipa-ad-trust`. | no
`two_way` | Establish bi-directional trust. By default trust is inbound one-way only. (bool) | no
`external` | Establish external trust to a domain in another forest. The trust is not transitive beyond the domain. (bool) | no
`state` | The state to ensure. It can be one of `present` or `absent`, default: `present`. | yes

Authors
=======

Rob Verduijn

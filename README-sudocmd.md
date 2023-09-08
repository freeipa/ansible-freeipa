Sudocmd module
================

Description
-----------

The sudocmd module allows to ensure presence and absence of sudo command.

The sudocmd module is as compatible as possible to the Ansible upstream `ipa_sudocmd` module.


Features
--------
* Sudo command management


Supported FreeIPA Versions
--------------------------

FreeIPA versions 4.4.0 and up are supported by the ipa_sudocmd module.


Requirements
------------

**Controller**
* Ansible version: 2.13+

**Node**
* Supported FreeIPA version (see above)


Usage
=====

Example inventory file

```ini
[ipaserver]
ipaserver.test.local
```


Example playbook to make sure sudocmd exists:

```yaml
---
- name: Playbook to handle sudocmd
  hosts: ipaserver
  become: true

  tasks:
  # Ensure sudocmd is present
  - ipasudocmd:
      ipaadmin_password: SomeADMINpassword
      name: /usr/bin/su
      state: present
```

Example playbook to make sure sudocmd is absent:

```yaml
---
- name: Playbook to handle sudocmd
  hosts: ipaserver
  become: true

  tasks:
  # Ensure sudocmd are absent
  - ipasudocmd:
      ipaadmin_password: SomeADMINpassword
      name: /usr/bin/su
      state: absent
```

Variables
=========

Variable | Description | Required
-------- | ----------- | --------
`ipaadmin_principal` | The admin principal is a string and defaults to `admin` | no
`ipaadmin_password` | The admin password is a string and is required if there is no admin ticket available on the node | no
`ipaapi_context` | The context in which the module will execute. Executing in a server context is preferred. If not provided context will be determined by the execution environment. Valid values are `server` and `client`. | no
`ipaapi_ldap_cache` | Use LDAP cache for IPA connection. The bool setting defaults to yes. (bool) | no
`name` \| `sudocmd` | The sudo command strings. | yes
`description` | The command description string. | no
`nomembers` | Suppress processing of membership attributes. (bool) | no
`state` | The state to ensure. It can be one of `present` or `absent`, default: `present`. | no


Authors
=======

Rafael Guterres Jeffman

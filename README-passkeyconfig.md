Passkeyconfig module
============

Description
-----------

The passkeyconfig module allows to manage FreeIPA passkey configuration settings.

Features
--------

* Passkeyconfig management


Supported FreeIPA Versions
--------------------------

FreeIPA versions 4.4.0 and up are supported by the ipapasskeyconfig module.


Requirements
------------

**Controller**
* Ansible version: 2.15+

**Node**
* Supported FreeIPA version (see above)


Usage
=====

Example inventory file

```ini
[ipaserver]
ipaserver.test.local
```


By default, user verification for passkey authentication is turned on (`true`). Example playbook to ensure that the requirement for user verification for passkey authentication is turned off:

```yaml
---
- name: Playbook to manage IPA passkeyconfig.
  hosts: ipaserver
  become: false

  tasks:
  - name: Ensure require_user_verification is false
    ipapasskeyconfig:
      ipaadmin_password: SomeADMINpassword
      require_user_verification: false
```


Example playbook to get current passkeyconfig:

```yaml
---
- name: Playbook to get IPA passkeyconfig.
  hosts: ipaserver
  become: false

  tasks:
  - name: Retrieve current passkey configuration
    ipapasskeyconfig:
      ipaadmin_password: SomeADMINpassword
```


Variables
---------

Variable | Description | Required
-------- | ----------- | --------
`ipaadmin_principal` | The admin principal is a string and defaults to `admin` | no
`ipaadmin_password` | The admin password is a string and is required if there is no admin ticket available on the node | no
`ipaapi_context` | The context in which the module will execute. Executing in a server context is preferred. If not provided context will be determined by the execution environment. Valid values are `server` and `client`. | no
`ipaapi_ldap_cache` | Use LDAP cache for IPA connection. The bool setting defaults to true. (bool) | no
`require_user_verification` \| `iparequireuserverification` | Require user verification for passkey authentication. (bool) | no


Authors
=======

Rafael Guterres Jeffman

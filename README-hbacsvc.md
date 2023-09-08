HBACsvc module
==============

Description
-----------

The hbacsvc (HBAC Service) module allows to ensure presence and absence of HBAC Services.


Features
--------
* HBACsvc management


Supported FreeIPA Versions
--------------------------

FreeIPA versions 4.4.0 and up are supported by the ipahbacsvc module.


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


Example playbook to make sure HBAC Service for http is present

```yaml
---
- name: Playbook to handle HBAC Services
  hosts: ipaserver
  become: true

  tasks:
  # Ensure HBAC Service for http is present
  - ipahbacsvc:
      ipaadmin_password: SomeADMINpassword
      name: http
      description: Web service
```

Example playbook to make sure HBAC Service for tftp is present

```yaml
---
- name: Playbook to handle HBAC Services
  hosts: ipaserver
  become: true

  tasks:
  # Ensure HBAC Service for tftp is present
  - ipahbacsvc:
      ipaadmin_password: SomeADMINpassword
      name: tftp
      description: TFTPWeb service
```

Example playbook to make sure HBAC Services for http and tftp are absent

```yaml
---
- name: Playbook to handle HBAC Services
  hosts: ipaserver
  become: true

  tasks:
  # Ensure HBAC Service for http and tftp are absent
  - ipahbacsvc:
      ipaadmin_password: SomeADMINpassword
      name: http,tftp
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
`name` \| `cn` \| `service` | The list of hbacsvc name strings. | no
`description` | The hbacsvc description string. | no
`state` | The state to ensure. It can be one of `present` or `absent`, default: `present`. | no


Authors
=======

Thomas Woerner

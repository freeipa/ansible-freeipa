HBACsvcgroup module
===================

Description
-----------

The hbacsvcgroup (HBAC Service Group) module allows to ensure presence and absence of HBAC Service Groups and members of the groups.


Features
--------
* HBAC Service Group management


Supported FreeIPA Versions
--------------------------

FreeIPA versions 4.4.0 and up are supported by the ipahbacsvcgroup module.


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


Example playbook to make sure HBAC Service Group login exists:

```yaml
---
- name: Playbook to handle hbacsvcgroups
  hbacsvcs: ipaserver
  become: true

  tasks:
  # Ensure HBAC Service Group login is present
  - ipahbacsvcgroup:
      ipaadmin_password: SomeADMINpassword
      name: login
```


Example playbook to make sure HBAC Service Group login exists with the only HBAC Service sshd:

```yaml
---
- name: Playbook to handle hbacsvcgroups
  hbacsvcs: ipaserver
  become: true

  tasks:
  # Ensure HBAC Service Group login is present with the only HBAC Service sshd
  - ipahbacsvcgroup:
      ipaadmin_password: SomeADMINpassword
      name: login
      hbacsvc:
      - sshd
```

Example playbook to make sure HBAC Service sshd is present in HBAC Service Group login:

```yaml
---
- name: Playbook to handle hbacsvcgroups
  hbacsvcs: ipaserver
  become: true

  tasks:
  # Ensure HBAC Service sshd is present in HBAC Service Group login
  - ipahbacsvcgroup:
      ipaadmin_password: SomeADMINpassword
      name: login
      hbacsvc:
      - sshd
      action: member
```

Example playbook to make sure HBAC Service sshd is absent in HBAC Service Group login:

```yaml
---
- name: Playbook to handle hbacsvcgroups
  hbacsvcs: ipaserver
  become: true

  tasks:
  # Ensure HBAC Service sshd is present in HBAC Service Group login
  - ipahbacsvcgroup:
      ipaadmin_password: SomeADMINpassword
      name: login
      hbacsvc:
      - sshd
      action: member
      state: absent
```

Example playbook to make sure HBAC Service Group login is absent:

```yaml
---
- name: Playbook to handle hbacsvcgroups
  hbacsvcs: ipaserver
  become: true

  tasks:
  # Ensure HBAC Service Group login is present
  - ipahbacsvcgroup:
      ipaadmin_password: SomeADMINpassword
      name: login
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
`name` \| `cn` | The list of hbacsvcgroup name strings. | no
`description` | The hbacsvcgroup description string. | no
`nomembers` | Suppress processing of membership attributes. (bool) | no
`hbacsvc` | List of hbacsvc name strings assigned to this hbacsvcgroup. | no
`action` | Work on hbacsvcgroup or member level. It can be on of `member` or `hbacsvcgroup` and defaults to `hbacsvcgroup`. | no
`state` | The state to ensure. It can be one of `present` or `absent`, default: `present`. | no


Authors
=======

Thomas Woerner

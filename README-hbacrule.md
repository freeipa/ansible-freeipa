HBACrule module
===============

Description
-----------

The hbacrule (HBAC Rule) module allows to ensure presence and absence of HBAC Rules and host, hostgroups, HBAC Services, HBAC Service Groups, users, and user groups as members of HBAC Rule.


Features
--------
* HBAC Rule management


Supported FreeIPA Versions
--------------------------

FreeIPA versions 4.4.0 and up are supported by the ipahbacrule module.


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


Example playbook to make sure HBAC Rule login exists:

```yaml
---
- name: Playbook to handle hbacrules
  hbacsvcs: ipaserver
  become: true

  tasks:
  # Ensure HBAC Rule login is present
  - ipahbacrule:
      ipaadmin_password: SomeADMINpassword
      name: login
```


Example playbook to make sure HBAC Rule login exists with the only HBAC Service sshd:

```yaml
---
- name: Playbook to handle hbacrules
  hbacsvcs: ipaserver
  become: true

  tasks:
  # Ensure HBAC Rule login is present with the only HBAC Service sshd
  - ipahbacrule:
      ipaadmin_password: SomeADMINpassword
      name: login
      hbacsvc:
      - sshd
```

Example playbook to make sure HBAC Service sshd is present in HBAC Rule login:

```yaml
---
- name: Playbook to handle hbacrules
  hbacsvcs: ipaserver
  become: true

  tasks:
  # Ensure HBAC Service sshd is present in HBAC Rule login
  - ipahbacrule:
      ipaadmin_password: SomeADMINpassword
      name: login
      hbacsvc:
      - sshd
      action: member
```

Example playbook to make sure HBAC Service sshd is absent in HBAC Rule login:

```yaml
---
- name: Playbook to handle hbacrules
  hbacsvcs: ipaserver
  become: true

  tasks:
  # Ensure HBAC Service sshd is present in HBAC Rule login
  - ipahbacrule:
      ipaadmin_password: SomeADMINpassword
      name: login
      hbacsvc:
      - sshd
      action: member
      state: absent
```

Example playbook to make sure HBAC Rule login is absent:

```yaml
---
- name: Playbook to handle hbacrules
  hbacsvcs: ipaserver
  become: true

  tasks:
  # Ensure HBAC Rule login is present
  - ipahbacrule:
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
`name` \| `cn` | The list of hbacrule name strings. | yes
`description` | The hbacrule description string. | no
`usercategory` \| `usercat` | User category the rule applies to. Choices: ["all", ""] | no
`hostcategory` \| `hostcat` | Host category the rule applies to. Choices: ["all", ""] | no
`servicecategory` \| `servicecat` | HBAC service category the rule applies to. Choices: ["all", ""] | no
`nomembers` | Suppress processing of membership attributes. (bool) | no
`host` | List of host name strings assigned to this hbacrule. | no
`hostgroup` | List of host group name strings assigned to this hbacrule. | no
`hbacsvc` | List of HBAC Service name strings assigned to this hbacrule. | no
`hbacsvcgroup` | List of HBAC Service Group name strings assigned to this hbacrule. | no
`user` | List of user name strings assigned to this hbacrule. | no
`group` | List of user group name strings assigned to this hbacrule. | no
`action` | Work on hbacrule or member level. It can be on of `member` or `hbacrule` and defaults to `hbacrule`. | no
`state` | The state to ensure. It can be one of `present`, `absent`, `enabled` or `disabled`, default: `present`. | no


Authors
=======

Thomas Woerner

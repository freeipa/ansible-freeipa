Sudorule module
===============

Description
-----------

The sudorule (Sudo Rule) module allows to ensure presence and absence of Sudo Rules and host, hostgroups, users, and user groups as members of Sudo Rule.


Features
--------
* Sudo Rule management


Supported FreeIPA Versions
--------------------------

FreeIPA versions 4.4.0 and up are supported by the ipasudorule module.


Requirements
------------

**Controller**
* Ansible version: 2.8+

**Node**
* Supported FreeIPA version (see above)


Usage
=====

Example inventory file

```ini
[ipaserver]
ipaserver.test.local
```


Example playbook to make sure Sudo Rule is present:

```yaml
---
- name: Playbook to handle sudorules
  hosts: ipaserver
  become: true

  tasks:
  # Ensure Sudo Rule is present
  - ipasudorule:
      ipaadmin_password: MyPassword123
      name: testrule1
```


Example playbook to make sure sudocmds are present in Sudo Rule:

```yaml
---
- name: Playbook to handle sudorules
  hosts: ipaserver
  become: true

  tasks:
  # Ensure Sudo Rule is present
  - ipasudorule:
      ipaadmin_password: MyPassword123
      name: testrule1
      cmd:
      - /sbin/ifconfig
      action: member
```


Example playbook to make sure sudocmds are not present in Sudo Rule:

```yaml
---
- name: Playbook to handle sudorules
  hosts: ipaserver
  become: true

  tasks:
  # Ensure Sudo Rule is present
  - ipasudorule:
      ipaadmin_password: MyPassword123
      name: testrule1
      cmd:
      - /sbin/ifconfig
      action: member
      state: absent
```

Example playbook to make sure Sudo Rule is absent:

```yaml
---
- name: Playbook to handle sudorules
  hosts: ipaserver
  become: true

  tasks:
  # Ensure Sudo Rule is present
  - ipasudorule:
      ipaadmin_password: MyPassword123
      name: testrule1
      state: absent
```


Variables
=========

ipasudorule
---------------

Variable | Description | Required
-------- | ----------- | --------
`ipaadmin_principal` | The admin principal is a string and defaults to `admin` | no
`ipaadmin_password` | The admin password is a string and is required if there is no admin ticket available on the node | no
`name` \| `cn` | The list of sudorule name strings. | yes
`description` | The sudorule description string. | no
`usercategory` | User category the rule applies to. Choices: ["all"] | no
`hostcategory` | Host category the rule applies to. Choices: ["all"] | no
`cmdcategory` | Command category the rule applies to. Choices: ["all"] | no
`nomembers` | Suppress processing of membership attributes. (bool) | no
`host` | List of host name strings assigned to this sudorule. | no
`hostgroup` | List of host group name strings assigned to this sudorule. | no
`user` | List of user name strings assigned to this sudorule. | no
`group` | List of user group name strings assigned to this sudorule. | no
`cmd` | List of sudocmd name strings assigned to this sudorule. | no
`cmdgroup` | List of sudocmd group name strings assigned wto this sudorule. | no
`action` | Work on sudorule or member level. It can be on of `member` or `sudorule` and defaults to `sudorule`. | no
`state` | The state to ensure. It can be one of `present`, `absent`, `enabled` or `disabled`, default: `present`. | no


Authors
=======

Rafael Jeffman

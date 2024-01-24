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


Example playbook to make sure Sudo Rule is present:

```yaml
---
- name: Playbook to handle sudorules
  hosts: ipaserver
  become: true

  tasks:
  # Ensure Sudo Rule is present
  - ipasudorule:
      ipaadmin_password: SomeADMINpassword
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
      ipaadmin_password: SomeADMINpassword
      name: testrule1
      allow_sudocmd:
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
      ipaadmin_password: SomeADMINpassword
      name: testrule1
      allow_sudocmd:
      - /sbin/ifconfig
      action: member
      state: absent
```


Example playbook to ensure a Group of RunAs User is present in sudo rule:

```yaml
---
- name: Playbook to manage sudorule member
  hosts: ipaserver
  become: no
  gather_facts: no

  tasks:
  - name: Ensure sudorule 'runasuser' has 'ipasuers' group as runas users.
    ipasudorule:
      ipaadmin_password: SomeADMINpassword
      name: testrule1
      runasuser_group: ipausers
      action: member
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
      ipaadmin_password: SomeADMINpassword
      name: testrule1
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
`name` \| `cn` | The list of sudorule name strings. | yes
`description` | The sudorule description string. | no
`usercategory` \| `usercat` | User category the rule applies to. Choices: ["all", ""] | no
`hostcategory` \| `hostcat` | Host category the rule applies to. Choices: ["all", ""] | no
`cmdcategory` \| `cmdcat` | Command category the rule applies to. Choices: ["all", ""] | no
`runasusercategory` \| `runasusercat` | RunAs User category the rule applies to. Choices: ["all", ""] | no
`runasgroupcategory` \| `runasgroupcat` | RunAs Group category the rule applies to. Choices: ["all", ""] | no
`nomembers` | Suppress processing of membership attributes. (bool) | no
`host` | List of host name strings assigned to this sudorule. | no
`hostgroup` | List of host group name strings assigned to this sudorule. | no
`hostmask` | List of host masks of allowed hosts | no
`user` | List of user name strings assigned to this sudorule. | no
`group` | List of user group name strings assigned to this sudorule. | no
`allow_sudocmd` | List of sudocmd name strings assigned to the allow group of this sudorule. | no
`deny_sudocmd` | List of sudocmd name strings assigned to the deny group of this sudorule. | no
`allow_sudocmdgroup` | List of sudocmd groups name strings assigned to the allow group of this sudorule. | no
`deny_sudocmdgroup` | List of sudocmd groups name strings assigned to the deny group of this sudorule. | no
`sudooption` \| `options` | List of options to the sudorule | no
`order` \| `sudoorder` | Integer to order the sudorule | no
`runasuser` | List of users for Sudo to execute as. | no
`runasgroup` | List of groups for Sudo to execute as. | no
`action` | Work on sudorule or member level. It can be on of `member` or `sudorule` and defaults to `sudorule`. | no
`state` | The state to ensure. It can be one of `present`, `absent`, `enabled` or `disabled`, default: `present`. | no


Authors
=======

Rafael Jeffman

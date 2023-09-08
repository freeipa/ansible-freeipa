Sudocmdgroup module
===================

Description
-----------

The sudocmdgroup module allows to ensure presence and absence of sudocmdgroups and members of sudocmdgroups.

The sudocmdgroup module is as compatible as possible to the Ansible upstream `ipa_sudocmdgroup` module, but additionally offers to make sure that sudocmds are present or absent in a sudocmdgroup.


Features
--------
* Sudocmdgroup management


Supported FreeIPA Versions
--------------------------

FreeIPA versions 4.4.0 and up are supported by the ipasudocmdgroup module.


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


Example playbook to make sure sudocmdgroup is present:

```yaml
---
- name: Playbook to handle sudocmdgroups
  hosts: ipaserver
  become: true

  tasks:
  # Ensure sudocmdgroup is present
  - ipasudocmdgroup:
      ipaadmin_password: SomeADMINpassword
      name: group01
      description: Group of important commands
```

Example playbook to make sure that a sudo command and sudocmdgroups are present in existing sudocmdgroup:

```yaml
---
- name: Playbook to handle sudocmdgroups
  hosts: ipaserver
  become: true

  tasks:
  # Ensure sudo commands are present in existing sudocmdgroup
  - ipasudocmdgroup:
      ipaadmin_password: SomeADMINpassword
      name: group01
      sudocmd:
      - /usr/bin/su
      - /usr/bin/less
      action: member
```
`action` controls if the sudocmdgroup or member will be handled. To add or remove members, set `action` to `member`.

Example playbook to make sure that a sudo command and sudocmdgroups are absent in sudocmdgroup:

```yaml
---
- name: Playbook to handle sudocmdgroups
  hosts: ipaserver
  become: true

  tasks:
  # Ensure sudocmds are absent in existing sudocmdgroup
  - ipasudocmdgroup:
      ipaadmin_password: SomeADMINpassword
      name: group01
      sudocmd:
      - /usr/bin/su
      - /usr/bin/less
      action: member
      state: absent
```

Example playbook to make sure sudocmdgroup is absent:

```yaml
---
- name: Playbook to handle sudocmdgroups
  hosts: ipaserver
  become: true

  tasks:
  # Ensure sudocmdgroup is absent
  - ipasudocmdgroup:
      ipaadmin_password: SomeADMINpassword
      name: group01
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
`name` \| `cn` | The list of sudocmdgroup name strings. | no
`description` | The sudocmdgroup description string. | no
`nomembers` | Suppress processing of membership attributes. (bool) | no
`sudocmd` | List of sudocmdgroup name strings assigned to this sudocmdgroup. | no
`action` | Work on sudocmdgroup or member level. It can be on of `member` or `sudocmdgroup` and defaults to `sudocmdgroup`. | no
`state` | The state to ensure. It can be one of `present` or `absent`, default: `present`. | no


Authors
=======

Rafael Guterres Jeffman

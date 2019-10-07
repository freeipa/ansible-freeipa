Hostgroup module
================

Description
-----------

The hostgroup module allows to ensure presence and absence of hostgroups and members of hostgroups.

The hostgroup module is as compatible as possible to the Ansible upstream `ipa_hostgroup` module, but additionally offers to make sure that hosts are present or absent in a hostgroup.


Features
--------
* Hostgroup management


Supported FreeIPA Versions
--------------------------

FreeIPA versions 4.4.0 and up are supported by the ipahostgroup module.


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


Example playbook to make sure hostgroup databases exists:

```yaml
---
- name: Playbook to handle hostgroups
  hosts: ipaserver
  become: true

  tasks:
  # Ensure host-group databases is present
  - ipahostgroup:
      ipaadmin_password: MyPassword123
      name: databases
      host:
      - db.example.com
      hostgroup:
      - mysql-server
      - oracle-server
```

Example playbook to make sure that hosts and hostgroups are present in existing databases hostgroup:

```yaml
---
- name: Playbook to handle hostgroups
  hosts: ipaserver
  become: true

  tasks:
  # Ensure hosts and hostgroups are present in existing databases hostgroup
  - ipahostgroup:
      ipaadmin_password: MyPassword123
      name: databases
      host:
      - db.example.com
      hostgroup:
      - mysql-server
      - oracle-server
      action: member
```
`action` controls if a the hostgroup or member will be handled. To add or remove members, set `action` to `member`.

Example playbook to make sure hosts and hostgroups are absent in databases hostgroup:

```yaml
---
- name: Playbook to handle hostgroups
  hosts: ipaserver
  become: true

  tasks:
  # Ensure hosts and hostgroups are absent in databases hostgroup
  - ipahostgroup:
      ipaadmin_password: MyPassword123
      name: databases
      host:
      - db.example.com
      hostgroup:
      - mysql-server
      - oracle-server
      action: member
      state: absent
```

Example playbook to make sure host-group databases is absent:

```yaml
---
- name: Playbook to handle hostgroups
  hosts: ipaserver
  become: true

  tasks:
  # Ensure host-group databases is absent
  - ipahostgroup:
      ipaadmin_password: MyPassword123
      name: databases
      state: absent
```


Variables
=========

ipahostgroup
-------

Variable | Description | Required
-------- | ----------- | --------
`ipaadmin_principal` | The admin principal is a string and defaults to `admin` | no
`ipaadmin_password` | The admin password is a string and is required if there is no admin ticket available on the node | no
`name` \| `cn` | The list of hostgroup name strings. | no
`description` | The hostgroup description string. | no
`nomembers` | Suppress processing of membership attributes. (bool) | no
`host` | List of host name strings assigned to this hostgroup. | no
`hostgroup` | List of hostgroup name strings assigned to this hostgroup. | no
`action` | Work on hostgroup or member level. It can be on of `member` or `hostgroup` and defaults to `hostgroup`. | no
`state` | The state to ensure. It can be one of `present` or `absent`, default: `present`. | no


Authors
=======

Thomas Woerner

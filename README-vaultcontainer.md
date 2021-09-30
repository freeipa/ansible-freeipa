Vaultcontainer module
=====================

Description
-----------

The vaultcontainer module allows to ensure presence and absence of vaultcontainers and members of vaultcontainers.


Features
--------
* Vaultcontainer management


Supported FreeIPA Versions
--------------------------

FreeIPA versions 4.4.0 and up are supported by the ipavaultcontainer module.


Requirements
------------

**Controller**
* Ansible version: 2.8+

**Node**
* Supported FreeIPA version (see above)
* KRA service must be enabled


Usage
=====

Example inventory file

```ini
[ipaserver]
ipaserver.test.local
```

Example playbook to make sure vaultcontainer is present for a specific user:

```yaml
---
- name: Playbook to ensure vaultcontainer is present for user user01.
  hosts: ipaserver
  become: true

  tasks:
  - ipavaultcontainer:
      ipaadmin_password: SomeADMINpassword
      username: user01
```

Example playbook to make sure vaultcontainer is present for a specific service:

```yaml
---
- name: Playbook to ensure vaultcontainer is present for user user01.
  hosts: ipaserver
  become: true

  tasks:
  - ipavaultcontainer:
      ipaadmin_password: SomeADMINpassword
      service: "HTTP/example.com"
```

Example playbook to make sure a shared vaultcontainer is present:

```yaml
---
- name: Playbook to ensure vaultcontainer is present for user user01.
  hosts: ipaserver
  become: true

  tasks:
  - ipavaultcontainer:
      ipaadmin_password: SomeADMINpassword
      shared: True
```

Example playbook to make sure that a vaultcontainer and its members are present:

```yaml
---
- name: Playbook to ensure vaultcontainer is present, with members.
  hosts: ipaserver
  become: true

  tasks:
  - ipavaultcontainer:
      ipaadmin_password: SomeADMINpassword
      username: user01
      users:
      - user01
      - user02
      - user03
      groups:
      - testusers
      services:
      - "HTTP/exmaple.com"
```

`action` controls if the vaultcontainer itself or its members will be handled. To add or remove members, set `action` to `member`.

Example playbook to make sure that a vaultcontainer member is present in vault:

```yaml
---
- name: Playbook to handle vaultcontainer members, ensuring they are present.
  hosts: ipaserver
  become: true

  tasks:
  - ipavaultcontainer:
      ipaadmin_password: SomeADMINpassword
      username: user01
      groups: ipausers
      action: member
```

Example playbook to make sure that a vaultcontainer member is absent in vault:

```yaml
---
- name: Playbook to handle vaultcontainer members, ensuring they are absent.
  hosts: ipaserver
  become: true

  tasks:
  - ipavaultcontainer:
      ipaadmin_password: SomeADMINpassword
      username: user01
      groups: ipausers
      action: member
```

A vaultcontainer can only be removed if it has no vaults. Example playbook to make sure vaultcontainer is absent:

```yaml
---
- name: Playbook to ensure vaultcontainer for user user01 is absent.
  hosts: ipaserver
  become: true

  tasks:
  - ipavaultcontainer:
      ipaadmin_password: SomeADMINpassword
      username: user01
      state: absent
```

Variables
=========

ipavaultcontainer
-----------------

Variable | Description | Required
-------- | ----------- | --------
`ipaadmin_principal` | The admin principal is a string and defaults to `admin` | no
`ipaadmin_password` | The admin password is a string and is required if there is no admin ticket available on the node | no
`ipaapi_context` | The context in which the module will execute. Executing in a server context is preferred. If not provided context will be determined by the execution environment. Valid values are `server` and `client`. | no
`service` | Any service can own one service vault container. | no
`user` | Any user can own one user vault container. | no
`shared` | Vault is shared. Default to false. (bool) | no
`users` | Users that are members of the vault container. | no
`groups` | Groups that are members of the vault container. | no
`services` | Services that are members of the vault container. | no
`action` | Work on vault container or member level. It can be on of `member` or `vaultcontainer` and defaults to `vaultcontainer`. | no
`state` | The state to ensure. It can be one of `present` or `absent`, default: `present`. | no


Notes
=====

This modules uses a client context to execute, and it might affect execution time.


Authors
=======

Rafael Guterres Jeffman

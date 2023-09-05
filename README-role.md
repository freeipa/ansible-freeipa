Role module
===========

Description
-----------

The role module allows to ensure presence, absence of roles and members of roles.

The role module is as compatible as possible to the Ansible upstream `ipa_role` module, but additionally offers role member management.


Features
--------

* Role management


Supported FreeIPA Versions
--------------------------

FreeIPA versions 4.4.0 and up are supported by the iparole module.


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


Example playbook to make sure role is present with all members:

```yaml
---
- name: Playbook to manage IPA role with members.
  hosts: ipaserver
  become: yes
  gather_facts: no

  tasks:
  - iparole:
      ipaadmin_password: SomeADMINpassword
      name: somerole
      user:
      - pinky
      group:
      - group01
      host:
      - host01.example.com
      hostgroup:
      - hostgroup01
      privilege:
      - Group Administrators
      - User Administrators
      service:
      - service01
```

Example playbook to rename a role:

```yaml
- iparole:
    ipaadmin_password: SomeADMINpassword
    name: somerole
    rename: anotherrole
```

Example playbook to make sure role is absent:

```yaml
---
- name: Playbook to manage IPA role.
  hosts: ipaserver
  become: yes
  gather_facts: no

  tasks:
  - iparole:
      ipaadmin_password: SomeADMINpassword
      name: somerole
      state: absent
```

Example playbook to ensure a user is a member of a role:

```yaml
---
- name: Playbook to manage IPA role member.
  hosts: ipaserver
  become: yes
  gather_facts: no

  tasks:
  - iparole:
      ipaadmin_password: SomeADMINpassword
      name: somerole
      user:
      - pinky
      action: member
```

Example playbook to ensure a group is a member of a role:

```yaml
---
- name: Playbook to manage IPA role member.
  hosts: ipaserver
  become: yes
  gather_facts: no

  tasks:
  - iparole:
      ipaadmin_password: SomeADMINpassword
      name: somerole
      host:
      - host01.example.com
      action: member
```

Example playbook to ensure a host is a member of a role:

```yaml
---
- name: Playbook to manage IPA role member.
  hosts: ipaserver
  become: yes
  gather_facts: no

  tasks:
  - iparole:
      ipaadmin_password: SomeADMINpassword
      name: somerole
      host:
      - host01.example.com
      action: member
```

Example playbook to ensure a hostgroup is a member of a role:

```yaml
---
- name: Playbook to manage IPA role member.
  hosts: ipaserver
  become: yes
  gather_facts: no

  tasks:
  - iparole:
      ipaadmin_password: SomeADMINpassword
      name: somerole
      hostgroup:
      - hostgroup01
      action: member
```

Example playbook to ensure a service is a member of a role:

```yaml
---
- name: Playbook to manage IPA role member.
  hosts: ipaserver
  become: yes
  gather_facts: no

  tasks:
  - iparole:
      ipaadmin_password: SomeADMINpassword
      name: somerole
      service:
      - service01
      action: member
```

Example playbook to ensure a privilege is a member of a role:

```yaml
---
- name: Playbook to manage IPA role member.
  hosts: ipaserver
  become: yes
  gather_facts: no

  tasks:
  - iparole:
      ipaadmin_password: SomeADMINpassword
      name: somerole
      privilege:
      - Group Administrators
      - User Administrators
      action: member
```

Example playbook to ensure that different members are not associated with a role.

```yaml
---
- name: Playbook to manage IPA role member.
  hosts: ipaserver
  become: yes
  gather_facts: no

  tasks:
  - iparole:
      ipaadmin_password: SomeADMINpassword
      name: somerole
      user:
      - pinky
      group:
      - group01
      host:
      - host01.example.com
      hostgroup:
      - hostgroup01
      privilege:
      - Group Administrators
      - User Administrators
      service:
      - service01
      action: member
      state: absent
```


Variables
---------

Variable | Description | Required
-------- | ----------- | --------
`ipaadmin_principal` | The admin principal is a string and defaults to `admin` | no
`ipaadmin_password` | The admin password is a string and is required if there is no admin ticket available on the node | no
`ipaapi_context` | The context in which the module will execute. Executing in a server context is preferred. If not provided context will be determined by the execution environment. Valid values are `server` and `client`. | no
`ipaapi_ldap_cache` | Use LDAP cache for IPA connection. The bool setting defaults to yes. (bool) | no
`name` \| `cn` | The list of role name strings. | yes
`description` | A description for the role. | no
`rename` \| `new_name` | Rename the role object. | no
`privilege` | Privileges associated to this role. | no
`user` | List of users to be assigned or not assigned to the role. | no
`group` | List of groups to be assigned or not assigned to the role. | no
`host` | List of hosts to be assigned or not assigned to the role. | no
`hostgroup` | List of hostgroups to be assigned or not assigned to the role. | no
`service` | List of services to be assigned or not assigned to the role. | no
`action` | Work on role or member level. It can be on of `member` or `role` and defaults to `role`. | no
`state` | The state to ensure. It can be one of `present`, `absent`, default: `present`. | no


Authors
=======

Rafael Jeffman

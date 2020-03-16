Group module
============

Description
-----------

The group module allows to ensure presence and absence of groups and members of groups.

The group module is as compatible as possible to the Ansible upstream `ipa_group` module, but additionally offers to add users to a group and also to remove users from a group.


Features
--------
* Group management


Supported FreeIPA Versions
--------------------------

FreeIPA versions 4.4.0 and up are supported by the ipagroup module.


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


Example playbook to add groups:

```yaml
---
- name: Playbook to handle groups
  hosts: ipaserver
  become: true

  tasks:
  # Create group ops with gid 1234
  - ipagroup:
      ipaadmin_password: SomeADMINpassword
      name: ops
      gidnumber: 1234

  # Create group sysops
  - ipagroup:
      ipaadmin_password: SomeADMINpassword
      name: sysops
      user:
      - pinky

  # Create group appops
  - ipagroup:
      ipaadmin_password: SomeADMINpassword
      name: appops
```

Example playbook to add users to a group:

```yaml
---
- name: Playbook to handle groups
  hosts: ipaserver
  become: true

  tasks:
  # Add user member brain to group sysops
  - ipagroup:
      ipaadmin_password: SomeADMINpassword
      name: sysops
      action: member
      user:
      - brain
```
`action` controls if a the group or member will be handled. To add or remove members, set `action` to `member`.


Example playbook to add group members to a group:

```yaml
---
- name: Playbook to handle groups
  hosts: ipaserver
  become: true

  tasks:
  # Add group members sysops and appops to group sysops
  - ipagroup:
      ipaadmin_password: SomeADMINpassword
      name: ops
      group:
      - sysops
      - appops
```

Example playbook to remove groups:

```yaml
---
- name: Playbook to handle groups
  hosts: ipaserver
  become: true

  tasks:
  # Remove goups sysops, appops and ops
  - ipagroup:
      ipaadmin_password: SomeADMINpassword
      name: sysops,appops,ops
      state: absent
```


Variables
=========

ipagroup
-------

Variable | Description | Required
-------- | ----------- | --------
`ipaadmin_principal` | The admin principal is a string and defaults to `admin` | no
`ipaadmin_password` | The admin password is a string and is required if there is no admin ticket available on the node | no
`name` \| `cn` | The list of group name strings. | no
`description` | The group description string. | no
`gid` \| `gidnumber` | The GID integer. | no
`nonposix` | Create as a non-POSIX group. (bool) | no
`external` | Allow adding external non-IPA members from trusted domains. (bool) | no
`nomembers` | Suppress processing of membership attributes. (bool) | no
`user` | List of user name strings assigned to this group. | no
`group` | List of group name strings assigned to this group. | no
`service` | List of service name strings assigned to this group. Only usable with IPA versions 4.7 and up. | no
`action` | Work on group or member level. It can be on of `member` or `group` and defaults to `group`. | no
`state` | The state to ensure. It can be one of `present` or `absent`, default: `present`. | yes


Authors
=======

Thomas Woerner

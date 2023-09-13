Idoverridegroup module
============

Description
-----------

The idoverridegroup module allows to ensure presence and absence of idoverridegroups and idoverridegroup members.


Use Cases
---------

With idoverridegroup it is possible to manage group attributes within ID views. These attributes are for example the group name or gid.


Features
--------

* Idoverridegroup management


Supported FreeIPA Versions
--------------------------

FreeIPA versions 4.4.0 and up are supported by the ipaidoverridegroup module.


Requirements
------------

**Controller**
* Ansible version: 2.13

**Node**
* Supported FreeIPA version (see above)


Usage
=====

Example inventory file

```ini
[ipaserver]
ipaserver.test.local
```


Example playbook to make sure test group test_group is present in idview test_idview

```yaml
---
- name: Playbook to manage idoverridegroup
  hosts: ipaserver
  become: false

  tasks:
  - name: Ensure test group test_group is present in idview test_idview.
    ipaidoverridegroup:
      ipaadmin_password: SomeADMINpassword
      idview: test_idview
      anchor: test_group
```


Example playbook to make sure test group test_group is present in idview test_idview with description

```yaml
---
- name: Playbook to manage idoverridegroup
  hosts: ipaserver
  become: false

  tasks:
  - name: Ensure test group test_group is present in idview test_idview with description
    ipaidoverridegroup:
      ipaadmin_password: SomeADMINpassword
      idview: test_idview
      anchor: test_group
      description: "test_group description"
```


Example playbook to make sure test group test_group is present in idview test_idview without description

```yaml
---
- name: Playbook to manage idoverridegroup
  hosts: ipaserver
  become: false

  tasks:
  - name: Ensure test group test_group is present in idview test_idview without description
    ipaidoverridegroup:
      ipaadmin_password: SomeADMINpassword
      idview: test_idview
      anchor: test_group
      description: ""
```


Example playbook to make sure test group test_group is present in idview test_idview with internal name test_123_group

```yaml
---
- name: Playbook to manage idoverridegroup
  hosts: ipaserver
  become: false

  tasks:
  - name: Ensure test group test_group is present in idview test_idview with internal name test_123_group
    ipaidoverridegroup:
      ipaadmin_password: SomeADMINpassword
      idview: test_idview
      anchor: test_group
      name: test_123_group
```


Example playbook to make sure test group test_group is present in idview test_idview without internal name

```yaml
---
- name: Playbook to manage idoverridegroup
- name: Ensure test group test_group is present in idview test_idview without internal name
  hosts: ipaserver
  become: false

  tasks:
  - ipaidoverridegroup:
      ipaadmin_password: SomeADMINpassword
      idview: test_idview
      anchor: test_group
      name: ""
```


Example playbook to make sure test group test_group is present in idview test_idview with gid 20001

```yaml
---
- name: Playbook to manage idoverridegroup
  hosts: ipaserver
  become: false

  tasks:
  - name: Ensure test group test_group is present in idview test_idview with gid 20001
    ipaidoverridegroup:
      ipaadmin_password: SomeADMINpassword
      idview: test_idview
      anchor: test_group
      gid: 20001
```


Example playbook to make sure test group test_group is present in idview test_idview without gid

```yaml
---
- name: Playbook to manage idoverridegroup
  hosts: ipaserver
  become: false

  tasks:
  - name: Ensure test group test_group is present in idview test_idview without gid
    ipaidoverridegroup:
      ipaadmin_password: SomeADMINpassword
      idview: test_idview
      anchor: test_group
      gid: ""
```


Example playbook to make sure test group test_group is present in idview test_idview with enabling falling back to AD DC LDAP when resolving AD trusted objects. (For two-way trusts only.)

```yaml
---
- name: Playbook to manage idoverridegroup
  hosts: ipaserver
  become: false

  tasks:
  - name: Ensure test group test_group is present in idview test_idview with fallback_to_ldap enabled
    ipaidoverridegroup:
      ipaadmin_password: SomeADMINpassword
      idview: test_idview
      anchor: test_group
      fallback_to_ldap: true
```


Example playbook to make sure test group test_group is absent in idview test_idview

```yaml
---
- name: Playbook to manage idoverridegroup
  hosts: ipaserver
  become: false

  tasks:
  - name: Ensure test group test_group is absent in idview test_idview
    ipaidoverridegroup:
      ipaadmin_password: SomeADMINpassword
      idview: test_idview
      anchor: test_group
      continue: true
      state: absent
```


Variables
---------

Variable | Description | Required
-------- | ----------- | --------
`ipaadmin_principal` | The admin principal is a string and defaults to `admin` | no
`ipaadmin_password` | The admin password is a string and is required if there is no admin ticket available on the node | no
`ipaapi_context` | The context in which the module will execute. Executing in a server context is preferred. If not provided context will be determined by the execution environment. Valid values are `server` and `client`. | no
`ipaapi_ldap_cache` | Use LDAP cache for IPA connection. The bool setting defaults to true. (bool) | no
`idview` \| `idviewcn` | The doverridegroup idview string. | yes
`anchor` \| `ipaanchoruuid` | The list of anchors to override. | yes
`description` \| `desc` | Description | no
`name` \| `group_name` \| `cn` | The group. | no
`gid` \| `gidnumber` | Group ID Number (int or "") | no
`fallback_to_ldap` | Allow falling back to AD DC LDAP when resolving AD trusted objects. For two-way trusts only. | no
`delete_continue` \| `continue` | Continuous mode. Don't stop on errors. Valid only if `state` is `absent`. | no
`state` | The state to ensure. It can be one of `present`, `absent`, default: `present`. | no


Authors
=======

Thomas Woerner

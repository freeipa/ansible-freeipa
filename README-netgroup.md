Netgroup module
============

Description
-----------

The netgroup module allows to ensure presence and absence of netgroups.

Features
--------

* Netgroup management


Supported FreeIPA Versions
--------------------------

FreeIPA versions 4.4.0 and up are supported by the ipanetgroup module.


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


Example playbook to make sure netgroup "my_netgroup1" is present:

```yaml
---
- name: Playbook to manage IPA netgroup.
  hosts: ipaserver
  become: no

  tasks:
  - name: Ensure netgroup my_netgroup1 is present
    ipanetgroup:
      ipaadmin_password: SomeADMINpassword
      name: my_netgroup1
      description: My netgroup 1
```


Example playbook to make sure netgroup "my_netgroup1" is absent:

```yaml
---
- name: Playbook to manage IPA netgroup.
  hosts: ipaserver
  become: no

  tasks:
  - name: Ensure netgroup my_netgroup1 is absent
    ipanetgroup:
      ipaadmin_password: SomeADMINpassword
      name: my_netgroup1
      state: absent
```


Example playbook to make sure netgroup is present with user "user1"

```yaml
---
- name: Playbook to manage IPA netgroup.
  hosts: ipaserver
  become: no

  tasks:
  - name: Ensure netgroup is present with user "user1"
    ipanetgroup:
      ipaadmin_password: SomeADMINpassword
      name: TestNetgroup1
      user: user1
      action: member
```


Example playbook to make sure netgroup user, "user1", is absent

```yaml
---
- name: Playbook to manage IPA netgroup.
  hosts: ipaserver
  become: no

  tasks:
  - name: Ensure netgroup user, "user1", is absent
    ipanetgroup:
      ipaadmin_password: SomeADMINpassword
      name: TestNetgroup1
      user: "user1"
      action: member
      state: absent
```


Example playbook to make sure netgroup is present with members

```yaml
---
- name: Playbook to manage IPA netgroup.
  hosts: ipaserver
  become: no

  tasks:
  - name: Ensure netgroup members are present
    ipanetgroup:
      ipaadmin_password: SomeADMINpassword
      name: TestNetgroup1
      user: user1,user2
      group: group1
      host: host1
      hostgroup: ipaservers
      netgroup: admins
      action: member
```


Example playbook to make sure 2 netgroups TestNetgroup1, admins are absent

```yaml
---
- name: Playbook to manage IPA netgroup.
  hosts: ipaserver
  become: no

  tasks:
  - name: Ensure netgroups are absent
    ipanetgroup:
      ipaadmin_password: SomeADMINpassword
      name:
      - TestNetgroup1
      - admins
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
`name` \| `cn` | The list of netgroup name strings. | yes
`description` | Netgroup description | no
`nisdomain` | NIS domain name | no
`nomembers` | Suppress processing of membership attributes. (bool) | no
`user` | List of user name strings assigned to this netgroup. | no
`group` | List of group name strings assigned to this netgroup. | no
`host` | List of host name strings assigned to this netgroup. | no
`hostgroup` | List of hostgroup name strings assigned to this netgroup. | no
`netgroup` | List of netgroup name strings assigned to this netgroup. | no
`action` | Work on group or member level. It can be on of `member` or `netgroup` and defaults to `netgroup`. | no
`state` | The state to ensure. It can be one of `present`, `absent`, default: `present`. | no


Authors
=======

Denis Karpelevich

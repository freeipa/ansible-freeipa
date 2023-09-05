Automountlocation module
=====================

Description
-----------

The automountlocation module allows the addition and removal of locations for automount maps

It is desgined to follow the IPA api as closely as possible while ensuring ease of use.


Features
--------
* Automount location management

Supported FreeIPA Versions
--------------------------

FreeIPA versions 4.4.0 and up are supported by the ipaautomountlocation module.

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


Example playbook to ensure presence of an automount location:

```yaml
---
- name: Playbook to add an automount location
  hosts: ipaserver
  become: true

  tasks:
  - name: ensure a automount location named DMZ exists
    ipaautomountlocation:
      ipaadmin_password: SomeADMINpassword
      name: DMZ
      state: present

```

Example playbook to ensure presence of multiple automount locations:

```yaml
---
- name: Playbook to add an automount location
  hosts: ipaserver
  become: true

  tasks:
  - name: ensure a automount location named DMZ exists
    ipaautomountlocation:
      ipaadmin_password: SomeADMINpassword
      name:
        - DMZ
        - PROD
        - development
        - test
      state: present
```


Example playbook to ensure absence of an automount location:

```yaml
---
- name: Playbook to ensure an automount location is absent
  hosts: ipaserver
  become: true

  tasks:
  - name: ensure automount locations LOCATION1 and LOCATION2 do not exist
    ipaautomountlocation:
      ipaadmin_password: SomeADMINpassword
      name:
        - LOCATION1
        - LOCATION2
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
`name` \| `cn` \| `location` | List of one or more automountlocation names. | yes
`state` | The state to ensure. It can be one of `present`, or `absent`, default: `present`. | no


Authors
=======

Chris Procter

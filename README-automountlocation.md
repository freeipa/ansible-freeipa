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


Example playbook to ensure presence of an automount location:

```yaml
---
- name: Playbook to add an automount location
  hosts: ipaserver
  become: true

  tasks:
  - name: ensure a automount location named DMZ exists
    ipaautomountlocation:
      ipaadmin_password: password01
      name: DMZ
      state: present

```

Variables
=========

ipaautomountlocation
-------

Variable | Description | Required
-------- | ----------- | --------
`ipaadmin_principal` | The admin principal is a string and defaults to `admin` | no
`ipaadmin_password` | The admin password is a string and is required if there is no admin ticket available on the node | no
`name` \| `cn` \| `location` | Location name. | yes 
`state` | The state to ensure. It can be one of `present`, or `absent`, default: `present`. | no


Authors
=======

Chris Procter

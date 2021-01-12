Automountkey module
=====================

Description
-----------

The automountkey module allows the addition and removal of keys within an automount map. 

It is desgined to follow the IPA api as closely as possible while ensuring ease of use.


Features
--------
* Automount key management

Supported FreeIPA Versions
--------------------------

FreeIPA versions 4.4.0 and up are supported by the ipaautomountkey module.

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


Example playbook to ensure presence of an automount map:

```yaml
---
- name: Playbook to add an automount map
  hosts: ipaserver
  become: true

  tasks:
  - name: create key TestKey
    ipaautomountkey:
      ipaadmin_password: SomeADMINpassword
      location: TestLocation
      mapname: TestMap
      key: TestKey
      info: 192.168.122.1:/exports
      state: present

  - name: ensure key TestKey is absent
    ipaautomountkey:
      ipaadmin_password: SomeADMINpassword
      location: TestLocation
      mapname: TestMap
      key: TestKey
      state: absent
```

Example playbook to rename an automount map:

```yaml
---
- name: Playbook to add an automount map
  - name: ensure key TestKey has been renamed to NewKeyName
    ipaautomountkey:
      ipaadmin_password: password01
      automountlocationcn: TestLocation
      automountmapname: TestMap
      automountkey: TestKey
      newname: NewKeyName
      state: rename
```


Variables
=========

ipaautomountkey
-------

Variable | Description | Required
-------- | ----------- | --------
`ipaadmin_principal` | The admin principal is a string and defaults to `admin` | no
`ipaadmin_password` | The admin password is a string and is required if there is no admin ticket available on the node | no
`location` \| `automountlocationcn` \| `automountlocation` | Location name. | yes 
`mapname` \|  `map` \| `automountmapname` \| `automountmap` | Map the key belongs to | yes 
`key` \| `name` \| `automountkey` | Automount key to manage | yes 
`newkey` \| newname` \| `newautomountkey` | the name to change the key to if state is `rename` | yes when state is `rename`
`info` \| `information` \| `automountinformation` | Mount information for the key | yes when state is `present`
`state` | The state to ensure. It can be one of `present`, or `absent`, default: `present`. | no

Authors
=======

Chris Procter

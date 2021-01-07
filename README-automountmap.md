Automountmap module
=====================

Description
-----------

The automountmap module allows the addition and removal of maps within automount locations. 

It is desgined to follow the IPA api as closely as possible while ensuring ease of use.


Features
--------
* Automount map management

Supported FreeIPA Versions
--------------------------

FreeIPA versions 4.4.0 and up are supported by the ipaautomountmap module.

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
  - name: ensure map named auto.DMZ in location DMZ is created
    ipaautomountmap:
      ipaadmin_password: password01
      name: auto.DMZ
      location: DMZ
      desc: "this is a map for servers in the DMZ"

```

Variables
=========

ipaautomountmap
-------

Variable | Description | Required
-------- | ----------- | --------
`ipaadmin_principal` | The admin principal is a string and defaults to `admin` | no
`ipaadmin_password` | The admin password is a string and is required if there is no admin ticket available on the node | no
`mapname` \| `cn` \| `name` \| `map` \| `automountmapname` | Location name. | yes 
`location` \| `automountlocationcn` | Location name. | yes 
`desc` \| `description` | Description of the map | yes 
`state` | The state to ensure. It can be one of `present`, or `absent`, default: `present`. | no


Authors
=======

Chris Procter

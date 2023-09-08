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

Example playbook to ensure presence of an automount map:

```yaml
---
- name: Playbook to add an automount map
  hosts: ipaserver
  become: no

  tasks:
  - name: ensure map named auto.DMZ in location DMZ is created
    ipaautomountmap:
      ipaadmin_password: SomeADMINpassword
      name: auto.DMZ
      location: DMZ
      desc: "this is a map for servers in the DMZ"
```

Automount maps can contain a submount key, which defines a mount location within the map the references another map. On FreeIPA, this is known as an indirect map. An indirect automount map is equivalent to adding a proper automount key to a map, referencyng another map (this second map is the indirect map). Use `parent` and `mount` parameters to create an indirect automount map with ansible-freeipa, without the need to directly manage the automount keys.

Example playbook to ensure an indirect automount map is present:

```yaml
---
- name: Playbook to add an indirect automount map
  ipaautomountmap:
    ipaadmin_password: SomeADMINpassword
    name: auto.indirect
    location: DMZ
    parent: auto.DMZ
    mount: dmz_indirect
```

Example playbook to ensure auto.DMZi is absent:

```yaml
---
- name: Playbook to remove an automount map
  hosts: ipaserver
  become: no

  tasks:
  - name: ensure map auto.DMZ has been removed
    ipaautomountmap:
      ipaadmin_password: SomeADMINpassword
      name: auto.DMZ
      location: DMZ
      state: absent
```


Variables
=========

Variable | Description | Required
-------- | ----------- | --------
`ipaadmin_principal` | The admin principal is a string and defaults to `admin` | no
`ipaadmin_password` | The admin password is a string and is required if there is no admin ticket available on the node | no
`name` \| `mapname` \| `map` \| `automountmapname` | Name of the map to manage | yes
`location` \| `automountlocation` \| `automountlocationcn` | Location name. | yes
`parentmap` | Parent map of the indirect map. Can only be used when creating new maps. Default: auto.master | no
`mount` | Indirect map mount point, relative to parent map. | yes, if `parent` is used.
`desc` \| `description` | Description of the map | yes
`state` | The state to ensure. It can be one of `present`, or `absent`, default: `present`. | no


Authors
=======

- Chris Procter
- Rafael Jeffman

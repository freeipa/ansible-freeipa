Location module
===============

Description
-----------

The location module allows to ensure presence and absence of locations.

Features
--------

* Location management


Supported FreeIPA Versions
--------------------------

FreeIPA versions 4.4.0 and up are supported by the ipalocation module.


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


Example playbook to make sure location "my_location1" is present:

```yaml
---
- name: Playbook to manage IPA location.
  hosts: ipaserver
  become: yes

  tasks:
  - ipalocation:
      ipaadmin_password: SomeADMINpassword
      name: my_location1
      description: My Location 1
```


Example playbook to make sure location "my_location1" is absent:

```yaml
---
- name: Playbook to manage IPA location.
  hosts: ipaserver
  become: yes

  tasks:
  - ipalocation:
      ipaadmin_password: SomeADMINpassword
      name: my_location1
      state: absent
```


Variables
---------

ipalocation
-------

Variable | Description | Required
-------- | ----------- | --------
`ipaadmin_principal` | The admin principal is a string and defaults to `admin` | no
`ipaadmin_password` | The admin password is a string and is required if there is no admin ticket available on the node | no
`name` \| `idnsname` | The list of location name strings. | yes
`description` | The IPA location string | false
`state` | The state to ensure. It can be one of `present`, `absent`, default: `present`. | no


Authors
=======

Thomas Woerner

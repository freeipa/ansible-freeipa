Selfservice module
=================

Description
-----------

The selfservice module allows to ensure presence, absence of selfservices and selfservice attributes.


Features
--------

* Selfservice management


Supported FreeIPA Versions
--------------------------

FreeIPA versions 4.4.0 and up are supported by the ipaselfservice module.


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


Example playbook to make sure selfservice "Users can manage their own name details" is present:

```yaml
---
- name: Playbook to manage IPA selfservice.
  hosts: ipaserver
  become: yes

  tasks:
  - ipaselfservice:
      ipaadmin_password: SomeADMINpassword
      name: "Users can manage their own name details"
      permission: read
      attribute:
      - title
      - initials
```


Example playbook to make sure selfservice "Users can manage their own name details" is absent:

```yaml
---
- name: Playbook to manage IPA selfservice.
  hosts: ipaserver
  become: yes

  tasks:
  - ipaselfservice:
      ipaadmin_password: SomeADMINpassword
      name: "Users can manage their own name details"
      state: absent
```


Example playbook to make sure "Users can manage their own name details" member attribute initials is present:

```yaml
---
- name: Playbook to manage IPA selfservice.
  hosts: ipaserver
  become: yes

  tasks:
  - ipaselfservice:
      ipaadmin_password: SomeADMINpassword
      name: "Users can manage their own name details"
      attribute:
      - initials
      action: member
```


Example playbook to make sure "Users can manage their own name details" member attribute initials is absent:

```yaml
---
- name: Playbook to manage IPA selfservice.
  hosts: ipaserver
  become: yes

  tasks:
  - ipaselfservice:
      ipaadmin_password: SomeADMINpassword
      name: "Users can manage their own name details"
      attribute:
      - initials
      action: member
      state: absent
```


Example playbook to make sure selfservice "Users can manage their own name details" is absent:

```yaml
---
- name: Playbook to manage IPA selfservice.
  hosts: ipaserver
  become: yes

  tasks:
  - ipaselfservice:
      ipaadmin_password: SomeADMINpassword
      name: "Users can manage their own name details"
      state: absent
```


Variables
---------

ipaselfservice
-------

Variable | Description | Required
-------- | ----------- | --------
`ipaadmin_principal` | The admin principal is a string and defaults to `admin` | no
`ipaadmin_password` | The admin password is a string and is required if there is no admin ticket available on the node | no
`name` \| `aciname` | The list of selfservice name strings. | yes
`permission` \| `permissions` |  The permission to grant `read`, `read,write`, `write`]. Default is `write`. | no
`attribute` \| `attrs` | The attribute list to which the selfservice applies. | no
`action` | Work on selfservice or member level. It can be on of `member` or `selfservice` and defaults to `selfservice`. | no
`state` | The state to ensure. It can be one of `present`, `absent`, default: `present`. | no


Authors
=======

Thomas Woerner

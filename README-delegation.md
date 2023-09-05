Delegation module
=================

Description
-----------

The delegation module allows to ensure presence, absence of delegations and delegation attributes.


Features
--------

* Delegation management


Supported FreeIPA Versions
--------------------------

FreeIPA versions 4.4.0 and up are supported by the ipadelegation module.


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


Example playbook to make sure delegation "basic manager attributes" is present:

```yaml
---
- name: Playbook to manage IPA delegation.
  hosts: ipaserver
  become: yes

  tasks:
  - ipadelegation:
      ipaadmin_password: SomeADMINpassword
      name: "basic manager attributes"
      permission: read
      attribute:
      - businesscategory
      - employeetype
      group: managers
      membergroup: employees
```


Example playbook to make sure delegation "basic manager attributes" is absent:

```yaml
---
- name: Playbook to manage IPA delegation.
  hosts: ipaserver
  become: yes

  tasks:
  - ipadelegation:
      ipaadmin_password: SomeADMINpassword
      name: "basic manager attributes"
      state: absent
```


Example playbook to make sure "basic manager attributes" member attributes employeetype and employeenumber are present:

```yaml
---
- name: Playbook to manage IPA delegation.
  hosts: ipaserver
  become: yes

  tasks:
  - ipadelegation:
      ipaadmin_password: SomeADMINpassword
      name: "basic manager attributes"
      attribute:
      - employeenumber
      - employeetype
      action: member
```


Example playbook to make sure "basic manager attributes" member attributes employeetype and employeenumber are absent:

```yaml
---
- name: Playbook to manage IPA delegation.
  hosts: ipaserver
  become: yes

  tasks:
  - ipadelegation:
      ipaadmin_password: SomeADMINpassword
      name: "basic manager attributes"
      attribute:
      - employeenumber
      - employeetype
      action: member
      state: absent
```


Example playbook to make sure delegation "basic manager attributes" is absent:

```yaml
---
- name: Playbook to manage IPA delegation.
  hosts: ipaserver
  become: yes

  tasks:
  - ipadelegation:
      ipaadmin_password: SomeADMINpassword
      name: "basic manager attributes"
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
`name` \| `aciname` | The list of delegation name strings. | yes
`permission` \| `permissions` |  The permission to grant `read`, `read,write`, `write`]. Default is `write`. | no
`attribute` \| `attrs` | The attribute list to which the delegation applies. | no
`membergroup` \| `memberof` | The user group to apply delegation to. | no
`group` | User group ACI grants access to. | no
`action` | Work on delegation or member level. It can be on of `member` or `delegation` and defaults to `delegation`. | no
`state` | The state to ensure. It can be one of `present`, `absent`, default: `present`. | no


Authors
=======

Thomas Woerner

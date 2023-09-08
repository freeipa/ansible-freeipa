Topology modules
================

Description
-----------

These modules allow to manage the topology. That means that it can made sure that topology segments are present, absent or reinitialized. Also it is possible to verify topology suffixes.


Features
--------
* Topology management


Supported FreeIPA Versions
--------------------------

FreeIPA versions 4.4.0 and up are supported by the ipatopologysegment and ipatopologysuffix modules.


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


Example playbook to add a topology segment with default name (cn):

```yaml
---
- name: Playbook to handle topologysegment
  hosts: ipaserver
  become: true

  tasks:
  - name: Add topology segment
    ipatopologysegment:
      ipaadmin_password: SomeADMINpassword
      suffix: domain
      left: ipareplica1.test.local
      right: ipareplica2.test.local
      state: present
```
The name (cn) can also be set if it should not be the default `{left}-to-{right}`.


Example playbook to delete a topology segment:

```yaml
---
- name: Playbook to handle topologysegment
  hosts: ipaserver
  become: true

  tasks:
  - name: Delete topology segment
    ipatopologysegment:
      ipaadmin_password: SomeADMINpassword
      suffix: domain
      left: ipareplica1.test.local
      right: ipareplica2.test.local
      state: absent
```
It is possible to either use the name (cn) or left and right nodes. If left and right nodes are used, then the name will be searched and used internally.


Example playbook to reinitialize a topology segment:

```yaml
---
- name: Playbook to handle topologysegment
  hosts: ipaserver
  become: true

  tasks:
  - name: Reinitialize topology segment
    ipatopologysegment:
      ipaadmin_password: SomeADMINpassword
      suffix: domain
      left: ipareplica1.test.local
      right: ipareplica2.test.local
      direction: left-to-right
      state: reinitialized
```
It is possible to either use the name (cn) or left and right nodes. If left and right nodes are used, then the name will be searched and used internally.


Example playbook to verify a topology suffix:

```yaml
---
- name: Playbook to handle topologysuffix
  hosts: ipaserver
  become: true

  tasks:
  - name: Verify topology suffix
    ipatopologysuffix:
      ipaadmin_password: SomeADMINpassword
      suffix: domain
      state: verified
```

Example playbook to add or remove or check or reinitialize a list of topology segments:

```yaml
---
- name: Add topology segments
  hosts: ipaserver
  become: true
  gather_facts: false

  vars:
    ipaadmin_password: password1
    ipatopology_segments:
    - {suffix: domain, left: replica1.test.local, right: replica2.test.local}
    - {suffix: domain, left: replica2.test.local, right: replica3.test.local}
    - {suffix: domain, left: replica3.test.local, right: replica4.test.local}
    - {suffix: domain+ca, left: replica4.test.local, right: replica1.test.local}

  tasks:
  - name: Add topology segment
    ipatopologysegment:
      ipaadmin_password: "{{ ipaadmin_password }}"
      suffix: "{{ item.suffix }}"
      name: "{{ item.name | default(omit) }}"
      left: "{{ item.left }}"
      right: "{{ item.right }}"
      state: present
      #state: absent
      #state: checked
      #state: reinitialized
    loop: "{{ ipatopology_segments | default([]) }}"
```


Variables
=========

ipatopologysegment
------------------

Variable | Description | Required
-------- | ----------- | --------
`ipaadmin_principal` | The admin principal is a string and defaults to `admin` | no
`ipaadmin_password` | The admin password is a string and is required if there is no admin ticket available on the node | no
`ipaapi_context` | The context in which the module will execute. Executing in a server context is preferred. If not provided context will be determined by the execution environment. Valid values are `server` and `client`. | no
`ipaapi_ldap_cache` | Use LDAP cache for IPA connection. The bool setting defaults to yes. (bool) | no
`suffix` | The topology suffix to be used, this can either be `domain`, `ca` or `domain+ca` | yes
`name` \| `cn` | The topology segment name (cn) is the unique identifier for a segment. | no
`left` \| `leftnode` | The left replication node string - an IPA server | no
`right` \| `rightnode` | The right replication node string - an IPA server | no
`direction` | The direction a segment will be reinitialized. It can either be `left-to-right` or `right-to-left` and only used with `state: reinitialized` | no
`state` | The state to ensure. It can be one of `present`, `absent`, `enabled`, `disabled`, `checked` or `reinitialized` | yes


ipatopologysuffix
-----------------

Verify FreeIPA topology suffix

Variable | Description | Required
-------- | ----------- | --------
`ipaadmin_principal` | The admin principal is a string and defaults to `admin` | no
`ipaadmin_password` | The admin password is a string and is required if there is no admin ticket available on the node | no
`ipaapi_context` | The context in which the module will execute. Executing in a server context is preferred. If not provided context will be determined by the execution environment. Valid values are `server` and `client`. | no
`ipaapi_ldap_cache` | Use LDAP cache for IPA connection. The bool setting defaults to yes. (bool) | no
`suffix` | The topology suffix to be used, this can either be `domain` or `ca` | yes
`state` | The state to ensure. It can only be `verified` | yes


Authors
=======

Thomas Woerner

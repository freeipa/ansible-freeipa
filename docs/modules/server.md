Server module
============

Description
-----------

The server module allows to ensure presence and absence of servers. The module requires an existing server, the deployment of a new server can not be done with the module.

Features
--------

* Server management


Supported FreeIPA Versions
--------------------------

FreeIPA versions 4.4.0 and up are supported by the ipaserver module.


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


Example playbook to make sure server "server.example.com" is present:

```yaml
---
- name: Playbook to manage IPA server.
  hosts: ipaserver
  become: yes

  tasks:
  - ipaserver:
      ipaadmin_password: SomeADMINpassword
      name: server.example.com
```


Example playbook to make sure server "server.example.com" is present with location mylocation:

```yaml
---
- name: Playbook to manage IPA server.
  hosts: ipaserver
  become: yes

  tasks:
  - ipaserver:
      ipaadmin_password: SomeADMINpassword
      name: server.example.com
      location: mylocation
```


Example playbook to make sure server "server.example.com" is present without a location:

```yaml
---
- name: Playbook to manage IPA server.
  hosts: ipaserver
  become: yes

  tasks:
  - ipaserver:
      ipaadmin_password: SomeADMINpassword
      name: server.example.com
      location: ""
```


Example playbook to make sure server "server.example.com" is present with service weight 1:

```yaml
---
- name: Playbook to manage IPA server.
  hosts: ipaserver
  become: yes

  tasks:
  - ipaserver:
      ipaadmin_password: SomeADMINpassword
      name: server.example.com
      service_weight: 1
```


Example playbook to make sure server "server.example.com" is present without service weight:

```yaml
---
- name: Playbook to manage IPA server.
  hosts: ipaserver
  become: yes

  tasks:
  - ipaserver:
      ipaadmin_password: SomeADMINpassword
      name: server.example.com
      service_weight: -1
```


Example playbook to make sure server "server.example.com" is present and hidden:

```yaml
---
- name: Playbook to manage IPA server.
  hosts: ipaserver
  become: yes

  tasks:
  - ipaserver:
      ipaadmin_password: SomeADMINpassword
      name: server.example.com
      hidden: yes
```


Example playbook to make sure server "server.example.com" is present and not hidden:

```yaml
---
- name: Playbook to manage IPA server.
  hosts: ipaserver
  become: yes

  tasks:
  - ipaserver:
      ipaadmin_password: SomeADMINpassword
      name: server.example.com
      hidden: no
```


Example playbook to make sure server "server.example.com" is absent:

```yaml
---
- name: Playbook to manage IPA server.
  hosts: ipaserver
  become: yes

  tasks:
  - ipaserver:
      ipaadmin_password: SomeADMINpassword
      name: server.example.com
      state: absent
```


Example playbook to make sure server "server.example.com" is absent in continuous mode in error case:

```yaml
---
- name: Playbook to manage IPA server.
  hosts: ipaserver
  become: yes

  tasks:
  - ipaserver:
      ipaadmin_password: SomeADMINpassword
      name: server.example.com
      continue: yes
      state: absent
```


Example playbook to make sure server "server.example.com" is absent with last of role check skip:

```yaml
---
- name: Playbook to manage IPA server.
  hosts: ipaserver
  become: yes

  tasks:
  - ipaserver:
      ipaadmin_password: SomeADMINpassword
      name: server.example.com
      ignore_last_of_role: yes
      state: absent
```


Example playbook to make sure server "server.example.com" is absent iwith topology disconnect check skip:

```yaml
---
- name: Playbook to manage IPA server.
  hosts: ipaserver
  become: yes

  tasks:
  - ipaserver:
      ipaadmin_password: SomeADMINpassword
      name: server.example.com
      ignore_topology_disconnect: yes
      state: absent
```


MORE EXAMPLE PLAYBOOKS HERE


Variables
---------

ipaserver
-------

Variable | Description | Required
-------- | ----------- | --------
`ipaadmin_principal` | The admin principal is a string and defaults to `admin` | no
`ipaadmin_password` | The admin password is a string and is required if there is no admin ticket available on the node | no
`name` \| `cn` | The list of server name strings. | yes
`location` \| `ipalocation_location` | The server location string. Only in state: present. "" for location reset. | no
`service_weight` \| `ipaserviceweight` | Weight for server services. Type Values 0 to 65535, -1 for weight reset. Only in state: present. (int) | no
`hidden` | Set hidden state of a server. Only in state: present. (bool) | no
`no_members` | Suppress processing of membership attributes. Only in state: present. (bool) | no
`delete_continue` \| `continue` | Continuous mode: Don't stop on errors. Only in state: absent. (bool) | no
`ignore_last_of_role` | Skip a check whether the last CA master or DNS server is removed. Only in state: absent. (bool) | no
`ignore_topology_disconnect` | Ignore topology connectivity problems after removal. Only in state: absent. (bool) | no
`force` | Force server removal even if it does not exist. Will always result in changed. Only in state: absent. (bool) | no
`state` | The state to ensure. It can be one of `present`, `absent`, default: `present`. `present` is only working with existing servers. | no


Authors
=======

Thomas Woerner

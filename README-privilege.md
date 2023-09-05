Privilege module
================

Description
-----------

The privilege module allows to ensure presence and absence of privileges and privilege members.

Features
--------

* Privilege management


Supported FreeIPA Versions
--------------------------

FreeIPA versions 4.4.0 and up are supported by the ipaprivilege module.


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


Example playbook to make sure privilege "Broad Privilege" is present:

```yaml
---
- name: Playbook to manage IPA privilege.
  hosts: ipaserver
  become: yes

  tasks:
  - ipaprivilege:
      ipaadmin_password: SomeADMINpassword
      name: Broad Privilege
      description: Broad Privilege
```

Example playbook to make sure privilege "Broad Privilege" member permission has multiple values:

```yaml
---
- name: Playbook to manage IPA privilege permission member.
  hosts: ipaserver
  become: yes

  tasks:
  - ipaprivilege:
      ipaadmin_password: SomeADMINpassword
      name: Broad Privilege
      permission:
      - "Write IPA Configuration"
      - "System: Write DNS Configuration"
      - "System: Update DNS Entries"
      action: member
```


Example playbook to make sure privilege "Broad Privilege" member permission 'Write IPA Configuration' is absent:


```yaml
---
- name: Playbook to manage IPA privilege permission member.
  hosts: ipaserver
  become: yes

  tasks:
  - ipaprivilege:
      ipaadmin_password: SomeADMINpassword
      name: Broad Privilege
      permission:
      - "Write IPA Configuration"
      action: member
      state: absent
```

Example playbook to rename privilege "Broad Privilege" to "DNS Special Privilege":

```yaml
---
- name: Playbook to manage IPA privilege.
  hosts: ipaserver
  become: yes

  tasks:
  - ipaprivilege:
      ipaadmin_password: SomeADMINpassword
      name: Broad Privilege
      rename: DNS Special Privilege
      state: renamed
```

Example playbook to make sure privilege "DNS Special Privilege" is absent:

```yaml
---
- name: Playbook to manage IPA privilege.
  hosts: ipaserver
  become: yes
  - name: Ensure privilege Broad Privilege is absent
      ipaadmin_password: SomeADMINpassword
      name: DNS Special Privilege
      state: absent
```


Variables
---------

Variable | Description | Required
-------- | ----------- | --------
`ipaadmin_principal` | The admin principal is a string and defaults to `admin`. | no
`ipaadmin_password` | The admin password is a string and is required if there is no admin ticket available on the node. | no
`ipaapi_context` | The context in which the module will execute. Executing in a server context is preferred. If not provided context will be determined by the execution environment. Valid values are `server` and `client`. | no
`ipaapi_ldap_cache` | Use LDAP cache for IPA connection. The bool setting defaults to yes. (bool) | no
`name` \| `cn` | The list of privilege name strings. | yes
`description` | Privilege description. | no
`rename` \| `new_name` | Rename the privilege object. | no
`permission` | Permissions to be added to the privilege. | no
`action` | Work on privilege or member level. It can be one of `member` or `privilege` and defaults to `privilege`. | no
`state` | The state to ensure. It can be one of `present`, `absent` or `renamed`, default: `present`. | no


Authors
=======

Rafael Guterres Jeffman

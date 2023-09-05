Servicedelegationtarget module
============

Description
-----------

The servicedelegationtarget module allows to ensure presence and absence of servicedelegationtargets and servicedelegationtarget members.

Features
--------

* Servicedelegationtarget management


Supported FreeIPA Versions
--------------------------

FreeIPA versions 4.4.0 and up are supported by the ipaservicedelegationtarget module.

Host princpals are only usable with IPA versions 4.9.0 and up.


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


Example playbook to make sure servicedelegationtarget delegation-target is present:

```yaml
---
- name: Playbook to manage IPA servicedelegationtarget
  hosts: ipaserver
  become: no

  tasks:
  - name: Ensure servicedelegationtarget delegation-target is present
    ipaservicedelegationtarget:
      ipaadmin_password: SomeADMINpassword
      name: delegation-target
```


Example playbook to make sure servicedelegationtarget delegation-target member principal test/example.com is present:

```yaml
---
- name: Playbook to manage IPA servicedelegationtarget
  hosts: ipaserver
  become: no

  tasks:
  - name: Ensure servicedelegationtarget delegation-target member principal test/example.com is present
    ipaservicedelegationtarget:
      ipaadmin_password: SomeADMINpassword
      name: delegation-target
      principal: test/example.com
      action: member
```


Example playbook to make sure servicedelegationtarget delegation-target member principal test/example.com is absent:

```yaml
---
- name: Playbook to manage IPA servicedelegationtarget
  hosts: ipaserver
  become: no

  tasks:
  - name: Ensure servicedelegationtarget delegation-target member principal test/example.com is absent
    ipaservicedelegationtarget:
      ipaadmin_password: SomeADMINpassword
      name: delegation-target
      principal: test/example.com
      action: member
      state: absent
    state: absent
```


Example playbook to make sure servicedelegationtarget delegation-target is absent:

```yaml
---
- name: Playbook to manage IPA servicedelegationtarget
  hosts: ipaserver
  become: no

  tasks:
  - name: Ensure servicedelegationtarget delegation-target is absent
    ipaservicedelegationtarget:
      ipaadmin_password: SomeADMINpassword
      name: delegation-target
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
`name` \| `cn` | The list of servicedelegationtarget name strings. | yes
`principal` |  The list of principals. A principal can be of the format: fqdn, fqdn@REALM, service/fqdn, service/fqdn@REALM, host/fqdn, host/fqdn@REALM, alias$, alias$@REALM, where fqdn and fqdn@REALM are host principals and the same as host/fqdn and host/fqdn@REALM. Host princpals are only usable with IPA versions 4.9.0 and up. | no
`action` | Work on servicedelegationtarget or member level. It can be on of `member` or `servicedelegationtarget` and defaults to `servicedelegationtarget`. | no
`state` | The state to ensure. It can be one of `present`, `absent`, default: `present`. | no


Authors
=======

Thomas Woerner

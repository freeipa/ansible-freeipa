Servicedelegationrule module
============

Description
-----------

The servicedelegationrule module allows to ensure presence and absence of servicedelegationrules and servicedelegationrule members.

Features
--------

* Servicedelegationrule management


Supported FreeIPA Versions
--------------------------

FreeIPA versions 4.4.0 and up are supported by the ipaservicedelegationrule module.

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


Example playbook to make sure servicedelegationrule delegation-rule is present:

```yaml
---
- name: Playbook to manage IPA servicedelegationrule
  hosts: ipaserver
  become: no

  tasks:
  - name: Ensure servicedelegationrule delegation-rule is present
    ipaservicedelegationrule:
      ipaadmin_password: SomeADMINpassword
      name: delegation-rule
```


Example playbook to make sure servicedelegationrule delegation-rule member principal test/example.com is present:

```yaml
---
- name: Playbook to manage IPA servicedelegationrule
  hosts: ipaserver
  become: no

  tasks:
  - name: Ensure servicedelegationrule delegation-rule member principal test/example.com is present
    ipaservicedelegationrule:
      ipaadmin_password: SomeADMINpassword
      name: delegation-rule
      principal: test/example.com
      action: member
```


Example playbook to make sure servicedelegationrule delegation-rule member principal test/example.com is absent:

```yaml
---
- name: Playbook to manage IPA servicedelegationrule
  hosts: ipaserver
  become: no

  tasks:
  - name: Ensure servicedelegationrule delegation-rule member principal test/example.com is absent
    ipaservicedelegationrule:
      ipaadmin_password: SomeADMINpassword
      name: delegation-rule
      principal: test/example.com
      action: member
      state: absent
    state: absent
```


Example playbook to make sure servicedelegationrule delegation-rule member target delegation-target is present:

```yaml
---
- name: Playbook to manage IPA servicedelegationrule
  hosts: ipaserver
  become: no

  tasks:
  - name: Ensure servicedelegationrule delegation-rule member target delegation-target is present
    ipaservicedelegationrule:
      ipaadmin_password: SomeADMINpassword
      name: delegation-rule
      target: delegation-target
      action: member
```


Example playbook to make sure servicedelegationrule delegation-rule member target delegation-target is absent:

```yaml
---
- name: Playbook to manage IPA servicedelegationrule
  hosts: ipaserver
  become: no

  tasks:
  - name: Ensure servicedelegationrule delegation-rule member target delegation-target is absent
    ipaservicedelegationrule:
      ipaadmin_password: SomeADMINpassword
      name: delegation-rule
      target: delegation-target
      action: member
      state: absent
    state: absent
```


Example playbook to make sure servicedelegationrule delegation-rule is absent:

```yaml
---
- name: Playbook to manage IPA servicedelegationrule
  hosts: ipaserver
  become: no

  tasks:
  - name: Ensure servicedelegationrule delegation-rule is absent
    ipaservicedelegationrule:
      ipaadmin_password: SomeADMINpassword
      name: delegation-rule
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
`name` \| `cn` | The list of servicedelegationrule name strings. | yes
`principal` |  The list of principals. A principal can be of the format: fqdn, fqdn@REALM, service/fqdn, service/fqdn@REALM, host/fqdn, host/fqdn@REALM, alias$, alias$@REALM, where fqdn and fqdn@REALM are host principals and the same as host/fqdn and host/fqdn@REALM. Host princpals are only usable with IPA versions 4.9.0 and up. | no
`target` \| `servicedelegationtarget` | The list of service delegation targets. | no
`action` | Work on servicedelegationrule or member level. It can be on of `member` or `servicedelegationrule` and defaults to `servicedelegationrule`. | no
`state` | The state to ensure. It can be one of `present`, `absent`, default: `present`. | no


Authors
=======

Thomas Woerner

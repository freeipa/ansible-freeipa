Pwpolicy module
===============

Description
-----------

The pwpolicy module allows to ensure presence and absence of pwpolicies.


Features
--------
* Pwpolicy management


Supported FreeIPA Versions
--------------------------

FreeIPA versions 4.4.0 and up are supported by the ipapwpolicy module.


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


Example playbook to ensure presence of pwpolicies for exisiting group ops:

```yaml
  tasks:
  - name: Ensure presence of pwpolicies for group ops
    ipapwpolicy:
      ipaadmin_password: MyPassword123
      name: ops
      minlife: 7
      maxlife: 49
      history: 5
      priority: 1
      lockouttime: 300
      minlength: 8
      maxfail: 3
```

Example playbook to ensure absence of pwpolicies for group ops

```yaml
---
- name: Playbook to handle pwpolicies
  hosts: ipaserver
  become: true

  tasks:
  # Ensure absence of pwpolicies for group ops
  - ipapwpolicy:
      ipaadmin_password: MyPassword123
      name: ops
      state: absent
```


Variables
=========

ipapwpolicy
-------

Variable | Description | Required
-------- | ----------- | --------
`ipaadmin_principal` | The admin principal is a string and defaults to `admin` | no
`ipaadmin_password` | The admin password is a string and is required if there is no admin ticket available on the node | no
`name` \| `cn` | The list of pwpolicy name strings. | no
`maxlife` \| `krbmaxpwdlife` | Maximum password lifetime in days. (int) | no
`minlife` \| `krbminpwdlife` | Minimum password lifetime in hours. (int) | no
`history` \| `krbpwdhistorylength` | Password history size. (int) | no
`minclasses` \| `krbpwdmindiffchars` | Minimum number of character classes. (int) | no
`minlength` \| `krbpwdminlength` | Minimum length of password. (int) | no
`priority` \| `cospriority` | Priority of the policy, higher number means lower priority. (int) | no
`maxfail` \| `krbpwdmaxfailure` | Consecutive failures before lockout. (int) | no
`failinterval` \| `krbpwdfailurecountinterval` | Period after which failure count will be reset in seconds. (int) | no
`lockouttime` \| `krbpwdlockoutduration` | Period for which lockout is enforced in seconds. (int) | no
`state` | The state to ensure. It can be one of `present` or `absent`, default: `present`. | yes


Authors
=======

Thomas Woerner

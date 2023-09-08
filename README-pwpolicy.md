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


Example playbook to ensure presence of pwpolicies for exisiting group ops:

```yaml
  tasks:
  - name: Ensure presence of pwpolicies for group ops
    ipapwpolicy:
      ipaadmin_password: SomeADMINpassword
      name: ops
      minlife: 7
      maxlife: 49
      history: 5
      priority: 1
      lockouttime: 300
      minlength: 8
      maxfail: 3
```

Example playbook to ensure absence of pwpolicies for group ops:

```yaml
---
- name: Playbook to handle pwpolicies
  hosts: ipaserver
  become: true

  tasks:
  # Ensure absence of pwpolicies for group ops
  - ipapwpolicy:
      ipaadmin_password: SomeADMINpassword
      name: ops
      state: absent
```

Example playbook to ensure maxlife is set to 49 in global policy:

```yaml
---
- name: Playbook to handle pwpolicies
  hosts: ipaserver
  become: true

  tasks:
  # Ensure maxlife is set to 49 in global policy
  - ipapwpolicy:
      ipaadmin_password: SomeADMINpassword
      maxlife: 49
```

Example playbook to ensure password grace period is set to 3 in global policy:

```yaml
---
- name: Playbook to handle pwpolicies
  hosts: ipaserver
  become: true

  tasks:
  # Ensure maxlife is set to 49 in global policy
  - ipapwpolicy:
      ipaadmin_password: SomeADMINpassword
      gracelimit: 3
```

Example playbook to ensure password grace period is set to unlimited in global policy:

```yaml
---
- name: Playbook to handle pwpolicies
  hosts: ipaserver
  become: true

  tasks:
  # Ensure maxlife is set to 49 in global policy
  - ipapwpolicy:
      ipaadmin_password: SomeADMINpassword
      gracelimit: -1
```


Variables
=========

Variable | Description | Required
-------- | ----------- | --------
`ipaadmin_principal` | The admin principal is a string and defaults to `admin` | no
`ipaadmin_password` | The admin password is a string and is required if there is no admin ticket available on the node | no
`ipaapi_context` | The context in which the module will execute. Executing in a server context is preferred. If not provided context will be determined by the execution environment. Valid values are `server` and `client`. | no
`ipaapi_ldap_cache` | Use LDAP cache for IPA connection. The bool setting defaults to yes. (bool) | no
`name` \| `cn` | The list of pwpolicy name strings. If name is not given, `global_policy` will be used automatically. | no
`maxlife` \| `krbmaxpwdlife` | Maximum password lifetime in days. (int or "") | no
`minlife` \| `krbminpwdlife` | Minimum password lifetime in hours. (int or "") | no
`history` \| `krbpwdhistorylength` | Password history size. (int or "") | no
`minclasses` \| `krbpwdmindiffchars` | Minimum number of character classes. (int or "") | no
`minlength` \| `krbpwdminlength` | Minimum length of password. (int or "") | no
`priority` \| `cospriority` | Priority of the policy, higher number means lower priority. (int or "") | no
`maxfail` \| `krbpwdmaxfailure` | Consecutive failures before lockout. (int or "") | no
`failinterval` \| `krbpwdfailurecountinterval` | Period after which failure count will be reset in seconds. (int or "") | no
`lockouttime` \| `krbpwdlockoutduration` | Period for which lockout is enforced in seconds. (int or "") | no
`maxrepeat` \| `ipapwdmaxrepeat` | Maximum number of same consecutive characters. Requires IPA 4.9+ (int or "") | no
`maxsequence` \| `ipapwdmaxsequence` |  The maximum length of monotonic character sequences (abcd). Requires IPA 4.9+ (int or "") | no
`dictcheck` \| `ipapwdictcheck` | Check if the password is a dictionary word. Requires IPA 4.9+. (bool or "") | no
`usercheck` \| `ipapwdusercheck` | Check if the password contains the username. Requires IPA 4.9+. (bool or "") | no
`gracelimit` \| `passwordgracelimit` |  Number of LDAP authentications allowed after expiration. Requires IPA 4.9.10 (int or "") | no
`state` | The state to ensure. It can be one of `present` or `absent`, default: `present`. | yes


Authors
=======

Thomas Woerner

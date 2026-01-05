Sysaccount module
============

Description
-----------

The sysaccount module allows to ensure presence and absence of system accounts.

Features
--------

* Sysaccount management


Supported FreeIPA Versions
--------------------------

FreeIPA versions 4.4.0 and up are supported by the ipasysaccount module.


Requirements
------------

**Controller**
* Ansible version: 2.15+

**Node**
* Supported FreeIPA version (see above)


Usage
=====

Example inventory file

```ini
[ipaserver]
ipaserver.test.local
```


Example playbook to make sure sysaccount "my-app" is present with random password:

```yaml
---
- name: Playbook to manage IPA sysaccount.
  hosts: ipaserver
  become: false

  tasks:
  - name: Ensure sysaccount "my-app" is present with random password
    ipasysaccount:
      ipaadmin_password: SomeADMINpassword
      name: my-app
      random: true
    register: result

  - name: Print generated random password
    debug:
      var: result.sysaccount.randompassword

```


Example playbook to make sure sysaccount "my-app" is present with given password:

```yaml
---
- name: Playbook to manage IPA sysaccount.
  hosts: ipaserver
  become: false

  tasks:
  - name: Ensure sysaccount "my-app" is present with given password
    ipasysaccount:
      ipaadmin_password: SomeADMINpassword
      name: my-app
      password: SomeAPPpassword
```


Example playbook to make sure sysaccount "my-app" is absent:

```yaml
---
- name: Playbook to manage IPA sysaccount.
  hosts: ipaserver
  become: false

  tasks:
  - name: Ensure sysaccount "my-app" is absent
    ipasysaccount:
      ipaadmin_password: SomeADMINpassword
      name: my-app
      state: absent
```

Example playbook to ensure existing sysaccount my-app is privileged

```yaml
---
- name: Playbook to manage IPA sysaccount.
  hosts: ipaserver
  become: false

  tasks:
  - name: Ensure existing sysaccount my-app is privileged
    ipasysaccount:
      ipaadmin_password: SomeADMINpassword
      name: my-app
      privileged: true
```

Example playbook to ensure existing sysaccount my-app is not privileged

```yaml
---
- name: Playbook to manage IPA sysaccount.
  hosts: ipaserver
  become: false

  tasks:
  - name: Ensure existing sysaccount my-app is not privileged
    ipasysaccount:
      ipaadmin_password: SomeADMINpassword
      name: my-app
      privileged: false
```

Example playbook to ensure existing sysaccount my-app is disabled

```yaml
---
- name: Playbook to manage IPA sysaccount.
  hosts: ipaserver
  become: false

  tasks:
  - name: Ensure existing sysaccount my-app is disabled
    ipasysaccount:
      ipaadmin_password: SomeADMINpassword
      name: my-app
      state: disabled
```

Example playbook to ensure existing sysaccount my-app is enabled

```yaml
---
- name: Playbook to manage IPA sysaccount.
  hosts: ipaserver
  become: false

  tasks:
  - name: Ensure existing sysaccount my-app is enabled
    ipasysaccount:
      ipaadmin_password: SomeADMINpassword
      name: my-app
      state: enabled
```


Variables
---------

Variable | Description | Required
-------- | ----------- | --------
`ipaadmin_principal` | The admin principal is a string and defaults to `admin` | no
`ipaadmin_password` | The admin password is a string and is required if there is no admin ticket available on the node | no
`ipaapi_context` | The context in which the module will execute. Executing in a server context is preferred. If not provided context will be determined by the execution environment. Valid values are `server` and `client`. | no
`ipaapi_ldap_cache` | Use LDAP cache for IPA connection. The bool setting defaults to true. (bool) | no
`name` \| `login` | The list of sysaccount name strings - internally uid. (list of strings) | yes
`description` | A description for the sysaccount. (string) | no
`privileged` | Allow password updates without reset. This flag is not replicated. It is needed to set privileged on all servers, where it is needed. (bool) | no
`random` | Generate a random user password. (bool) | no
`password` \| `userpassword` | Set the password. (string) | no
`update_password` | Set password for a sysaccount in present state only on creation or always. It can be one of `always` or `on_create` and defaults to `always`. | no
`state` | The state to ensure. It can be one of `present`, `absent`, 'enabled', 'disabled',  default: `present`. | no


Return Values
=============

There are only return values if a random passwords has been generated.

Variable | Description | Returned When
-------- | ----------- | -------------
`sysaccount` | Sysaccount dict (dict) <br>Options: | Always
&nbsp; | `randompassword` - The generated random password | If random is yes and sysaccount did not exist or update_password is yes



Authors
=======

Thomas Woerner

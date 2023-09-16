Idoverrideuser module
============

Description
-----------

The idoverrideuser module allows to ensure presence and absence of idoverrideusers and idoverrideuser members.


Use Cases
---------

With idoverrideuser it is possible to manage user attributes within ID views. These attributes are for example the login name, home directory, certificate for authentication or SSH keys.


Features
--------

* Idoverrideuser management


Supported FreeIPA Versions
--------------------------

FreeIPA versions 4.4.0 and up are supported by the ipaidoverrideuser module.


Requirements
------------

**Controller**
* Ansible version: 2.13

**Node**
* Supported FreeIPA version (see above)


Usage
=====

Example inventory file

```ini
[ipaserver]
ipaserver.test.local
```


Example playbook to make sure test user test_user is present in idview test_idview

```yaml
---
- name: Playbook to manage idoverrideuser
  hosts: ipaserver
  become: false

  tasks:
  - name: Ensure test user test_user is present in idview test_idview.
    ipaidoverrideuser:
      ipaadmin_password: SomeADMINpassword
      idview: test_idview
      anchor: test_user
```


Example playbook to make sure test user test_user is present in idview test_idview with description

```yaml
---
- name: Playbook to manage idoverrideuser
  hosts: ipaserver
  become: false

  tasks:
  - name: Ensure test user test_user is present in idview test_idview with description
    ipaidoverrideuser:
      ipaadmin_password: SomeADMINpassword
      idview: test_idview
      anchor: test_user
      description: "test_user description"
```


Example playbook to make sure test user test_user is present in idview test_idview without description

```yaml
---
- name: Playbook to manage idoverrideuser
  hosts: ipaserver
  become: false

  tasks:
  - name: Ensure test user test_user is present in idview test_idview without description
    ipaidoverrideuser:
      ipaadmin_password: SomeADMINpassword
      idview: test_idview
      anchor: test_user
      description: ""
```


Example playbook to make sure test user test_user is present in idview test_idview with internal name test_123_user

```yaml
---
- name: Playbook to manage idoverrideuser
  hosts: ipaserver
  become: false

  tasks:
  - name: Ensure test user test_user is present in idview test_idview with internal name test_123_user
    ipaidoverrideuser:
      ipaadmin_password: SomeADMINpassword
      idview: test_idview
      anchor: test_user
      name: test_123_user
```


Example playbook to make sure test user test_user is present in idview test_idview without internal name

```yaml
---
- name: Playbook to manage idoverrideuser
  hosts: ipaserver
  become: false

  tasks:
  - name: Ensure test user test_user is present in idview test_idview without internal name
    ipaidoverrideuser:
      ipaadmin_password: SomeADMINpassword
      idview: test_idview
      anchor: test_user
      name: ""
```


Example playbook to make sure test user test_user is present in idview test_idview with uid 20001

```yaml
---
- name: Playbook to manage idoverrideuser
  hosts: ipaserver
  become: false

  tasks:
  - name: Ensure test user test_user is present in idview test_idview with uid 20001
    ipaidoverrideuser:
      ipaadmin_password: SomeADMINpassword
      idview: test_idview
      anchor: test_user
      uid: 20001
```


Example playbook to make sure test user test_user is present in idview test_idview without uid

```yaml
---
- name: Playbook to manage idoverrideuser
  hosts: ipaserver
  become: false

  tasks:
  - name: Ensure test user test_user is present in idview test_idview without uid
    ipaidoverrideuser:
      ipaadmin_password: SomeADMINpassword
      idview: test_idview
      anchor: test_user
      uid: ""
```


Example playbook to make sure test user test_user is present in idview test_idview with gecos "Gecos Test"

```yaml
---
- name: Playbook to manage idoverrideuser
  hosts: ipaserver
  become: false

  tasks:
  - name: Ensure test user test_user is present in idview test_idview with gecos "Gecos Test"
    ipaidoverrideuser:
      ipaadmin_password: SomeADMINpassword
      idview: test_idview
      anchor: test_user
      gecos: Gecos Test
```


Example playbook to make sure test user test_user is present in idview test_idview without gecos

```yaml
---
- name: Playbook to manage idoverrideuser
  hosts: ipaserver
  become: false

  tasks:
  - name: Ensure test user test_user is present in idview test_idview without gecos
    ipaidoverrideuser:
      ipaadmin_password: SomeADMINpassword
      idview: test_idview
      anchor: test_user
      gecos: ""
```


Example playbook to make sure test user test_user is present in idview test_idview with gidnumber

```yaml
---
- name: Playbook to manage idoverrideuser
  hosts: ipaserver
  become: false

  tasks:
  - name: Ensure test user test_user is present in idview test_idview with gidnumber
    ipaidoverrideuser:
      ipaadmin_password: SomeADMINpassword
      idview: test_idview
      anchor: test_user
      gidnumber: 20001
```


Example playbook to make sure test user test_user is present in idview test_idview without gidnumber

```yaml
---
- name: Playbook to manage idoverrideuser
  hosts: ipaserver
  become: false

  tasks:
  - name: Ensure test user test_user is present in idview test_idview without gidnumber
    ipaidoverrideuser:
      ipaadmin_password: SomeADMINpassword
      idview: test_idview
      anchor: test_user
      gidnumber: ""
```


Example playbook to make sure test user test_user is present in idview test_idview with homedir /Users

```yaml
---
- name: Playbook to manage idoverrideuser
  hosts: ipaserver
  become: false

  tasks:
  - name: Ensure test user test_user is present in idview test_idview with homedir /Users
    ipaidoverrideuser:
      ipaadmin_password: SomeADMINpassword
      idview: test_idview
      anchor: test_user
      homedir: /Users
```


Example playbook to make sure test user test_user is present in idview test_idview without homedir

```yaml
---
- name: Playbook to manage idoverrideuser
  hosts: ipaserver
  become: false

  tasks:
  - name: Ensure test user test_user is present in idview test_idview without homedir
    ipaidoverrideuser:
      ipaadmin_password: SomeADMINpassword
      idview: test_idview
      anchor: test_user
      homedir: ""
```


Example playbook to make sure test user test_user is present in idview test_idview with shell

```yaml
---
- name: Playbook to manage idoverrideuser
  hosts: ipaserver
  become: false

  tasks:
  - name: Ensure test user test_user is present in idview test_idview with shell
    ipaidoverrideuser:
      ipaadmin_password: SomeADMINpassword
      idview: test_idview
      anchor: test_user
      shell: /bin/someshell
```


Example playbook to make sure test user test_user is present in idview test_idview without shell

```yaml
---
- name: Playbook to manage idoverrideuser
  hosts: ipaserver
  become: false

  tasks:
  - name: Ensure test user test_user is present in idview test_idview without shell
    ipaidoverrideuser:
      ipaadmin_password: SomeADMINpassword
      idview: test_idview
      anchor: test_user
      shell: ""
```


Example playbook to make sure test user test_user is present in idview test_idview with sshpubkey

```yaml
---
- name: Playbook to manage idoverrideuser
  hosts: ipaserver
  become: false

  tasks:
  - name: Ensure test user test_user is present in idview test_idview with sshpubkey
    ipaidoverrideuser:
      ipaadmin_password: SomeADMINpassword
      idview: test_idview
      anchor: test_user
      sshpubkey:
      - ssh-rsa AAAAB3NzaC1yc2EAAADAQABAAABgQCqmVDpEX5gnSjKuv97Ay ...
```


Example playbook to make sure test user test_user is present in idview test_idview without sshpubkey

```yaml
---
- name: Playbook to manage idoverrideuser
  hosts: ipaserver
  become: false

  tasks:
  - name: Ensure test user test_user is present in idview test_idview without sshpubkey
    ipaidoverrideuser:
      ipaadmin_password: SomeADMINpassword
      idview: test_idview
      anchor: test_user
      sshpubkey: []
```


Example playbook to make sure test user test_user is present in idview test_idview with 1 certificate

```yaml
---
- name: Playbook to manage idoverrideuser
  hosts: ipaserver
  become: false

  tasks:
  - name: Ensure test user test_user is present in idview test_idview with 1 certificate
    ipaidoverrideuser:
      ipaadmin_password: SomeADMINpassword
      idview: test_idview
      anchor: test_user
      certificate:
      - "{{ lookup('file', 'cert1.b64', rstrip=False) }}"
```


Example playbook to make sure test user test_user is present in idview test_idview with 3 certificate members

```yaml
---
- name: Playbook to manage idoverrideuser
  hosts: ipaserver
  become: false

  tasks:
  - name: Ensure test user test_user is present in idview test_idview with 3 certificate members
    ipaidoverrideuser:
      ipaadmin_password: SomeADMINpassword
      idview: test_idview
      anchor: test_user
      certificate:
      - "{{ lookup('file', 'cert1.b64', rstrip=False) }}"
      - "{{ lookup('file', 'cert2.b64', rstrip=False) }}"
      - "{{ lookup('file', 'cert3.b64', rstrip=False) }}"
      action: member
```


Example playbook to make sure test user test_user is present in idview test_idview without 2 certificate members

```yaml
---
- name: Playbook to manage idoverrideuser
  hosts: ipaserver
  become: false

  tasks:
  - name: Ensure test user test_user is present in idview test_idview without 2 certificate members
    ipaidoverrideuser:
      ipaadmin_password: SomeADMINpassword
      idview: test_idview
      anchor: test_user
      certificate:
      - "{{ lookup('file', 'cert2.b64', rstrip=False) }}"
      - "{{ lookup('file', 'cert3.b64', rstrip=False) }}"
      action: member
      state: absent
```


Example playbook to make sure test user test_user is present in idview test_idview without certificates

```yaml
---
- name: Playbook to manage idoverrideuser
  hosts: ipaserver
  become: false

  tasks:
  - name: Ensure test user test_user is present in idview test_idview without certificates
    ipaidoverrideuser:
      ipaadmin_password: SomeADMINpassword
      idview: test_idview
      anchor: test_user
      certificate: []
```


Example playbook to make sure test user test_user is present in idview test_idview with enabling falling back to AD DC LDAP when resolving AD trusted objects. (For two-way trusts only.)

```yaml
---
- name: Playbook to manage idoverrideuser
  hosts: ipaserver
  become: false

  tasks:
  - name: Ensure test user test_user is present in idview test_idview with fallback_to_ldap enabled
    ipaidoverrideuser:
      ipaadmin_password: SomeADMINpassword
      idview: test_idview
      anchor: test_user
      fallback_to_ldap: true
```


Example playbook to make sure test user test_user is absent in idview test_idview

```yaml
---
- name: Playbook to manage idoverrideuser
  hosts: ipaserver
  become: false

  tasks:
  - name: Ensure test user test_user is absent in idview test_idview
    ipaidoverrideuser:
      ipaadmin_password: SomeADMINpassword
      idview: test_idview
      anchor: test_user
      continue: true
      state: absent
```


Variables
---------

Variable | Description | Required
-------- | ----------- | --------
`ipaadmin_principal` | The admin principal is a string and defaults to `admin` | no
`ipaadmin_password` | The admin password is a string and is required if there is no admin ticket available on the node | no
`ipaapi_context` | The context in which the module will execute. Executing in a server context is preferred. If not provided context will be determined by the execution environment. Valid values are `server` and `client`. | no
`ipaapi_ldap_cache` | Use LDAP cache for IPA connection. The bool setting defaults to true. (bool) | no
`idview` \| `idviewcn` | The doverrideuser idview string. | yes
`anchor` \| `ipaanchoruuid` | The list of anchors to override. | yes
`description` \| `desc` | Description | no
`name` \| `login` | The user (internally uid) | no
`uid` \| `uidnumber` | User ID Number (int or "") | no
`gecos` | GECOS | no
`gidnumber` | Group ID Number (int or ""). | no
`homedir` \| `homedirectory` | Home directory. | no
`shell` \| `loginshell` | Login shell. | no
`sshpubkey` \| `ipasshpubkey` | List of SSH public keys. | no
`certificate` \| `usercertificate` | List of Base-64 encoded user certificates. This variable can also be used with `action: member`. | no
`fallback_to_ldap` | Allow falling back to AD DC LDAP when resolving AD trusted objects. For two-way trusts only. | no
`delete_continue` \| `continue` | Continuous mode. Don't stop on errors. Valid only if `state` is `absent`. | no
`nomembers` \| `no_members` | Suppress processing of membership attributes. Valid only if `state` is `absent`. | no
`action` | Work on idoverrideuser or member level. It can be on of `member` or `idoverrideuser` and defaults to `idoverrideuser`. | no
`state` | The state to ensure. It can be one of `present`, `absent`, default: `present`. | no


Authors
=======

Thomas Woerner

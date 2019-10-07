User module
===========

Description
-----------

The user module allows to ensure presence, absence, disablement, unlocking and undeletion of users.

The user module is as compatible as possible to the Ansible upstream `ipa_user` module, but additionally offers to preserve delete, enable, disable, unlock and undelete users.


Features
--------
* User management


Supported FreeIPA Versions
--------------------------

FreeIPA versions 4.4.0 and up are supported by the ipauser module.


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


Example playbook to add users:

```yaml
---
- name: Playbook to handle users
  hosts: ipaserver
  become: true

  tasks:
  # Create user pinky
  - ipauser:
      ipaadmin_password: MyPassword123
      name: pinky
      first: pinky
      last: Acme
      uid: 10001
      gid: 100
      phone: "+555123457"
      email: pinky@acme.com
      passwordexpiration: "2023-01-19 23:59:59"
      password: "no-brain"
      update_password: on_create

  # Create user brain
  - ipauser:
      ipaadmin_password: MyPassword123
      name: brain
      first: brain
      last: Acme
```
`update_password` controls if a password for a user will be set in present state only on creation or every time (always).


Example playbook to delete a user, but preserve it:

```yaml
---
- name: Playbook to handle users
  hosts: ipaserver
  become: true

  tasks:
  # Remove but preserve user pinky
  - ipauser:
      ipaadmin_password: MyPassword123
      name: pinky
      preserve: yes
      state: absent
```


Example playbook to undelete a preserved user.

```yaml
---
- name: Playbook to handle users
  hosts: ipaserver
  become: true

  tasks:
  # Undelete preserved user pinky
  - ipauser:
      ipaadmin_password: MyPassword123
      name: pinky
      state: undeleted
```


Example playbook to disable a user:

```yaml
---
- name: Playbook to handle users
  hosts: ipaserver
  become: true

  tasks:
  # Disable user pinky
  - ipauser:
      ipaadmin_password: MyPassword123
      name: pinky
      state: disabled
```


Example playbook to enable users:

```yaml
---
- name: Playbook to handle users
  hosts: ipaserver
  become: true

  tasks:
  # Enable user pinky and brain
  - ipauser:
      ipaadmin_password: MyPassword123
      name: pinky,brain
      state: enabled
```


Example playbook to unlock users:

```yaml
---
- name: Playbook to handle users
  hosts: ipaserver
  become: true

  tasks:
  # Unlock user pinky and brain
  - ipauser:
      ipaadmin_password: MyPassword123
      name: pinky,brain
      state: unlocked
```


Example playbook to delete users:

```yaml
---
- name: Playbook to handle users
  hosts: ipaserver
  become: true

  tasks:
  # Remove user pinky and brain
  - ipauser:
      ipaadmin_password: MyPassword123
      name: pinky,brain
      state: absent
```


Variables
=========

ipauser
-------

Variable | Description | Required
-------- | ----------- | --------
`ipaadmin_principal` | The admin principal is a string and defaults to `admin` | no
`ipaadmin_password` | The admin password is a string and is required if there is no admin ticket available on the node | no
`name` | The list of user name strings. | no
`first` \| `givenname` | The first name string. | no
`last` | The last name | no
`fullname` \| `cn` | The full name string. | no
`displayname` | The display name string. | no
`homedir` | The home directory string. | no
`shell` \| `loginshell` | The login shell string. | no
`email` | List of email address strings. | no
`principalname` \| `krbprincipalname` | The kerberos principal sptring. | no
`passwordexpiration` \| `krbpasswordexpiration` | The kerberos password expiration date. Possible formats: `YYYYMMddHHmmssZ`, `YYYY-MM-ddTHH:mm:ssZ`, `YYYY-MM-ddTHH:mmZ`, `YYYY-MM-ddZ`, `YYYY-MM-dd HH:mm:ssZ` or `YYYY-MM-dd HH:mmZ`. The trailing 'Z' can be skipped. | no
`password` | The user password string. | no
`uid` \| `uidnumber` | The UID integer. | no
`gid` \| `gidnumber` | The GID integer. | no
`phone` \| `telephonenumber` | List of telephone number strings, | no
`title` | The job title string. | no
~~`sshpubkey` \| `ipasshpubkey`~~ | ~~List of SSH public keys.~~ | ~~no~~
`update_password` | Set password for a user in present state only on creation or always. It can be one of `always` or `on_create` and defaults to `always`. | no
`preserve` | Delete a user, keeping the entry available for future use. (bool)  | no
`state` | The state to ensure. It can be one of `present`, `absent`, `enabled`, `disabled`, `unlocked` or `undeleted`, default: `present`. | yes


Authors
=======

Thomas Woerner

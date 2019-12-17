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


Example playbook to ensure a user is present:

```yaml
---
- name: Playbook to handle users
  hosts: ipaserver
  become: true

  tasks:
  # Ensure user pinky is present
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

  # Ensure user brain is present
  - ipauser:
      ipaadmin_password: MyPassword123
      name: brain
      first: brain
      last: Acme
```
`update_password` controls if a password for a user will be set in present state only on creation or every time (always).


These two `ipauser` module calls can be combined into one with the `users` variable:

```yaml
---
- name: Playbook to handle users
  hosts: ipaserver
  become: true

  tasks:
  # Ensure users pinky and brain are present
  - ipauser:
      ipaadmin_password: MyPassword123
      users:
      - name: pinky
        first: pinky
        last: Acme
        uid: 10001
        gid: 100
        phone: "+555123457"
        email: pinky@acme.com
        passwordexpiration: "2023-01-19 23:59:59"
        password: "no-brain"
      - name: brain
        first: brain
        last: Acme
      update_password: on_create
```

You can also alternatively use a json file containing the users, here `users_present.json`:

```json
{
  "users": [
    {
      "name": "user1",
      "first": "First 1",
      "last": "Last 1"
    },
    {
      "name": "user2",
      "first": "First 2",
      "last": "Last 2"
    },
    ...
  ]
}
```

And ensure the presence of the users with this example playbook:

```yaml
---
- name: Tests
  hosts: ipaserver
  become: true
  gather_facts: false

  tasks:
  - name: Include users_present.json
    include_vars:
      file: users_present.json

  - name: Users present
    ipauser:
      ipaadmin_password: SomeADMINpassword
      users: "{{ users }}"
```

Ensure user pinky is present with a generated random password and print the random password:

```yaml
---
- name: Playbook to handle users
  hosts: ipaserver
  become: true

  tasks:
  # Ensure user pinky is present with a random password
  - ipauser:
      ipaadmin_password: MyPassword123
      name: brain
      first: brain
      last: Acme
      random: yes
    register: ipauser

  - name: Print generated random password
    debug:
      var: ipauser.user.randompassword
```

Ensure users pinky and brain are present with a generated random password and print the random passwords:

```yaml
---
- name: Playbook to handle users
  hosts: ipaserver
  become: true

  tasks:
  # Ensure users pinky and brain are present with random password
  - ipauser:
      ipaadmin_password: MyPassword123
      users:
      - name: pinky
        first: pinky
        last: Acme
        uid: 10001
        gid: 100
        phone: "+555123457"
        email: pinky@acme.com
        passwordexpiration: "2023-01-19 23:59:59"
        password: "no-brain"
      - name: brain
        first: brain
        last: Acme
    register: ipauser

  - name: Print generated random password of pinky
    debug:
      var: ipauser.user.pinky.randompassword

  - name: Print generated random password of brain
    debug:
      var: ipauser.user.brain.randompassword
```

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

This can also be done with the `users` variable containing only names, this can be combined into one module call:

Example playbook to delete a user, but preserve it using the `users` variable:

```yaml
---
- name: Playbook to handle users
  hosts: ipaserver
  become: true

  tasks:
  # Remove but preserve user pinky
  - ipauser:
      ipaadmin_password: MyPassword123
      users:
      - name: pinky
      preserve: yes
      state: absent
```

This can also be done as an alternative with the `users` variable containing only names.


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

This can also be done as an alternative with the `users` variable containing only names.


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

This can also be done as an alternative with the `users` variable containing only names.


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

This can also be done as an alternative with the `users` variable containing only names.


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


Example playbook to ensure users are absent:

```yaml
---
- name: Playbook to handle users
  hosts: ipaserver
  become: true

  tasks:
  # Ensure users pinky and brain are absent
  - ipauser:
      ipaadmin_password: MyPassword123
      name: pinky,brain
      state: absent
```

This can also be done as an alternative with the `users` variable containing only names.


Example playbook to ensure users are absent:

```yaml
---
- name: Playbook to handle users
  hosts: ipaserver
  become: true

  tasks:
  # Ensure users pinky and brain are absent
  - ipauser:
      ipaadmin_password: MyPassword123
      users:
      - name: pinky
      - name: brain
      state: absent
```


Variables
=========

ipauser
-------

**General Variables:**

Variable | Description | Required
-------- | ----------- | --------
`ipaadmin_principal` | The admin principal is a string and defaults to `admin` | no
`ipaadmin_password` | The admin password is a string and is required if there is no admin ticket available on the node | no
`name` | The list of user name strings. `name` with *user variables* or `users` containing *user variables* need to be used. | no
**User variables** | Only used with `name` variable in the first level. | no
`users` | The list of user dicts. Each `users` dict entry can contain **user variables**.<br>There is one required option in the `users` dict:| no
&nbsp; | `name` - The user name string of the entry. | yes
&nbsp; | **User variables** | no
`preserve` | Delete a user, keeping the entry available for future use. (bool) | no
`update_password` | Set password for a user in present state only on creation or always. It can be one of `always` or `on_create` and defaults to `always`. | no
`preserve` | Delete a user, keeping the entry available for future use. (bool)  | no
`action` | Work on user or member level. It can be on of `member` or `user` and defaults to `user`. | no
`state` | The state to ensure. It can be one of `present`, `absent`, `enabled`, `disabled`, `unlocked` or `undeleted`, default: `present`. Only `names` or `users` with only `name` set are allowed if state is not `present`. | yes



**User Variables:**

Variable | Description | Required
-------- | ----------- | --------
`first` \| `givenname` | The first name string. | no
`last` \| `sn` | The last name string. | no
`fullname` \| `cn` | The full name string. | no
`displayname` | The display name string. | no
`homedir` | The home directory string. | no
`shell` \| `loginshell` | The login shell string. | no
`email` | List of email address strings. | no
`principal` \| `principalnam` \| `krbprincipalname` | The kerberos principal sptring. | no
`principalexpiration` \| `krbprincipalexpiration` | The kerberos principal expiration date. Possible formats: `YYYYMMddHHmmssZ`, `YYYY-MM-ddTHH:mm:ssZ`, `YYYY-MM-ddTHH:mmZ`, `YYYY-MM-ddZ`, `YYYY-MM-dd HH:mm:ssZ` or `YYYY-MM-dd HH:mmZ`. The trailing 'Z' can be skipped. | no
`passwordexpiration` \| `krbpasswordexpiration` | The kerberos password expiration date. Possible formats: `YYYYMMddHHmmssZ`, `YYYY-MM-ddTHH:mm:ssZ`, `YYYY-MM-ddTHH:mmZ`, `YYYY-MM-ddZ`, `YYYY-MM-dd HH:mm:ssZ` or `YYYY-MM-dd HH:mmZ`. The trailing 'Z' can be skipped. Only usable with IPA versions 4.7 and up. | no
`password` | The user password string. | no
`random` | Generate a random user password | no
`uid` \| `uidnumber` | The UID integer. | no
`gid` \| `gidnumber` | The GID integer. | no
`city` | City | no
`userstate` \| `st` | State/Province | no
`postalcode` \| `zip` | Postalcode/ZIP | no
`phone` \| `telephonenumber` | List of telephone number strings, | no
`mobile` | List of mobile telephone number strings. | no
`pager` | List of pager number strings. | no
`fax` \| `facsimiletelephonenumber` | List of fax number strings. | no
`orgunit` | The Organisation unit. | no
`title` | The job title string. | no
`manager` | List of manager user names. | no
`carlicense` | List of car licenses. | no
`sshpubkey` \| `ipasshpubkey` | List of SSH public keys. | no
`userauthtype` | List of supported user authentication types. Choices: `password`, `radius`, `otp` and ``. Use empty string to reset userauthtype to the initial value. | no
`userclass` | User category. (semantics placed on this attribute are for local interpretation). | no
`radius` | RADIUS proxy configuration  | no
`radiususer` | RADIUS proxy username | no
`departmentnumber` | Department Number | no
`employeenumber` | Employee Number | no
`employeetype` | Employee Type | no
`preferredlanguage` | Preferred Language | no
`certificate` | List of base-64 encoded user certificates. | no
`certmapdata` | List of certificate mappings. Either `certificate` or `issuer` together with `subject` need to be specified. <br>Options: | no
&nbsp; | `certificate` - Base-64 encoded user certificate | no
&nbsp; | `issuer` - Issuer of the certificate | no
&nbsp; | `subject` - Subject of the certificate | no
`noprivate` | Do not create user private group. (bool) | no
`nomembers` | Suppress processing of membership attributes. (bool) | no



Return Values
=============

ipauser
-------

There are only return values if one or more random passwords have been generated.

Variable | Description | Returned When
-------- | ----------- | -------------
`host` | Host dict with random password. (dict) <br>Options: | If random is yes and user did not exist or update_password is yes
&nbsp; | `randompassword` - The generated random password | If only one user is handled by the module
&nbsp; | `name` - The user name of the user that got a new random password. (dict) <br> Options: <br> &nbsp; `randompassword` - The generated random password | If several users are handled by the module


Authors
=======

Thomas Woerner

Idview module
============

Description
-----------

The idview module allows to ensure presence and absence of idviews and idview host members.

Use Cases
---------

With ID views it is possible to override user or group attributes for users stored in the LDAP server. For example the login name, home directory, certificate for authentication or SSH keys. An ID view is client-side and specifies new values for user or group attributes and also the client host or hosts on which the values apply.

The ID view and the applied hosts are managed with idview, the user attributes are managed with idoverrideuser and the group attributes with idoverridegroup.

Features
--------

* Idview management


Supported FreeIPA Versions
--------------------------

FreeIPA versions 4.4.0 and up are supported by the ipaidview module.


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


Example playbook to make sure idview "test_idview" is present:

```yaml
---
- name: Playbook to manage IPA idview.
  hosts: ipaserver
  become: false

  tasks:
  - ipaidview:
      ipaadmin_password: SomeADMINpassword
      name: test_idview
```


Example playbook to make sure idview "test_idview" member host "testhost.example.com" is present:

```yaml
---
- name: Playbook to manage IPA idview host member.
  hosts: ipaserver
  become: false

  tasks:
  - ipaidview:
      ipaadmin_password: SomeADMINpassword
      name: test_idview
      host: testhost.example.com
      action: member
```


Example playbook to make sure idview "test_idview" member host "testhost.example.com" is absent:

```yaml
---
- name: Playbook to manage IPA idview host member.
  hosts: ipaserver
  become: false

  tasks:
  - ipaidview:
      ipaadmin_password: SomeADMINpassword
      name: test_idview
      host: testhost.example.com
      action: member
      state: absent
```


Example playbook to make sure idview "test_idview" is present with domain_resolution_order for "ad.example.com:ipa.example.com":

```yaml
---
- name: Playbook to manage IPA idview host member.
  hosts: ipaserver
  become: false

  tasks:
  - ipaidview:
      ipaadmin_password: SomeADMINpassword
      name: test_idview
      domain_resolution_order: "ad.example.com:ipa.example.com"
```


Example playbook to make sure idview "test_idview" is absent:

```yaml
---
- name: Playbook to manage IPA idview.
  hosts: ipaserver
  become: false

  tasks:
  - ipaidview:
      ipaadmin_password: SomeADMINpassword
      name: test_idview
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
`name` \| `cn` | The list of idview name strings. | yes
`description` \| `desc` | The description string of the idview. | no
`domain_resolution_order` \| `ipadomainresolutionorder` | Colon-separated list of domains used for short name qualification. | no
`host` \| `hosts` | List of hosts to apply the ID View to. A host can only be applied to a single idview at any time. Applying a host that is already applied to a different idview will change the idview the host is applied to to the new one. | no
`rename` \| `new_name` | Rename the ID view object to the new name string. Only usable with `state: renamed`. | no
`delete_continue` \| `continue` | Continuous mode. Don't stop on errors. Valid only if `state` is `absent`. | no
`action` | Work on idview or member level. It can be on of `member` or `idview` and defaults to `idview`. | no
`state` | The state to ensure. It can be one of `present`, `absent` and `renamed`, default: `present`. | no


Authors
=======

Thomas Woerner

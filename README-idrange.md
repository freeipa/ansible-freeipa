Idrange module
============

Description
-----------

The idrange module allows the management of ID ranges.

In general it is not necessary to modify or delete ID ranges. If there is no other way to achieve a certain configuration than to modify or delete an ID range it should be done with great care. Because UIDs are stored in the file system and are used for access control it might be possible that users are allowed to access files of other users if an ID range got deleted and reused for a different domain.


Use cases
---------

* Add an ID range from a transitively trusted domain

If the trusted domain (A) trusts another domain (B) as well and this trust is transitive 'ipa trust-add domain-A' will only create a range for domain A. The ID range for domain B must be added manually.

* Add an additional ID range for the local domain

If the ID range of the local domain is exhausted, i.e. no new IDs can be assigned to Posix users or groups by the DNA plugin, a new range has to be created to allow new users and groups to be added. (Currently there is no connection between this range CLI and the DNA plugin, but a future version might be able to modify the configuration of the DNS plugin as well).


Features
--------

* ID Range management


Supported FreeIPA Versions
--------------------------

FreeIPA versions 4.4.0 and up are supported by the ipaidrange module.


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

Example playbook to ensure a local domain idrange is present:

```yaml
---
- name: Playbook to manage IPA idrange.
  hosts: ipaserver
  become: no

  tasks:
  - name: Ensure an ID Range for the local domain is present.
    ipaidrange:
      ipaadmin_password: SomeADMINpassword
      name: local_domain_id_range
      base_id: 150000
      range_size: 200000
```

Example playbook to ensure a local domain idrange is present, with RID and secondary RID base values:

```yaml
---
- name: Playbook to manage IPA idrange.
  hosts: ipaserver
  become: no

  tasks:
  - name: Ensure local idrange is present
    ipaidrange:
      ipaadmin_password: SomeADMINpassword
      name: local_domain_id_range
      base_id: 150000000
      range_size: 200000
      rid_base: 1000000
      secondary_rid_base: 200000000
```

Example playbook to ensure an AD-trust idrange is present, with range type 'trust-ad' and using domain SID:

```yaml
---
- name: Playbook to manage IPA idrange.
  hosts: ipaserver
  become: no

  tasks:
  - name: Ensure AD-trust idrange is present
    ipaidrange:
      ipaadmin_password: SomeADMINpassword
      name: ad_id_range
      base_id: 150000000
      range_size: 200000
      idrange_type: ipa-ad-trust
      dom_sid: S-1-5-21-2870384104-3340008087-3140804251
```

Example playbook to ensure an AD-trust idrange is present, with range type 'trust-ad-posix' and using domain SID:

```yaml
---
- name: Playbook to manage IPA idrange.
  hosts: ipaserver
  become: no

  tasks:
  - name: Ensure AD-trust idrange is present
    ipaidrange:
      name: ad_posix_id_range
      base_id: 150000000
      range_size: 200000
      idrange_type: ipa-ad-trust-posix
      dom_name: ad.ipa.test
```

Example playbook to ensure an AD-trust idrange has auto creation of groups set to 'hybrid':

```yaml
---
- name: Playbook to manage IPA idrange.
  hosts: ipaserver
  become: no

  tasks:
  - name: Modify AD-trust idrange 'auto_private_groups'
    ipaidrange:
      ipaadmin_password: SomeADMINpassword
      ipaapi_context: "{{ ipa_context | default(omit) }}"
      name: ad_id_range
      auto_private_groups: "hybrid"
```

Example playbook to make sure an idrange is absent:

```yaml
---
- name: Playbook to manage IPA idrange.
  hosts: ipaserver
  become: no

  tasks:
  - name: Ensure ID range 'ad_id_range' is absent.
    ipaidrange:
      ipaadmin_password: SomeADMINpassword
      name: ad_id_range
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
`name` \| `cn` | The list of idrange name strings. | yes
`base_id` \| `ipabaseid` | First Posix ID of the range. (int) | yes, if `state: present`
`range_size` \| `ipaidrangesize` | Number of IDs in the range. (int) | yes, if `state: present`
`rid_base` \| `ipabaserid` | First RID of the corresponding RID range. (int) | no
`secondary_rid_base` \| `ipasecondarybaserid` | First RID of the secondary RID range. (int) | no
`dom_sid` \| `ipanttrusteddomainsid` | Domain SID of the trusted domain. | no
`idrange_type` \| `iparangetype` | ID range type, one of `ipa-ad-trust`, `ipa-ad-trust-posix`, `ipa-local`. Only valid if idrange does not exist. | no
`dom_name` \| `ipanttrusteddomainname` | Name of the trusted domain. Can only be used when `ipaapi_context: server`. | no
`auto_private_groups` \| `ipaautoprivategroups` | Auto creation of private groups, one of `true`, `false`, `hybrid`. | no
`delete_continue` \| `continue` | Continuous mode: don't stop on errors. Valid only if `state` is `absent`. Default: `no` (bool) | no
`state` | The state to ensure. It can be one of `present`, `absent`, default: `present`. | no


Notes
=====

DNA plugin in 389-ds will allocate IDs based on the ranges configured for the local domain. Currently the DNA plugin *cannot* be reconfigured itself based on the local ranges set via this family of commands.

Manual configuration change has to be done in the DNA plugin configuration for the new local range. Specifically, The dnaNextRange attribute of 'cn=Posix IDs,cn=Distributed Numeric Assignment Plugin,cn=plugins,cn=config' has to be modified to match the new range.


Authors
=======

Rafael Guterres Jeffman

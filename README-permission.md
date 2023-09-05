Permission module
============

Description
-----------

The permission module allows to ensure presence and absence of permissions and permission members.

Features
--------

* Permission management


Supported FreeIPA Versions
--------------------------

FreeIPA versions 4.4.0 and up are supported by the ipapermission module.


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


Example playbook to make sure permission "MyPermission" is present:

```yaml
---
- name: Playbook to handle IPA permissions
  hosts: ipaserver
  become: yes

  tasks:
  - name: Ensure permission MyPermission is present
    ipapermission:
      ipaadmin_password: SomeADMINpassword
      name: MyPermission
      object_type: host
      right: all
```


Example playbook to ensure permission "MyPermission" is present with attr carlicense:

```yaml
---
- name: Playbook to handle IPA permissions
  hosts: ipaserver
  become: yes

  tasks:
  - name: Ensure permission "MyPermission" is present with attr carlicense
    ipapermission:
      ipaadmin_password: SomeADMINpassword
      name: MyPermission
      object_type: host
      right: all
      attrs:
      - carlicense
```


Example playbook to ensure attr gecos is present in permission "MyPermission":

```yaml
---
- name: Playbook to handle IPA permissions
  hosts: ipaserver
  become: yes

  tasks:
  - name: Ensure attr gecos is present in permission "MyPermission"
    ipapermission:
      ipaadmin_password: SomeADMINpassword
      name: MyPermission
      attrs:
      - gecos
      action: member
```


Example playbook to ensure attr gecos is absent in permission "MyPermission":

```yaml
---
- name: Playbook to handle IPA permissions
  hosts: ipaserver
  become: yes

  tasks:
  - name: Ensure attr gecos is present in permission "MyPermission"
    ipapermission:
      ipaadmin_password: SomeADMINpassword
      name: MyPermission
      attrs:
      - gecos
      action: member
      state: absent
```


Example playbook to make sure permission "MyPermission" is absent:

```yaml
---
- name: Playbook to handle IPA permissions
  hosts: ipaserver
  become: yes

  tasks:
  - name: Ensure permission "MyPermission" is absent
    ipapermission:
      ipaadmin_password: SomeADMINpassword
      name: MyPermission
      state: absent
```


Example playbook to make sure permission "MyPermission" is renamed to "MyNewPermission":

```yaml
---
- name: Playbook to handle IPA permissions
  hosts: ipaserver
  become: yes

  tasks:
  - name: Ensure permission "MyPermission" is renamed to "MyNewPermission
    ipapermission:
      ipaadmin_password: SomeADMINpassword
      name: MyPermission
      rename: MyNewPermission
      state: renamed
```


Variables
---------

Variable | Description | Required
-------- | ----------- | --------
`ipaadmin_principal` | The admin principal is a string and defaults to `admin` | no
`ipaadmin_password` | The admin password is a string and is required if there is no admin ticket available on the node | no
`ipaapi_context` | The context in which the module will execute. Executing in a server context is preferred. If not provided context will be determined by the execution environment. Valid values are `server` and `client`. | no
`ipaapi_ldap_cache` | Use LDAP cache for IPA connection. The bool setting defaults to yes. (bool) | no
`name` \| `cn` | The permission name string. | yes
`right` \| `ipapermright` | Rights to grant. It can be a list of one or more of `read`, `search`, `compare`, `write`, `add`, `delete`, and `all` default: `all` | no
`attrs` | All attributes to which the permission applies. | no
`bindtype` \| `ipapermbindruletype` | Bind rule type. It can be one of `permission`, `all`, `self`, or `anonymous` defaults to `permission` for new permissions. Bind rule type `self` can only be used on IPA versions 4.8.7 or up.| no
`subtree` \| `ipapermlocation` | Subtree to apply permissions to | no
`filter` \| `extratargetfilter` | Extra target filter | no
`rawfilter` \| `ipapermtargetfilter` | All target filters | no
`target` \| `ipapermtarget` | Optional DN to apply the permission to | no
`targetto` \| `ipapermtargetto` | Optional DN subtree where an entry can be moved to | no
`targetfrom` \| `ipapermtargetfrom` | Optional DN subtree from where an entry can be moved | no
`memberof` | Target members of a group (sets memberOf targetfilter) | no
`targetgroup` | User group to apply permissions to (sets target) | no
`object_type` | Type of IPA object (sets subtree and objectClass targetfilter) | no
`no_members` | Suppress processing of membership | no
`rename` \| `new_name` | Rename the permission object | no
`action` | Work on permission or member level. It can be on of `member` or `permission` and defaults to `permission`. | no
`state` | The state to ensure. It can be one of `present`, `absent`, or `renamed` default: `present`. | no

The `includedattrs` and `excludedattrs` variables are only usable for managed permisions and are not exposed by the module. Using `attrs` for managed permissions will result in the automatic generation of `includedattrs` and `excludedattrs` in the IPA server.


Authors
=======

Seth Kress

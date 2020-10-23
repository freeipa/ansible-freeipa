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


Example playbook to make sure permission "MyPermission" is present:

```yaml
---
- name: Playbook to create an IPA permission.
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

Example playbook to make sure permission "MyPermission" member "privilege" with value "User Administrators" is present:

```yaml
---
- name: Permission add privilege to a permission
  hosts: ipaserver
  become: true

  tasks:
  - name: Ensure permission MyPermission is present with the User Administrators privilege present
    ipapermission:
      ipaadmin_password: SomeADMINpassword
      name: MyPermission
      privilege: "User Administrators"
      action: member
```


Example playbook to make sure permission "MyPermission" member "privilege" with value "User Administrators" is absent:


```yaml
---
- name: Permission remove privilege from a permission
  hosts: ipaserver
  become: true

  tasks:
  - name: Ensure permission MyPermission is present without the User Administrators privilege
    ipapermission:
      ipaadmin_password: SomeADMINpassword
      name: MyPermission
      privilege: "User Administrators"
      action: member
      state: absent
```


Example playbook to make sure permission "MyPermission" is absent:

```yaml
---
- name: Playbook to manage IPA permission.
  hosts: ipaserver
  become: yes

  tasks:
  - ipapermission:
      ipaadmin_password: SomeADMINpassword
      name: MyPermission
      state: absent
```

Example playbook to make sure permission "MyPermission" is renamed to "MyNewPermission":

```yaml
---
- name: Playbook to manage IPA permission.
  hosts: ipaserver
  become: yes

  tasks:
  - ipapermission:
      ipaadmin_password: SomeADMINpassword
      name: MyPermission
      rename: MyNewPermission
      state: renamed
```




Variables
---------

ipapermission
-------

Variable | Description | Required
-------- | ----------- | --------
`ipaadmin_principal` | The admin principal is a string and defaults to `admin` | no
`ipaadmin_password` | The admin password is a string and is required if there is no admin ticket available on the node | no
`name` \| `cn` | The permission name string. | yes
`right` \| `ipapermright` | Rights to grant. It can be a list of one or more of `read`, `search`, `compare`, `write`, `add`, `delete`, and `all` default: `all` | no
`attrs` | All attributes to which the permission applies | no
`bindtype` \| `ipapermbindruletype` | Bind rule type. It can be one of `permission`, `all`, `self`, or `anonymous` defaults to `permission` for new permissions.| no
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
`rename` | Rename the permission object | no
`privilege` | Member Privilege of Permission | no
`action` | Work on permission or member level. It can be on of `member` or `permission` and defaults to `permission`. | no
`state` | The state to ensure. It can be one of `present`, `absent`, or `renamed` default: `present`. | no

Authors
=======

Seth Kress

Automember module
===========

Description
-----------

The automember module allows to ensure presence or absence of automember rules and manage automember rule conditions.

Features
--------

* Automember management


Supported FreeIPA Versions
--------------------------

FreeIPA versions 4.4.0 and up are supported by the ipaautomember module.


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

Example playbook to make sure group automember rule is present with no conditions.

```yaml
---
- name: Playbook to ensure a group automember rule is present with no conditions
  hosts: ipaserver
  become: yes
  gather_facts: no
  tasks:
    - ipaautomember:
        ipaadmin_password: SomeADMINpassword
        name: admins
        description: "my automember rule"
        automember_type: group
```

Example playbook to make sure group automember rule is present with conditions:

```yaml
---
- name: Playbook to add a group automember rule with two conditions
  hosts: ipaserver
  become: yes
  gather_facts: no
  tasks:
  - ipaautomember:
      ipaadmin_password: SomeADMINpassword
      name: admins
      description: "my automember rule"
      automember_type: group
      inclusive:
        - key: mail
          expression: '@example.com$'
      exclusive:
        - key: uid
          expression: "1234"
```

Example playbook to delete a group automember rule:

```yaml
- name: Playbook to delete a group automember rule
  hosts: ipaserver
  become: yes
  gather_facts: no
  tasks:
    - ipaautomember:
        ipaadmin_password: SomeADMINpassword
        name: admins
        description: "my automember rule"
        automember_type: group
        state: absent
```

Example playbook to add an inclusive condition to an existing rule

```yaml
- name: Playbook to add an inclusive condition to an existing rule
  hosts: ipaserver
  become: yes
  gather_facts: no
  tasks:
    - ipaautomember:
        ipaadmin_password: SomeADMINpassword
        name: "My domain hosts"
        description: "my automember condition"
        automember_tye: hostgroup
        action: member
        inclusive:
          - key: fqdn
            expression: ".*.mydomain.com"
```


Variables
---------

ipaautomember
-------

Variable | Description | Required
-------- | ----------- | --------
`ipaadmin_principal` | The admin principal is a string and defaults to `admin` | no
`ipaadmin_password` | The admin password is a string and is required if there is no admin ticket available on the node | no
`name` \| `cn` | Automember rule. | yes
`description` | A description of this auto member rule. | no
`automember_type` | Grouping to which the rule applies. It can be one of `group`, `hostgroup`. | yes
`inclusive` | List of dictionaries in the format of `{'key': attribute, 'expression': inclusive_regex}` | no
`exclusive` | List of dictionaries in the format of `{'key': attribute, 'expression': exclusive_regex}` | no
`action` | Work on automember or member level. It can be one of `member` or `automember` and defaults to `automember`. | no
`state` | The state to ensure. It can be one of `present`, `absent`, default: `present`. | no


Authors
=======

Mark Hahl

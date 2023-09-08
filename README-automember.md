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
        automember_type: hostgroup
        action: member
        inclusive:
          - key: fqdn
            expression: ".*.mydomain.com"
```

Example playbook to ensure group membership for all users has been rebuilt

```yaml
- name: Playbook to ensure group membership for all users has been rebuilt
  hosts: ipaserver
  become: yes
  gather_facts: no
  tasks:
    - ipaautomember:
        ipaadmin_password: SomeADMINpassword
        automember_type: group
        state: rebuilt
```

Example playbook to ensure group membership for given users has been rebuilt


```yaml
- name: Playbook to ensure group membership for given users has been rebuilt
  hosts: ipaserver
  become: yes
  gather_facts: no
  tasks:
    - ipaautomember:
        ipaadmin_password: SomeADMINpassword
        users:
        - user1
        - user2
        state: rebuilt
```

Example playbook to ensure hostgroup membership for all hosts has been rebuilt

```yaml
- name: Playbook to ensure hostgroup membership for all hosts has been rebuilt
  hosts: ipaserver
  become: yes
  gather_facts: no
  tasks:
    - ipaautomember:
        ipaadmin_password: SomeADMINpassword
        automember_type: hostgroup
        state: rebuilt
```

Example playbook to ensure hostgroup membership for given hosts has been rebuilt

```yaml
- name: Playbook to ensure hostgroup membership for given hosts has been rebuilt
  hosts: ipaserver
  become: yes
  gather_facts: no
  tasks:
    - ipaautomember:
        ipaadmin_password: SomeADMINpassword
        hosts:
        - host1.mydomain.com
        - host2.mydomain.com
        state: rebuilt
```

Example playbook to ensure default group fallback_group for all unmatched group entries is set

```yaml
- name: Playbook to ensure default group fallback_group for all unmatched group entries is set
  hosts: ipaserver
  become: yes
  gather_facts: no
  tasks:
    - ipaautomember:
        ipaadmin_password: SomeADMINpassword
        automember_type: group
        default_group: fallback_group
```

Example playbook to ensure default group for all unmatched group entries is not set

```yaml
- name: Playbook to ensure default group for all unmatched group entries is not set
  hosts: ipaserver
  become: yes
  gather_facts: no
  tasks:
    - ipaautomember:
        ipaadmin_password: SomeADMINpassword
        default_group: ""
        automember_type: group
        state: absent
```

Example playbook to ensure default hostgroup fallback_hostgroup for all unmatched group entries

```yaml
- name: Playbook to ensure default hostgroup fallback_hostgroup for all unmatched group entries
  hosts: ipaserver
  become: yes
  gather_facts: no
  tasks:
    - ipaautomember:
        ipaadmin_password: SomeADMINpassword
        automember_type: hostgroup
        default_group: fallback_hostgroup
```

Example playbook to ensure default hostgroup for all unmatched group entries is not set

```yaml
- name: Playbook to ensure default hostgroup for all unmatched group entries is not set
  hosts: ipaserver
  become: yes
  gather_facts: no
  tasks:
    - ipaautomember:
        ipaadmin_password: SomeADMINpassword
        automember_type: hostgroup
        default_group: ""
        state: absent
```

Example playbook to ensure all orphan automember group rules are removed:

```yaml
- name: Playbook to ensure all orphan automember group rules are removed
  hosts: ipaserver
  become: yes
  gather_facts: no
  tasks:
    - ipaautomember:
        ipaadmin_password: SomeADMINpassword
        automember_type: group
        state: orphans_removed
```

Example playbook to ensure all orphan automember hostgroup rules are removed:

```yaml
- name: Playbook to ensure all orphan automember hostgroup rules are removed
  hosts: ipaserver
  become: yes
  gather_facts: no
  tasks:
    - ipaautomember:
        ipaadmin_password: SomeADMINpassword
        automember_type: hostgroup
        state: orphans_removed
```


Variables
---------

Variable | Description | Required
-------- | ----------- | --------
`ipaadmin_principal` | The admin principal is a string and defaults to `admin` | no
`ipaadmin_password` | The admin password is a string and is required if there is no admin ticket available on the node | no
`ipaapi_context` | The context in which the module will execute. Executing in a server context is preferred. If not provided context will be determined by the execution environment. Valid values are `server` and `client`. | no
`ipaapi_ldap_cache` | Use LDAP cache for IPA connection. The bool setting defaults to yes. (bool) | no
`name` \| `cn` | Automember rule. | yes
`description` | A description of this auto member rule. | no
`automember_type` | Grouping to which the rule applies. It can be one of `group`, `hostgroup`. | yes
`inclusive` | List of dictionaries in the format of `{'key': attribute, 'expression': inclusive_regex}` | no
`exclusive` | List of dictionaries in the format of `{'key': attribute, 'expression': exclusive_regex}` | no
`users` | Users to rebuild membership for. | no
`hosts` | Hosts to rebuild membership for. | no
`no_wait` | Don't wait for rebuilding membership. | no
`default_group` | Default (fallback) group for all unmatched entries. Use the empty string "" for ensuring the default group is not set. | no
`action` | Work on automember or member level. It can be one of `member` or `automember` and defaults to `automember`. | no
`state` | The state to ensure. It can be one of `present`, `absent`, 'rebuilt'. 'orphans_removed' default: `present`. | no


Authors
=======

Mark Hahl
Thomas Woerner

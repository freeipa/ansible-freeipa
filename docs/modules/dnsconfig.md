DNSConfig module
============

Description
-----------

The dnsconfig module allows to modify global DNS configuration.


Features
--------
* Global DNS configuration


Supported FreeIPA Versions
--------------------------

FreeIPA versions 4.4.0 and up are supported by the ipadnsconfig module.


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

Example playbook to set global DNS configuration:

```yaml
---
- name: Playbook to handle global DNS configuration
  hosts: ipaserver
  become: true

  tasks:
  # Set dnsconfig.
  - ipadnsconfig:
      forwarders:
        - ip_address: 8.8.4.4
        - ip_address: 2001:4860:4860::8888
          port: 53
      forward_policy: only
      allow_sync_ptr: yes
```

Example playbook to ensure a global forwarder, with a custom port, is absent:

```yaml
---
- name: Playbook to handle global DNS configuration
  hosts: ipaserver
  become: true

  tasks:
  # Ensure global forwarder with a custom port is absent.
  - ipadnsconfig:
      forwarders:
          - ip_address: 2001:4860:4860::8888
            port: 53
      state: absent
```

Example playbook to disable global forwarders:

```yaml
---
- name: Playbook to disable global DNS forwarders
  hosts: ipaserver
  become: true

  tasks:
  # Disable global forwarders.
  - ipadnsconfig:
      forward_policy: none
```

Example playbook to change global forward policy:

```yaml
---
- name: Playbook to change global forward policy
  hosts: ipaserver
  become: true

  tasks:
  # Disable global forwarders.
  - ipadnsconfig:
      forward_policy: first
```

Example playbook to disallow synchronization of forward (A, AAAA) and reverse (PTR) records:

```yaml
---
- name: Playbook to disallow reverse synchronization.
  hosts: ipaserver
  become: true

  tasks:
  # Disable global forwarders.
  - ipadnsconfig:
      allow_sync_ptr: no
```

Variables
=========

ipadnsconfig
------------

Variable | Description | Required
-------- | ----------- | --------
`ipaadmin_principal` | The admin principal is a string and defaults to `admin` | no
`ipaadmin_password` | The admin password is a string and is required if there is no admin ticket available on the node | no
`forwarders` | The list of forwarders dicts. Each `forwarders` dict entry has:| no
&nbsp; | `ip_address` - The IPv4 or IPv6 address of the DNS server. | yes
&nbsp; | `port` - The custom port that should be used on this server. | no
`forward_policy` | The global forwarding policy. It can be one of `only`, `first`, or `none`.  | no
`allow_sync_ptr` | Allow synchronization of forward (A, AAAA) and reverse (PTR) records (bool). | yes
`state` | The state to ensure. It can be one of `present` or `absent`, default: `present`. | yes


Authors
=======

Rafael Guterres Jeffman

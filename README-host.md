Host module
===========

Description
-----------

The host module allows to ensure presence, absence and disablement of hosts.

The host module is as compatible as possible to the Ansible upstream `ipa_host` module, but additionally offers to disable hosts.


Features
--------
* Host management


Supported FreeIPA Versions
--------------------------

FreeIPA versions 4.4.0 and up are supported by the ipahost module.


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


Example playbook to add hosts:

```yaml
---
- name: Playbook to handle hosts
  hosts: ipaserver
  become: true

  tasks:
  # Ensure host is present
  - ipahost:
      ipaadmin_password: MyPassword123
      name: host01.example.com
      description: Example host
      ip_address: 192.168.0.123
      locality: Lab
      ns_host_location: Lab
      ns_os_version: CentOS 7
      ns_hardware_platform: Lenovo T61
      mac_address:
      - "08:00:27:E3:B1:2D"
      - "52:54:00:BD:97:1E"
      state: present
```


Example playbook to create host without DNS:

```yaml
---
- name: Playbook to handle hosts
  hosts: ipaserver
  become: true

  tasks:
  # Ensure host is present without DNS
  - ipahost:
      ipaadmin_password: MyPassword123
      name: host02.example.com
      description: Example host
      force: yes
```


Example playbook to initiate the generation of a random password to be used in bulk enrollment:

```yaml
---
- name: Playbook to handle hosts
  hosts: ipaserver
  become: true

  tasks:
  # Generate a random password for bulk enrollment
  - ipahost:
      ipaadmin_password: MyPassword123
      name: host01.example.com
      description: Example host
      ip_address: 192.168.0.123
      random: yes
```


Example playbook to disable a host:

```yaml
---
- name: Playbook to handle hosts
  hosts: ipaserver
  become: true

  tasks:
  # Ensure host is disabled
  - ipahost:
      ipaadmin_password: MyPassword123
      name: host01.example.com
      update_dns: yes
      state: disabled
```
`update_dns` controls if the DNS entries will be updated.


Example playbook to ensure a host is absent:

```yaml
---
- name: Playbook to handle hosts
  hosts: ipaserver
  become: true

  tasks:
  # Ensure host is absent
  - ipahost:
      ipaadmin_password: password1
      name: host01.example.com
      state: absent
```


Variables
=========

ipahost
-------

Variable | Description | Required
-------- | ----------- | --------
`ipaadmin_principal` | The admin principal is a string and defaults to `admin` | no
`ipaadmin_password` | The admin password is a string and is required if there is no admin ticket available on the node | no
`name` \| `fqdn` | The list of host name strings. | yes
`description` | The host description. | no
`locality` | Host locality (e.g. "Baltimore, MD"). | no
`location` \| `ns_host_location` | Host location (e.g. "Lab 2"). | no
`platform` \| `ns_hardware_platform` | Host hardware platform (e.g. "Lenovo T61"). | no
`os` \| `ns_os_version` | Host operating system and version (e.g. "Fedora 9"). | no
`password` \| `user_password` \| `userpassword` | Password used in bulk enrollment. | no
`random` \| `random_password` |  Initiate the generation of a random password to be used in bulk enrollment. | no
`mac_address` \| `macaddress` | List of hardware MAC addresses. | no
`force` | Force host name even if not in DNS. | no
`reverse` | Reverse DNS detection. | no
`ip_address` \| `ipaddress` | The host IP address. | no
`update_dns` | Update DNS entries. | no
`update_password` |  Set password for a host in present state only on creation or always. It can be one of `always` or `on_create` and defaults to `always`. | no
`state` | The state to ensure. It can be one of `present`, `absent` or `disabled`, default: `present`. | yes


Authors
=======

Thomas Woerner

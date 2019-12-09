Dnsforwardzone module
=====================

Description
-----------

The dnsforwardzone module allows the addition and removal of dns forwarders from the IPA DNS config.

It is desgined to follow the IPA api as closely as possible while ensuring ease of use.


Features
--------
* DNS zone management

Supported FreeIPA Versions
--------------------------

FreeIPA versions 4.4.0 and up are supported by the ipadnsforwardzone module.

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


Example playbook to ensure presence of a forwardzone to ipa DNS:

```yaml
---
- name: Playbook to handle add a forwarder
  hosts: ipaserver
  become: true

  tasks:
  - name: ensure presence of forwardzone for DNS requests for example.com to 8.8.8.8
    ipadnsforwardzone:
      ipaadmin_password: password01
      state: present
      name: example.com
      forwarders:
        - 8.8.8.8
      forwardpolicy: first
      skip_overlap_check: true

  - name: ensure the forward zone is disabled
    ipadnsforwardzone:
      ipaadmin_password: password01
      name: example.com
      state: disabled

  - name: ensure presence of multiple upstream DNS servers for example.com
    ipadnsforwardzone:
      ipaadmin_password: password01
      state: present
      name: example.com
      forwarders:
        - 8.8.8.8
        - 4.4.4.4

  - name: ensure presence of another forwarder to any existing ones for example.com
    ipadnsforwardzone:
      ipaadmin_password: password01
      state: present
      name: example.com
      forwarders:
        - 1.1.1.1
      action: member

  - name: ensure the forwarder for example.com does not exists (delete it if needed)
    ipadnsforwardzone:
      ipaadmin_password: password01
      name: example.com
      state: absent
```

Variables
=========

ipagroup
-------

Variable | Description | Required
-------- | ----------- | --------
`ipaadmin_principal` | The admin principal is a string and defaults to `admin` | no
`ipaadmin_password` | The admin password is a string and is required if there is no admin ticket available on the node | no
`name` \| `cn` | Zone name (FQDN). | yes if `state` == `present`
`forwarders` \| `idnsforwarders` |  Per-zone conditional forwarding policy. Possible values are `only`, `first`, `none`) | no
`forwardpolicy` \| `idnsforwardpolicy` | Per-zone conditional forwarding policy. Set to "none" to disable forwarding to global forwarder for this zone. In that case, conditional zone forwarders are disregarded. | no
`skip_overlap_check` | Force DNS zone creation even if it will overlap with an existing zone. Defaults to False. | no
`action` | Work on group or member level. It can be on of `member` or `dnsforwardzone` and defaults to `dnsforwardzone`. | no
`state` | The state to ensure. It can be one of `present`, `absent`, `enabled` or `disabled`, default: `present`. | yes


Authors
=======

Chris Procter

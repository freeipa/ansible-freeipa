DNSZone Module
==============

Description
-----------

The dnszone module allows to configure zones in DNS server.


Features
--------

* Add, remove, modify, enable or disable DNS zones.


Supported FreeIPA Versions
--------------------------

FreeIPA versions 4.4.0 and up are supported by ipadnszone module.


Requirements
------------

**Controller**
* Ansible version: 2.13+


**Node**
* Supported FreeIPA version (see above)


Usage
-----


```ini
[ipaserver]
ipaserver.test.local
```

Example playbook to create a simple DNS zone:

```yaml

---
- name: dnszone present
  hosts: ipaserver
  become: true

  tasks:
  - name: Ensure zone is present.
    ipadnszone:
      ipaadmin_password: SomeADMINpassword
      name: testzone.local
      state: present

```


Example playbook to create a DNS zone with all currently supported variables:
```yaml

---
- name: dnszone present
  hosts: ipaserver
  become: true

  tasks:
  - name: Ensure zone is present.
    ipadnszone:
      ipaadmin_password: SomeADMINpassword
      name: testzone.local
      allow_sync_ptr: true
      dynamic_update: true
      dnssec: true
      allow_transfer:
        - 1.1.1.1
        - 2.2.2.2
      allow_query:
        - 1.1.1.1
        - 2.2.2.2
      forwarders:
        - ip_address: 8.8.8.8
        - ip_address: 8.8.4.4
          port: 52
      refresh: 3600
      retry: 900
      expire: 1209600
      minimum: 3600
      ttl: 60
      default_ttl: 90
      name_server: ipaserver.test.local.
      admin_email: admin.admin@example.com
      nsec3param_rec: "1 7 100 0123456789abcdef"
      skip_overlap_check: true
      skip_nameserver_check: true
      state: present
```


Example playbook to disable a zone:

```yaml

---
- name: Playbook to disable DNS zone
  hosts: ipaserver
  become: true

  tasks:
  - name: Disable zone.
    ipadnszone:
      ipaadmin_password: SomeADMINpassword
      name: testzone.local
      state: disabled
```


Example playbook to enable a zone:
```yaml

---
- name: Playbook to enable DNS zone
  hosts: ipaserver
  become: true

  tasks:
  - name: Enable zone.
    ipadnszone:
      ipaadmin_password: SomeADMINpassword
      name: testzone.local
      state: enabled
```

Example playbook to allow per-zone privilege delegation:

```yaml
---
- name: Playbook to enable per-zone privilege delegation
  hosts: ipaserver
  become: true

  tasks:
  - name: Enable privilege delegation.
    ipadnszone:
      ipaadmin_password: SomeADMINpassword
      name: testzone.local
      permission: true
```


Example playbook to remove a zone:
```yaml

---
- name: Playbook to remove DNS zone
  hosts: ipaserver
  become: true

  tasks:
  - name: Remove zone.
    ipadnszone:
      ipaadmin_password: SomeADMINpassword
      name: testzone.local
      state: absent

```

Example playbook to create a zone for reverse DNS lookup, from an IP address:

```yaml

---
- name: dnszone present
  hosts: ipaserver
  become: true

  tasks:
  - name: Ensure zone for reverse DNS lookup is present.
    ipadnszone:
      ipaadmin_password: SomeADMINpassword
      name_from_ip: 192.168.1.2
      state: present
```

Note that, on the previous example the zone created with `name_from_ip` might be "1.168.192.in-addr.arpa.", "168.192.in-addr.arpa.", or "192.in-addr.arpa.", depending on the DNS response the system get while querying for zones, and for this reason, when creating a zone using `name_from_ip`, the inferred zone name is returned to the controller, in the attribute `dnszone.name`. Since the zone inferred might not be what a user expects, `name_from_ip` can only be used with `state: present`. To have more control over the zone name, the prefix length for the IP address can be provided.

Example playbook to create a zone for reverse DNS lookup, from an IP address, given the prefix length and displaying the resulting zone name:

```yaml

---
- name: dnszone present
  hosts: ipaserver
  become: true

  tasks:
  - name: Ensure zone for reverse DNS lookup is present.
    ipadnszone:
      ipaadmin_password: SomeADMINpassword
      name_from_ip: 192.168.1.2/24
      state: present
    register: result
  - name: Display inferred zone name.
    debug:
      msg: "Zone name: {{ result.dnszone.name }}"
```


Variables
=========

Variable | Description | Required
-------- | ----------- | --------
`ipaadmin_principal` | The admin principal is a string and defaults to `admin` | no
`ipaadmin_password` | The admin password is a string and is required if there is no admin ticket available on the node | no
`ipaapi_context` | The context in which the module will execute. Executing in a server context is preferred. If not provided context will be determined by the execution environment. Valid values are `server` and `client`. | no
`ipaapi_ldap_cache` | Use LDAP cache for IPA connection. The bool setting defaults to yes. (bool) | no
`name` \| `zone_name` | The zone name string or list of strings. | no
`name_from_ip` | Derive zone name from reverse of IP (PTR). Can only be used with `state: present`. | no
`forwarders` | The list of forwarders dicts. Each `forwarders` dict entry has:| no
&nbsp; | `ip_address` - The IPv4 or IPv6 address of the DNS server. | yes
&nbsp; | `port` - The custom port that should be used on this server. | no
`forward_policy` | The global forwarding policy. It can be one of `only`, `first`, or `none`.  | no
`allow_sync_ptr` | Allow synchronization of forward (A, AAAA) and reverse (PTR) records (bool). | no
`state` | The state to ensure. It can be one of `present`, `enabled`, `disabled` or `absent`, default: `present`. | yes
`name_server`| Authoritative nameserver domain name | no
`admin_email`| Administrator e-mail address | no
`update_policy`| BIND update policy | no
`dynamic_update` \| `dynamicupdate` | Allow dynamic updates | no
`dnssec`| Allow inline DNSSEC signing of records in the zone | no
`allow_transfer`| List of IP addresses or networks which are allowed to transfer the zone | no
`allow_query`| List of IP addresses or networks which are allowed to issue queries | no
`refresh`| SOA record refresh time | no
`retry`| SOA record retry time | no
`expire`| SOA record expire time | no
`minimum`| How long should negative responses be cached | no
`ttl`| Time to live for records at zone apex | no
`default_ttl`| Time to live for records without explicit TTL definition | no
`nsec3param_rec`| NSEC3PARAM record for zone in format: hash_algorithm flags iterations salt | no
`permission` \| `managedby` | Set per-zone access delegation permission. | no
`skip_overlap_check`| Force DNS zone creation even if it will overlap with an existing zone | no
`skip_nameserver_check` | Force DNS zone creation even if nameserver is not resolvable | no


Return Values
=============

Variable | Description | Returned When
-------- | ----------- | -------------
`dnszone` | DNS Zone dict with zone name infered from `name_from_ip`. <br>Options: |  If `state` is `present`, `name_from_ip` is used, and a zone was created.
&nbsp; | `name` - The name of the zone created, inferred from `name_from_ip`. | Always

Authors
=======

- Sergio Oliveira Campos
- Thomas Woerner
- Rafael Jeffman

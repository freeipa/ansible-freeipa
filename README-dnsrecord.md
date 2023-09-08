DNSRecord module
================

Description
-----------

The dnsrecord module allows management of DNS records and is as compatible as possible with the Ansible upstream `ipa_dnsrecord` module, but provide some other features like multiple record management in one execution and support for more DNS record types.


Features
--------
* DNS record management.


Supported FreeIPA Versions
--------------------------

FreeIPA versions 4.4.0 and up are supported by the ipadnsrecord module.


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
ipaserver.example.com
```

Example playbook to ensure an AAAA record is present:

```yaml
---
- ipadnsrecord:
    ipaadmin_password: SomeADMINpassword
    name: host01
    zone_name: example.com
    record_type: 'AAAA'
    record_value: '::1'
```

Example playbook to ensure an AAAA record is present, with a TTL of 300:

```yaml
---
- ipadnsrecord:
    ipaadmin_password: SomeADMINpassword
    name: host01
    zone_name: example.com
    record_type: 'AAAA'
    record_value: '::1'
    record_ttl: 300
```

Example playbook to ensure an AAAA record is present, with a reverse PTR record:
```yaml
---
- ipadnsrecord:
    ipaadmin_password: SomeADMINpassword
    name: host02
    zone_name: example.com
    record_type: 'AAAA'
    record_value: 'fd00::0002'
    create_reverse: yes
```

Example playbook to ensure a LOC record is present, given its individual attributes:
```yaml
---
- ipadnsrecord:
    ipaadmin_password: SomeADMINpassword
    zone_name: example.com
    name: host03
    loc_lat_deg: 52
    loc_lat_min: 22
    loc_lat_sec: 23.000
    loc_lat_dir: N
    loc_lon_deg: 4
    loc_lon_min: 53
    loc_lon_sec: 32.00
    loc_lon_dir: E
    loc_altitude: -2.00
    loc_size: 1.00
    loc_h_precision: 10000
    loc_v_precision: 10
```

Example playbook to ensure multiple DNS records are present:

```yaml
---
ipadnsrecord:
  ipaadmin_password: SomeADMINpassword
  records:
    - name: host02
      zone_name: example.com
      record_type: A
      record_value:
        - "{{ ipv4_prefix }}.112"
        - "{{ ipv4_prefix }}.122"
    - name: host02
      zone_name: example.com
      record_type: AAAA
      record_value: ::1
```

Example playbook to ensure multiple CNAME records are present:

```yaml
---
- name: Ensure that 'host03' and 'host04' have CNAME records.
  ipadnsrecord:
    ipaadmin_password: SomeADMINpassword
    zone_name: example.com
    records:
    - name: host03
      cname_hostname: host03.example.com
    - name: host04
      cname_hostname: host04.example.com
```

Example playbook to ensure NS record is absent:

```yaml
---
- ipadnsrecord:
    ipaadmin_password: SomeADMINpassword
    zone_name: example.com
    name: host04
    ns_hostname: host04
    state: absent
```

Example playbook to ensure LOC record is present, with fields:

```yaml
---
- ipadnsrecord:
    ipaadmin_password: SomeADMINpassword
    zone_name: example.com
    name: host04
    loc_lat_deg: 52
    loc_lat_min: 22
    loc_lat_sec: 23.000
    loc_lat_dir: N
    loc_lon_deg: 4
    loc_lon_min: 53
    loc_lon_sec: 32.000
    loc_lon_dir: E
    loc_altitude: -2.00
    loc_size: 0.00
    loc_h_precision: 10000
    loc_v_precision: 10
```

Change value of an existing LOC record:

```yaml
---
- ipadnsrecord:
  ipaadmin_password: SomeADMINpassword
  zone_name: example.com
  name: host04
  loc_size: 1.00
  loc_rec: 52 22 23 N 4 53 32 E -2 0 10000 10
```

Example playbook to ensure multiple A records are present:

```yaml
- ipadnsrecord:
    ipaadmin_password: SomeADMINpassword
    zone_name: example.com
    name: host04
    a_rec:
      - 192.168.122.221
      - 192.168.122.222
      - 192.168.122.223
      - 192.168.122.224
```

Example playbook to ensure A and AAAA records are present, with reverse records (PTR):
```yaml
- ipadnsrecord:
    ipaadmin_password: SomeADMINpassword
    zone_name: example.com
    name: host01
    a_rec:
      - 192.168.122.221
      - 192.168.122.222
    aaaa_rec:
      - fd00:;0001
      - fd00::0002
    create_reverse: yes
```

Example playbook to ensure multiple A and AAAA records are present, but only A records have reverse records:
```yaml
- ipadnsrecord:
    ipaadmin_password: SomeADMINpassword
    zone_name: example.com
    name: host01
    a_ip_address: 192.168.122.221
    aaaa_ip_address: fd00::0001
    a_create_reverse: yes
```

Example playbook to ensure multiple DNS records are absent:

```yaml
---
- ipadnsrecord:
    ipaadmin_password: SomeADMINpassword
    zone_name: example.com
    records:
    - name: host01
      del_all: yes
    - name: host02
      del_all: yes
    - name: host03
      del_all: yes
    - name: host04
      del_all: yes
    - name: _ftp._tcp
      del_all: yes
    - name: _sip._udp
      del_all: yes
    state: absent
```

Variables
=========

Variable | Description | Required
-------- | ----------- | --------
`ipaadmin_principal` | The admin principal is a string and defaults to `admin` | no
`ipaadmin_password` | The admin password is a string and is required if there is no admin ticket available on the node | no
`ipaapi_context` | The context in which the module will execute. Executing in a server context is preferred. If not provided context will be determined by the execution environment. Valid values are `server` and `client`. | no
`ipaapi_ldap_cache` | Use LDAP cache for IPA connection. The bool setting defaults to yes. (bool) | no
`zone_name` \| `dnszone` | The DNS zone name to which DNS record needs to be managed. You can use one global zone name for multiple records. | no
  required: true
`records` | The list of dns records dicts. Each `records` dict entry can contain **record variables**. | no
&nbsp; | **Record variables** | no
**Record variables** | Used when defining a single record. | no
`state` | The state to ensure. It can be one of `present` or `absent`, and defaults to `present`. | yes


**Record Variables:**

Variable | Description | Required
-------- | ----------- | --------
`zone_name` \| `dnszone` | The DNS zone name to which DNS record needs to be managed. You can use one global zone name for multiple records. When used on a `records` dict, overrides the global `zone_name`. | yes
`name` \| `record_name` | The DNS record name to manage. | yes
`record_type` | The type of DNS record. Supported values are  `A`, `AAAA`, `A6`, `AFSDB`, `CERT`, `CNAME`, `DLV`, `DNAME`, `DS`, `KX`, `LOC`, `MX`, `NAPTR`, `NS`, `PTR`, `SRV`, `SSHFP`, `TLSA`, `TXT`, `URI`, and defaults to `A`. | no
`record_value` | Manage DNS record name with this values. | no
`record_ttl` | Set the TTL for the record. (int) | no
`del_all` | Delete all associated records. (bool) | no
`a_rec` \| `a_record` | Raw A record. | no
`aaaa_rec` \| `aaaa_record` |  Raw AAAA record. | no
`a6_rec` \| `a6_record` | Raw A6 record data. | no
`afsdb_rec` \| `afsdb_record` | Raw AFSDB record. | no
`cert_rec` \| `cert_record` | Raw CERT record. | no
`cname_rec` \| `cname_record` | Raw CNAME record. | no
`dlv_rec` \| `dlv_record` |  Raw DLV record. | no
`dname_rec` \| `dname_record` | Raw DNAM record. | no
`ds_rec` \| `ds_record` | Raw DS record. | no
`kx_rec` \| `kx_record` |  Raw KX record. | no
`loc_rec` \| `loc_record` | Raw LOC record. | no
`mx_rec` \| `mx_record` | Raw MX record. | no
`naptr_rec` \| `naptr_record` | Raw NAPTR record. | no
`ns_rec` \| `ns_record` | Raw NS record. | no
`ptr_rec` \| `ptr_record` | Raw PTR record. | no
`srv_rec` \| `srv_record` | Raw SRV record. | no
`sshfp_rec` \| `sshfp_record` | Raw SSHFP record. | no
`tlsa_rec` \| `tlsa_record` | Raw TLSA record. | no
`txt_rec` \| `txt_record` | Raw TXT record. | no
`uri_rec` \| `uri_record` | Raw URI record. | no
`ip_address` | IP adress for A or AAAA records. Set `record_type` to `A` or `AAAA`. | no
`create_reverse` \| `reverse` | Create reverse records for `A` and `AAAA` record types. There is no equivalent to remove reverse records. (bool) | no
`a_ip_address` | IP adress for A records. Set `record_type` to `A`. | no
`a_create_reverse` | Create reverse records only for `A` records. There is no equivalent to remove reverse records. (bool) | no
`aaaa_ip_address` | IP adress for AAAA records. Set `record_type` `AAAA`. | no
`aaaa_create_reverse` | Create reverse records only for `AAAA` record types. There is no equivalent to remove reverse records. (bool) | no
`a6_data` | A6 record. Set `record_type` to `A6`. | no
`afsdb_subtype` | AFSDB Subtype. Set `record_type` to `AFSDB`. (int) | no
`afsdb_hostname` | AFSDB Hostname. Set `record_type` to `AFSDB`. | no
`cert_type` | CERT Certificate Type. Set `record_type` to `CERT`. (int) | no
`cert_key_tag` | CERT Key Tag. Set `record_type` to `CERT`. (int) | no
`cert_algorithm` | CERT Algorithm. Set `record_type` to `CERT`. (int) | no
`cert_certificate_or_crl` | CERT Certificate or  Certificate Revocation List (CRL). Set `record_type` to `CERT`. | no
`cname_hostname` | A hostname which this alias hostname points to. Set `record_type` to `CNAME`. | no
`dlv_key_tag` | DS Key Tag. Set `record_type` to `DLV`. (int) | no
`dlv_algorithm` | DLV Algorithm. Set `record_type` to `DLV`. (int) | no
`dlv_digest_type` | DLV Digest Type. Set `record_type` to `DLV`. (int) | no
`dlv_digest` | DLV Digest. Set `record_type` to `DLV`. | no
`dname_target` | DNAME Target. Set `record_type` to `DNAME`. | no
`ds_key_tag` | DS Key Tag. Set `record_type` to `DS`. (int) | no
`ds_algorithm` | DS Algorithm. Set `record_type` to `DS`. (int) | no
`ds_digest_type` | DS Digest Type. Set `record_type` to `DS`. (int) | no
`ds_digest` | DS Digest. Set `record_type` to `DS`. | no
`kx_preference` | Preference given to this exchanger. Lower values are more preferred. Set `record_type` to `KX`. (int) | no
`kx_exchanger` | A host willing to act as a key exchanger.  Set `record_type` to `KX`. | no
`loc_lat_deg` | LOC Degrees Latitude. Set `record_type` to `LOC`. (int) | no
`loc_lat_min` | LOC Minutes Latitude. Set `record_type` to `LOC`. (int) | no
`loc_lat_sec` | LOC Seconds Latitude. Set `record_type` to `LOC`. (float) | no
`loc_lat_dir` | LOC Direction Latitude. Valid values are `N` or `S`. Set `record_type` to `LOC`. (int) | no
`loc_lon_deg` | LOC Degrees Longitude. Set `record_type` to `LOC`. (int) | no
`loc_lon_min` | LOC Minutes Longitude. Set `record_type` to `LOC`. (int) | no
`loc_lon_sec` | LOC Seconds Longitude. Set `record_type` to `LOC`. (float) | no
`loc_lon_dir` | LOC Direction Longitude. Valid values are `E` or `W`. Set `record_type` to `LOC`. (int) | no
`loc_altitude` | LOC Altitude. Set `record_type` to `LOC`. (float) | no
`loc_size` | LOC Size. Set `record_type` to `LOC`. (float) | no
`loc_h_precision` | LOC Horizontal Precision. Set `record_type` to `LOC`. (float) | no
`loc_v_precision` | LOC Vertical Precision. Set `record_type` to `LOC`. (float) | no
`mx_preference` | Preference given to this exchanger. Lower values are more preferred. Set `record_type` to `MX`. (int) | no
`mx_exchanger` | A host willing to act as a mail exchanger.  Set `record_type` to `LOC`. | no
`naptr_order` | NAPTR Order. Set `record_type` to `NAPTR`. (int) | no
`naptr_preference` | NAPTR Preference. Set `record_type` to `NAPTR`. (int) | no
`naptr_flags` | NAPTR Flags. Set `record_type` to `NAPTR`. | no
`naptr_service` | NAPTR Service. Set `record_type` to `NAPTR`. | no
`naptr_regexp` | NAPTR Regular Expression. Set `record_type` to `NAPTR`. | no
`naptr_replacement` | NAPTR Replacement. Set `record_type` to `NAPTR`. | no
`ns_hostname` | NS Hostname. Set `record_type` to `NS`. | no
`ptr_hostname` | The hostname this reverse record points to. . Set `record_type` to `PTR`. | no
`srv_priority` | Lower number means higher priority. Clients will attempt to contact the server with the lowest-numbered priority they can reach. Set `record_type` to `SRV`. (int) | no
`srv_weight` | Relative weight for entries with the same priority. Set `record_type` to `SRV`. (int) | no
`srv_port` | SRV Port. Set `record_type` to `SRV`. (int) | no
`srv_target` | The domain name of the target host or '.' if the service is decidedly not available at this domain. Set `record_type` to `SRV`. | no
`sshfp_algorithm` | SSHFP Algorithm. Set `record_type` to `SSHFP`. (int) | no
`sshfp_fp_type` | SSHFP Fingerprint Type. Set `record_type` to `SSHFP`. (int) | no
`sshfp_fingerprint`| SSHFP Fingerprint. Set `record_type` to `SSHFP`. (int) | no
`txt_data` | TXT Text Data. Set `record_type` to `TXT`. | no
`tlsa_cert_usage` | TLSA Certificate Usage. Set `record_type` to `TLSA`. (int) | no
`tlsa_selector` | TLSA Selector. Set `record_type` to `TLSA`. (int) | no
`tlsa_matching_type` | TLSA Matching Type. Set `record_type` to `TLSA`. (int) | no
`tlsa_cert_association_data` | TLSA Certificate Association Data. Set `record_type` to `TLSA`. | no
`uri_target` | Target Uniform Resource Identifier according to RFC 3986. Set `record_type` to `URI`. | no
`uri_priority` | Lower number means higher priority. Clients will attempt to contact the URI with the lowest-numbered priority they can reach. Set `record_type` to `URI`. (int) | no
`uri_weight` | Relative weight for entries with the same priority. Set `record_type` to `URI`. (int) | no


Authors
=======

Rafael Guterres Jeffman

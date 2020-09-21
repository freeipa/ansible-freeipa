#!/usr/bin/python
# -*- coding: utf-8 -*-

# Authors:
#   Rafael Guterres Jeffman <rjeffman@redhat.com>
#
# Copyright (C) 2020 Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""DNS Record ansible-freeipa module."""

ANSIBLE_METADATA = {
    "metadata_version": "1.0",
    "supported_by": "community",
    "status": ["preview"],
}

DOCUMENTATION = """
---
module: ipadnsrecord
short description: Manage FreeIPA DNS records
description: Manage FreeIPA DNS records
options:
  ipaadmin_principal:
    description: The admin principal
    default: admin
  ipaadmin_password:
    description: The admin password
    required: false
  records:
    description: The list of user dns records dicts
    required: false
    options:
      name:
        description: The DNS record name to manage.
        aliases: ["record_name"]
        required: true
      zone_name:
        description: |
          The DNS zone name to which DNS record needs to be managed.
          Required if not provided globally.
        aliases: ["dnszone"]
        required: false
      record_type:
        description: The type of DNS record.
        choices: ["A", "AAAA", "A6", "AFSDB", "CERT", "CNAME", "DLV", "DNAME",
                  "DS", "KX", "LOC", "MX", "NAPTR", "NS", "PTR", "SRV",
                  "SSHFP", "TLSA", "TXT", "URI"]
        default: "A"
      record_value:
        description: Manage DNS record name with these values.
        required: false
        type: list
      record_ttl:
        description: Set the TTL for the record.
        required: false
        type: int
      del_all:
        description: Delete all associated records.
        required: false
        type: bool
      a_rec:
        description: Raw A record.
        required: false
        aliases: ["a_record"]
      aaaa_rec:
        description: Raw AAAA record.
        required: false
        aliases: ["aaaa_record"]
      a6_rec:
        description: Raw A6 record.
        required: false
        aliases: ["a6_record"]
      afsdb_rec:
        description: Raw AFSDB record.
        required: false
        aliases: ["afsdb_record"]
      cert_rec:
        description: Raw CERT record.
        required: false
        aliases: ["cert_record"]
      cname_rec:
        description: Raw CNAME record.
        required: false
        aliases: ["cname_record"]
      dlv_rec:
        description: Raw DLV record.
        required: false
        aliases: ["dlv_record"]
      dname_rec:
        description: Raw DNAM record.
        required: false
        aliases: ["dname_record"]
      ds_rec:
        description: Raw DS record.
        required: false
        aliases: ["ds_record"]
      kx_rec:
        description: Raw KX record.
        required: false
        aliases: ["kx_record"]
      loc_rec:
        description: Raw LOC record.
        required: false
        aliases: ["loc_record"]
      mx_rec:
        description: Raw MX record.
        required: false
        aliases: ["mx_record"]
      naptr_rec:
        description: Raw NAPTR record.
        required: false
        aliases: ["naptr_record"]
      ns_rec:
        description: Raw NS record.
        required: false
        aliases: ["ns_record"]
      ptr_rec:
        description: Raw PTR record.
        required: false
        aliases: ["ptr_record"]
      srv_rec:
        description: Raw SRV record.
        required: false
        aliases: ["srv_record"]
      sshfp_rec:
        description: Raw SSHFP record.
        required: false
        aliases: ["sshfp_record"]
      tlsa_rec:
        description: Raw TLSA record.
        required: false
        aliases: ["tlsa_record"]
      txt_rec:
        description: Raw TXT record.
        required: false
        aliases: ["txt_record"]
      uri_rec:
        description: Raw URI record.
        required: false
        aliases: ["uri_record"]
      ip_address:
        description: IP adresses for A or AAAA records.
        required: false
        type: string
      a_ip_address:
        description: IP adresses for A records.
        required: false
        type: string
      a_create_reverse:
        description: |
          Create reverse record for A records.
          There is no equivalent to remove reverse records.
        type: bool
        required: false
      aaaa_ip_address:
        description: IP adresses for AAAA records.
        required: false
        type: string
      aaaa_create_reverse:
        description: |
          Create reverse record for AAAA records.
          There is no equivalent to remove reverse records.
        type: bool
        required: false
      create_reverse:
        description: |
          Create reverse record for A or AAAA record types.
          There is no equivalent to remove reverse records.
        type: bool
        required: false
        aliases: ["reverse"]
      a6_data:
        description: A6 record data.
        required: false
      afsdb_subtype:
        description: AFSDB Subtype
        required: false
        type: int
      afsdb_hostname:
        description: AFSDB Hostname
        required: false
        type: string
      cert_type:
        description: CERT Certificate Type
        required: false
        type: int
      cert_key_tag:
        description: CERT Key Tag
        required: false
        type: int
      cert_algorithm:
        description: CERT Algorithm
        required: false
        type: int
      cert_certificate_or_crl:
        description: CERT Certificate or Certificate Revocation List (CRL).
        required: false
        type: string
      cname_hostname:
        description: A hostname which this alias hostname points to.
        required: false
        type: string
      dlv_key_tag:
        description: DS Key Tag
        required: false
        type: int
      dlv_algorithm:
        description: DLV Algorithm
        required: false
        type: int
      dlv_digest_type:
        description: DLV Digest Type
        required: false
        type: int
      dlv_digest:
        description: DLV Digest
        required: false
        type: string
      dname_target:
        description: DNAME Target
        required: false
        type: string
      ds_key_tag:
        description: DS Key Tag
        required: false
        type: int
      ds_algorithm:
        description: DS Algorithm
        required: false
        type: int
      ds_digest_type:
        description: DS Digest Type
        required: false
        type: int
      ds_digest:
        description: DS Digest
        required: false
        type: string
      kx_preference:
        description: |
          Preference given to this exchanger. Lower values are more preferred.
        required: false
        type: int
      kx_exchanger:
        description: A host willing to act as a key exchanger.
        required: false
        type: string
      loc_lat_deg:
        description: LOC Degrees Latitude
        required: false
        type: int
      loc_lat_min:
        description: LOC Minutes Latitude
        required: false
        type: int
      loc_lat_sec:
        description: LOC Seconds Latitude
        required: false
        type: float
      loc_lat_dir:
        description: LOC Direction Latitude
        required: false
        choices: ["N", "S"]
      loc_lon_deg:
        description: LOC Degrees Longitude
        required: false
        type: int
      loc_lon_min:
        description: LOC Minutes Longitude
        required: false
        type: int
      loc_lon_sec:
        description: LOC Seconds Longitude
        required: false
        type: float
      loc_lon_dir:
        description: LOC Direction Longitude
        required: false
        choices: ["E", "W"]
      loc_altitude:
        description: LOC Altitude
        required: false
        type: float
      loc_size:
        description: LOC Size
        required: false
        type: float
      loc_h_precision:
        description: LOC Horizontal Precision
        required: false
        type: float
      loc_v_precision:
        description: LOC Vertical Precision
        required: false
        type: float
      mx_preference:
        description: |
          Preference given to this exchanger. Lower values are more preferred.
        required: false
        type: int
      mx_exchanger:
        description: A host willing to act as a mail exchanger.
        required: false
        type: string
      naptr_order:
        description: NAPTR Order
        required: false
        type: int
      naptr_preference:
        description: NAPTR Preference
        required: false
        type: int
      naptr_flags:
        description: NAPTR Flags
        required: false
        type: string
      naptr_service:
        description: NAPTR Service
        required: false
        type: string
      naptr_regexp:
        description: NAPTR Regular Expression
        required: false
        type: string
      naptr_replacement:
        description: NAPTR Replacement
        required: false
        type: string
      ns_hostname:
        description: NS Hostname
        required: false
        type: string
      ptr_hostname:
        description: The hostname this reverse record points to.
        required: false
        type: string
      srv_priority:
        description: |
          Lower number means higher priority. Clients will attempt to contact
          the server with the lowest-numbered priority they can reach.
        required: false
        type: int
      srv_weight:
        description: Relative weight for entries with the same priority.
        required: false
        type: int
      srv_port:
        description: SRV Port
        required: false
        type: int
      srv_target:
        description: |
          The domain name of the target host or '.' if the service is decidedly
          not available at this domain.
        required: false
        type: string
      sshfp_algorithm:
        description: SSHFP Algorithm
        required: False
        type: int
      sshfp_fp_type:
        description: SSHFP Fingerprint Type
        required: False
        type: int
      sshfp_fingerprint:
        description: SSHFP Fingerprint
        required: False
        type: string
      txt_data:
        description: TXT Text Data
        required: false
        type: string
      tlsa_cert_usage:
        description: TLSA Certificate Usage
        required: false
        type: int
      tlsa_selector:
        description: TLSA Selector
        required: false
        type: int
      tlsa_matching_type:
        description: TLSA Matching Type
        required: false
        type: int
      tlsa_cert_association_data:
        description: TLSA Certificate Association Data
        required: false
        type: string
      uri_target:
        description: Target Uniform Resource Identifier according to RFC 3986.
        required: false
        type: string
      uri_priority:
        description: |
          Lower number means higher priority. Clients will attempt to contact
          the URI with the lowest-numbered priority they can reach.
        required: false
        type: int
      uri_weight:
        description: Relative weight for entries with the same priority.
        required: false
        type: int
  zone_name:
    description: |
      The DNS zone name to which DNS record needs to be managed.
      Required if not provided globally.
    aliases: ["dnszone"]
    required: false
  name:
    description: The DNS record name to manage.
    aliases: ["record_name"]
    required: true
  record_type:
    description: The type of DNS record.
    required: false
    choices: ["A", "AAAA", "A6", "AFSDB", "CERT", "CNAME", "DLV", "DNAME",
              "DS", "KX", "LOC", "MX", "NAPTR", "NS", "PTR", "SRV", "SSHFP",
              "TLSA", "TXT", "URI"]
    default: "A"
  record_value:
    description: Manage DNS record name with this values.
    required: false
    type: list
  record_ttl:
    description: Set the TTL for the record.
    required: false
    type: int
  del_all:
    description: Delete all associated records.
    required: false
    type: bool
  a_rec:
    description: Raw A record.
    required: false
    aliases: ["a_record"]
  aaaa_rec:
    description: Raw AAAA record.
    required: false
    aliases: ["aaaa_record"]
  a6_rec:
    description: Raw A6 record.
    required: false
    aliases: ["a6_record"]
  afsdb_rec:
    description: Raw AFSDB record.
    required: false
    aliases: ["afsdb_record"]
  cert_rec:
    description: Raw CERT record.
    required: false
    aliases: ["cert_record"]
  cname_rec:
    description: Raw CNAME record.
    required: false
    aliases: ["cname_record"]
  dlv_rec:
    description: Raw DLV record.
    required: false
    aliases: ["dlv_record"]
  dname_rec:
    description: Raw DNAM record.
    required: false
    aliases: ["dname_record"]
  ds_rec:
    description: Raw DS record.
    required: false
    aliases: ["ds_record"]
  kx_rec:
    description: Raw KX record.
    required: false
    aliases: ["kx_record"]
  loc_rec:
    description: Raw LOC record.
    required: false
    aliases: ["loc_record"]
  mx_rec:
    description: Raw MX record.
    required: false
    aliases: ["mx_record"]
  naptr_rec:
    description: Raw NAPTR record.
    required: false
    aliases: ["naptr_record"]
  ns_rec:
    description: Raw NS record.
    required: false
    aliases: ["ns_record"]
  ptr_rec:
    description: Raw PTR record.
    required: false
    aliases: ["ptr_record"]
  srv_rec:
    description: Raw SRV record.
    required: false
    aliases: ["srv_record"]
  sshfp_rec:
    description: Raw SSHFP record.
    required: false
    aliases: ["sshfp_record"]
  tlsa_rec:
    description: Raw TLSA record.
    required: false
    aliases: ["tlsa_record"]
  txt_rec:
    description: Raw TXT record.
    required: false
    aliases: ["txt_record"]
  uri_rec:
    description: Raw URI record.
    required: false
    aliases: ["uri_record"]
  ip_address:
    description: IP adresses for A ar AAAA.
    aliases: ["a_ip_address", "aaaa_ip_address"]
    required: false
    type: string
  create_reverse:
    description: |
      Create reverse record for A or AAAA record types.
      There is no equivalent to remove reverse records.
    type: bool
    required: false
    aliases: ["reverse"]
  a_ip_address:
    description: IP adresses for A records.
    required: false
    type: string
  a_create_reverse:
    description: |
      Create reverse record for A records.
      There is no equivalent to remove reverse records.
    type: bool
    required: false
  aaaa_ip_address:
    description: IP adresses for AAAA records.
    required: false
    type: string
  aaaa_create_reverse:
    description: |
      Create reverse record for AAAA records.
      There is no equivalent to remove reverse records.
    type: bool
    required: false
  afsdb_subtype:
    description: AFSDB Subtype
    required: false
    type: int
  afsdb_hostname:
    description: AFSDB Hostname
    required: false
    type: string
  cert_type:
    description: CERT Certificate Type
    required: false
    type: int
  cert_key_tag:
    description: CERT Key Tag
    required: false
    type: int
  cert_algorithm:
    description: CERT Algorithm
    required: false
    type: int
  cert_certificate_or_crl:
    description: CERT Certificate/CRL
    required: false
    type: string
  cname_hostname:
    description: A hostname which this alias hostname points to.
    required: false
    type: string
  dlv_key_tag:
    description: DS Key Tag
    required: false
    type: int
  dlv_algorithm:
    description: DLV Algorithm
    required: false
    type: int
  dlv_digest_type:
    description: DLV Digest Type
    required: false
    type: int
  dlv_digest:
    description: DLV Digest
    required: false
    type: string
  dname_target:
    description: DNAME Target
    required: false
    type: string
  ds_key_tag:
    description: DS Key Tag
    required: false
    type: int
  ds_algorithm:
    description: DS Algorithm
    required: false
    type: int
  ds_digest_type:
    description: DS Digest Type
    required: false
    type: int
  ds_digest:
    description: DS Digest
    required: false
    type: string
  kx_preference:
    description: |
      Preference given to this exchanger. Lower values are more preferred.
    required: false
    type: int
  kx_exchanger:
    description: A host willing to act as a key exchanger.
    required: false
    type: string
  loc_lat_deg:
    description: LOC Degrees Latitude
    required: false
    type: int
  loc_lat_min:
    description: LOC Minutes Latitude
    required: false
    type: int
  loc_lat_sec:
    description: LOC Seconds Latitude
    required: false
    type: float
  loc_lat_dir:
    description: LOC Direction Latitude
    required: false
    choices: ["N", "S"]
  loc_lon_deg:
    description: LOC Degrees Longitude
    required: false
    type: int
  loc_lon_min:
    description: LOC Minutes Longitude
    required: false
    type: int
  loc_lon_sec:
    description: LOC Seconds Longitude
    required: false
    type: float
  loc_lon_dir:
    description: LOC Direction Longitude
    required: false
    choices: ["E", "W"]
  loc_altitude:
    description: LOC Altitude
    required: false
    type: float
  loc_size:
    description: LOC Size
    required: false
    type: float
  loc_h_precision:
    description: LOC Horizontal Precision
    required: false
    type: float
  loc_v_precision:
    description: LOC Vertical Precision
    required: false
    type: float
  mx_preference:
    description: |
      Preference given to this exchanger. Lower values are more preferred.
    required: false
    type: int
  mx_exchanger:
    description: A host willing to act as a mail exchanger.
    required: false
    type: string
  naptr_order:
    description: NAPTR Order
    required: false
    type: int
  naptr_preference:
    description: NAPTR Preference
    required: false
    type: int
  naptr_flags:
    description: NAPTR Flags
    required: false
    type: string
  naptr_service:
    description: NAPTR Service
    required: false
    type: string
  naptr_regexp:
    description: NAPTR Regular Expression
    required: false
    type: string
  naptr_replacement:
    description: NAPTR Replacement
    required: false
    type: string
  ns_hostname:
    description: NS Hostname
    required: false
    type: string
  ptr_hostname:
    description: The hostname this reverse record points to.
    required: false
    type: string
  srv_priority:
    description: |
      Lower number means higher priority. Clients will attempt to contact the
      server with the lowest-numbered priority they can reach.
    required: false
    type: int
  srv_weight:
    description: Relative weight for entries with the same priority.
    required: false
    type: int
  srv_port:
    description: SRV Port
    required: false
    type: int
  srv_target:
    description: |
      The domain name of the target host or '.' if the service is decidedly not
      available at this domain.
    required: false
    type: string
  sshfp_algorithm:
    description: SSHFP Algorithm
    required: false
    type: int
  sshfp_fp_type:
    description: SSHFP Fingerprint Type
    required: false
    type: int
  sshfp_fingerprint:
    description: SSHFP Fingerprint
    required: false
    type: string
  txt_data:
    description: TXT Text Data
    required: false
    type: string
  tlsa_cert_usage:
    description: TLSA Certificate Usage
    required: false
    type: int
  tlsa_selector:
    description: TLSA Selector
    required: false
    type: int
  tlsa_matching_type:
    description: TLSA Matching Type
    required: false
    type: int
  tlsa_cert_association_data:
    description: TLSA Certificate Association Data
    required: false
    type: string
  uri_target:
    description: Target Uniform Resource Identifier according to RFC 3986.
    required: false
    type: string
  uri_priority:
    description: |
      Lower number means higher priority. Clients will attempt to contact the
      URI with the lowest-numbered priority they can reach.
    required: false
    type: int
  uri_weight:
    description: Relative weight for entries with the same priority.
    required: false
    type: int
  state:
    description: State to ensure
    default: present
    choices: ["present", "absent"]

author:
    - Rafael Guterres Jeffman
"""

EXAMPLES = """
# Ensure dns record is present
- ipadnsrecord:
    ipaadmin_password: SomeADMINpassword
    name: vm-001
    zone_name: example.com
    record_type: 'AAAA'
    record_value: '::1'

# Ensure that dns record exists with a TTL
- ipadnsrecord:
    ipaadmin_password: SomeADMINpassword
    name: host01
    zone_name: example.com
    record_type: 'AAAA'
    record_value: '::1'
    record_ttl: 300

# Ensure that dns record exists with a reverse record
- ipadnsrecord:
    ipaadmin_password: SomeADMINpassword
    name: host02
    zone_name: example.com
    record_type: 'AAAA'
    record_value: 'fd00::0002'
    create_reverse: yes

# Ensure a PTR record is present
- ipadnsrecord:
    ipaadmin_password: SomeADMINpassword
    name: 5
    zone_name: 2.168.192.in-addr.arpa
    record_type: 'PTR'
    record_value: 'internal.ipa.example.com'

# Ensure a TXT record is present
- ipadnsrecord:
    ipaadmin_password: SomeADMINpassword
    name: _kerberos
    zone_name: example.com
    record_type: 'TXT'
    record_value: 'EXAMPLE.COM'

# Ensure a SRV record is present
- ipadnsrecord:
    ipaadmin_password: SomeADMINpassword
    name: _kerberos._udp.example.com
    zone_name: example.com
    record_type: 'SRV'
    record_value: '10 50 88 ipa.example.com'

# Ensure an MX record is present
- ipadnsrecord:
    ipaadmin_password: SomeADMINpassword
    name: '@'
    zone_name: example.com
    record_type: 'MX'
    record_value: '1 mailserver.example.com'

# Ensure that dns record is absent
- ipadnsrecord:
    ipaadmin_password: SomeADMINpassword
    name: host01
    zone_name: example.com
    record_type: 'AAAA'
    record_value: '::1'
    state: absent
"""

RETURN = """
"""


from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_text
from ansible.module_utils.ansible_freeipa_module import temp_kinit, \
    temp_kdestroy, valid_creds, api_connect, api_command, module_params_get, \
    is_ipv4_addr, is_ipv6_addr
import dns.reversename
import dns.resolver
import ipalib.errors
import six


if six.PY3:
    unicode = str

_SUPPORTED_RECORD_TYPES = [
    "A", "AAAA", "A6", "AFSDB", "CERT", "CNAME", "DLV", "DNAME", "DS", "KX",
    "LOC", "MX", "NAPTR", "NS", "PTR", "SRV", "SSHFP", "TLSA", "TXT", "URI"]

_RECORD_FIELDS = [
    "a_rec", "aaaa_rec", "a6_rec", "afsdb_rec", "cert_rec",
    "cname_rec", "dlv_rec", "dname_rec", "ds_rec", "kx_rec", "loc_rec",
    "mx_rec", "naptr_rec", "ns_rec", "ptr_rec", "srv_rec", "sshfp_rec",
    "tlsa_rec", "txt_rec", "uri_rec"
]

_PART_MAP = {
    'a_ip_address': 'a_part_ip_address',
    'a_create_reverse': 'a_extra_create_reverse',
    'aaaa_ip_address': 'aaaa_part_ip_address',
    'aaaa_create_reverse': 'aaaa_extra_create_reverse',
    'a6_data': 'a6_part_data',
    'afsdb_subtype': 'afsdb_part_subtype',
    'afsdb_hostname': 'afsdb_part_hostname',
    'cert_type': 'cert_part_type',
    'cert_key_tag': 'cert_part_key_tag',
    'cert_algorithm': 'cert_part_algorithm',
    'cert_certificate_or_crl': 'cert_part_certificate_or_crl',
    'cname_hostname': 'cname_part_hostname',
    'dlv_algorithm': 'dlv_part_algorithm',
    'dlv_digest': 'dlv_part_digest',
    'dlv_digest_type': 'dlv_part_digest_type',
    'dlv_key_tag': 'dlv_part_key_tag',
    'dname_target': 'dname_part_target',
    'ds_algorithm': 'ds_part_algorithm',
    'ds_digest': 'ds_part_digest',
    'ds_digest_type': 'ds_part_digest_type',
    'ds_key_tag': 'ds_part_key_tag',
    'kx_preference': 'kx_part_preference',
    'kx_exchanger': 'kx_part_exchanger',
    "loc_lat_deg": "loc_part_lat_deg",
    "loc_lat_min": "loc_part_lat_min",
    "loc_lat_sec": "loc_part_lat_sec",
    "loc_lat_dir": "loc_part_lat_dir",
    "loc_lon_deg": "loc_part_lon_deg",
    "loc_lon_min": "loc_part_lon_min",
    "loc_lon_sec": "loc_part_lon_sec",
    "loc_lon_dir": "loc_part_lon_dir",
    "loc_altitude": "loc_part_altitude",
    "loc_size": "loc_part_size",
    "loc_h_precision": "loc_part_h_precision",
    "loc_v_precision": "loc_part_v_precision",
    "mx_preference": "mx_part_preference",
    "mx_exchanger": 'mx_part_exchanger',
    "naptr_order": "naptr_part_order",
    "naptr_preference": "naptr_part_preference",
    "naptr_flags": "naptr_part_flags",
    "naptr_service": "naptr_part_service",
    "naptr_regexp": "naptr_part_regexp",
    "naptr_replacement": "naptr_part_replacement",
    'ns_hostname': 'ns_part_hostname',
    'ptr_hostname': 'ptr_part_hostname',
    "srv_priority": "srv_part_priority",
    "srv_weight": "srv_part_weight",
    "srv_port": "srv_part_port",
    "srv_target": "srv_part_target",
    'sshfp_algorithm': 'sshfp_part_algorithm',
    'sshfp_fingerprint': 'sshfp_part_fingerprint',
    'sshfp_fp_type': 'sshfp_part_fp_type',
    "tlsa_cert_usage": "tlsa_part_cert_usage",
    "tlsa_cert_association_data": "tlsa_part_cert_association_data",
    "tlsa_matching_type": "tlsa_part_matching_type",
    "tlsa_selector": "tlsa_part_selector",
    'txt_data': 'txt_part_data',
    "uri_priority": "uri_part_priority",
    "uri_target": "uri_part_target",
    "uri_weight": "uri_part_weight"
}

_RECORD_PARTS = {
    "arecord": ["a_part_ip_address", "a_extra_create_reverse"],
    "aaaarecord": [
        "aaaa_part_ip_address", "aaaa_extra_create_reverse"
    ],
    "a6record": ["a6_part_data"],
    "afsdbrecord": ['afsdb_part_subtype', 'afsdb_part_hostname'],
    "cert_rec": [
        'cert_part_type', 'cert_part_key_tag', 'cert_part_algorithm',
        'cert_part_certificate_or_crl'
    ],
    "cnamerecord": ["cname_part_hostname"],
    "dlvrecord": [
        'dlv_part_key_tag', 'dlv_part_algorithm', 'dlv_part_digest_type',
        'dlv_part_digest'
    ],
    "dnamerecord": ["dname_part_target"],
    "dsrecord": ['ds_part_key_tag', 'ds_part_algorithm',
                 'ds_part_digest_type', 'ds_part_digest'],
    "kxrecord": ['kx_part_preference', 'kx_part_exchanger'],
    "locrecord": [
        "loc_part_lat_deg", "loc_part_lat_min", "loc_part_lat_sec",
        "loc_part_lat_dir", "loc_part_lon_deg", "loc_part_lon_min",
        "loc_part_lon_sec", "loc_part_lon_dir", "loc_part_altitude",
        "loc_part_size", "loc_part_h_precision", "loc_part_v_precision"
    ],
    "mxrecord": ['mx_part_preference', 'mx_part_exchanger'],
    "naptrrecord": [
        "naptr_part_order", "naptr_part_preference", "naptr_part_flags",
        "naptr_part_service", "naptr_part_regexp", "naptr_part_replacement"
    ],
    "nsrecord": ["ns_part_hostname"],
    "ptrrecord": ["ptr_part_hostname"],
    "srvrecord": [
        "srv_part_priority", "srv_part_weight", "srv_part_port",
        "srv_part_target",
    ],
    "sshfprecord": [
        'sshfp_part_algorithm', 'sshfp_part_fingerprint',
        'sshfp_part_fp_type'
    ],
    "tlsarecord": [
        "tlsa_part_cert_usage", "tlsa_part_cert_association_data",
        "tlsa_part_matching_type", "tlsa_part_selector"
    ],
    "txtrecord": ["txt_part_data"],
    "urirecord": ["uri_part_priority", "uri_part_target", "uri_part_weight"],
}


def configure_module():
    """Configure ipadnsrecord ansible module variables."""
    record_spec = dict(
        zone_name=dict(type='str', required=False, aliases=['dnszone']),
        record_type=dict(type='str', default="A",
                         choices=["A", "AAAA", "A6", "AFSDB", "CERT", "CNAME",
                                  "DLV", "DNAME", "DS", "KX", "LOC", "MX",
                                  "NAPTR", "NS", "PTR", "SRV", "SSHFP", "TLSA",
                                  "TXT", "URI"]),
        record_value=dict(type='list', required=False),
        record_ttl=dict(type='int', required=False),
        del_all=dict(type='bool', required=False),
        a_rec=dict(type='list', required=False, aliases=['a_record']),
        aaaa_rec=dict(type='list', required=False, aliases=['aaaa_record']),
        a6_rec=dict(type='list', required=False, aliases=['a6_record']),
        afsdb_rec=dict(type='list', required=False, aliases=['afsdb_record']),
        cert_rec=dict(type='list', required=False, aliases=['cert_record']),
        cname_rec=dict(type='list', required=False, aliases=['cname_record']),
        dlv_rec=dict(type='list', required=False, aliases=['dlv_record']),
        dname_rec=dict(type='list', required=False, aliases=['dname_record']),
        ds_rec=dict(type='list', required=False, aliases=['ds_record']),
        kx_rec=dict(type='list', required=False, aliases=['kx_record']),
        loc_rec=dict(type='list', required=False, aliases=['loc_record']),
        mx_rec=dict(type='list', required=False, aliases=['mx_record']),
        naptr_rec=dict(type='list', required=False, aliases=['naptr_record']),
        ns_rec=dict(type='list', required=False, aliases=['ns_record']),
        ptr_rec=dict(type='list', required=False, aliases=['ptr_record']),
        srv_rec=dict(type='list', required=False, aliases=['srv_record']),
        sshfp_rec=dict(type='list', required=False, aliases=['sshfp_record']),
        tlsa_rec=dict(type='list', required=False, aliases=['tlsa_record']),
        txt_rec=dict(type='list', required=False, aliases=['txt_record']),
        uri_rec=dict(type='list', required=False, aliases=['uri_record']),
        ip_address=dict(type='str', required=False),
        create_reverse=dict(type='bool', required=False, aliases=['reverse']),
        a_ip_address=dict(type='str', required=False),
        a_create_reverse=dict(type='bool', required=False),
        aaaa_ip_address=dict(type='str', required=False),
        aaaa_create_reverse=dict(type='bool', required=False),
        a6_data=dict(type='str', required=False),
        afsdb_subtype=dict(type='int', required=False),
        afsdb_hostname=dict(type='str', required=False),
        cert_type=dict(type='int', required=False),
        cert_key_tag=dict(type='int', required=False),
        cert_algorithm=dict(type='int', required=False),
        cert_certificate_or_crl=dict(type='str', required=False),
        cname_hostname=dict(type='str', required=False),
        dlv_key_tag=dict(type='int', required=False),
        dlv_algorithm=dict(type='int', required=False),
        dlv_digest_type=dict(type='int', required=False),
        dlv_digest=dict(type='str', required=False),
        dname_target=dict(type='str', required=False),
        ds_key_tag=dict(type='int', required=False),
        ds_algorithm=dict(type='int', required=False),
        ds_digest_type=dict(type='int', required=False),
        ds_digest=dict(type='str', required=False),
        kx_preference=dict(type='int', required=False),
        kx_exchanger=dict(type='str', required=False),
        loc_lat_deg=dict(type='int', required=False),
        loc_lat_min=dict(type='int', required=False),
        loc_lat_sec=dict(type='float', required=False),
        loc_lat_dir=dict(type='str', required=False),
        loc_lon_deg=dict(type='int', required=False),
        loc_lon_min=dict(type='int', required=False),
        loc_lon_sec=dict(type='float', required=False),
        loc_lon_dir=dict(type='str', required=False),
        loc_altitude=dict(type='float', required=False),
        loc_size=dict(type='float', required=False),
        loc_h_precision=dict(type='float', required=False),
        loc_v_precision=dict(type='float', required=False),
        mx_preference=dict(type='int', required=False),
        mx_exchanger=dict(type='str', required=False),
        naptr_order=dict(type='int', required=False),
        naptr_preference=dict(type='int', required=False),
        naptr_flags=dict(type='str', required=False),
        naptr_service=dict(type='str', required=False),
        naptr_regexp=dict(type='str', required=False),
        naptr_replacement=dict(type='str', required=False),
        ns_hostname=dict(type='str', required=False),
        ptr_hostname=dict(type='str', required=False),
        srv_priority=dict(type='int', required=False),
        srv_weight=dict(type='int', required=False),
        srv_port=dict(type='int', required=False),
        srv_target=dict(type='str', required=False),
        sshfp_algorithm=dict(type='int', required=False),
        sshfp_fingerprint=dict(type='str', required=False),
        sshfp_fp_type=dict(type='int', required=False),
        tlsa_cert_usage=dict(type='int', required=False),
        tlsa_cert_association_data=dict(type='str', required=False),
        tlsa_matching_type=dict(type='int', required=False),
        tlsa_selector=dict(type='int', required=False),
        txt_data=dict(type='str', required=False),
        uri_priority=dict(type='int', required=False),
        uri_target=dict(type='str', required=False),
        uri_weight=dict(type='int', required=False),
    )

    ansible_module = AnsibleModule(
        argument_spec=dict(
            # general
            ipaadmin_principal=dict(type="str", default="admin"),
            ipaadmin_password=dict(type="str", no_log=True),

            name=dict(type="list", aliases=["record_name"], default=None,
                      required=False),

            records=dict(type="list", default=None,
                         options=dict(
                            # Here name is a simple string
                            name=dict(type='str', required=True,
                                      aliases=['record_name']),
                            **record_spec),
                         ),

            # general
            state=dict(type="str", default="present",
                       choices=["present", "absent", "disabled"]),

            # Add record specific parameters for simple use case
            **record_spec
        ),
        mutually_exclusive=[["name", "records"], ['record_value', 'del_all']],
        required_one_of=[["name", "records"]],
        supports_check_mode=True,
    )

    ansible_module._ansible_debug = True

    return ansible_module


def find_dnsrecord(module, dnszone, name, **records):
    """Find a DNS record based on its name (idnsname)."""
    _args = {record: value for record, value in records.items()}
    _args["all"] = True
    if name != '@':
        _args['idnsname'] = to_text(name)

    try:
        _result = api_command(
            module, "dnsrecord_find", to_text(dnszone), _args)
    except ipalib.errors.NotFound:
        return None

    if len(_result["result"]) > 1 and name != '@':
        module.fail_json(
            msg="There is more than one dnsrecord for '%s',"
                " zone '%s'" % (name, dnszone))
    else:
        if len(_result["result"]) == 1:
            return _result["result"][0]
        else:
            for _res in _result["result"]:
                if 'idnsname' in _res:
                    for x in _res['idnsname']:
                        if '@' == to_text(x):
                            return _res
    return None


def check_parameters(module, state, zone_name, record):
    """Check if parameters are correct."""
    if zone_name is None:
        module.fail_json(msg="Msssing required argument: zone_name")

    record_type = record.get('record_type', None)
    record_value = record.get('record_value', None)
    if record_type is not None:
        if record_type not in _SUPPORTED_RECORD_TYPES:
            module.fail_json(
                msg="Record Type '%s' is not supported." % record_type)

    has_record = any(record.get(rec, None) for rec in _RECORD_FIELDS)

    has_part_record = any(record.get(rec, None) for rec in _PART_MAP)

    special_list = ['ip_address']
    has_special = any(record.get(rec, None) for rec in special_list)

    invalid = []

    if state == 'present':
        if has_record or has_part_record or has_special:
            if record_value:
                module.fail_json(
                    msg="Cannot use record data with `record_value`.")
        elif not record_value:
            module.fail_json(msg="No record data provided.")

        invalid = ['del_all']

    if state == 'absent':
        del_all = record.get('del_all', None)
        if record_value:
            if has_record or has_part_record or del_all:
                module.fail_json(
                    msg="Cannot use record data with `record_value`.")
        elif not (has_record or has_part_record or del_all):
            module.fail_json(
                msg="Either a record description or `del_all` is required.")
        invalid = list(_PART_MAP.keys())
        invalid.extend(['create_reverse', 'dns_ttl'])

    for x in invalid:
        if x in record:
            module.fail_json(
                msg="Variable `%s` cannot be used in state `%s`" %
                    (x, state))


def connect_to_api(module):
    """Connect to the IPA API."""
    ipaadmin_principal = module_params_get(module, "ipaadmin_principal")
    ipaadmin_password = module_params_get(module, "ipaadmin_password")

    ccache_dir = None
    ccache_name = None
    if not valid_creds(module, ipaadmin_principal):
        ccache_dir, ccache_name = temp_kinit(ipaadmin_principal,
                                             ipaadmin_password)
    api_connect()

    return ccache_dir, ccache_name


def get_entry_from_module(module, name):
    """Create an entry dict from attributes in module."""
    attrs = [
        'del_all', 'zone_name', 'record_type', 'record_value', 'record_ttl',
        "ip_address", "create_reverse"
    ]

    entry = {'name': name}

    for key_set in [_RECORD_FIELDS, _PART_MAP, attrs]:
        entry.update({
            key: module_params_get(module, key)
            for key in key_set
            if module_params_get(module, key) is not None
        })

    return entry


def create_reverse_ip_record(module, zone_name, name, ips):
    """Create a reverse record for an IP (PTR record)."""
    _cmds = []
    for address in ips:
        reverse_ip = dns.reversename.from_address(address)
        reverse_zone = dns.resolver.zone_for_name(reverse_ip)
        reverse_host = to_text(reverse_ip).replace(".%s" % reverse_zone, '')

        rev_find = find_dnsrecord(module, reverse_zone, reverse_host)
        if rev_find is None:
            rev_args = {
                'idnsname': to_text(reverse_host),
                "ptrrecord": "%s.%s" % (name, zone_name)
            }
            _cmds.append([reverse_zone, 'dnsrecord_add', rev_args])

    return _cmds


def ensure_data_is_list(data):
    """Ensure data is represented as a list."""
    return data if isinstance(data, list) else [data]


def gen_args(entry):
    """Generate IPA API arguments for a given `entry`."""
    args = {'idnsname': to_text(entry['name'])}

    if 'del_all' in entry:
        args['del_all'] = entry['del_all']

    record_value = entry.get('record_value', None)

    if record_value is not None:
        record_type = entry['record_type']
        rec = "{}record".format(record_type.lower())
        args[rec] = ensure_data_is_list(record_value)

    else:
        for field in _RECORD_FIELDS:
            record_value = entry.get(field, None)
            if record_value is not None:
                record_type = field.split('_')[0]
                rec = "{}record".format(record_type.lower())
                args[rec] = ensure_data_is_list(record_value)

        records = {
            key: rec for key, rec in _PART_MAP.items() if key in entry
        }
        for key, rec in records.items():
            args[rec] = entry[key]

    if 'ip_address' in entry:
        ip_address = entry['ip_address']
        if is_ipv4_addr(ip_address):
            args['a_part_ip_address'] = ip_address
        if is_ipv6_addr(ip_address):
            args['aaaa_part_ip_address'] = ip_address

    if entry.get('create_reverse', False):
        if 'a_part_ip_address' in args or 'arecord' in args:
            args['a_extra_create_reverse'] = True
        if 'aaaa_part_ip_address' in args or 'aaaarecord' in args:
            args['aaaa_extra_create_reverse'] = True

    if 'record_ttl' in entry:
        args['dnsttl'] = entry['record_ttl']

    return args


def define_commands_for_present_state(module, zone_name, entry, res_find):
    """Define commnads for `state: present`."""
    _commands = []

    name = to_text(entry['name'])
    args = gen_args(entry)

    if res_find is None:
        _commands.append([zone_name, 'dnsrecord_add', args])
    else:
        # Create reverse records for existing records
        for ipv in ['a', 'aaaa']:
            record = ('%srecord' % ipv)
            if record in args and ('%s_extra_create_reverse' % ipv) in args:
                cmds = create_reverse_ip_record(
                    module, zone_name, name, args[record])
                _commands.extend(cmds)
                del args['%s_extra_create_reverse' % ipv]
                if '%s_ip_address' not in args:
                    del args[record]
        for record, fields in _RECORD_PARTS.items():
            part_fields = [f for f in fields if f in args]
            if part_fields:
                if record in args:
                    # user wants to update record.
                    if len(args[record]) > 1:
                        module.fail_json(msg="Cannot modify multiple records "
                                             "of the same type at once.")

                    existing = find_dnsrecord(module, zone_name, name,
                                              **{record: args[record][0]})
                    if existing is None:
                        module.fail_json(msg="``%s` not found." % record)
                    else:
                        # update DNS record
                        _args = {k: args[k] for k in part_fields if k in args}
                        _args["idnsname"] = to_text(args["idnsname"])
                        _args[record] = res_find[record]
                        if 'dns_ttl' in args:
                            _args['dns_ttl'] = args['dns_ttl']
                        _commands.append([zone_name, 'dnsrecord_mod', _args])
                    # remove record from args, as it will not be used again.
                    del args[record]
                else:
                    for f in part_fields:
                        _args = {k: args[k] for k in part_fields}
                        _args['idnsname'] = name
                        _commands.append([zone_name, 'dnsrecord_add', _args])
                # clean used fields from args
                for f in part_fields:
                    if f in args:
                        del args[f]
            else:
                if record in args:
                    add_list = []
                    for value in args[record]:
                        existing = find_dnsrecord(module, zone_name, name,
                                                  **{record: value})
                        if existing is None:
                            add_list.append(value)
                    if add_list:
                        args[record] = add_list
                        _commands.append([zone_name, 'dnsrecord_add', args])

    return _commands


def define_commands_for_absent_state(module, zone_name, entry, res_find):
    """Define commands for `state: absent`."""
    _commands = []
    if res_find is None:
        return []

    name = entry['name']
    args = gen_args(entry)

    del_all = args.get('del_all', False)

    records_to_delete = {k: v for k, v in args.items() if k.endswith('record')}

    if del_all and records_to_delete:
        module.fail_json(msg="Cannot use del_all and record together.")

    if not del_all:
        delete_records = False
        for record, values in records_to_delete.items():
            del_list = []
            for value in values:
                existing = find_dnsrecord(
                    module, zone_name, name, **{record: value})
                if existing:
                    del_list.append(value)
            if del_list:
                args[record] = del_list
                delete_records = True
        if delete_records:
            _commands.append([zone_name, 'dnsrecord_del', args])
    else:
        _commands.append([zone_name, 'dnsrecord_del', args])

    return _commands


def main():
    """Execute DNS record playbook."""
    ansible_module = configure_module()

    global_zone_name = module_params_get(ansible_module, "zone_name")
    names = module_params_get(ansible_module, "name")
    records = module_params_get(ansible_module, "records")
    state = module_params_get(ansible_module, "state")

    # Check parameters

    if (names is None or len(names) < 1) and \
       (records is None or len(records) < 1):
        ansible_module.fail_json(msg="One of name and records is required")

    if state == "present":
        if names is not None and len(names) != 1:
            ansible_module.fail_json(
                msg="Only one record can be added at a time.")

    if records is not None:
        names = records

    # Init

    changed = False
    exit_args = {}
    ccache_dir = None
    ccache_name = None

    try:
        ccache_dir, ccache_name = connect_to_api(ansible_module)

        commands = []

        for record in names:
            if isinstance(record, dict):
                # ensure name is a string
                zone_name = record.get("zone_name", global_zone_name)
                name = record['name'] = str(record['name'])
                entry = record
            else:
                zone_name = global_zone_name
                name = record
                entry = get_entry_from_module(ansible_module, name)

            check_parameters(ansible_module, state, zone_name, entry)

            res_find = find_dnsrecord(ansible_module, zone_name, name)

            if state == 'present':
                cmds = define_commands_for_present_state(
                    ansible_module, zone_name, entry, res_find)
            elif state == 'absent':
                cmds = define_commands_for_absent_state(
                    ansible_module, zone_name, entry, res_find)
            else:
                ansible_module.fail_json(msg="Unkown state '%s'" % state)

            if cmds:
                commands.extend(cmds)

        # Execute commands
        for name, command, args in commands:
            try:
                result = api_command(
                    ansible_module, command, to_text(name), args)
                if "completed" in result:
                    if result["completed"] > 0:
                        changed = True
                else:
                    changed = True

            except ipalib.errors.EmptyModlist:
                continue
            except ipalib.errors.DuplicateEntry:
                continue
            except Exception as e:
                error_message = str(e)

                ansible_module.fail_json(
                    msg="%s: %s: %s" % (command, name, error_message))

    except Exception as e:
        ansible_module.fail_json(msg=str(e))

    finally:
        temp_kdestroy(ccache_dir, ccache_name)

    # Done
    ansible_module.exit_json(changed=changed, host=exit_args)


if __name__ == "__main__":
    main()

# -*- coding: utf-8 -*-

# Authors:
#   Thomas Woerner <twoerner@redhat.com>
#
# Based on ipa-client-install code
#
# Copyright (C) 2017-2022  Red Hat
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

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

ANSIBLE_METADATA = {
    'metadata_version': '1.0',
    'supported_by': 'community',
    'status': ['preview'],
}

DOCUMENTATION = '''
---
module: ipaserver_setup_dns
short_description: Setup DNS
description: Setup DNS
options:
  ip_addresses:
    description: List of Master Server IP Addresses
    type: list
    elements: str
    required: no
    default: []
  domain:
    description: Primary DNS domain of the IPA deployment
    type: str
    required: yes
  realm:
    description: Kerberos realm name of the IPA deployment
    type: str
    required: yes
  hostname:
    description: Fully qualified name of this host
    type: str
    required: yes
  setup_dns:
    description: Configure bind with our zone
    type: bool
    required: yes
  setup_ca:
    description: Configure a dogtag CA
    type: bool
    required: yes
  zonemgr:
    description: DNS zone manager e-mail address. Defaults to hostmaster@DOMAIN
    type: str
    required: no
  forwarders:
    description: Add DNS forwarders
    type: list
    elements: str
    required: yes
  forward_policy:
    description: DNS forwarding policy for global forwarders
    type: str
    choices: ['first', 'only']
    default: 'first'
    required: no
  no_dnssec_validation:
    description: Disable DNSSEC validation
    type: bool
    default: no
    required: no
  dot_forwarders:
    description: List of DNS over TLS forwarders
    type: list
    elements: str
    default: []
    required: no
  dns_over_tls:
    description: Configure DNS over TLS
    type: bool
    default: no
    required: no
  dns_over_tls_cert:
    description:
      Certificate to use for DNS over TLS. If empty, a new
      certificate will be requested from IPA CA
    type: str
    required: no
  dns_over_tls_key:
    description: Key for certificate specified in dns_over_tls_cert
    type: str
    required: no
  dns_policy:
    description: Encrypted DNS policy
    type: str
    choices: ['relaxed', 'enforced']
    default: 'relaxed'
  dns_ip_addresses:
    description: The dns ip_addresses setting
    type: list
    elements: str
    required: yes
  dns_reverse_zones:
    description: The dns reverse_zones setting
    type: list
    elements: str
    required: yes
author:
    - Thomas Woerner (@t-woerner)
'''

EXAMPLES = '''
'''

RETURN = '''
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.ansible_ipa_server import (
    check_imports, AnsibleModuleLog, setup_logging, options, paths, dns,
    ansible_module_get_parsed_ip_addresses, sysrestore, api_Backend_ldap2,
    redirect_stdout
)

# pylint: disable=unused-import
from ansible.module_utils.ansible_ipa_server import bindinstance  # noqa: F401
# pylint: enable=unused-import


def main():
    ansible_module = AnsibleModule(
        argument_spec=dict(
            # basic
            ip_addresses=dict(required=False, type='list', elements='str',
                              default=[]),
            domain=dict(required=True, type='str'),
            realm=dict(required=True, type='str'),
            hostname=dict(required=True, type='str'),
            # server
            setup_dns=dict(required=True, type='bool'),
            setup_ca=dict(required=True, type='bool'),
            # dns
            zonemgr=dict(required=False, type='str'),
            forwarders=dict(required=True, type='list', elements='str'),
            forward_policy=dict(required=False, choices=['first', 'only'],
                                default='first'),
            no_dnssec_validation=dict(required=False, type='bool',
                                      default=False),
            dot_forwarders=dict(required=False, type='list', elements='str',
                                default=[]),
            dns_over_tls=dict(required=False, type='bool', default=False),
            dns_over_tls_cert=dict(required=False, type='str'),
            dns_over_tls_key=dict(required=False, type='str'),
            dns_policy=dict(required=False, type='str',
                            choices=['relaxed', 'enforced'],
                            default='relaxed'),
            # additional
            dns_ip_addresses=dict(required=True, type='list', elements='str'),
            dns_reverse_zones=dict(required=True, type='list', elements='str'),
        ),
    )

    ansible_module._ansible_debug = True
    check_imports(ansible_module)
    setup_logging()
    ansible_log = AnsibleModuleLog(ansible_module)

    # set values ############################################################

    # basic
    options.ip_addresses = ansible_module_get_parsed_ip_addresses(
        ansible_module)
    options.domain_name = ansible_module.params.get('domain')
    options.realm_name = ansible_module.params.get('realm')
    options.host_name = ansible_module.params.get('hostname')
    # server
    options.setup_dns = ansible_module.params.get('setup_dns')
    options.setup_ca = ansible_module.params.get('setup_ca')
    # dns
    options.zonemgr = ansible_module.params.get('zonemgr')
    options.forwarders = ansible_module.params.get('forwarders')
    options.forward_policy = ansible_module.params.get('forward_policy')
    options.no_dnssec_validation = ansible_module.params.get(
        'no_dnssec_validation')
    options.dot_forwarders = ansible_module.params.get('dot_forwarders')
    options.dns_over_tls = ansible_module.params.get('dns_over_tls')
    options.dns_over_tls_cert = ansible_module.params.get('dns_over_tls_cert')
    options.dns_over_tls_key = ansible_module.params.get('dns_over_tls_key')
    options.dns_policy = ansible_module.params.get('dns_policy')
    # additional
    dns.ip_addresses = ansible_module_get_parsed_ip_addresses(
        ansible_module, 'dns_ip_addresses')
    dns.reverse_zones = ansible_module.params.get('dns_reverse_zones')

    # init ##################################################################

    # pylint: disable=unused-variable
    fstore = sysrestore.FileStore(paths.SYSRESTORE)  # noqa: F841
    # pylint: enable=unused-variable

    api_Backend_ldap2(options.host_name, options.setup_ca, connect=True)

    # setup dns #############################################################

    with redirect_stdout(ansible_log):
        dns.install(False, False, options)

    # done ##################################################################

    ansible_module.exit_json(changed=True)


if __name__ == '__main__':
    main()

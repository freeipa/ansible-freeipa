#!/usr/bin/python
# -*- coding: utf-8 -*-

# Authors:
#   Thomas Woerner <twoerner@redhat.com>
#
# Based on ipa-client-install code
#
# Copyright (C) 2017  Red Hat
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

from __future__ import print_function

ANSIBLE_METADATA = {
    'metadata_version': '1.0',
    'supported_by': 'community',
    'status': ['preview'],
}

DOCUMENTATION = '''
---
module: ipaserver_setup_dns
short description: Setup DNS
description: Setup DNS
options:
  ip_addresses:
    description: List of Master Server IP Addresses
    required: yes
  domain:
    description: Primary DNS domain of the IPA deployment
    required: no
  realm:
    description: Kerberos realm name of the IPA deployment
    required: no
  hostname:
    description: Fully qualified name of this host
    required: no
  setup_dns:
    description: Configure bind with our zone
    required: no
  setup_ca:
    description: Configure a dogtag CA
    required: no
  zonemgr:
    description: DNS zone manager e-mail address. Defaults to hostmaster@DOMAIN
    required: yes
  forwarders:
    description: Add DNS forwarders
    required: no
  forward_policy:
    description: DNS forwarding policy for global forwarders
    required: yes
  no_dnssec_validation:
    description: Disable DNSSEC validation
    required: yes
  dns_ip_addresses:
    description: The dns ip_addresses setting
    required: no
  dns_reverse_zones:
    description: The dns reverse_zones setting
    required: no
author:
    - Thomas Woerner
'''

EXAMPLES = '''
'''

RETURN = '''
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.ansible_ipa_server import (
    AnsibleModuleLog, setup_logging, options, paths, dns,
    ansible_module_get_parsed_ip_addresses, sysrestore, api_Backend_ldap2,
    redirect_stdout, bindinstance
)


def main():
    ansible_module = AnsibleModule(
        argument_spec=dict(
            # basic
            ip_addresses=dict(required=False, type='list', default=[]),
            domain=dict(required=True),
            realm=dict(required=True),
            hostname=dict(required=True),
            # server
            setup_dns=dict(required=True, type='bool'),
            setup_ca=dict(required=True, type='bool'),
            # dns
            zonemgr=dict(required=False),
            forwarders=dict(required=True, type='list'),
            forward_policy=dict(default='first', choices=['first', 'only']),
            no_dnssec_validation=dict(required=False, type='bool',
                                      default=False),
            # additional
            dns_ip_addresses=dict(required=True, type='list'),
            dns_reverse_zones=dict(required=True, type='list'),
        ),
    )

    ansible_module._ansible_debug = True
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
    # additional
    dns.ip_addresses = ansible_module_get_parsed_ip_addresses(
        ansible_module, 'dns_ip_addresses')
    dns.reverse_zones = ansible_module.params.get('dns_reverse_zones')

    # init ##################################################################

    fstore = sysrestore.FileStore(paths.SYSRESTORE)

    api_Backend_ldap2(options.host_name, options.setup_ca, connect=True)

    # setup dns #############################################################

    with redirect_stdout(ansible_log):
        if options.setup_dns:
            dns.install(False, False, options)
        else:
            # Create a BIND instance
            bind = bindinstance.BindInstance(fstore)
            bind.set_output(ansible_log)
            bind.setup(options.host_name, options.ip_addresses,
                       options.realm_name,
                       options.domain_name, (), 'first', (),
                       zonemgr=options.zonemgr,
                       no_dnssec_validation=options.no_dnssec_validation)
            bind.create_file_with_system_records()

    # done ##################################################################

    ansible_module.exit_json(changed=True)


if __name__ == '__main__':
    main()

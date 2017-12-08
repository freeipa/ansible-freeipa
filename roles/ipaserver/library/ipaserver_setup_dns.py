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
module: setup_dns
short description: 
description:
options:
  hostname:
  setup_dns:
  setup_ca:
  zonemgr:
  forwarders:
  forward_policy:
  no_dnssec_validation:
author:
    - Thomas Woerner
'''

EXAMPLES = '''
'''

RETURN = '''
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.ansible_ipa_server import *

def main():
    ansible_module = AnsibleModule(
        argument_spec = dict(
            ### basic ###
            hostname=dict(required=True),
            ### server ###
            setup_dns=dict(required=True, type='bool'),
            setup_ca=dict(required=True, type='bool'),
            ### dns ###
            zonemgr=dict(required=False),
            forwarders=dict(required=True, type='list'),
            forward_policy=dict(default='first', choices=['first', 'only']),
            no_dnssec_validation=dict(required=False, type='bool',
                                      default=False),
            ### additional ###
            dns_ip_addresses=dict(required=True, type='list'),
            dns_reverse_zones=dict(required=True, type='list'),
        ),
    )

    ansible_module._ansible_debug = True
    ansible_log = AnsibleModuleLog(ansible_module)

    # set values ############################################################

    ### basic ###
    options.host_name = ansible_module.params.get('hostname')
    ### server ###
    options.setup_dns = ansible_module.params.get('setup_dns')
    options.setup_ca = ansible_module.params.get('setup_ca')
    ### dns ###
    options.zonemgr = ansible_module.params.get('zonemgr')
    options.forwarders = ansible_module.params.get('forwarders')
    options.forward_policy = ansible_module.params.get('forward_policy')
    options.no_dnssec_validation = ansible_module.params.get(
        'no_dnssec_validation')
    ### additional ###
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
            bind.setup(host_name, ip_addresses, realm_name,
                       domain_name, (), 'first', (),
                       zonemgr=options.zonemgr,
                       no_dnssec_validation=options.no_dnssec_validation)
            bind.create_file_with_system_records()

    # done ##################################################################

    ansible_module.exit_json(changed=True)

if __name__ == '__main__':
    main()

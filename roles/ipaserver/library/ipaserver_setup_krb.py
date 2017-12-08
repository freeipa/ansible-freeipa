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
module: setup_ds
short description: 
description:
options:
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
            # basic
            dm_password=dict(required=True, no_log=True),
            password=dict(required=True, no_log=True),
            master_password=dict(required=True, no_log=True),
            domain=dict(required=True),
            realm=dict(required=True),
            hostname=dict(required=False),

            ip_addresses=dict(required=False, type='list', default=[]),
            reverse_zones=dict(required=False, type='list', default=[]),

            setup_adtrust=dict(required=False, type='bool', default=False),
            setup_kra=dict(required=False, type='bool', default=False),
            setup_dns=dict(required=False, type='bool', default=False),
            setup_ca=dict(required=False, type='bool', default=False),

            no_host_dns=dict(required=False, type='bool', default=False),
            no_pkinit=dict(required=False, type='bool', default=False),
            no_hbac_allow=dict(required=False, type='bool', default=False),

            external_cert_files=dict(required=False, type='list', default=[]),
            subject_base=dict(required=False),
            ca_subject=dict(required=False),

            idstart=dict(required=True, type='int'),
            idmax=dict(required=True, type='int'),

            no_reverse=dict(required=False, type='bool', default=False),
            auto_forwarders=dict(required=False, type='bool', default=False),

            _pkinit_pkcs12_info=dict(required=False),
        ),
    )

    ansible_module._ansible_debug = True
    ansible_log = AnsibleModuleLog(ansible_module)

    # set values ############################################################

    options.dm_password = ansible_module.params.get('dm_password')
    options.admin_password = ansible_module.params.get('password')
    options.master_password = ansible_module.params.get('master_password')
    options.domain_name = ansible_module.params.get('domain')
    options.realm_name = ansible_module.params.get('realm')
    options.host_name = ansible_module.params.get('hostname')

    options.ip_addresses = ansible_module_get_parsed_ip_addresses(
        ansible_module)
    options.reverse_zones = ansible_module.params.get('reverse_zones')

    options.setup_adtrust = ansible_module.params.get('setup_adtrust')
    options.setup_kra = ansible_module.params.get('setup_kra')
    options.setup_dns = ansible_module.params.get('setup_dns')
    options.setup_ca = ansible_module.params.get('setup_ca')

    options.no_host_dns = ansible_module.params.get('no_host_dns')
    options.no_pkinit = ansible_module.params.get('no_pkinit')
    options.no_hbac_allow = ansible_module.params.get('no_hbac_allow')

    options.external_cert_files = ansible_module.params.get(
        'external_cert_files')
    options.subject_base = ansible_module.params.get('subject_base')
    options.ca_subject = ansible_module.params.get('ca_subject')

    options.no_reverse = ansible_module.params.get('no_reverse')
    options.auto_forwarders = ansible_module.params.get('auto_forwarders')

    options.idstart = ansible_module.params.get('idstart')
    options.idmax = ansible_module.params.get('idmax')

    options._pkinit_pkcs12_info = ansible_module.params.get(
        '_pkinit_pkcs12_info')

    #options._update_hosts_file = ansible_module.params.get('update_hosts_file')

    # init ##################################################################

    fstore = sysrestore.FileStore(paths.SYSRESTORE)

    api_Backend_ldap2(options.host_name, options.setup_ca, connect=True)

    # setup KRB #############################################################

    krb = krbinstance.KrbInstance(fstore)
    krb.set_output(ansible_log)
    with redirect_stdout(ansible_log):
        if not options.external_cert_files:
            krb.create_instance(options.realm_name, options.host_name,
                                options.domain_name,
                                options.dm_password, options.master_password,
                                setup_pkinit=not options.no_pkinit,
                                pkcs12_info=options._pkinit_pkcs12_info,
                                subject_base=options.subject_base)
        else:
            krb.init_info(options.realm_name, options.host_name,
                          setup_pkinit=not options.no_pkinit,
                          subject_base=options.subject_base)

    ansible_module.exit_json(changed=True)

if __name__ == '__main__':
    main()

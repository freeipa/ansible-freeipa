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
module: set_ds_password
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
            ### basic ###
            dm_password=dict(required=True, no_log=True),
            password=dict(required=True, no_log=True),
            domain=dict(required=True),
            realm=dict(required=True),
            hostname=dict(required=True),
            ### server ###
            setup_ca=dict(required=True, type='bool'),
            idstart=dict(required=True, type='int'),
            idmax=dict(required=True, type='int'),
            no_hbac_allow=dict(required=False, type='bool', default=False),
            no_pkinit=dict(required=False, type='bool', default=False),
            dirsrv_config_file=dict(required=False),
            _dirsrv_pkcs12_info=dict(required=False),
            ### ssl certificate ###
            dirsrv_cert_files=dict(required=False, type='list', default=[]),
            subject_base=dict(required=False),
            ca_subject=dict(required=False),
            ### certificate system ###
            external_cert_files=dict(required=False, type='list', default=[]),
            ### additional ###
            domainlevel=dict(required=False, type='int',
                             default=MAX_DOMAIN_LEVEL),
        ),
    )

    ansible_module._ansible_debug = True
    ansible_log = AnsibleModuleLog(ansible_module)

    # set values ####################################################

    ### basic ###
    options.dm_password = ansible_module.params.get('dm_password')
    options.admin_password = ansible_module.params.get('password')
    options.domain_name = ansible_module.params.get('domain')
    options.realm_name = ansible_module.params.get('realm')
    options.host_name = ansible_module.params.get('hostname')
    ### server ###
    options.setup_ca = ansible_module.params.get('setup_ca')
    options.idstart = ansible_module.params.get('idstart')
    options.idmax = ansible_module.params.get('idmax')
    options.no_hbac_allow = ansible_module.params.get('no_hbac_allow')
    options.no_pkinit = ansible_module.params.get('no_pkinit')
    options.dirsrv_config_file = ansible_module.params.get('dirsrv_config_file')
    options._dirsrv_pkcs12_info = ansible_module.params.get(
        '_dirsrv_pkcs12_info')
    ### ssl certificate ###
    options.dirsrv_cert_files = ansible_module.params.get('dirsrv_cert_files')
    options.subject_base = ansible_module.params.get('subject_base')
    options.ca_subject = ansible_module.params.get('ca_subject')
    ### certificate system ###
    options.external_cert_files = ansible_module.params.get(
        'external_cert_files')
    ### additional ###
    options.domainlevel = ansible_module.params.get('domainlevel')
    options.domain_level = options.domainlevel

    # init ##########################################################

    fstore = sysrestore.FileStore(paths.SYSRESTORE)
    sstore = sysrestore.StateFile(paths.SYSRESTORE)

    api_Backend_ldap2(options.host_name, options.setup_ca, connect=True)

    ds = ds_init_info(ansible_log, fstore,
                      options.domainlevel, options.dirsrv_config_file,
                      options.realm_name, options.host_name,
                      options.domain_name, options.dm_password,
                      options.idstart, options.idmax,
                      options.subject_base, options.ca_subject,
                      options.no_hbac_allow, options._dirsrv_pkcs12_info,
                      options.no_pkinit)

    # set ds password ###############################################

    with redirect_stdout(ansible_log):
        ds.change_admin_password(options.admin_password)

    # done ##########################################################

    ansible_module.exit_json(changed=True)

if __name__ == '__main__':
    main()

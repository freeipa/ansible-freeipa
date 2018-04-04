#!/usr/bin/python
# -*- coding: utf-8 -*-

# Authors:
#   Thomas Woerner <twoerner@redhat.com>
#
# Based on ipa-replica-install code
#
# Copyright (C) 2018  Red Hat
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
module: ipareplica_ds_enable_ssl
short description: DS enable SSL
description:
  DS enable SSL
options:
  setup_ca:
    description: 
    required: yes
  setup_kra:
    description: 
    required: yes
  no_pkinit:
    description: 
    required: yes
  subject_base:
    description: 
    required: yes
  config_master_host_name:
    description: 
    required: yes
  ccache:
    description: 
    required: yes
  _ca_enabled:
    description: 
    required: yes
  _ca_file:
    description: 
    required: yes
  _dirsrv_pkcs12_info:
    description: 
    required: yes
  _pkinit_pkcs12_info:
    description: 
    required: yes
  _top_dir:
    description: 
    required: yes
  dirman_password:
    description: 
    required: yes
  ds_ca_subject:
    description: 
    required: yes
author:
    - Thomas Woerner
'''

EXAMPLES = '''
'''

RETURN = '''
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.ansible_ipa_replica import *

def main():
    ansible_module = AnsibleModule(
        argument_spec = dict(
            #### server ###
            setup_ca=dict(required=False, type='bool'),
            setup_kra=dict(required=False, type='bool'),
            no_pkinit=dict(required=False, type='bool'),
            dirsrv_config_file=dict(required=False),
            #### certificate system ###
            subject_base=dict(required=True),
            #### additional ###
            config_master_host_name=dict(required=True),
            ccache=dict(required=True),
            _ca_enabled=dict(required=False, type='bool'),
            _ca_file=dict(required=False),
            _dirsrv_pkcs12_info = dict(required=False),
            _pkinit_pkcs12_info = dict(required=False),
            _top_dir = dict(required=True),
            dirman_password=dict(required=True, no_log=True),
            ds_ca_subject=dict(required=True),
        ),
        supports_check_mode = True,
    )

    ansible_module._ansible_debug = True
    ansible_log = AnsibleModuleLog(ansible_module)

    # get parameters #

    options = installer
    ### server ###
    options.setup_ca = ansible_module.params.get('setup_ca')
    options.setup_kra = ansible_module.params.get('setup_kra')
    options.no_pkinit = ansible_module.params.get('no_pkinit')
    options.dirsrv_config_file = ansible_module.params.get('dirsrv_config_file')
    ### certificate system ###
    options.subject_base = ansible_module.params.get('subject_base')
    if options.subject_base is not None:
        options.subject_base = DN(options.subject_base)
    ### additional ###
    master_host_name = ansible_module.params.get('config_master_host_name')
    ccache = ansible_module.params.get('ccache')
    os.environ['KRB5CCNAME'] = ccache
    #os.environ['KRB5CCNAME'] = ansible_module.params.get('installer_ccache')
    #installer._ccache = ansible_module.params.get('installer_ccache')
    ca_enabled = ansible_module.params.get('_ca_enabled')
    options._dirsrv_pkcs12_info = ansible_module.params.get('_dirsrv_pkcs12_info')
    options._pkinit_pkcs12_info = ansible_module.params.get('_pkinit_pkcs12_info')
    options._top_dir = ansible_module.params.get('_top_dir')
    dirman_password = ansible_module.params.get('dirman_password')
    ds_ca_subject = ansible_module.params.get('ds_ca_subject')

    # init #

    fstore = sysrestore.FileStore(paths.SYSRESTORE)
    sstore = sysrestore.StateFile(paths.SYSRESTORE)

    ansible_log.debug("== INSTALL ==")

    options = installer
    promote = installer.promote
    pkinit_pkcs12_info = installer._pkinit_pkcs12_info

    env = gen_env_boostrap_finalize_core(paths.ETC_IPA,
                                         constants.DEFAULT_CONFIG)
    api_bootstrap_finalize(env)
    config = gen_ReplicaConfig()
    config.dirman_password = dirman_password
    config.subject_base = options.subject_base

    remote_api = gen_remote_api(master_host_name, paths.ETC_IPA)
    #installer._remote_api = remote_api

    conn = remote_api.Backend.ldap2
    ccache = os.environ['KRB5CCNAME']

    # There is a api.Backend.ldap2.connect call somewhere in ca, ds, dns or
    # ntpinstance
    api.Backend.ldap2.connect()
    conn.connect(ccache=ccache)

    with redirect_stdout(ansible_log):
        ds = replica_ds_init_info(ansible_log,
                                  config, options, ca_enabled,
                                  remote_api, ds_ca_subject,
                                  ca_file=paths.IPA_CA_CRT,
                                  promote=promote,
                                  pkcs12_info=installer._dirsrv_pkcs12_info)

        ansible_log.debug("-- DS.ENABLE_SSL --")

        # we now need to enable ssl on the ds
        ds.enable_ssl()

    # done #

    ansible_module.exit_json(changed=True)

if __name__ == '__main__':
    main()

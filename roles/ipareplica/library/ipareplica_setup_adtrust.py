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
module: ipareplica_setup_adtrust
short description: Setup adtrust
description:
  Setup adtrust
options:
  setup_adtrust:
    description: 
    required: yes
  setup_kra:
    description: 
    required: yes
  subject_base:
    description: 
    required: yes
  ccache:
    description: 
    required: yes
  _top_dir:
    description: 
    required: yes
  config_setup_ca:
    description: 
    required: yes
  config_master_host_name:
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
            ### server ###
            setup_adtrust=dict(required=False, type='bool'),
            setup_kra=dict(required=False, type='bool'),
            ### certificate system ###
            subject_base=dict(required=True),
            ### additional ###
            ccache=dict(required=True),
            _top_dir = dict(required=True),
            config_setup_ca=dict(required=True),
            config_master_host_name=dict(required=True),
        ),
        supports_check_mode = True,
    )

    ansible_module._ansible_debug = True
    ansible_log = AnsibleModuleLog(ansible_module)

    # get parameters #

    options = installer
    ### server ###
    options.setup_adtrust = ansible_module.params.get('setup_adtrust')
    options.setup_kra = ansible_module.params.get('setup_kra')
    ### certificate system ###
    options.subject_base = ansible_module.params.get('subject_base')
    if options.subject_base is not None:
        options.subject_base = DN(options.subject_base)
    ### additional ###
    ccache = ansible_module.params.get('ccache')
    os.environ['KRB5CCNAME'] = ccache
    options._top_dir = ansible_module.params.get('_top_dir')
    config_setup_ca = ansible_module.params.get('config_setup_ca')
    config_master_host_name = ansible_module.params.get('config_master_host_name')

    # init #

    fstore = sysrestore.FileStore(paths.SYSRESTORE)
    sstore = sysrestore.StateFile(paths.SYSRESTORE)

    ansible_log.debug("== INSTALL ==")

    options = installer
    promote = installer.promote

    env = gen_env_boostrap_finalize_core(paths.ETC_IPA,
                                         constants.DEFAULT_CONFIG)
    api_bootstrap_finalize(env)
    config = gen_ReplicaConfig()
    config.subject_base = options.subject_base

    remote_api = gen_remote_api(master_host_name, paths.ETC_IPA)
    installer._remote_api = remote_api

    conn = remote_api.Backend.ldap2
    ccache = os.environ['KRB5CCNAME']

    with redirect_stdout(ansible_log):
        #if options.setup_adtrust:
        ansible_log.debug("-- INSTALL ADTRUST --")

        adtrust.install(False, options, fstore, api)

    # done #

    ansible_module.exit_json(changed=True)

if __name__ == '__main__':
    main()

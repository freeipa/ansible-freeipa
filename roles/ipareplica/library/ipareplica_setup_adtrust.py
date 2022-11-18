# -*- coding: utf-8 -*-

# Authors:
#   Thomas Woerner <twoerner@redhat.com>
#
# Based on ipa-replica-install code
#
# Copyright (C) 2018-2022  Red Hat
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
module: ipareplica_setup_adtrust
short_description: Setup adtrust
description:
  Setup adtrust
options:
  setup_kra:
    description: Configure a dogtag KRA
    type: bool
    required: no
  subject_base:
    description:
      The certificate subject base (default O=<realm-name>).
      RDNs are in LDAP order (most specific RDN first).
    type: str
    required: yes
  enable_compat:
    description: Enable support for trusted domains for old clients
    type: bool
    default: no
    required: no
  rid_base:
    description: Start value for mapping UIDs and GIDs to RIDs
    type: int
    required: no
  secondary_rid_base:
    description:
      Start value of the secondary range for mapping UIDs and GIDs to RIDs
    type: int
    required: no
  adtrust_netbios_name:
    description: The adtrust netbios_name setting
    type: str
    required: yes
  adtrust_reset_netbios_name:
    description: The adtrust reset_netbios_name setting
    type: bool
    required: yes
  ccache:
    description: The local ccache
    type: str
    required: yes
  _top_dir:
    description: The installer _top_dir setting
    type: str
    required: yes
  setup_ca:
    description: Configure a dogtag CA
    type: bool
    required: yes
  setup_adtrust:
    description: Configure AD trust capability
    type: bool
    required: yes
  config_master_host_name:
    description: The config master_host_name setting
    type: str
    required: yes
author:
    - Thomas Woerner (@t-woerner)
'''

EXAMPLES = '''
'''

RETURN = '''
'''

import os

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.ansible_ipa_replica import (
    AnsibleModuleLog, setup_logging, installer, DN, paths, sysrestore,
    gen_env_boostrap_finalize_core, constants, api_bootstrap_finalize,
    gen_ReplicaConfig, gen_remote_api, api, redirect_stdout, adtrust,
    check_imports
)


def main():
    ansible_module = AnsibleModule(
        argument_spec=dict(
            # server
            setup_kra=dict(required=False, type='bool'),
            # certificate system
            subject_base=dict(required=True, type='str'),
            # ad trust
            enable_compat=dict(required=False, type='bool', default=False),
            rid_base=dict(required=False, type='int'),
            secondary_rid_base=dict(required=False, type='int'),
            # additional
            adtrust_netbios_name=dict(required=True, type='str'),
            adtrust_reset_netbios_name=dict(required=True, type='bool'),
            # additional
            ccache=dict(required=True, type='str'),
            _top_dir=dict(required=True, type='str'),
            setup_ca=dict(required=True, type='bool'),
            setup_adtrust=dict(required=True, type='bool'),
            config_master_host_name=dict(required=True, type='str'),
        ),
        supports_check_mode=False,
    )

    ansible_module._ansible_debug = True
    check_imports(ansible_module)
    setup_logging()
    ansible_log = AnsibleModuleLog(ansible_module)

    # get parameters #

    options = installer
    # server
    options.setup_kra = ansible_module.params.get('setup_kra')
    # certificate system
    options.subject_base = ansible_module.params.get('subject_base')
    if options.subject_base is not None:
        options.subject_base = DN(options.subject_base)
    # ad trust
    options.enable_compat = ansible_module.params.get('enable_compat')
    options.rid_base = ansible_module.params.get('rid_base')
    options.secondary_rid_base = ansible_module.params.get(
        'secondary_rid_base')
    # additional
    ccache = ansible_module.params.get('ccache')
    os.environ['KRB5CCNAME'] = ccache
    options._top_dir = ansible_module.params.get('_top_dir')
    options.setup_ca = ansible_module.params.get('setup_ca')
    options.setup_adtrust = ansible_module.params.get('setup_adtrust')
    config_master_host_name = ansible_module.params.get(
        'config_master_host_name')
    adtrust.netbios_name = ansible_module.params.get('adtrust_netbios_name')
    adtrust.reset_netbios_name = ansible_module.params.get(
        'adtrust_reset_netbios_name')

    # init #

    fstore = sysrestore.FileStore(paths.SYSRESTORE)

    ansible_log.debug("== INSTALL ==")

    env = gen_env_boostrap_finalize_core(paths.ETC_IPA,
                                         constants.DEFAULT_CONFIG)
    api_bootstrap_finalize(env)
    config = gen_ReplicaConfig()
    config.subject_base = options.subject_base
    config.master_host_name = config_master_host_name

    remote_api = gen_remote_api(config.master_host_name, paths.ETC_IPA)
    installer._remote_api = remote_api

    ccache = os.environ['KRB5CCNAME']

    api.Backend.ldap2.connect()

    with redirect_stdout(ansible_log):
        ansible_log.debug("-- INSTALL ADTRUST --")

        adtrust.install(False, options, fstore, api)

    # done #

    ansible_module.exit_json(changed=True)


if __name__ == '__main__':
    main()

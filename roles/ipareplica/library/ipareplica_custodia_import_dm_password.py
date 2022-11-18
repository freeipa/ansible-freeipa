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
module: ipareplica_custodia_import_dm_password
short_description: Import dm password into custodia
description:
  Import dm password into custodia
options:
  setup_ca:
    description: Configure a dogtag CA
    type: bool
    required: no
  setup_kra:
    description: Configure a dogtag KRA
    type: bool
    required: no
  no_pkinit:
    description: Disable pkinit setup steps
    type: bool
    required: no
  no_ui_redirect:
    description: Do not automatically redirect to the Web UI
    type: bool
    required: no
  subject_base:
    description:
      The certificate subject base (default O=<realm-name>).
      RDNs are in LDAP order (most specific RDN first).
    type: str
    required: yes
  ccache:
    description: The local ccache
    type: str
    required: yes
  _ca_enabled:
    description: The installer _ca_enabled setting
    type: bool
    required: no
  _ca_file:
    description: The installer _ca_file setting
    type: str
    required: no
  _kra_enabled:
    description: The installer _kra_enabled setting
    type: bool
    required: no
  _kra_host_name:
    description: The installer _kra_host_name setting
    type: str
    required: no
  _top_dir:
    description: The installer _top_dir setting
    type: str
    required: yes
  dirman_password:
    description: Directory Manager (master) password
    type: str
    required: yes
  config_setup_ca:
    description: The config setup_ca setting
    type: bool
    required: yes
  config_master_host_name:
    description: The config master_host_name setting
    type: str
    required: yes
  config_ca_host_name:
    description: The config ca_host_name setting
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
    check_imports, AnsibleModuleLog, setup_logging, installer, DN, paths,
    gen_env_boostrap_finalize_core, constants, api_bootstrap_finalize,
    gen_ReplicaConfig, gen_remote_api, redirect_stdout, custodiainstance,
    getargspec
)


def main():
    ansible_module = AnsibleModule(
        argument_spec=dict(
            # server
            setup_ca=dict(required=False, type='bool'),
            setup_kra=dict(required=False, type='bool'),
            no_pkinit=dict(required=False, type='bool'),
            no_ui_redirect=dict(required=False, type='bool'),
            # certificate system
            subject_base=dict(required=True, type='str'),
            # additional
            ccache=dict(required=True, type='str'),
            _ca_enabled=dict(required=False, type='bool'),
            _ca_file=dict(required=False, type='str'),
            _kra_enabled=dict(required=False, type='bool'),
            _kra_host_name=dict(required=False, type='str'),
            _top_dir=dict(required=True, type='str'),
            dirman_password=dict(required=True, type='str', no_log=True),
            config_setup_ca=dict(required=True, type='bool'),
            config_master_host_name=dict(required=True, type='str'),
            config_ca_host_name=dict(required=True, type='str'),
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
    options.setup_ca = ansible_module.params.get('setup_ca')
    options.setup_kra = ansible_module.params.get('setup_kra')
    options.no_pkinit = ansible_module.params.get('no_pkinit')
    # certificate system
    options.subject_base = ansible_module.params.get('subject_base')
    if options.subject_base is not None:
        options.subject_base = DN(options.subject_base)
    # additional
    master_host_name = ansible_module.params.get('config_master_host_name')
    ccache = ansible_module.params.get('ccache')
    os.environ['KRB5CCNAME'] = ccache
    # os.environ['KRB5CCNAME'] = ansible_module.params.get('installer_ccache')
    # installer._ccache = ansible_module.params.get('installer_ccache')
    ca_enabled = ansible_module.params.get('_ca_enabled')
    kra_enabled = ansible_module.params.get('_kra_enabled')
    kra_host_name = ansible_module.params.get('_kra_host_name')
    options._top_dir = ansible_module.params.get('_top_dir')
    dirman_password = ansible_module.params.get('dirman_password')
    config_setup_ca = ansible_module.params.get('config_setup_ca')
    config_ca_host_name = ansible_module.params.get('config_ca_host_name')

    # init #

    ansible_log.debug("== INSTALL ==")

    options = installer

    env = gen_env_boostrap_finalize_core(paths.ETC_IPA,
                                         constants.DEFAULT_CONFIG)
    api_bootstrap_finalize(env)
    config = gen_ReplicaConfig()
    config.dirman_password = dirman_password
    config.setup_ca = config_setup_ca
    config.master_host_name = master_host_name
    config.ca_host_name = config_ca_host_name
    config.subject_base = options.subject_base
    config.promote = installer.promote
    config.kra_enabled = kra_enabled
    config.kra_host_name = kra_host_name

    remote_api = gen_remote_api(config.master_host_name, paths.ETC_IPA)
    installer._remote_api = remote_api

    ccache = os.environ['KRB5CCNAME']

    # do the work #

    with redirect_stdout(ansible_log):
        if not hasattr(custodiainstance, "get_custodia_instance"):
            custodia = custodiainstance.CustodiaInstance(config.host_name,
                                                         config.realm_name)
        else:
            if ca_enabled:
                mode = custodiainstance.CustodiaModes.CA_PEER
            else:
                mode = custodiainstance.CustodiaModes.MASTER_PEER
            custodia = custodiainstance.get_custodia_instance(config, mode)

        ansible_log.debug("-- CUSTODIA IMPORT DM PASSWORD --")

        # pylint: disable=deprecated-method
        argspec = getargspec(custodia.import_dm_password)
        # pylint: enable=deprecated-method
        if "master_host_name" in argspec.args:
            custodia.import_dm_password(config.master_host_name)
        else:
            custodia.import_dm_password()

    # done #

    ansible_module.exit_json(changed=True)


if __name__ == '__main__':
    main()

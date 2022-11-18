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
module: ipareplica_ds_apply_updates
short_description: DS apply updates
description:
  DS apply updates
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
  dirsrv_config_file:
    description:
      The path to LDIF file that will be used to modify configuration of
      dse.ldif during installation of the directory server instance
    type: str
    required: no
  subject_base:
    description:
      The certificate subject base (default O=<realm-name>).
      RDNs are in LDAP order (most specific RDN first).
    type: str
    required: yes
  config_master_host_name:
    description: The config master_host_name setting
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
  _dirsrv_pkcs12_info:
    description: The installer _dirsrv_pkcs12_info setting
    type: list
    elements: str
    required: no
  _pkinit_pkcs12_info:
    description: The installer _pkinit_pkcs12_info setting
    type: list
    elements: str
    required: no
  _top_dir:
    description: The installer _top_dir setting
    type: str
    required: yes
  dirman_password:
    description: Directory Manager (master) password
    type: str
    required: yes
  ds_ca_subject:
    description: The ds.ca_subject setting
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
    gen_ReplicaConfig, gen_remote_api, api, redirect_stdout,
    replica_ds_init_info, dsinstance, upgradeinstance, installutils
)


def main():
    ansible_module = AnsibleModule(
        argument_spec=dict(
            # server
            setup_ca=dict(required=False, type='bool'),
            setup_kra=dict(required=False, type='bool'),
            no_pkinit=dict(required=False, type='bool'),
            no_ui_redirect=dict(required=False, type='bool'),
            dirsrv_config_file=dict(required=False, type='str'),
            # certificate system
            subject_base=dict(required=True, type='str'),
            # additional
            config_master_host_name=dict(required=True, type='str'),
            ccache=dict(required=True, type='str'),
            _ca_enabled=dict(required=False, type='bool'),
            _ca_file=dict(required=False, type='str'),
            _dirsrv_pkcs12_info=dict(required=False, type='list',
                                     elements='str'),
            _pkinit_pkcs12_info=dict(required=False, type='list',
                                     elements='str'),
            _top_dir=dict(required=True, type='str'),
            dirman_password=dict(required=True, type='str', no_log=True),
            ds_ca_subject=dict(required=True, type='str'),
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
    options.dirsrv_config_file = ansible_module.params.get(
        'dirsrv_config_file')
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
    installer._dirsrv_pkcs12_info = ansible_module.params.get(
        '_dirsrv_pkcs12_info')
    installer._pkinit_pkcs12_info = ansible_module.params.get(
        '_pkinit_pkcs12_info')
    options._top_dir = ansible_module.params.get('_top_dir')
    dirman_password = ansible_module.params.get('dirman_password')
    ds_ca_subject = ansible_module.params.get('ds_ca_subject')

    # init #

    ansible_log.debug("== INSTALL ==")

    options = installer
    promote = installer.promote

    env = gen_env_boostrap_finalize_core(paths.ETC_IPA,
                                         constants.DEFAULT_CONFIG)
    api_bootstrap_finalize(env)
    config = gen_ReplicaConfig()
    config.dirman_password = dirman_password
    config.subject_base = options.subject_base
    config.master_host_name = master_host_name

    remote_api = gen_remote_api(master_host_name, paths.ETC_IPA)

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

        ansible_log.debug("-- DS APPLY_UPDATES --")

        # Apply any LDAP updates. Needs to be done after the replica is
        # synced-up
        # service.print_msg("Applying LDAP updates")
        # ds.apply_updates()
        schema_files = dsinstance.get_all_external_schema_files(
            paths.EXTERNAL_SCHEMA_DIR)
        data_upgrade = upgradeinstance.IPAUpgrade(ds.realm,
                                                  schema_files=schema_files)
        data_upgrade.set_output(ansible_log)
        try:
            data_upgrade.create_instance()
        except Exception as e:
            # very fatal errors only will raise exception
            raise RuntimeError("Update failed: %s" % e)
        installutils.store_version()

    # done #

    ansible_module.exit_json(changed=True)


if __name__ == '__main__':
    main()

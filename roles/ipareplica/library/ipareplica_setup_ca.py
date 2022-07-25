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

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

ANSIBLE_METADATA = {
    'metadata_version': '1.0',
    'supported_by': 'community',
    'status': ['preview'],
}

DOCUMENTATION = '''
---
module: ipareplica_setup_ca
short description: Setup CA
description:
  Setup CA
options:
  pki_config_override:
    description: Path to ini file with config overrides
    required: yes
  setup_ca:
    description: Configure a dogtag CA
    required: yes
  setup_kra:
    description: Configure a dogtag KRA
    required: yes
  no_pkinit:
    description: Disable pkinit setup steps
    required: yes
  subject_base:
    description:
      The certificate subject base (default O=<realm-name>).
      RDNs are in LDAP order (most specific RDN first).
    required: no
  ccache:
    description: The local ccache
    required: no
  _ca_enabled:
    description: The installer _ca_enabled setting
    required: yes
  _ca_file:
    description: The installer _ca_file setting
    required: yes
  _kra_enabled:
    description: The installer _kra_enabled setting
    required: yes
  _kra_host_name:
    description: The installer _kra_host_name setting
    required: yes
  _dirsrv_pkcs12_info:
    description: The installer _dirsrv_pkcs12_info setting
    required: yes
  _pkinit_pkcs12_info:
    description: The installer _pkinit_pkcs12_info setting
    required: yes
  _top_dir:
    description: The installer _top_dir setting
    required: no
  _ca_subject:
    description: The installer _ca_subject setting
    required: no
  _subject_base:
    description: The installer _subject_base setting
    required: no
  _random_serial_numbers:
    description: The installer _random_serial_numbers setting
    required: yes
  dirman_password:
    description: Directory Manager (master) password
    required: no
  config_setup_ca:
    description: The config setup_ca setting
    required: no
  config_master_host_name:
    description: The config master_host_name setting
    required: no
  config_ca_host_name:
    description: The config ca_host_name setting
    required: no
  config_ips:
    description: The config ips setting
    required: yes
author:
    - Thomas Woerner
'''

EXAMPLES = '''
'''

RETURN = '''
'''

import os

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.ansible_ipa_replica import (
    AnsibleModuleLog, setup_logging, installer, DN, paths,
    ansible_module_get_parsed_ip_addresses,
    gen_env_boostrap_finalize_core, constants, api_bootstrap_finalize,
    gen_ReplicaConfig, gen_remote_api, api, redirect_stdout, ca,
    custodiainstance
)


def main():
    ansible_module = AnsibleModule(
        argument_spec=dict(
            # basic
            pki_config_override=dict(required=False),
            # server
            setup_ca=dict(required=False, type='bool'),
            setup_kra=dict(required=False, type='bool'),
            no_pkinit=dict(required=False, type='bool'),
            # certificate system
            subject_base=dict(required=True),
            # additional
            ccache=dict(required=True),
            _ca_enabled=dict(required=False, type='bool'),
            _ca_file=dict(required=False),
            _kra_enabled=dict(required=False, type='bool'),
            _kra_host_name=dict(required=False),
            _dirsrv_pkcs12_info=dict(required=False, type='list'),
            _pkinit_pkcs12_info=dict(required=False, type='list'),
            _top_dir=dict(required=True),
            _ca_subject=dict(required=True),
            _subject_base=dict(required=True),
            _random_serial_numbers=dict(required=True, type='bool'),
            dirman_password=dict(required=True, no_log=True),
            config_setup_ca=dict(required=True, type='bool'),
            config_master_host_name=dict(required=True),
            config_ca_host_name=dict(required=True),
            config_ips=dict(required=False, type='list', default=[]),
        ),
        supports_check_mode=True,
    )

    ansible_module._ansible_debug = True
    setup_logging()
    ansible_log = AnsibleModuleLog(ansible_module)

    # get parameters #

    options = installer
    # basic
    options.pki_config_override = ansible_module.params.get(
        'pki_config_override')
    # server
    options.setup_ca = ansible_module.params.get('setup_ca')
    options.setup_kra = ansible_module.params.get('setup_kra')
    options.no_pkinit = ansible_module.params.get('no_pkinit')
    # certificate system
    options.subject_base = ansible_module.params.get('subject_base')
    if options.subject_base is not None:
        options.subject_base = DN(options.subject_base)
    # additional
    ccache = ansible_module.params.get('ccache')
    os.environ['KRB5CCNAME'] = ccache
    # os.environ['KRB5CCNAME'] = ansible_module.params.get('installer_ccache')
    # installer._ccache = ansible_module.params.get('installer_ccache')
    ca_enabled = ansible_module.params.get('_ca_enabled')
    kra_enabled = ansible_module.params.get('_kra_enabled')
    kra_host_name = ansible_module.params.get('_kra_host_name')
    installer._dirsrv_pkcs12_info = ansible_module.params.get(
        '_dirsrv_pkcs12_info')
    installer._pkinit_pkcs12_info = ansible_module.params.get(
        '_pkinit_pkcs12_info')
    options._top_dir = ansible_module.params.get('_top_dir')
    options._ca_subject = ansible_module.params.get('_ca_subject')
    if options._ca_subject is not None:
        options._ca_subject = DN(options._ca_subject)
    options._subject_base = ansible_module.params.get('_subject_base')
    if options._subject_base is not None:
        options._subject_base = DN(options._subject_base)
    options._random_serial_numbers = ansible_module.params.get(
        '_random_serial_numbers')
    dirman_password = ansible_module.params.get('dirman_password')
    config_setup_ca = ansible_module.params.get('config_setup_ca')
    config_master_host_name = ansible_module.params.get(
        'config_master_host_name')
    config_ca_host_name = ansible_module.params.get('config_ca_host_name')
    config_ips = ansible_module_get_parsed_ip_addresses(ansible_module,
                                                        "config_ips")

    # init #

    ansible_log.debug("== INSTALL ==")

    options = installer

    env = gen_env_boostrap_finalize_core(paths.ETC_IPA,
                                         constants.DEFAULT_CONFIG)
    api_bootstrap_finalize(env)

    config = gen_ReplicaConfig()
    config.dirman_password = dirman_password
    config.setup_ca = config_setup_ca
    config.master_host_name = config_master_host_name
    config.ca_host_name = config_ca_host_name
    config.ips = config_ips
    config.promote = options.promote
    config.kra_enabled = kra_enabled
    config.kra_host_name = kra_host_name

    remote_api = gen_remote_api(config.master_host_name, paths.ETC_IPA)
    options._remote_api = remote_api

    ccache = os.environ['KRB5CCNAME']

    # There is a api.Backend.ldap2.connect call somewhere in ca, ds, dns or
    # ntpinstance
    api.Backend.ldap2.connect()
    # conn.connect(ccache=ccache)

    ansible_log.debug("-- INSTALL CA --")

    with redirect_stdout(ansible_log):
        options.realm_name = config.realm_name
        options.domain_name = config.domain_name
        options.host_name = config.host_name
        options.dm_password = config.dirman_password

        if not hasattr(custodiainstance, "get_custodia_instance"):
            ca.install(False, config, options)
        else:
            if kra_enabled:
                # A KRA peer always provides a CA, too.
                mode = custodiainstance.CustodiaModes.KRA_PEER
            elif ca_enabled:
                mode = custodiainstance.CustodiaModes.CA_PEER
            else:
                mode = custodiainstance.CustodiaModes.MASTER_PEER
            custodia = custodiainstance.get_custodia_instance(config, mode)

            ca.install(False, config, options, custodia=custodia)

    # done #

    ansible_module.exit_json(changed=True)


if __name__ == '__main__':
    main()

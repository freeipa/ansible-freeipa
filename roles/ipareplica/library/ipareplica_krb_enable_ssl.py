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
module: ipareplica_krb_enable_ssl
short description: KRB enable SSL
description:
  KRB enable SSL
options:
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
  config_master_host_name:
    description: The config master_host_name setting
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
  _pkinit_pkcs12_info:
    description: The installer _pkinit_pkcs12_info setting
    required: yes
  _top_dir:
    description: The installer _top_dir setting
    required: no
  dirman_password:
    description: Directory Manager (master) password
    required: no
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
    AnsibleModuleLog, setup_logging, installer, DN, paths, sysrestore,
    gen_env_boostrap_finalize_core, constants, api_bootstrap_finalize,
    gen_ReplicaConfig, gen_remote_api, api, krbinstance, redirect_stdout
)


def main():
    ansible_module = AnsibleModule(
        argument_spec=dict(
            # server
            setup_ca=dict(required=False, type='bool'),
            setup_kra=dict(required=False, type='bool'),
            no_pkinit=dict(required=False, type='bool'),
            # certificate system
            subject_base=dict(required=True),
            # additional
            config_master_host_name=dict(required=True),
            ccache=dict(required=True),
            _ca_enabled=dict(required=False, type='bool'),
            _ca_file=dict(required=False),
            _pkinit_pkcs12_info=dict(required=False, type='list'),
            _top_dir=dict(required=True),
            dirman_password=dict(required=True, no_log=True),
        ),
        supports_check_mode=True,
    )

    ansible_module._ansible_debug = True
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
    options._pkinit_pkcs12_info = ansible_module.params.get(
        '_pkinit_pkcs12_info')
    options._top_dir = ansible_module.params.get('_top_dir')
    dirman_password = ansible_module.params.get('dirman_password')

    # init #

    fstore = sysrestore.FileStore(paths.SYSRESTORE)

    ansible_log.debug("== INSTALL ==")

    options = installer

    env = gen_env_boostrap_finalize_core(paths.ETC_IPA,
                                         constants.DEFAULT_CONFIG)
    api_bootstrap_finalize(env)
    config = gen_ReplicaConfig()
    config.dirman_password = dirman_password

    remote_api = gen_remote_api(master_host_name, paths.ETC_IPA)
    # installer._remote_api = remote_api

    conn = remote_api.Backend.ldap2
    ccache = os.environ['KRB5CCNAME']

    # There is a api.Backend.ldap2.connect call somewhere in ca, ds, dns or
    # ntpinstance
    api.Backend.ldap2.connect()
    conn.connect(ccache=ccache)

    # krb
    krb = krbinstance.KrbInstance(fstore)
    krb.set_output(ansible_log)
    with redirect_stdout(ansible_log):
        krb.init_info(api.env.realm, api.env.host,
                      setup_pkinit=not options.no_pkinit,
                      subject_base=options.subject_base)
        krb.pkcs12_info = options._pkinit_pkcs12_info
        krb.master_fqdn = master_host_name

        ansible_log.debug("-- KRB ENABLE_SSL --")

        # configure PKINIT now that all required services are in place
        krb.enable_ssl()

    # done #

    ansible_module.exit_json(changed=True)


if __name__ == '__main__':
    main()

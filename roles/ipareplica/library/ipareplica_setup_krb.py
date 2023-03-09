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
module: ipareplica_setup_krb
short_description: Setup KRB
description:
  Setup KRB
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
author:
    - Thomas Woerner (@t-woerner)
'''

EXAMPLES = '''
'''

RETURN = '''
'''

import os

from ansible.module_utils.ansible_ipa_replica import (
    check_imports,
    AnsibleModuleLog, setup_logging, installer, DN, paths, sysrestore,
    gen_env_boostrap_finalize_core, constants, api_bootstrap_finalize,
    gen_ReplicaConfig, api, redirect_stdout, install_krb, getargspec,
    IPAAnsibleModule
)


def main():
    ansible_module = IPAAnsibleModule(
        argument_spec=dict(
            # server
            setup_ca=dict(required=False, type='bool'),
            setup_kra=dict(required=False, type='bool'),
            no_pkinit=dict(required=False, type='bool'),
            # certificate system
            subject_base=dict(required=True, type='str'),
            # additional
            config_master_host_name=dict(required=True, type='str'),
            ccache=dict(required=True, type='str'),
            _pkinit_pkcs12_info=dict(required=False, type='list',
                                     elements='str'),
            _top_dir=dict(required=True, type='str'),
            dirman_password=dict(required=True, type='str', no_log=True),
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
    config_master_host_name = ansible_module.params.get(
        'config_master_host_name')
    ccache = ansible_module.params.get('ccache')
    os.environ['KRB5CCNAME'] = ccache
    installer._pkinit_pkcs12_info = ansible_module.params.get(
        '_pkinit_pkcs12_info')

    options._top_dir = ansible_module.params.get('_top_dir')
    dirman_password = ansible_module.params.get('dirman_password')

    # init #

    fstore = sysrestore.FileStore(paths.SYSRESTORE)

    ansible_log.debug("== INSTALL ==")

    options = installer
    promote = installer.promote
    pkinit_pkcs12_info = installer._pkinit_pkcs12_info

    env = gen_env_boostrap_finalize_core(paths.ETC_IPA,
                                         constants.DEFAULT_CONFIG)
    api_bootstrap_finalize(env)
    config = gen_ReplicaConfig()
    config.dirman_password = dirman_password
    config.master_host_name = config_master_host_name
    config.subject_base = options.subject_base
    config.setup_ca = options.setup_ca

    ccache = os.environ['KRB5CCNAME']

    # There is a api.Backend.ldap2.connect call somewhere in ca, ds, dns or
    # ntpinstance
    api.Backend.ldap2.connect()

    ansible_log.debug("-- INSTALL_KRB --")

    with redirect_stdout(ansible_log):
        # pylint: disable=deprecated-method
        argspec = getargspec(install_krb)
        # pylint: enable=deprecated-method
        if "promote" in argspec.args:
            install_krb(
                config,
                setup_pkinit=not options.no_pkinit,
                pkcs12_info=pkinit_pkcs12_info,
                promote=promote)
        else:
            if "fstore" not in argspec.args:
                install_krb(
                    config,
                    setup_pkinit=not options.no_pkinit,
                    pkcs12_info=pkinit_pkcs12_info)
            else:
                install_krb(
                    config,
                    setup_pkinit=not options.no_pkinit,
                    pkcs12_info=pkinit_pkcs12_info,
                    fstore=fstore)

    # done #

    ansible_module.exit_raw_json(
        changed=True,
        config_master_host_name=config.master_host_name
    )


if __name__ == '__main__':
    main()

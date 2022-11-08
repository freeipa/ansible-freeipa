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
module: ipareplica_create_ipa_conf
short_description: Create ipa.conf
description:
  Create ipa.conf
options:
  dm_password:
    description: Directory Manager password
    type: str
    required: no
  password:
    description: Admin user kerberos password
    type: str
    required: no
  ip_addresses:
    description: List of Master Server IP Addresses
    type: list
    elements: str
    required: no
  domain:
    description: Primary DNS domain of the IPA deployment
    type: str
    required: no
  realm:
    description: Kerberos realm name of the IPA deployment
    type: str
    required: no
  hostname:
    description: Fully qualified name of this host
    type: str
    required: no
  ca_cert_files:
    description:
      List of files containing CA certificates for the service certificate
      files
    type: list
    elements: str
    required: no
  no_host_dns:
    description: Do not use DNS for hostname lookup during installation
    type: bool
    default: no
    required: no
  setup_adtrust:
    description: Configure AD trust capability
    type: bool
    required: no
  setup_ca:
    description: Configure a dogtag CA
    type: bool
    required: no
  setup_kra:
    description: Configure a dogtag KRA
    type: bool
    required: no
  setup_dns:
    description: Configure bind with our zone
    type: bool
    required: no
  dirsrv_cert_files:
    description:
      Files containing the Directory Server SSL certificate and private key
    type: list
    elements: str
    required: no
  force_join:
    description: Force client enrollment even if already enrolled
    type: bool
    required: no
  subject_base:
    description:
      The certificate subject base (default O=<realm-name>).
      RDNs are in LDAP order (most specific RDN first).
    type: str
    required: yes
  server:
    description: Fully qualified name of IPA server to enroll to
    type: str
    required: yes
  config_master_host_name:
    description: The config master_host_name setting
    type: str
    required: yes
  config_ca_host_name:
    description: The config ca_host_name setting
    type: str
    required: yes
  ccache:
    description: The local ccache
    type: str
    required: yes
  installer_ccache:
    description: The installer ccache setting
    type: str
    required: yes
  _ca_enabled:
    description: The installer _ca_enabled setting
    type: bool
    required: no
  _top_dir:
    description: The installer _top_dir setting
    type: str
    required: yes
  _add_to_ipaservers:
    description: The installer _add_to_ipaservers setting
    type: bool
    required: yes
  _ca_subject:
    description: The installer _ca_subject setting
    type: str
    required: yes
  _subject_base:
    description: The installer _subject_base setting
    type: str
    required: yes
  master:
    description: Master host name
    type: str
    required: no
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

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.ansible_ipa_replica import (
    check_imports, AnsibleModuleLog, setup_logging, installer, DN, paths,
    ansible_module_get_parsed_ip_addresses, sysrestore,
    gen_env_boostrap_finalize_core, constants, api_bootstrap_finalize,
    gen_ReplicaConfig, gen_remote_api, create_ipa_conf
)


def main():
    ansible_module = AnsibleModule(
        argument_spec=dict(
            # basic
            dm_password=dict(required=False, type='str', no_log=True),
            password=dict(required=False, type='str', no_log=True),
            ip_addresses=dict(required=False, type='list', elements='str',
                              default=[]),
            domain=dict(required=False, type='str'),
            realm=dict(required=False, type='str'),
            hostname=dict(required=False, type='str'),
            ca_cert_files=dict(required=False, type='list', elements='str',
                               default=[]),
            no_host_dns=dict(required=False, type='bool', default=False),
            # server
            setup_adtrust=dict(required=False, type='bool'),
            setup_ca=dict(required=False, type='bool'),
            setup_kra=dict(required=False, type='bool'),
            setup_dns=dict(required=False, type='bool'),
            # ssl certificate
            dirsrv_cert_files=dict(required=False, type='list', elements='str',
                                   default=[]),
            # client
            force_join=dict(required=False, type='bool'),
            # certificate system
            subject_base=dict(required=True, type='str'),
            # additional
            server=dict(required=True, type='str'),
            config_master_host_name=dict(required=True, type='str'),
            config_ca_host_name=dict(required=True, type='str'),
            ccache=dict(required=True, type='str'),
            installer_ccache=dict(required=True, type='str'),
            _ca_enabled=dict(required=False, type='bool'),
            _top_dir=dict(required=True, type='str'),
            _add_to_ipaservers=dict(required=True, type='bool'),
            _ca_subject=dict(required=True, type='str'),
            _subject_base=dict(required=True, type='str'),
            master=dict(required=False, type='str', default=None),

            dirman_password=dict(required=True, no_log=True),
        ),
        supports_check_mode=False,
    )

    ansible_module._ansible_debug = True
    check_imports(ansible_module)
    setup_logging()
    ansible_log = AnsibleModuleLog(ansible_module)

    # get parameters #

    options = installer
    options.dm_password = ansible_module.params.get('dm_password')
    options.password = options.dm_password
    options.admin_password = ansible_module.params.get('password')
    options.ip_addresses = ansible_module_get_parsed_ip_addresses(
        ansible_module)
    options.domain_name = ansible_module.params.get('domain')
    options.realm_name = ansible_module.params.get('realm')
    options.host_name = ansible_module.params.get('hostname')
    options.ca_cert_files = ansible_module.params.get('ca_cert_files')
    options.no_host_dns = ansible_module.params.get('no_host_dns')
    # server
    options.setup_adtrust = ansible_module.params.get('setup_adtrust')
    options.setup_ca = ansible_module.params.get('setup_ca')
    options.setup_kra = ansible_module.params.get('setup_kra')
    options.setup_dns = ansible_module.params.get('setup_dns')
    # ssl certificate
    options.dirsrv_cert_files = ansible_module.params.get('dirsrv_cert_files')
    # client
    options.force_join = ansible_module.params.get('force_join')
    # certificate system
    options.external_ca = ansible_module.params.get('external_ca')
    options.external_cert_files = ansible_module.params.get(
        'external_cert_files')
    options.subject_base = ansible_module.params.get('subject_base')
    if options.subject_base is not None:
        options.subject_base = DN(options.subject_base)
    options.ca_subject = ansible_module.params.get('ca_subject')
    # additional
    # options._host_name_overridden = ansible_module.params.get(
    #     '_hostname_overridden')
    options.server = ansible_module.params.get('server')
    master_host_name = ansible_module.params.get('config_master_host_name')
    ca_host_name = ansible_module.params.get('config_ca_host_name')
    ccache = ansible_module.params.get('ccache')
    os.environ['KRB5CCNAME'] = ccache
    # os.environ['KRB5CCNAME'] = ansible_module.params.get('installer_ccache')
    installer._ccache = ansible_module.params.get('installer_ccache')
    ca_enabled = ansible_module.params.get('_ca_enabled')

    options.subject_base = ansible_module.params.get('subject_base')
    if options.subject_base is not None:
        options.subject_base = DN(options.subject_base)
    options._top_dir = ansible_module.params.get('_top_dir')
    options._add_to_ipaservers = ansible_module.params.get(
        '_add_to_ipaservers')

    options._ca_subject = ansible_module.params.get('_ca_subject')
    options._subject_base = ansible_module.params.get('_subject_base')
    master = ansible_module.params.get('master')

    dirman_password = ansible_module.params.get('dirman_password')

    # init #

    fstore = sysrestore.FileStore(paths.SYSRESTORE)

    # prepare (install prepare, install checks) #

    ansible_log.debug("== INSTALL ==")

    options = installer
    promote = installer.promote

    env = gen_env_boostrap_finalize_core(paths.ETC_IPA,
                                         constants.DEFAULT_CONFIG)
    api_bootstrap_finalize(env)
    config = gen_ReplicaConfig()
    config.subject_base = options.subject_base
    config.dirman_password = dirman_password
    config.ca_host_name = ca_host_name
    config.setup_ca = options.setup_ca

    remote_api = gen_remote_api(master_host_name, paths.ETC_IPA)
    installer._remote_api = remote_api

    ccache = os.environ['KRB5CCNAME']

    if promote:
        ansible_log.debug("-- CREATE_IPA_CONF --")
        # Create the management framework config file. Do this irregardless
        # of the state of DS installation. Even if it fails,
        # we need to have master-like configuration in order to perform a
        # successful uninstallation
        # The configuration creation has to be here otherwise previous call
        # To config certmonger would try to connect to local server
        create_ipa_conf(fstore, config, ca_enabled, master)

    # done #

    ansible_module.exit_json(changed=True)


if __name__ == '__main__':
    main()

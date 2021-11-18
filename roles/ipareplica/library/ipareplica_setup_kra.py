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
module: ipareplica_setup_kra
short description: Setup KRA
description:
  Setup KRA
options:
  dm_password:
    description: Directory Manager password
    required: yes
  password:
    description: Admin user kerberos password
    required: yes
  ip_addresses:
    description: List of Master Server IP Addresses
    required: yes
  domain:
    description: Primary DNS domain of the IPA deployment
    required: yes
  realm:
    description: Kerberos realm name of the IPA deployment
    required: yes
  hostname:
    description: Fully qualified name of this host
    required: yes
  ca_cert_files:
    description:
      List of files containing CA certificates for the service certificate
      files
    required: yes
  no_host_dns:
    description: Do not use DNS for hostname lookup during installation
    required: yes
  pki_config_override:
    description: Path to ini file with config overrides
    required: yes
  setup_adtrust:
    description: Configure AD trust capability
    required: yes
  setup_ca:
    description: Configure a dogtag CA
    required: yes
  setup_kra:
    description: Configure a dogtag KRA
    required: yes
  setup_dns:
    description: Configure bind with our zone
    required: yes
  dirsrv_cert_files:
    description:
      Files containing the Directory Server SSL certificate and private key
    required: yes
  force_join:
    description: Force client enrollment even if already enrolled
    required: yes
  subject_base:
    description:
      The certificate subject base (default O=<realm-name>).
      RDNs are in LDAP order (most specific RDN first).
    required: no
  server:
    description: Fully qualified name of IPA server to enroll to
    required: no
  config_master_host_name:
    description: The config master_host_name setting
    required: no
  installer_ccache:
    description: The installer ccache setting
    required: no
  _ca_enabled:
    description: The installer _ca_enabled setting
    required: yes
  _kra_enabled:
    description: The installer _kra_enabled setting
    required: yes
  _kra_host_name:
    description: The installer _kra_host_name setting
    required: yes
  _top_dir:
    description: The installer _top_dir setting
    required: no
  _add_to_ipaservers:
    description: The installer _add_to_ipaservers setting
    required: no
  _ca_subject:
    description: The installer _ca_subject setting
    required: no
  _subject_base:
    description: The installer _subject_base setting
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
    AnsibleModuleLog, setup_logging, installer, DN, paths,
    ansible_module_get_parsed_ip_addresses,
    gen_env_boostrap_finalize_core, constants, api_bootstrap_finalize,
    gen_ReplicaConfig, gen_remote_api, api, redirect_stdout, custodiainstance,
    kra
)


def main():
    ansible_module = AnsibleModule(
        argument_spec=dict(
            # basic
            dm_password=dict(required=False, no_log=True),
            password=dict(required=False, no_log=True),
            ip_addresses=dict(required=False, type='list', default=[]),
            domain=dict(required=False),
            realm=dict(required=False),
            hostname=dict(required=False),
            ca_cert_files=dict(required=False, type='list', default=[]),
            no_host_dns=dict(required=False, type='bool', default=False),
            pki_config_override=dict(required=False),
            # server
            setup_adtrust=dict(required=False, type='bool'),
            setup_ca=dict(required=False, type='bool'),
            setup_kra=dict(required=False, type='bool'),
            setup_dns=dict(required=False, type='bool'),
            # ssl certificate
            dirsrv_cert_files=dict(required=False, type='list', default=[]),
            # client
            force_join=dict(required=False, type='bool'),
            # certificate system
            subject_base=dict(required=True),
            # additional
            server=dict(required=True),
            config_master_host_name=dict(required=True),
            installer_ccache=dict(required=True),
            _ca_enabled=dict(required=False, type='bool'),
            _kra_enabled=dict(required=False, type='bool'),
            _kra_host_name=dict(required=False),
            _ca_host_name=dict(required=False),
            _top_dir=dict(required=True),
            _add_to_ipaservers=dict(required=True, type='bool'),
            _ca_subject=dict(required=True),
            _subject_base=dict(required=True),
            dirman_password=dict(required=True, no_log=True),
        ),
        supports_check_mode=True,
    )

    ansible_module._ansible_debug = True
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
    options.pki_config_override = ansible_module.params.get(
        'pki_config_override')
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
    # dns
    options.reverse_zones = ansible_module.params.get('reverse_zones')
    options.no_reverse = ansible_module.params.get('no_reverse')
    options.auto_reverse = ansible_module.params.get('auto_reverse')
    options.forwarders = ansible_module.params.get('forwarders')
    options.no_forwarders = ansible_module.params.get('no_forwarders')
    options.auto_forwarders = ansible_module.params.get('auto_forwarders')
    options.forward_policy = ansible_module.params.get('forward_policy')
    # additional
    options.server = ansible_module.params.get('server')
    master_host_name = ansible_module.params.get('config_master_host_name')
    os.environ['KRB5CCNAME'] = ansible_module.params.get('installer_ccache')
    installer._ccache = ansible_module.params.get('installer_ccache')
    ca_enabled = ansible_module.params.get('_ca_enabled')
    kra_enabled = ansible_module.params.get('_kra_enabled')
    kra_host_name = ansible_module.params.get('_kra_host_name')
    ca_host_name = ansible_module.params.get('_ca_host_name')

    options.subject_base = ansible_module.params.get('subject_base')
    if options.subject_base is not None:
        options.subject_base = DN(options.subject_base)
    options._top_dir = ansible_module.params.get('_top_dir')
    options._add_to_ipaservers = ansible_module.params.get(
        '_add_to_ipaservers')

    options._ca_subject = ansible_module.params.get('_ca_subject')
    options._subject_base = ansible_module.params.get('_subject_base')
    dirman_password = ansible_module.params.get('dirman_password')

    # init #

    ansible_log.debug("== INSTALL ==")

    options = installer

    env = gen_env_boostrap_finalize_core(paths.ETC_IPA,
                                         constants.DEFAULT_CONFIG)
    api_bootstrap_finalize(env)
    config = gen_ReplicaConfig()
    config.dirman_password = dirman_password
    config.subject_base = options.subject_base
    config.promote = installer.promote
    config.kra_enabled = kra_enabled
    config.kra_host_name = kra_host_name
    config.ca_host_name = ca_host_name
    config.master_host_name = master_host_name

    remote_api = gen_remote_api(master_host_name, paths.ETC_IPA)
    installer._remote_api = remote_api

    conn = remote_api.Backend.ldap2
    ccache = os.environ['KRB5CCNAME']

    # There is a api.Backend.ldap2.connect call somewhere in ca, ds, dns or
    # ntpinstance
    api.Backend.ldap2.connect()
    conn.connect(ccache=ccache)

    with redirect_stdout(ansible_log):
        ansible_log.debug("-- INSTALL KRA --")

        if not hasattr(custodiainstance, "get_custodia_instance"):
            kra.install(api, config, options)
        else:
            if ca_enabled:
                mode = custodiainstance.CustodiaModes.CA_PEER
            else:
                mode = custodiainstance.CustodiaModes.MASTER_PEER
            custodia = custodiainstance.get_custodia_instance(config, mode)

            kra.install(api, config, options, custodia=custodia)

    # done #

    ansible_module.exit_json(changed=True)


if __name__ == '__main__':
    main()

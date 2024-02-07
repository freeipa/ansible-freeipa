# -*- coding: utf-8 -*-

# Authors:
#   Thomas Woerner <twoerner@redhat.com>
#
# Based on ipa-client-install code
#
# Copyright (C) 2017-2022  Red Hat
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
module: ipaserver_set_ds_password
short_description: Set DS password
description: Set DS password
options:
  dm_password:
    description: Directory Manager password
    type: str
    required: yes
  password:
    description: Admin user kerberos password
    type: str
    required: yes
  domain:
    description: Primary DNS domain of the IPA deployment
    type: str
    required: yes
  realm:
    description: Kerberos realm name of the IPA deployment
    type: str
    required: yes
  hostname:
    description: Fully qualified name of this host
    type: str
    required: yes
  setup_ca:
    description: Configure a dogtag CA
    type: bool
    required: yes
  idstart:
    description: The starting value for the IDs range (default random)
    type: int
    required: yes
  idmax:
    description: The max value for the IDs range (default idstart+199999)
    type: int
    required: yes
  no_hbac_allow:
    description: Don't install allow_all HBAC rule
    type: bool
    default: no
    required: no
  no_pkinit:
    description: Disable pkinit setup steps
    type: bool
    default: no
    required: no
  dirsrv_config_file:
    description:
      The path to LDIF file that will be used to modify configuration of
      dse.ldif during installation of the directory server instance
    type: str
    required: no
  _dirsrv_pkcs12_info:
    description: The installer _dirsrv_pkcs12_info setting
    type: list
    elements: str
    required: no
  dirsrv_cert_files:
    description:
      Files containing the Directory Server SSL certificate and private key
    type: list
    elements: str
    required: no
  subject_base:
    description:
      The certificate subject base (default O=<realm-name>).
      RDNs are in LDAP order (most specific RDN first).
    type: str
    required: no
  ca_subject:
    description: The installer ca_subject setting
    type: str
    required: no
  external_cert_files:
    description:
      File containing the IPA CA certificate and the external CA certificate
      chain
    type: list
    elements: str
    required: no
  domainlevel:
    description: The domain level
    type: int
    required: no
author:
    - Thomas Woerner (@t-woerner)
'''

EXAMPLES = '''
'''

RETURN = '''
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.ansible_ipa_server import (
    check_imports,
    MAX_DOMAIN_LEVEL, AnsibleModuleLog, options, sysrestore, paths,
    api_Backend_ldap2, ds_init_info, redirect_stdout, setup_logging,
    krbinstance, service
)


def main():
    ansible_module = AnsibleModule(
        argument_spec=dict(
            # basic
            dm_password=dict(required=True, type='str', no_log=True),
            password=dict(required=True, type='str', no_log=True),
            domain=dict(required=True, type='str'),
            realm=dict(required=True, type='str'),
            hostname=dict(required=True, type='str'),
            # server
            setup_ca=dict(required=True, type='bool'),
            idstart=dict(required=True, type='int'),
            idmax=dict(required=True, type='int'),
            no_hbac_allow=dict(required=False, type='bool', default=False),
            no_pkinit=dict(required=False, type='bool', default=False),
            dirsrv_config_file=dict(required=False, type='str'),
            _dirsrv_pkcs12_info=dict(required=False, type='list',
                                     elements='str'),
            # ssl certificate
            dirsrv_cert_files=dict(required=False, type='list', elements='str',
                                   default=[]),
            subject_base=dict(required=False, type='str'),
            ca_subject=dict(required=False, type='str'),
            # certificate system
            external_cert_files=dict(required=False, type='list',
                                     elements='str', default=[]),
            # additional
            domainlevel=dict(required=False, type='int',
                             default=MAX_DOMAIN_LEVEL),
        ),
    )

    ansible_module._ansible_debug = True
    check_imports(ansible_module)
    setup_logging()
    ansible_log = AnsibleModuleLog(ansible_module)

    # set values ####################################################

    # basic
    options.dm_password = ansible_module.params.get('dm_password')
    options.admin_password = ansible_module.params.get('password')
    options.domain_name = ansible_module.params.get('domain')
    options.realm_name = ansible_module.params.get('realm')
    options.host_name = ansible_module.params.get('hostname')
    # server
    options.setup_ca = ansible_module.params.get('setup_ca')
    options.idstart = ansible_module.params.get('idstart')
    options.idmax = ansible_module.params.get('idmax')
    options.no_hbac_allow = ansible_module.params.get('no_hbac_allow')
    options.no_pkinit = ansible_module.params.get('no_pkinit')
    options.dirsrv_config_file = ansible_module.params.get(
        'dirsrv_config_file')
    options._dirsrv_pkcs12_info = ansible_module.params.get(
        '_dirsrv_pkcs12_info')
    # ssl certificate
    options.dirsrv_cert_files = ansible_module.params.get('dirsrv_cert_files')
    options.subject_base = ansible_module.params.get('subject_base')
    options.ca_subject = ansible_module.params.get('ca_subject')
    # certificate system
    options.external_cert_files = ansible_module.params.get(
        'external_cert_files')
    # additional
    options.domainlevel = ansible_module.params.get('domainlevel')
    options.domain_level = options.domainlevel

    # init ##########################################################

    fstore = sysrestore.FileStore(paths.SYSRESTORE)

    api_Backend_ldap2(options.host_name, options.setup_ca, connect=True)

    ds = ds_init_info(ansible_log, fstore,
                      options.domainlevel, options.dirsrv_config_file,
                      options.realm_name, options.host_name,
                      options.domain_name, options.dm_password,
                      options.idstart, options.idmax,
                      options.subject_base, options.ca_subject,
                      options.no_hbac_allow, options._dirsrv_pkcs12_info,
                      options.no_pkinit)

    # set ds password ###############################################

    with redirect_stdout(ansible_log):
        ds.change_admin_password(options.admin_password)

    # Force KDC to refresh the cached value of ipaKrbAuthzData by restarting.
    # ipaKrbAuthzData has to be set with "MS-PAC" to trigger PAC generation,
    # which is required to handle S4U2Proxy with the Bronze-Bit fix.
    # Not doing so would cause API malfunction for around a minute, which is
    # long enough to cause the hereafter client installation to fail.
    krb = krbinstance.KrbInstance(fstore)
    krb.set_output(ansible_log)
    service.print_msg("Restarting the KDC")
    krb.restart()

    # done ##########################################################

    ansible_module.exit_json(changed=True)


if __name__ == '__main__':
    main()

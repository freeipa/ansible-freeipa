#!/usr/bin/python
# -*- coding: utf-8 -*-

# Authors:
#   Thomas Woerner <twoerner@redhat.com>
#
# Based on ipa-client-install code
#
# Copyright (C) 2017  Red Hat
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
module: ipaserver_setup_ds
short description: Configure directory server
description: Configure directory server
options:
  dm_password:
    description: Directory Manager password
    required: no
  password:
    description: Admin user kerberos password
    required: no
  domain:
    description: Primary DNS domain of the IPA deployment
    required: no
  realm:
    description: Kerberos realm name of the IPA deployment
    required: no
  hostname:
    description: Fully qualified name of this host
    required: yes
  idstart:
    description: The starting value for the IDs range (default random)
    required: no
  idmax:
    description: The max value for the IDs range (default idstart+199999)
    required: no
  no_hbac_allow:
    description: Don't install allow_all HBAC rule
    required: yes
  no_pkinit:
    description: Disable pkinit setup steps
    required: yes
  dirsrv_config_file:
    description:
      The path to LDIF file that will be used to modify configuration of
      dse.ldif during installation of the directory server instance
    required: yes
  dirsrv_cert_files:
    description:
      Files containing the Directory Server SSL certificate and private key
    required: yes
  _dirsrv_pkcs12_info:
    description: The installer _dirsrv_pkcs12_info setting
    required: yes
  external_cert_files:
    description:
      File containing the IPA CA certificate and the external CA certificate
      chain
    required: yes
  subject_base:
    description:
      The certificate subject base (default O=<realm-name>).
      RDNs are in LDAP order (most specific RDN first).
    required: yes
  ca_subject:
    description: The installer ca_subject setting
    required: yes
  setup_ca:
    description: Configure a dogtag CA
    required: yes
author:
    - Thomas Woerner
'''

EXAMPLES = '''
'''

RETURN = '''
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.ansible_ipa_server import (
    AnsibleModuleLog, setup_logging, options, sysrestore, paths,
    api_Backend_ldap2, redirect_stdout, api, NUM_VERSION, tasks,
    dsinstance, ntpinstance, IPAAPI_USER
)


def main():
    ansible_module = AnsibleModule(
        argument_spec=dict(
            # basic
            dm_password=dict(required=True, no_log=True),
            password=dict(required=True, no_log=True),
            domain=dict(required=True),
            realm=dict(required=True),
            hostname=dict(required=False),
            # server
            idstart=dict(required=True, type='int'),
            idmax=dict(required=True, type='int'),
            no_hbac_allow=dict(required=False, type='bool', default=False),
            no_pkinit=dict(required=False, type='bool', default=False),
            dirsrv_config_file=dict(required=False),
            # ssl certificate
            dirsrv_cert_files=dict(required=False, type='list', default=[]),
            _dirsrv_pkcs12_info=dict(required=False, type='list'),
            # certificate system
            external_cert_files=dict(required=False, type='list', default=[]),
            subject_base=dict(required=False),
            ca_subject=dict(required=False),

            # additional
            setup_ca=dict(required=False, type='bool', default=False),
        ),
    )

    ansible_module._ansible_debug = True
    setup_logging()
    ansible_log = AnsibleModuleLog(ansible_module)

    # set values ############################################################

    # basic
    options.dm_password = ansible_module.params.get('dm_password')
    options.domain_name = ansible_module.params.get('domain')
    options.realm_name = ansible_module.params.get('realm')
    options.host_name = ansible_module.params.get('hostname')
    # server
    options.idstart = ansible_module.params.get('idstart')
    options.idmax = ansible_module.params.get('idmax')
    options.no_pkinit = ansible_module.params.get('no_pkinit')
    options.no_hbac_allow = ansible_module.params.get('no_hbac_allow')
    options.dirsrv_config_file = ansible_module.params.get(
        'dirsrv_config_file')
    options._dirsrv_pkcs12_info = ansible_module.params.get(
        '_dirsrv_pkcs12_info')
    # ssl certificate
    options.dirsrv_cert_files = ansible_module.params.get('dirsrv_cert_files')
    # certificate system
    options.external_cert_files = ansible_module.params.get(
        'external_cert_files')
    options.subject_base = ansible_module.params.get('subject_base')
    options.ca_subject = ansible_module.params.get('ca_subject')

    # additional
    options.setup_ca = ansible_module.params.get('setup_ca')

    # init ##################################################################

    fstore = sysrestore.FileStore(paths.SYSRESTORE)

    # api Backend connect only if external_cert_files is not set
    api_Backend_ldap2(options.host_name, options.setup_ca, connect=False)

    # setup DS ##############################################################

    # Make sure tmpfiles dir exist before installing components
    if NUM_VERSION == 40504:
        tasks.create_tmpfiles_dirs(IPAAPI_USER)
    elif 40500 <= NUM_VERSION <= 40503:
        tasks.create_tmpfiles_dirs()

    # Create a directory server instance
    if not options.external_cert_files:
        ds = dsinstance.DsInstance(fstore=fstore,
                                   domainlevel=options.domainlevel,
                                   config_ldif=options.dirsrv_config_file)
        ds.set_output(ansible_log)

        if options.dirsrv_cert_files:
            _dirsrv_pkcs12_info = options._dirsrv_pkcs12_info
        else:
            _dirsrv_pkcs12_info = None

        with redirect_stdout(ansible_log):
            ds.create_instance(options.realm_name, options.host_name,
                               options.domain_name,
                               options.dm_password, _dirsrv_pkcs12_info,
                               idstart=options.idstart, idmax=options.idmax,
                               subject_base=options.subject_base,
                               ca_subject=options.ca_subject,
                               hbac_allow=not options.no_hbac_allow,
                               setup_pkinit=not options.no_pkinit)
            if not options.dirsrv_cert_files and NUM_VERSION < 40690:
                ntpinstance.ntp_ldap_enable(options.host_name, ds.suffix,
                                            options.realm_name)

    else:
        api.Backend.ldap2.connect()

        ds = dsinstance.DsInstance(fstore=fstore,
                                   domainlevel=options.domainlevel)
        ds.set_output(ansible_log)

        with redirect_stdout(ansible_log):
            ds.init_info(
                options.realm_name, options.host_name, options.domain_name,
                options.dm_password,
                options.subject_base, options.ca_subject, 1101, 1100, None,
                setup_pkinit=not options.no_pkinit)

    # done ##################################################################

    ansible_module.exit_json(changed=True)


if __name__ == '__main__':
    main()

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
module: ipaserver_setup_ca
short description: 
description:
options:
  dm_password:
  password:
  master_password:
  ip_addresses:
  domain:
  realm:
  hostname:
  no_host_dns:
  setup_adtrust:
  setup_kra:
  setup_dns:
  setup_ca:
  idstart:
  idmax:
  no_hbac_allow:
  no_pkinit:
  dirsrv_config_file:
  dirsrv_cert_files:
  _dirsrv_pkcs12_info:
  external_ca:
  subject_base:
  _subject_base:
  ca_subject:
  _ca_subject:
  ca_signing_algorithm:
  reverse_zones:
  no_reverse:
  auto_forwarders:
  domainlevel:
  _http_ca_cert:
author:
    - Thomas Woerner
'''

EXAMPLES = '''
'''

RETURN = '''
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.ansible_ipa_server import *

def main():
    ansible_module = AnsibleModule(
        argument_spec = dict(
            ### basic ###
            dm_password=dict(required=True, no_log=True),
            password=dict(required=True, no_log=True),
            master_password=dict(required=True, no_log=True),
            ip_addresses=dict(required=False, type='list', default=[]),
            domain=dict(required=True),
            realm=dict(required=True),
            hostname=dict(required=False),
            no_host_dns=dict(required=False, type='bool', default=False),
            ### server ###
            setup_adtrust=dict(required=False, type='bool', default=False),
            setup_kra=dict(required=False, type='bool', default=False),
            setup_dns=dict(required=False, type='bool', default=False),
            setup_ca=dict(required=False, type='bool', default=False),
            idstart=dict(required=True, type='int'),
            idmax=dict(required=True, type='int'),
            no_hbac_allow=dict(required=False, type='bool', default=False),
            no_pkinit=dict(required=False, type='bool', default=False),
            dirsrv_config_file=dict(required=False),
            dirsrv_cert_files=dict(required=False),
            _dirsrv_pkcs12_info=dict(required=False),
            ### certificate system ###
            external_ca=dict(required=False, type='bool', default=False),
            external_cert_files=dict(required=False, type='list', default=[]),
            subject_base=dict(required=False),
            _subject_base=dict(required=False),
            ca_subject=dict(required=False),
            _ca_subject=dict(required=False),
            ca_signing_algorithm=dict(required=False),
            ### dns ###
            reverse_zones=dict(required=False, type='list', default=[]),
            no_reverse=dict(required=False, type='bool', default=False),
            auto_forwarders=dict(required=False, type='bool', default=False),
            ### additional ###
            domainlevel=dict(required=False, type='int'),
            _http_ca_cert=dict(required=False),
        ),
    )

    ansible_module._ansible_debug = True
    ansible_log = AnsibleModuleLog(ansible_module)

    # set values ############################################################

    ### basic ###
    options.dm_password = ansible_module.params.get('dm_password')
    options.admin_password = ansible_module.params.get('password')
    options.master_password = ansible_module.params.get('master_password')
    options.ip_addresses = ansible_module_get_parsed_ip_addresses(
        ansible_module)
    options.domain_name = ansible_module.params.get('domain')
    options.realm_name = ansible_module.params.get('realm')
    options.host_name = ansible_module.params.get('hostname')
    options.no_host_dns = ansible_module.params.get('no_host_dns')
    ### server ###
    options.setup_adtrust = ansible_module.params.get('setup_adtrust')
    options.setup_kra = ansible_module.params.get('setup_kra')
    options.setup_dns = ansible_module.params.get('setup_dns')
    options.setup_ca = ansible_module.params.get('setup_ca')
    options.idstart = ansible_module.params.get('idstart')
    options.idmax = ansible_module.params.get('idmax')
    options.no_hbac_allow = ansible_module.params.get('no_hbac_allow')
    options.no_pkinit = ansible_module.params.get('no_pkinit')
    options.dirsrv_config_file = ansible_module.params.get('dirsrv_config_file')
    options.dirsrv_cert_files = ansible_module.params.get('dirsrv_cert_files')
    options._dirsrv_pkcs12_info = ansible_module.params.get(
        '_dirsrv_pkcs12_info')
    ### certificate system ###
    options.external_ca = ansible_module.params.get('external_ca')
    options.external_cert_files = ansible_module.params.get(
        'external_cert_files')
    options.subject_base = ansible_module.params.get('subject_base')
    options._subject_base = ansible_module.params.get('_subject_base')
    options.ca_subject = ansible_module.params.get('ca_subject')
    options._ca_subject = ansible_module.params.get('_ca_subject')
    options.ca_signing_algorithm = ansible_module.params.get(
        'ca_signing_algorithm')
    ### dns ###
    options.reverse_zones = ansible_module.params.get('reverse_zones')
    options.no_reverse = ansible_module.params.get('no_reverse')
    options.auto_forwarders = ansible_module.params.get('auto_forwarders')
    ### additional ###
    options.domainlevel = ansible_module.params.get('domainlevel')
    options._http_ca_cert = ansible_module.params.get('_http_ca_cert')
    #options._update_hosts_file = ansible_module.params.get('update_hosts_file')

    # init #################################################################

    options.promote = False  # first master, no promotion

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

    # setup CA ##############################################################

    with redirect_stdout(ansible_log):
        if hasattr(custodiainstance, "get_custodia_instance"):
            if hasattr(custodiainstance.CustodiaModes, "FIRST_MASTER"):
                mode = custodiainstance.CustodiaModes.FIRST_MASTER
            else:
                mode = custodiainstance.CustodiaModes.MASTER_PEER
            custodia = custodiainstance.get_custodia_instance(options, mode)
            custodia.create_instance()

        if options.setup_ca:
            if not options.external_cert_files and options.external_ca:
                # stage 1 of external CA installation
                cache_vars = {n: options.__dict__[n] for o, n in options.knobs()
                              if n in options.__dict__}
                write_cache(cache_vars)

            if hasattr(custodiainstance, "get_custodia_instance"):
                ca.install_step_0(False, None, options, custodia=custodia)
            else:
                ca.install_step_0(False, None, options)
        else:
            # Put the CA cert where other instances expect it
            x509.write_certificate(options._http_ca_cert, paths.IPA_CA_CRT)
            os.chmod(paths.IPA_CA_CRT, 0o444)

            if not options.no_pkinit:
                x509.write_certificate(options._http_ca_cert,
                                       paths.KDC_CA_BUNDLE_PEM)
            else:
                with open(paths.KDC_CA_BUNDLE_PEM, 'w'):
                    pass
            os.chmod(paths.KDC_CA_BUNDLE_PEM, 0o444)

            x509.write_certificate(options._http_ca_cert, paths.CA_BUNDLE_PEM)
            os.chmod(paths.CA_BUNDLE_PEM, 0o444)

        # we now need to enable ssl on the ds
        ds.enable_ssl()

        if options.setup_ca:
            with redirect_stdout(ansible_log):
                if hasattr(custodiainstance, "get_custodia_instance"):
                    ca.install_step_1(False, None, options, custodia=custodia)
                else:
                    ca.install_step_1(False, None, options)

    ansible_module.exit_json(changed=True)

if __name__ == '__main__':
    main()

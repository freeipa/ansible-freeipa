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
module: ipaserver_prepare
short description:
description:
options:
  dm_password:
  password:
  ip_addresses:
  domain:
  realm:
  hostname:
  ca_cert_files:
  no_host_dns:
  setup_adtrust:
  setup_kra:
  setup_dns:
  external_ca:
  external_cert_files:
  subject_base:
  ca_subject:
  reverse_zones:
  no_reverse:
  auto_reverse:
  forwarders:
  no_forwarders:
  auto_forwarders:
  forward_policy:
  enable_compat:
  netbios_name:
  rid_base:
  secondary_rid_base:
  setup_ca:
  _hostname_overridden:
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
            force=dict(required=False, type='bool', default=False),
            dm_password=dict(required=True, no_log=True),
            password=dict(required=True, no_log=True),
            ip_addresses=dict(required=False, type='list', default=[]),
            domain=dict(required=True),
            realm=dict(required=True),
            hostname=dict(required=False),
            ca_cert_files=dict(required=False, type='list', default=[]),
            no_host_dns=dict(required=False, type='bool', default=False),
            ### server ###
            setup_adtrust=dict(required=False, type='bool', default=False),
            setup_kra=dict(required=False, type='bool', default=False),
            setup_dns=dict(required=False, type='bool', default=False),
            ### ssl certificate ###
            ### client ###
            ### certificate system ###
            external_ca=dict(required=False),
            external_cert_files=dict(required=False, type='list', default=[]),
            subject_base=dict(required=False),
            ca_subject=dict(required=False),
            ### dns ###
            allow_zone_overlap=dict(required=False, type='bool', default=False),
            reverse_zones=dict(required=False, type='list', default=[]),
            no_reverse=dict(required=False, type='bool', default=False),
            auto_reverse=dict(required=False, type='bool', default=False),
            forwarders=dict(required=False, type='list', default=[]),
            no_forwarders=dict(required=False, type='bool', default=False),
            auto_forwarders=dict(required=False, type='bool', default=False),
            forward_policy=dict(required=False),
            no_dnssec_validation=dict(required=False, type='bool',
                                      default=False),
            ### ad trust ###
            enable_compat=dict(required=False, type='bool', default=False),
            netbios_name=dict(required=False),
            rid_base=dict(required=False, type='int'),
            secondary_rid_base=dict(required=False, type='int'),

            ### additional ###
            setup_ca=dict(required=False, type='bool', default=False),
            _hostname_overridden=dict(required=False, type='bool',
                                       default=False),
        ),
        supports_check_mode = True,
    )

    ansible_module._ansible_debug = True
    ansible_log = AnsibleModuleLog(ansible_module)

    # set values ####################################################

    options.force = ansible_module.params.get('force')
    options.dm_password = ansible_module.params.get('dm_password')
    options.admin_password = ansible_module.params.get('password')
    options.ip_addresses = ansible_module_get_parsed_ip_addresses(
        ansible_module)
    options.domain_name = ansible_module.params.get('domain')
    options.realm_name = ansible_module.params.get('realm')
    options.host_name = ansible_module.params.get('hostname')
    options.ca_cert_files = ansible_module.params.get('ca_cert_files')
    options.no_host_dns = ansible_module.params.get('no_host_dns')
    ### server ###
    options.setup_adtrust = ansible_module.params.get('setup_adtrust')
    options.setup_kra = ansible_module.params.get('setup_kra')
    options.setup_dns = ansible_module.params.get('setup_dns')
    #options.no_pkinit = ansible_module.params.get('no_pkinit')
    ### ssl certificate ###
    #options.dirsrv_cert_files = ansible_module.params.get('dirsrv_cert_files')
    ### client ###
    #options.no_ntp = ansible_module.params.get('no_ntp')
    ### certificate system ###
    options.external_ca = ansible_module.params.get('external_ca')
    options.external_cert_files = ansible_module.params.get(
        'external_cert_files')
    options.subject_base = ansible_module.params.get('subject_base')
    options.ca_subject = ansible_module.params.get('ca_subject')
    ### dns ###
    options.allow_zone_overlap = ansible_module.params.get('allow_zone_overlap')
    options.reverse_zones = ansible_module.params.get('reverse_zones')
    options.no_reverse = ansible_module.params.get('no_reverse')
    options.auto_reverse = ansible_module.params.get('auto_reverse')
    options.forwarders = ansible_module.params.get('forwarders')
    options.no_forwarders = ansible_module.params.get('no_forwarders')
    options.auto_forwarders = ansible_module.params.get('auto_forwarders')
    options.forward_policy = ansible_module.params.get('forward_policy')
    options.no_dnssec_validation = ansible_module.params.get(
        'no_dnssec_validation')
    ### ad trust ###
    options.enable_compat = ansible_module.params.get('enable_compat')
    options.netbios_name = ansible_module.params.get('netbios_name')
    ### additional ###
    options.setup_ca = ansible_module.params.get('setup_ca')
    options._host_name_overridden = ansible_module.params.get(
        '_hostname_overridden')
    options.kasp_db_file = None

    # init ##################################################################

    fstore = sysrestore.FileStore(paths.SYSRESTORE)
    sstore = sysrestore.StateFile(paths.SYSRESTORE)

    # Configuration for ipalib, we will bootstrap and finalize later, after
    # we are sure we have the configuration file ready.
    cfg = dict(
        context='installer',
        confdir=paths.ETC_IPA,
        in_server=True,
        # make sure host name specified by user is used instead of default
        host=options.host_name,
    )
    if options.setup_ca:
        # we have an IPA-integrated CA
        cfg['ca_host'] = options.host_name

    # Create the management framework config file and finalize api
    target_fname = paths.IPA_DEFAULT_CONF
    fd = open(target_fname, "w")
    fd.write("[global]\n")
    fd.write("host=%s\n" % options.host_name)
    fd.write("basedn=%s\n" % ipautil.realm_to_suffix(options.realm_name))
    fd.write("realm=%s\n" % options.realm_name)
    fd.write("domain=%s\n" % options.domain_name)
    fd.write("xmlrpc_uri=https://%s/ipa/xml\n" % \
             ipautil.format_netloc(options.host_name))
    fd.write("ldap_uri=ldapi://%%2fvar%%2frun%%2fslapd-%s.socket\n" % \
             installutils.realm_to_serverid(options.realm_name))
    if options.setup_ca:
        fd.write("enable_ra=True\n")
        fd.write("ra_plugin=dogtag\n")
        fd.write("dogtag_version=10\n")
    else:
        fd.write("enable_ra=False\n")
        fd.write("ra_plugin=none\n")
    fd.write("mode=production\n")
    fd.close()

    # Must be readable for everyone
    os.chmod(target_fname, 0o644)

    api.bootstrap(**cfg)
    api.finalize()

    if options.setup_ca:
        with redirect_stdout(ansible_log):
            ca.install_check(False, None, options)
    if options.setup_kra:
        with redirect_stdout(ansible_log):
            kra.install_check(api, None, options)

    if options.setup_dns:
        with redirect_stdout(ansible_log):
            dns.install_check(False, api, False, options, options.host_name)
        ip_addresses = dns.ip_addresses
    else:
        ip_addresses = get_server_ip_address(options.host_name,
                                             not options.interactive, False,
                                             options.ip_addresses)

        # check addresses here, dns module is doing own check
        no_matching_interface_for_ip_address_warning(ip_addresses)
    options.ip_addresses = ip_addresses
    options.reverse_zones = dns.reverse_zones

    instance_name = "-".join(options.realm_name.split("."))
    dirsrv = services.knownservices.dirsrv
    if (options.external_cert_files
           and dirsrv.is_installed(instance_name)
           and not dirsrv.is_running(instance_name)):
        logger.debug('Starting Directory Server')
        services.knownservices.dirsrv.start(instance_name)

    if options.setup_adtrust:
        with redirect_stdout(ansible_log):
            adtrust.install_check(False, options, api)

    _update_hosts_file = False
    # options needs to update hosts file when DNS subsystem will be
    # installed or custom addresses are used
    if options.ip_addresses or options.setup_dns:
        _update_hosts_file = True

    if options._host_name_overridden:
        tasks.backup_hostname(fstore, sstore)
        tasks.set_hostname(options.host_name)

    if _update_hosts_file:
        update_hosts_file(ip_addresses, options.host_name, fstore)

    ansible_module.exit_json(changed=True)

if __name__ == '__main__':
    main()

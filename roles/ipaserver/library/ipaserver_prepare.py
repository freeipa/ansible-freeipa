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
module: ipaserver_prepare
short_description: Prepare IPA server deployment
description: Prepare IPA server deployment
options:
  force:
    description: Installer force parameter
    type: bool
    default: no
    required: no
  dm_password:
    description: Directory Manager password
    type: str
    required: yes
  password:
    description: Admin user kerberos password
    type: str
    required: yes
  ip_addresses:
    description: List of Master Server IP Addresses
    type: list
    elements: str
    required: no
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
    default: no
    required: no
  setup_kra:
    description: Configure a dogtag KRA
    type: bool
    default: no
    required: no
  setup_dns:
    description: Configure bind with our zone
    type: bool
    default: no
    required: no
  external_ca:
    description: External ca setting
    type: bool
    required: no
  external_ca_type:
    description: Type of the external CA
    type: str
    required: no
  external_ca_profile:
    description:
      Specify the certificate profile/template to use at the external CA
    type: str
    required: no
  external_cert_files:
    description:
      File containing the IPA CA certificate and the external CA certificate
      chain
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
  allow_zone_overlap:
    description: Create DNS zone even if it already exists
    type: bool
    default: no
    required: no
  reverse_zones:
    description: The reverse DNS zones to use
    type: list
    elements: str
    required: no
  no_reverse:
    description: Do not create new reverse DNS zone
    type: bool
    default: no
    required: no
  auto_reverse:
    description: Create necessary reverse zones
    type: bool
    default: no
    required: no
  forwarders:
    description: Add DNS forwarders
    type: list
    elements: str
    required: no
  no_forwarders:
    description: Do not add any DNS forwarders, use root servers instead
    type: bool
    default: no
    required: no
  auto_forwarders:
    description: Use DNS forwarders configured in /etc/resolv.conf
    type: bool
    default: no
    required: no
  forward_policy:
    description: DNS forwarding policy for global forwarders
    type: str
    choices: ['first', 'only']
    required: no
  no_dnssec_validation:
    description: Disable DNSSEC validation
    type: bool
    default: no
    required: no
  enable_compat:
    description: Enable support for trusted domains for old clients
    type: bool
    default: no
    required: no
  netbios_name:
    description: NetBIOS name of the IPA domain
    type: str
    required: no
  rid_base:
    description: Start value for mapping UIDs and GIDs to RIDs
    type: int
    required: no
  secondary_rid_base:
    description:
      Start value of the secondary range for mapping UIDs and GIDs to RIDs
    type: int
    required: no
  setup_ca:
    description: Configure a dogtag CA
    type: bool
    default: no
    required: no
  random_serial_numbers:
    description: Enable random serial numbers
    type: bool
    default: no
    required: no
  sid_generation_always:
    description: Enable SID generation always
    type: bool
    default: no
    required: no
  _hostname_overridden:
    description: The installer _hostname_overridden setting
    type: bool
    default: no
    required: no
author:
    - Thomas Woerner (@t-woerner)
'''

EXAMPLES = '''
'''

RETURN = '''
'''

import os

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.ansible_ipa_server import (
    check_imports, AnsibleModuleLog, setup_logging, options, sysrestore,
    paths, ansible_module_get_parsed_ip_addresses,
    redirect_stdout, adtrust, api, default_subject_base,
    default_ca_subject_dn, ipautil, installutils, ca, kra, dns,
    get_server_ip_address, no_matching_interface_for_ip_address_warning,
    services, logger, tasks, update_hosts_file, ScriptError
)


def main():
    ansible_module = AnsibleModule(
        argument_spec=dict(
            # basic
            force=dict(required=False, type='bool', default=False),
            dm_password=dict(required=True, type='str', no_log=True),
            password=dict(required=True, type='str', no_log=True),
            ip_addresses=dict(required=False, type='list', elements='str',
                              default=[]),
            domain=dict(required=True, type='str'),
            realm=dict(required=True, type='str'),
            hostname=dict(required=False, type='str'),
            ca_cert_files=dict(required=False, type='list', elements='str',
                               default=[]),
            no_host_dns=dict(required=False, type='bool', default=False),
            # server
            setup_adtrust=dict(required=False, type='bool', default=False),
            setup_kra=dict(required=False, type='bool', default=False),
            setup_dns=dict(required=False, type='bool', default=False),
            # ssl certificate
            # client
            # certificate system
            external_ca=dict(required=False, type='bool'),
            external_ca_type=dict(required=False, type='str'),
            external_ca_profile=dict(required=False, type='str'),
            external_cert_files=dict(required=False, type='list',
                                     elements='str', default=[]),
            subject_base=dict(required=False, type='str'),
            ca_subject=dict(required=False, type='str'),
            # dns
            allow_zone_overlap=dict(required=False, type='bool',
                                    default=False),
            reverse_zones=dict(required=False, type='list', elements='str',
                               default=[]),
            no_reverse=dict(required=False, type='bool', default=False),
            auto_reverse=dict(required=False, type='bool', default=False),
            forwarders=dict(required=False, type='list', elements='str',
                            default=[]),
            no_forwarders=dict(required=False, type='bool', default=False),
            auto_forwarders=dict(required=False, type='bool', default=False),
            forward_policy=dict(required=False, type='str',
                                choices=['first', 'only'], default=None),
            no_dnssec_validation=dict(required=False, type='bool',
                                      default=False),
            # ad trust
            enable_compat=dict(required=False, type='bool', default=False),
            netbios_name=dict(required=False, type='str'),
            rid_base=dict(required=False, type='int'),
            secondary_rid_base=dict(required=False, type='int'),

            # additional
            setup_ca=dict(required=False, type='bool', default=False),
            random_serial_numbers=dict(required=False, type='bool',
                                       default=False),
            sid_generation_always=dict(required=False, type='bool',
                                       default=False),
            _hostname_overridden=dict(required=False, type='bool',
                                      default=False),
        ),
        supports_check_mode=False,
    )

    ansible_module._ansible_debug = True
    check_imports(ansible_module)
    setup_logging()
    ansible_log = AnsibleModuleLog(ansible_module)

    # initialize return values for flake ############################

    # These are set by ca.install_check and need to be passed to ca.install
    # in the _setup_ca module and also some others.
    options._subject_base = None
    options._ca_subject = None
    options._random_serial_numbers = False

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
    # server
    options.setup_adtrust = ansible_module.params.get('setup_adtrust')
    options.setup_kra = ansible_module.params.get('setup_kra')
    options.setup_dns = ansible_module.params.get('setup_dns')
    # options.no_pkinit = ansible_module.params.get('no_pkinit')
    # ssl certificate
    # options.dirsrv_cert_files = ansible_module.params.get(
    #     'dirsrv_cert_files')
    # client
    # options.no_ntp = ansible_module.params.get('no_ntp')
    # certificate system
    options.external_ca = ansible_module.params.get('external_ca')
    options.external_ca_type = ansible_module.params.get('external_ca_type')
    options.external_ca_profile = ansible_module.params.get(
        'external_ca_profile')
    options.external_cert_files = ansible_module.params.get(
        'external_cert_files')
    options.subject_base = ansible_module.params.get('subject_base')
    options.ca_subject = ansible_module.params.get('ca_subject')
    # dns
    options.allow_zone_overlap = ansible_module.params.get(
        'allow_zone_overlap')
    options.reverse_zones = ansible_module.params.get('reverse_zones')
    options.no_reverse = ansible_module.params.get('no_reverse')
    options.auto_reverse = ansible_module.params.get('auto_reverse')
    options.forwarders = ansible_module.params.get('forwarders')
    options.no_forwarders = ansible_module.params.get('no_forwarders')
    options.auto_forwarders = ansible_module.params.get('auto_forwarders')
    options.forward_policy = ansible_module.params.get('forward_policy')
    options.no_dnssec_validation = ansible_module.params.get(
        'no_dnssec_validation')
    # ad trust
    options.enable_compat = ansible_module.params.get('enable_compat')
    options.netbios_name = ansible_module.params.get('netbios_name')
    # additional
    options.setup_ca = ansible_module.params.get('setup_ca')
    options.random_serial_numbers = ansible_module.params.get(
        'random_serial_numbers')
    options._host_name_overridden = ansible_module.params.get(
        '_hostname_overridden')
    sid_generation_always = ansible_module.params.get('sid_generation_always')
    options.kasp_db_file = None

    # init ##################################################################

    fstore = sysrestore.FileStore(paths.SYSRESTORE)
    sstore = sysrestore.StateFile(paths.SYSRESTORE)

    # subject_base
    if not options.subject_base:
        options.subject_base = str(default_subject_base(options.realm_name))
        # set options.subject for old ipa releases
        options.subject = options.subject_base

    if not options.ca_subject:
        options.ca_subject = str(default_ca_subject_dn(options.subject_base))

    try:

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
        # pylint: disable=invalid-name, consider-using-with
        fd = open(target_fname, "w")
        fd.write("[global]\n")
        fd.write("host=%s\n" % options.host_name)
        fd.write("basedn=%s\n" % ipautil.realm_to_suffix(options.realm_name))
        fd.write("realm=%s\n" % options.realm_name)
        fd.write("domain=%s\n" % options.domain_name)
        fd.write("xmlrpc_uri=https://%s/ipa/xml\n" %
                 ipautil.format_netloc(options.host_name))
        fd.write("ldap_uri=ldapi://%%2fvar%%2frun%%2fslapd-%s.socket\n" %
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
        # pylint: enable=invalid-name, consider-using-with

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
                dns.install_check(False, api, False, options,
                                  options.host_name)
            ip_addresses = dns.ip_addresses
        else:
            ip_addresses = get_server_ip_address(options.host_name,
                                                 not options.interactive,
                                                 False,
                                                 options.ip_addresses)

            # check addresses here, dns module is doing own check
            no_matching_interface_for_ip_address_warning(ip_addresses)
        options.ip_addresses = ip_addresses
        options.reverse_zones = dns.reverse_zones

        instance_name = "-".join(options.realm_name.split("."))
        dirsrv = services.knownservices.dirsrv
        if options.external_cert_files \
           and dirsrv.is_installed(instance_name) \
           and not dirsrv.is_running(instance_name):
            logger.debug('Starting Directory Server')
            services.knownservices.dirsrv.start(instance_name)

        if options.setup_adtrust or sid_generation_always:
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

        if hasattr(tasks, "configure_pkcs11_modules"):
            if tasks.configure_pkcs11_modules(fstore):
                ansible_log.info("Disabled p11-kit-proxy")

    except (RuntimeError, ValueError, ScriptError,
            ipautil.CalledProcessError) as err:
        ansible_module.fail_json(msg=str(err))

    ansible_module.exit_json(
        changed=True,
        # basic
        ip_addresses=[str(ip) for ip in ip_addresses],
        # certificate system
        subject_base=options.subject_base,
        _subject_base=options._subject_base,
        ca_subject=options.ca_subject,
        _ca_subject=options._ca_subject,
        _random_serial_numbers=options._random_serial_numbers,
        # dns
        reverse_zones=options.reverse_zones,
        forward_policy=options.forward_policy,
        forwarders=options.forwarders,
        no_dnssec_validation=options.no_dnssec_validation,
        # additional
        dns_ip_addresses=[str(ip) for ip
                          in dns.ip_addresses],
        dns_reverse_zones=dns.reverse_zones,
        adtrust_netbios_name=adtrust.netbios_name,
        adtrust_reset_netbios_name=adtrust.reset_netbios_name)


if __name__ == '__main__':
    main()

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

ANSIBLE_METADATA = {
    'metadata_version': '1.0',
    'supported_by': 'community',
    'status': ['preview'],
}

DOCUMENTATION = '''
---
module: sssd_conf
short description: Configure sssd
description:
Configure sssd
options:
  servers:
    description: The FQDN of the IPA servers to connect to.
    required: true
    type: list
  domain:
    description: The primary DNS domain of an existing IPA deployment.
    required: true
  realm:
    description: The Kerberos realm of an existing IPA deployment.
    required: true
  hostname:
    description: The hostname of the machine to join (FQDN).
    required: true
  services:
    description: The services that should be enabled in the ssd configuration.
    required: true
    type: list
  krb5_offline_passwords:
    description: Whether user passwords are stored when the server is offline.
    required: false
    type: bool
    default: no
  on_master:
    description: Whether the configuration is done on the master or not.
    required: false
    type: bool
    default: no
  primary:
    description: Whether to use fixed server as primary IPA server.
    required: false
    type: bool
    default: no
  preserve_sssd:
    description: Preserve old SSSD configuration if possible.
    required: false
    type: bool
    default: no
  permit:
    description: Disable access rules by default, permit all access.
    required: false
    type: bool
    default: no
  dns_updates:
    description: Configures the machine to attempt dns updates when the ip address changes.
    required: false
    type: bool
    default: no
  all_ip_addresses:
    description: All routable IP addresses configured on any interface will be added to DNS.
    required: false
    type: bool
    default: no
author:
    - Thomas Woerner
'''

EXAMPLES = '''
- name: Configure SSSD
  sssd:
    servers: ["server1.example.com","server2.example.com"]
    domain: example.com
    realm: EXAMPLE.COM
    hostname: client1.example.com
    services: ["ssh", "sudo"]
    cache_credentials: yes
    krb5_offline_passwords: yes
'''

RETURN = '''
'''

import os
import sys
import tempfile
import SSSDConfig

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.ansible_ipa_client import *

def sssd_enable_service(module, sssdconfig, service):
    try:
        sssdconfig.new_service(service)
    except SSSDConfig.ServiceAlreadyExists:
        pass
    except SSSDConfig.ServiceNotRecognizedError:
        module.fail_json(
            msg="Unable to activate the %s service in SSSD config." % service)
    sssdconfig.activate_service(service)

def main():
    module = AnsibleModule(
        argument_spec = dict(
            servers=dict(required=True, type='list'),
            domain=dict(required=True),
            realm=dict(required=True),
            hostname=dict(required=True),
            services=dict(required=True, type='list'),
            krb5_offline_passwords=dict(required=False, type='bool'),
            on_master=dict(required=False, type='bool'),
            primary=dict(required=False, type='bool'),
            preserve_sssd=dict(required=False, type='bool'),
            permit=dict(required=False, type='bool'),
            dns_updates=dict(required=False, type='bool'),
            all_ip_addresses=dict(required=False, type='bool'),
        ),
        supports_check_mode = True,
    )

    module._ansible_debug = True
    cli_servers = module.params.get('servers')
    cli_domain = module.params.get('domain')
    cli_realm = module.params.get('realm')
    client_hostname = module.params.get('hostname')
    services = module.params.get('services')
    krb5_offline_passwords = module.params.get('krb5_offline_passwords')
    on_master = module.params.get('on_master')
    primary = module.params.get('primary')
    preserve_sssd = module.params.get('preserve_sssd')
    permit = module.params.get('permit')
    dns_updates = module.params.get('dns_updates')
    all_ip_addresses = module.params.get('all_ip_addresses')

    fstore = sysrestore.FileStore(paths.IPA_CLIENT_SYSRESTORE)
    client_domain = client_hostname[client_hostname.find(".")+1:]

    try:
        sssdconfig = SSSDConfig.SSSDConfig()
        sssdconfig.import_config()
    except Exception as e:
        if os.path.exists(paths.SSSD_CONF) and preserve_sssd:
            # SSSD config is in place but we are unable to read it
            # In addition, we are instructed to preserve it
            # This all means we can't use it and have to bail out
            module.fail_json(
                msg="SSSD config exists but cannot be parsed: %s" % str(e))

        # SSSD configuration does not exist or we are not asked to preserve it,
        # create new one
        # We do make new SSSDConfig instance because IPAChangeConf-derived
        # classes have no means to reset their state and ParseError exception
        # could come due to parsing error from older version which cannot be
        # upgraded anymore, leaving sssdconfig instance practically unusable
        # Note that we already backed up sssd.conf before going into this
        # routine
        if isinstance(e, IOError):
            pass
        else:
            # It was not IOError so it must have been parsing error
            module.fail_json(msg="Unable to parse existing SSSD config.")

        module.log("New SSSD config will be created")
        sssdconfig = SSSDConfig.SSSDConfig()
        sssdconfig.new_config()

    try:
        domain = sssdconfig.new_domain(cli_domain)
    except SSSDConfig.DomainAlreadyExistsError:
        module.log("Domain %s is already configured in existing SSSD "
                   "config, creating a new one." % cli_domain)
        sssdconfig = SSSDConfig.SSSDConfig()
        sssdconfig.new_config()
        domain = sssdconfig.new_domain(cli_domain)

    if on_master:
        sssd_enable_service(module, sssdconfig, 'ifp')

    if (("ssh" in services and os.path.isfile(paths.SSH_CONFIG)) or
        ("sshd" in services and os.path.isfile(paths.SSHD_CONFIG))):
        sssd_enable_service(module, sssdconfig, 'ssh')

    if "sudo" in services:
        sssd_enable_service(module, sssdconfig, 'sudo')
        configure_nsswitch_database(fstore, 'sudoers', ['sss'],
                                    default_value=['files'])

    domain.add_provider('ipa', 'id')

    # add discovery domain if client domain different from server domain
    # do not set this config in server mode (#3947)
    if not on_master and cli_domain != client_domain:
        domain.set_option('dns_discovery_domain', cli_domain)

    if not on_master:
        if primary:
            domain.set_option('ipa_server', ', '.join(cli_servers))
        else:
            domain.set_option('ipa_server',
                              '_srv_, %s' % ', '.join(cli_servers))
    else:
        domain.set_option('ipa_server_mode', 'True')
        # the master should only use itself for Kerberos
        domain.set_option('ipa_server', cli_servers[0])

        # increase memcache timeout to 10 minutes when in server mode
        try:
            nss_service = sssdconfig.get_service('nss')
        except SSSDConfig.NoServiceError:
            nss_service = sssdconfig.new_service('nss')

        nss_service.set_option('memcache_timeout', 600)
        sssdconfig.save_service(nss_service)

    domain.set_option('ipa_domain', cli_domain)
    domain.set_option('ipa_hostname', client_hostname)
    if cli_domain.lower() != cli_realm.lower():
        domain.set_option('krb5_realm', cli_realm)

    # Might need this if /bin/hostname doesn't return a FQDN
    # domain.set_option('ipa_hostname', 'client.example.com')

    domain.add_provider('ipa', 'auth')
    domain.add_provider('ipa', 'chpass')
    if not permit:
        domain.add_provider('ipa', 'access')
    else:
        domain.add_provider('permit', 'access')

    domain.set_option('cache_credentials', True)

    # SSSD will need TLS for checking if ipaMigrationEnabled attribute is set
    # Note that SSSD will force StartTLS because the channel is later used for
    # authentication as well if password migration is enabled. Thus set
    # the option unconditionally.
    domain.set_option('ldap_tls_cacert', paths.IPA_CA_CRT)

    if dns_updates:
        domain.set_option('dyndns_update', True)
        if all_ip_addresses:
            domain.set_option('dyndns_iface', '*')
        else:
            iface = get_server_connection_interface(cli_servers[0])
            domain.set_option('dyndns_iface', iface)
    if krb5_offline_passwords:
        domain.set_option('krb5_store_password_if_offline', True)

    domain.set_active(True)

    sssdconfig.save_domain(domain)
    sssdconfig.write(paths.SSSD_CONF)

    module.exit_json(changed=True)

if __name__ == '__main__':
    main()

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
module: ipadiscovery
short description: Tries to discover IPA server
description:
  Tries to discover IPA server using DNS or host name
options:
  servers:
    description: The FQDN of the IPA servers to connect to.
    required: false
    type: list
    default: []
  domain:
    description: The primary DNS domain of an existing IPA deployment.
    required: false
  realm:
    description:  The Kerberos realm of an existing IPA deployment.
    required: false
  hostname:
    description: The hostname of the machine to join (FQDN).
    required: false
  ca_cert_file:
    description: A CA certificate to use.
    required: false
  on_master:
    description: IPA client installation on IPA server
    required: false
    default: false
    type: bool
    default: no
  ntp_servers:
    description: List of NTP servers to use
    required: false
    type: list
    default: []
  ntp_pool:
    description: ntp server pool to use
    required: false
  no_ntp:
    description: Do not sync time and do not detect time servers
    required: false
    default: false
    type: bool
    default: no
  no_nisdomain:
    description: Do not configure NIS domain name
    required: false
    type: bool
    default: no
  nisdomain:
    description: NIS domain name
    required: false
author:
    - Thomas Woerner
'''

EXAMPLES = '''
# Complete autodiscovery, register return values as ipadiscovery
- name: IPA discovery
  ipadiscovery:
  register: ipadiscovery

# Discovery using servers, register return values as ipadiscovery
- name: IPA discovery
  ipadiscovery:
    servers: server1.domain.com,server2.domain.com
  register: ipadiscovery

# Discovery using domain name, register return values as ipadiscovery
- name: IPA discovery
  ipadiscovery:
    domain: domain.com
  register: ipadiscovery

# Discovery using realm, register return values as ipadiscovery
- name: IPA discovery
  ipadiscovery:
    realm: DOMAIN.COM
  register: ipadiscovery

# Discovery using hostname, register return values as ipadiscovery
- name: IPA discovery
  ipadiscovery:
    hostname: host.domain.com
  register: ipadiscovery
'''

RETURN = '''
servers:
  description: The list of detected or passed in IPA servers.
  returned: always
  type: list
  sample: ["server1.example.com","server2.example.com"]
domain:
  description: The DNS domain of the detected or passed in IPA deployment.
  returned: always
  type: string
  sample: example.com
realm:
  description: The Kerberos realm of the detected or passed in IPA deployment.
  returned: always
  type: string
  sample: EXAMPLE.COM
kdc:
  description: The detected KDC server name.
  returned: always
  type: string
  sample: server1.example.com
basedn:
  description: The basedn of the detected IPA server.
  returned: always
  type: string
  sample: dc=example,dc=com
hostname:
  description: The detected or passed in FQDN hostname of the client.
  returned: always
  type: string
  sample: client1.example.com
client_domain:
  description: The domain name of the client.
  returned: always
  type: string
  sample: example.com
dnsok:
  description: True if DNS discovery worked and not passed in any servers.
  returned: always
  type: bool
ntp_servers:
  description: The list of detected NTP servers.
  returned: always
  type: list
  sample: ["ntp.example.com"]
ipa_python_version:
  description: The IPA python version as a number: <major version>*10000+<minor version>*100+<release>
  returned: always
  type: int
  sample: 040400
'''

import os
import socket

from six.moves.configparser import RawConfigParser
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.ansible_ipa_client import *

def get_cert_path(cert_path):
    """
    If a CA certificate is passed in on the command line, use that.

    Else if a CA file exists in paths.IPA_CA_CRT then use that.

    Otherwise return None.
    """
    if cert_path is not None:
        return cert_path

    if os.path.exists(paths.IPA_CA_CRT):
        return paths.IPA_CA_CRT

    return None

def is_client_configured():
    """
    Check if ipa client is configured.

    IPA client is configured when /etc/ipa/default.conf exists and
    /var/lib/ipa-client/sysrestore/sysrestore.state exists.

    :returns: boolean
    """

    return (os.path.isfile(paths.IPA_DEFAULT_CONF) and
            os.path.isfile(os.path.join(paths.IPA_CLIENT_SYSRESTORE,
                                        sysrestore.SYSRESTORE_STATEFILE)))

def get_ipa_conf():
    """
    Return IPA configuration read from /etc/ipa/default.conf

    :returns: dict containing key,value
    """

    parser = RawConfigParser()
    parser.read(paths.IPA_DEFAULT_CONF)
    result = dict()
    for item in ['basedn', 'realm', 'domain', 'server', 'host', 'xmlrpc_uri']:
        if parser.has_option('global', item):
            value = parser.get('global', item)
        else:
            value = None
        if value:
            result[item] = value

    return result

def main():
    module = AnsibleModule(
        argument_spec = dict(
            servers=dict(required=False, type='list', default=[]),
            domain=dict(required=False),
            realm=dict(required=False),
            hostname=dict(required=False),
            ca_cert_file=dict(required=False),
            on_master=dict(required=False, type='bool', default=False),
            ntp_servers=dict(required=False, type='list', default=[]),
            ntp_pool=dict(required=False),
            no_ntp=dict(required=False, type='bool', default=False),
            #no_nisdomain=dict(required=False, type='bool', default='no'),
            #nisdomain=dict(required=False),
        ),
        supports_check_mode = True,
    )

    module._ansible_debug = True
    options.domain = module.params.get('domain')
    options.servers = module.params.get('servers')
    options.realm = module.params.get('realm')
    options.hostname = module.params.get('hostname')
    options.ca_cert_file = module.params.get('ca_cert_file')
    options.on_master = module.params.get('on_master')
    options.ntp_servers = module.params.get('ntp_servers')
    options.ntp_pool = module.params.get('ntp_pool')
    options.no_ntp = module.params.get('no_ntp')
    options.conf_ntp = not options.no_ntp
    #options.no_nisdomain = module.params.get('no_nisdomain')
    #options.nisdomain = module.params.get('nisdomain')
    #options.ip_addresses
    #options.all_ip_addresses
    #options.enable_dns_updates

    hostname = None
    hostname_source = None
    dnsok = False
    cli_domain = None
    cli_server = None
    cli_realm = None
    cli_kdc = None
    client_domain = None
    cli_basedn = None

    fstore = sysrestore.FileStore(paths.IPA_CLIENT_SYSRESTORE)
    statestore = sysrestore.StateFile(paths.IPA_CLIENT_SYSRESTORE)

    if options.ntp_servers and options.no_ntp:
        module.fail_json(
            "--ntp-server cannot be used together with --no-ntp")

    if options.ntp_pool and options.no_ntp:
        module.fail_json(
            "--ntp-pool cannot be used together with --no-ntp")

    #if options.no_nisdomain and options.nisdomain:
    #    module.fail_json(
    #        "--no-nisdomain cannot be used together with --nisdomain")

    #if options.ip_addresses:
    #    if options.enable_dns_updates:
    #        module.fail_json(
    #            "--ip-addresses cannot be used together with"
    #            " --enable-dns-updates")

    #    if options.all_ip_addresses:
    #        module.fail_json(
    #            "--ip-address cannot be used together with"
    #            "--all-ip-addresses")

    if options.hostname:
        hostname = options.hostname
        hostname_source = 'Provided as option'
    else:
        hostname = socket.getfqdn()
        hostname_source = "Machine's FQDN"
    if hostname != hostname.lower():
        module.fail_json(
            msg="Invalid hostname '%s', must be lower-case." % hostname)

    if (hostname == 'localhost') or (hostname == 'localhost.localdomain'):
        module.fail_json(
            msg="Invalid hostname, '%s' must not be used." % hostname)

    # Get domain from first server if domain is not set, but there are servers
    if options.domain is None and len(options.servers) > 0:
        options.domain = options.servers[0][options.servers[0].find(".")+1:]

    # Create the discovery instance
    ds = ipadiscovery.IPADiscovery()

    ret = ds.search(
        domain=options.domain,
        servers=options.servers,
        realm=options.realm,
        hostname=hostname,
        ca_cert_path=get_cert_path(options.ca_cert_file))

    if options.servers and ret != 0:
        # There is no point to continue with installation as server list was
        # passed as a fixed list of server and thus we cannot discover any
        # better result
        module.fail_json(msg="Failed to verify that %s is an IPA Server." % \
                         ', '.join(options.servers))

    if ret == ipadiscovery.BAD_HOST_CONFIG:
        module.fail_json(msg="Can't get the fully qualified name of this host")
    if ret == ipadiscovery.NOT_FQDN:
        module.fail_json(msg="%s is not a fully-qualified hostname" % hostname)
    if ret in (ipadiscovery.NO_LDAP_SERVER, ipadiscovery.NOT_IPA_SERVER) \
            or not ds.domain:
        if ret == ipadiscovery.NO_LDAP_SERVER:
            if ds.server:
                module.log("%s is not an LDAP server" % ds.server)
            else:
                module.log("No LDAP server found")
        elif ret == ipadiscovery.NOT_IPA_SERVER:
            if ds.server:
                module.log("%s is not an IPA server" % ds.server)
            else:
                module.log("No IPA server found")
        else:
            module.log("Domain not found")
        if options.domain:
            cli_domain = options.domain
            cli_domain_source = 'Provided as option'
        else:
            module.fail_json(
                msg="Unable to discover domain, not provided")

        ret = ds.search(
            domain=cli_domain,
            servers=options.servers,
            hostname=hostname,
            ca_cert_path=get_cert_path(options.ca_cert_file))

    if not cli_domain:
        if ds.domain:
            cli_domain = ds.domain
            cli_domain_source = ds.domain_source
            module.debug("will use discovered domain: %s" % cli_domain)

    client_domain = hostname[hostname.find(".")+1:]

    if ret in (ipadiscovery.NO_LDAP_SERVER, ipadiscovery.NOT_IPA_SERVER) \
            or not ds.server:
        module.debug("IPA Server not found")
        if options.servers:
            cli_server = options.servers
            cli_server_source = 'Provided as option'
        else:
            module.fail_json(msg="Unable to find IPA Server to join")

        ret = ds.search(
            domain=cli_domain,
            servers=cli_server,
            hostname=hostname,
            ca_cert_path=get_cert_path(options.ca_cert_file))

    else:
        # Only set dnsok to True if we were not passed in one or more servers
        # and if DNS discovery actually worked.
        if not options.servers:
            (server, domain) = ds.check_domain(
                ds.domain, set(), "Validating DNS Discovery")
            if server and domain:
                module.debug("DNS validated, enabling discovery")
                dnsok = True
            else:
                module.debug("DNS discovery failed, disabling discovery")
        else:
            module.debug(
                "Using servers from command line, disabling DNS discovery")

    if not cli_server:
        if options.servers:
            cli_server = ds.servers
            cli_server_source = 'Provided as option'
            module.debug(
                "will use provided server: %s" % ', '.join(options.servers))
        elif ds.server:
            cli_server = ds.servers
            cli_server_source = ds.server_source
            module.debug("will use discovered server: %s" % cli_server[0])

    if ret == ipadiscovery.NOT_IPA_SERVER:
        module.fail_json(msg="%s is not an IPA v2 Server." % cli_server[0])

    if ret == ipadiscovery.NO_ACCESS_TO_LDAP:
        module.warn("Anonymous access to the LDAP server is disabled.")
        ret = 0

    if ret == ipadiscovery.NO_TLS_LDAP:
        module.warn(
            "The LDAP server requires TLS is but we do not have the CA.")
        ret = 0

    if ret != 0:
        module.fail_json(
            msg="Failed to verify that %s is an IPA Server." % cli_server[0])

    cli_kdc = ds.kdc
    if dnsok and not cli_kdc:
        module.fail_json(
            msg="DNS domain '%s' is not configured for automatic "
            "KDC address lookup." % ds.realm.lower())

    if dnsok:
        module.log("Discovery was successful!")

    cli_realm = ds.realm
    cli_realm_source = ds.realm_source
    module.debug("will use discovered realm: %s" % cli_realm)

    if options.realm and options.realm != cli_realm:
        module.fail_json(
            msg=
            "The provided realm name [%s] does not match discovered one [%s]" %
            (options.realm, cli_realm))

    cli_basedn = str(ds.basedn)
    cli_basedn_source = ds.basedn_source
    module.debug("will use discovered basedn: %s" % cli_basedn)

    module.log("Client hostname: %s" % hostname)
    module.debug("Hostname source: %s" % hostname_source)
    module.log("Realm: %s" % cli_realm)
    module.debug("Realm source: %s" % cli_realm_source)
    module.log("DNS Domain: %s" % cli_domain)
    module.debug("DNS Domain source: %s" % cli_domain_source)
    module.log("IPA Server: %s" % ', '.join(cli_server))
    module.debug("IPA Server source: %s" % cli_server_source)
    module.log("BaseDN: %s" % cli_basedn)
    module.debug("BaseDN source: %s" % cli_basedn_source)

    # ipa-join would fail with IP address instead of a FQDN
    for srv in cli_server:
        try:
            socket.inet_pton(socket.AF_INET, srv)
            is_ipaddr = True
        except socket.error:
            try:
                socket.inet_pton(socket.AF_INET6, srv)
                is_ipaddr = True
            except socket.error:
                is_ipaddr = False

        if is_ipaddr:
            module.warn(
                "It seems that you are using an IP address "
                "instead of FQDN as an argument to --server. The "
                "installation may fail.")
            break

    ntp_servers = [ ]
    if sync_time is not None:
        if options.conf_ntp:
            # Attempt to configure and sync time with NTP server (chrony).
            sync_time(options, fstore, statestore)
        elif options.on_master:
            # If we're on master skipping the time sync here because it was done
            # in ipa-server-install
            logger.info("Skipping attempt to configure and synchronize time with"
                        " chrony server as it has been already done on master.")
        else:
            logger.info("Skipping chrony configuration")

    elif not options.on_master and options.conf_ntp:
        # Attempt to sync time with IPA server.
        # If we're skipping NTP configuration, we also skip the time sync here.
        # We assume that NTP servers are discoverable through SRV records
        # in the DNS.
        # If that fails, we try to sync directly with IPA server,
        # assuming it runs NTP
        if len(options.ntp_servers) < 1:
            # Detect NTP servers
            ds = ipadiscovery.IPADiscovery()
            ntp_servers = ds.ipadns_search_srv(cli_domain, '_ntp._udp',
                                               None, break_on_first=False)
        else:
            ntp_servers = options.ntp_servers

        # Attempt to sync time:
        # At first with given or dicovered time servers. If no ntp
        # servers have been given or discovered, then with the ipa
        # server.
        module.log('Synchronizing time ...')
        synced_ntp = False
        # use user specified NTP servers if there are any
        for s in ntp_servers:
            synced_ntp = timeconf.synconce_ntp(s, False)
            if synced_ntp:
                break
        if not synced_ntp and not ntp_servers:
            synced_ntp = timeconf.synconce_ntp(cli_server[0], False)
        if not synced_ntp:
            module.warn("Unable to sync time with NTP server")

    # Check if ipa client is already configured
    if is_client_configured():
        # Check that realm and domain match
        current_config = get_ipa_conf()
        if cli_domain != current_config.get('domain'):
            return module.fail_json(msg="IPA client already installed "
                                        "with a conflicting domain")
        if cli_realm != current_config.get('realm'):
            return module.fail_json(msg="IPA client already installed "
                                        "with a conflicting realm")

    # Done
    module.exit_json(changed=True,
                     servers=cli_server,
                     domain=cli_domain,
                     realm=cli_realm,
                     kdc=cli_kdc,
                     basedn=cli_basedn,
                     hostname=hostname,
                     client_domain=client_domain,
                     dnsok=dnsok,
                     ntp_servers=ntp_servers,
                     ipa_python_version=IPA_PYTHON_VERSION)

if __name__ == '__main__':
    main()

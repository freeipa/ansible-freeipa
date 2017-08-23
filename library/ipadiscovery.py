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

ANSIBLE_METADATA = {'metadata_version': '1.0',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
---
module: ipadiscovery
short description: Tries to discover IPA server
description:
  Tries to discover IPA server using DNS or host name
options:
  domain:
    description: The primary DNS domain of an existing IPA deployment.
    required: false
  servers:
    description: The FQDN of the IPA servers to connect to.
    required: false
  realm:
    description:  The Kerberos realm of an existing IPA deployment.
    required: false
  hostname:
    description: The authorized kerberos principal used to join the IPA realm.
    required: false
    default: admin
author:
    - Thomas Woerner
'''

EXAMPLES = '''
# Example from Ansible Playbooks
# Complete autodiscovery
- ipadiscovery:

# Discovery using hostname
- ipadiscovery:
    hostname: host.domain.com
'''

RETURN = '''
'''

import os, socket
from ansible.module_utils.basic import AnsibleModule
from ipapython.dn import DN
from ipaclient.install import ipadiscovery

def main():
    module = AnsibleModule(
        argument_spec = dict(
            domain=dict(required=False),
            servers=dict(required=False, type='list', default=[]),
            realm=dict(required=False),
            hostname=dict(required=False),
        ),
        # required_one_of = ( [ '', '' ] ),
        supports_check_mode = True,
    )

    module._ansible_debug = True
    opt_domain = module.params.get('domain')
    opt_servers = module.params.get('servers')
    opt_realm = module.params.get('realm')
    opt_hostname = module.params.get('hostname')

    hostname = None
    hostname_source = None
    dnsok = False
    cli_domain = None
    cli_server = None
    subject_base = None
    cli_realm = None
    cli_kdc = None
    client_domain = None
    cli_basedn = None

    if opt_hostname:
        hostname = opt_hostname
        hostname_source = 'Provided as option'
    else:
        hostname = socket.getfqdn()
        hostname_source = "Machine's FQDN"
    if hostname != hostname.lower():
        module.fail_json(msg="Invalid hostname '{}', must be lower-case.".format(hostname))

    if (hostname == 'localhost') or (hostname == 'localhost.localdomain'):
        module.fail_json(msg="Invalid hostname, '{}' must not be used.".format(hostname))

    # Create the discovery instance
    ds = ipadiscovery.IPADiscovery()

    ret = ds.search(
        domain=opt_domain,
        servers=opt_servers,
        realm=opt_realm,
        hostname=hostname,
        ca_cert_path=None)

    if opt_servers and ret != 0:
        # There is no point to continue with installation as server list was
        # passed as a fixed list of server and thus we cannot discover any
        # better result
        module.fail_json(msg="Failed to verify that %s is an IPA Server." % \
                         ', '.join(opt_servers))

    if ret == ipadiscovery.BAD_HOST_CONFIG:
        module.fail_json(msg="Can't get the fully qualified name of this host")
    if ret == ipadiscovery.NOT_FQDN:
        module.fail_json(msg="{} is not a fully-qualified hostname".format(hostname))
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
        if opt_domain:
            cli_domain = opt_domain
            cli_domain_source = 'Provided as option'
        else:
            module.fail_json(msg="Unable to discover domain, not provided on command line")

        ret = ds.search(
            domain=cli_domain,
            servers=opt_servers,
            hostname=hostname,
            ca_cert_path=None)

    if not cli_domain:
        if ds.domain:
            cli_domain = ds.domain
            cli_domain_source = ds.domain_source
            module.debug("will use discovered domain: %s" % cli_domain)

    client_domain = hostname[hostname.find(".")+1:]

    if ret in (ipadiscovery.NO_LDAP_SERVER, ipadiscovery.NOT_IPA_SERVER) \
            or not ds.server:
        module.debug("IPA Server not found")
        if opt_servers:
            cli_server = opt_servers
            cli_server_source = 'Provided as option'
        else:
            module.fail_json(msg="Unable to find IPA Server to join")

        ret = ds.search(
            domain=cli_domain,
            servers=cli_server,
            hostname=hostname,
            ca_cert_path=None)

    else:
        # Only set dnsok to True if we were not passed in one or more servers
        # and if DNS discovery actually worked.
        if not opt_servers:
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
        if opt_servers:
            cli_server = ds.servers
            cli_server_source = 'Provided as option'
            module.debug(
                "will use provided server: %s" % ', '.join(opt_servers))
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

    if opt_realm and opt_realm != cli_realm:
        module.fail_json(
            msg=
            "The provided realm name [%s] does not match discovered one [%s]" %
            (opt_realm, cli_realm))

    cli_basedn = str(ds.basedn)
    cli_basedn_source = ds.basedn_source
    module.debug("will use discovered basedn: %s" % cli_basedn)
    subject_base = str(DN(('O', cli_realm)))

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

    module.exit_json(changed=True,
                     dnsok=dnsok, domain=cli_domain, server=cli_server,
                     subject_base=subject_base, realm=cli_realm,
                     kdc=cli_kdc, client_domain=client_domain,
                     basedn=cli_basedn, hostname=hostname)

if __name__ == '__main__':
    main()

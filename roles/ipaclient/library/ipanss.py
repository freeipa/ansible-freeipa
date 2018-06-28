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
module: ipanss
short description: Create IPA NSS database
description:
Create IPA NSS database
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
  basedn:
    description: The basedn of the IPA server (of the form dc=example,dc=com).
    required: true
  principal:
    description: The authorized kerberos principal used to join the IPA realm.
    required: false
  subject_base:
    description: The subject base, needed for certmonger
    required: true
  ca_enabled:
    description: Whether the Certificate Authority is enabled or not.
    required: true
    type: bool
    default: no
  mkhomedir:
    description: Whether to create home directories for users on their first login.
    required: false
    type: bool
    default: no
  on_master:
    description: Whether the configuration is done on the master or not.
    required: false
    type: bool
    default: no
author:
    - Thomas Woerner
'''

EXAMPLES = '''
- name: Create IPA NSS database
  ipanss:
    servers: ["server1.example.com","server2.example.com"]
    domain: example.com
    realm: EXAMPLE.COM
    basedn: dc=example,dc=com
    hostname: client1.example.com
    subject_base: O=EXAMPLE.COM
    principal: admin
    ca_enabled: yes
'''

RETURN = '''
'''

import os
import time

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.ansible_ipa_client import *

def main():
    module = AnsibleModule(
        argument_spec = dict(
            servers=dict(required=True, type='list'),
            domain=dict(required=True),
            realm=dict(required=True),
            hostname=dict(required=True),
            basedn=dict(required=True),
            principal=dict(required=False),
            subject_base=dict(required=True),
            ca_enabled=dict(required=True, type='bool'),
            mkhomedir=dict(required=False, type='bool'),
            on_master=dict(required=False, type='bool'),
        ),
        supports_check_mode = True,
    )

    module._ansible_debug = True
    servers = module.params.get('servers')
    realm = module.params.get('realm')
    hostname = module.params.get('hostname')
    basedn = module.params.get('basedn')
    domain = module.params.get('domain')
    principal = module.params.get('principal')
    subject_base = module.params.get('subject_base')
    ca_enabled = module.params.get('ca_enabled')
    mkhomedir = module.params.get('mkhomedir')
    on_master = module.params.get('on_master')

    fstore = sysrestore.FileStore(paths.IPA_CLIENT_SYSRESTORE)
    statestore = sysrestore.StateFile(paths.IPA_CLIENT_SYSRESTORE)
    standard_logging_setup(
        paths.IPACLIENT_INSTALL_LOG, verbose=True, debug=False,
        filemode='a', console_format='%(message)s')

    os.environ['KRB5CCNAME'] = paths.IPA_DNS_CCACHE
    
    options.dns_updates = False
    options.all_ip_addresses = False
    options.ip_addresses = None
    options.request_cert = False
    options.hostname = hostname
    options.preserve_sssd = False
    options.on_master = False
    options.conf_ssh = True
    options.conf_sshd = True
    options.conf_sudo = True
    options.primary = False
    options.permit = False
    options.krb5_offline_passwords = False
    options.create_sshfp = True

    ##########################################################################

    # Create IPA NSS database
    try:
        create_ipa_nssdb()
    except ipautil.CalledProcessError as e:
        module.fail_json(msg="Failed to create IPA NSS database: %s" % e)

    # Get CA certificates from the certificate store
    try:
        ca_certs = get_certs_from_ldap(servers[0], basedn, realm,
                                       ca_enabled)
    except errors.NoCertificateError:
        if ca_enabled:
            ca_subject = DN(('CN', 'Certificate Authority'), subject_base)
        else:
            ca_subject = None
        ca_certs = certstore.make_compat_ca_certs(ca_certs, realm,
                                                  ca_subject)
    ca_certs_trust = [(c, n, certstore.key_policy_to_trust_flags(t, True, u))
                      for (c, n, t, u) in ca_certs]

    if hasattr(paths, "KDC_CA_BUNDLE_PEM"):
        x509.write_certificate_list(
            [c for c, n, t, u in ca_certs if t is not False],
            paths.KDC_CA_BUNDLE_PEM)
    if hasattr(paths, "CA_BUNDLE_PEM"):
        x509.write_certificate_list(
            [c for c, n, t, u in ca_certs if t is not False],
            paths.CA_BUNDLE_PEM)

    # Add the CA certificates to the IPA NSS database
    module.debug("Adding CA certificates to the IPA NSS database.")
    ipa_db = certdb.NSSDatabase(paths.IPA_NSSDB_DIR)
    for cert, nickname, trust_flags in ca_certs_trust:
        try:
            ipa_db.add_cert(cert, nickname, trust_flags)
        except CalledProcessError as e:
            module.fail_json(msg="Failed to add %s to the IPA NSS database." % nickname)

    # Add the CA certificates to the platform-dependant systemwide CA store
    tasks.insert_ca_certs_into_systemwide_ca_store(ca_certs)

    if not on_master:
        client_dns(servers[0], hostname, options)
        configure_certmonger(fstore, subject_base, realm, hostname,
                             options, ca_enabled)

    if hasattr(paths, "SSH_CONFIG_DIR"):
        ssh_config_dir = paths.SSH_CONFIG_DIR
    else:
        ssh_config_dir = services.knownservices.sshd.get_config_dir()
    update_ssh_keys(hostname, ssh_config_dir, options.create_sshfp)

    try:
        os.remove(paths.IPA_DNS_CCACHE)
    except Exception:
        pass

    ##########################################################################

    # Name Server Caching Daemon. Disable for SSSD, use otherwise
    # (if installed)
    nscd = services.knownservices.nscd
    if nscd.is_installed():
        if NUM_VERSION < 40500:
            save_state(nscd)
        else:
            save_state(nscd, statestore)

        try:
            nscd_service_action = 'stop'
            nscd.stop()
        except Exception:
            module.warn("Failed to %s the %s daemon" %
                        (nscd_service_action, nscd.service_name))

        try:
            nscd.disable()
        except Exception:
            module.warn("Failed to disable %s daemon. Disable it manually." %
                        nscd.service_name)

    nslcd = services.knownservices.nslcd
    if nslcd.is_installed():
        if NUM_VERSION < 40500:
            save_state(nslcd)
        else:
            save_state(nslcd, statestore)

    ##########################################################################

    # Modify nsswitch/pam stack
    tasks.modify_nsswitch_pam_stack(sssd=True,
                                    mkhomedir=mkhomedir,
                                    statestore=statestore)

    module.log("SSSD enabled")

    argspec = inspect.getargspec(services.service)
    if len(argspec.args) > 1:
        sssd = services.service('sssd', api)
    else:
        sssd = services.service('sssd')
    try:
        sssd.restart()
    except CalledProcessError:
        module.warn("SSSD service restart was unsuccessful.")

    try:
        sssd.enable()
    except CalledProcessError as e:
        module.warn(
            "Failed to enable automatic startup of the SSSD daemon: "
            "%s", e)

    if configure_openldap_conf(fstore, basedn, servers):
        module.log("Configured /etc/openldap/ldap.conf")
    else:
        module.log("Failed to configure /etc/openldap/ldap.conf")

    # Check that nss is working properly
    if not on_master:
        user = principal
        if user is None or user == "":
            user = "admin@%s" % domain
            module.log("Principal is not set when enrolling with OTP"
                       "; using principal '%s' for 'getent passwd'" % user)
        elif '@' not in user:
            user = "%s@%s" % (user, domain)
        n = 0
        found = False
        # Loop for up to 10 seconds to see if nss is working properly.
        # It can sometimes take a few seconds to connect to the remote
        # provider.
        # Particulary, SSSD might take longer than 6-8 seconds.
        while n < 10 and not found:
            try:
                ipautil.run([paths.GETENT if hasattr(paths, "GETENT") else "getent", "passwd", user])
                found = True
            except Exception as e:
                time.sleep(1)
                n = n + 1

        if not found:
            module.fail_json(msg="Unable to find '%s' user with 'getent "
                             "passwd %s'!" % (user.split("@")[0], user))
            if conf:
                module.log("Recognized configuration: %s" % conf)
            else:
                module.fail_json(msg=
                                 "Unable to reliably detect "
                                 "configuration. Check NSS setup manually.")

            try:
                hardcode_ldap_server(servers)
            except Exception as e:
                module.fail_json(msg="Adding hardcoded server name to "
                                 "/etc/ldap.conf failed: %s" % str(e))

    ##########################################################################

    module.exit_json(changed=True,
                     ca_enabled_ra=ca_enabled)

if __name__ == '__main__':
    main()

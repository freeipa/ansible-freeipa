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
module: ipaclient_setup_nss
short description: Create IPA client NSS database
description: Create IPA NSS database
options:
  servers:
    description: Fully qualified name of IPA servers to enroll to
    required: no
  domain:
    description: Primary DNS domain of the IPA deployment
    required: no
  realm:
    description: Kerberos realm name of the IPA deployment
    required: no
  hostname:
    description: Fully qualified name of this host
    required: no
  basedn:
    description: The basedn of the IPA server (of the form dc=example,dc=com)
    required: no
  principal:
    description:
      User Principal allowed to promote replicas and join IPA realm
    required: yes
  subject_base:
    description: |
      The certificate subject base (default O=<realm-name>).
      RDNs are in LDAP order (most specific RDN first).
    required: no
  ca_enabled:
    description: Whether the Certificate Authority is enabled or not
    required: no
  mkhomedir:
    description: Create home directories for users on their first login
    required: yes
  on_master:
    description: Whether the configuration is done on the master or not
    required: yes
  dnsok:
    description: The installer dnsok setting
    required: yes
  enable_dns_updates:
    description: |
      Configures the machine to attempt dns updates when the ip address
      changes
    required: yes
  all_ip_addresses:
    description: |
      All routable IP addresses configured on any interface will be added
      to DNS
    required: yes
  ip_addresses:
    description: List of Master Server IP Addresses
    required: yes
  request_cert:
    description: Request certificate for the machine
    required: yes
  preserve_sssd:
    description: Preserve old SSSD configuration if possible
    required: yes
  no_ssh:
    description: Do not configure OpenSSH client
    required: yes
  no_sshd:
    description: Do not configure OpenSSH server
    required: yes
  no_sudo:
    description: Do not configure SSSD as data source for sudo
    required: yes
  fixed_primary:
    description: Configure sssd to use fixed server as primary IPA server
    required: yes
  permit:
    description: Disable access rules by default, permit all access
    required: yes
  no_krb5_offline_passwords:
    description:
      Configure SSSD not to store user password when the server is offline
    required: yes
  no_dns_sshfp:
    description: Do not automatically create DNS SSHFP records
    required: yes
author:
    - Thomas Woerner
'''

EXAMPLES = '''
- name: Create IPA client NSS database
  ipaclient_setup_nss:
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
import inspect

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.ansible_ipa_client import (
    setup_logging,
    options, sysrestore, paths, ansible_module_get_parsed_ip_addresses,
    api, errors, create_ipa_nssdb, ipautil, ScriptError, CLIENT_INSTALL_ERROR,
    get_certs_from_ldap, DN, certstore, x509, logger, certdb,
    CalledProcessError, tasks, client_dns, configure_certmonger, services,
    update_ssh_keys, save_state, configure_ldap_conf, configure_nslcd_conf,
    nosssd_files, configure_openldap_conf, hardcode_ldap_server
)


def main():
    module = AnsibleModule(
        argument_spec=dict(
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
            dnsok=dict(required=False, type='bool', default=False),

            enable_dns_updates=dict(required=False, type='bool'),
            all_ip_addresses=dict(required=False, type='bool', default=False),
            ip_addresses=dict(required=False, type='list', default=None),
            request_cert=dict(required=False, type='bool', default=False),
            preserve_sssd=dict(required=False, type='bool'),
            no_ssh=dict(required=False, type='bool'),
            no_sshd=dict(required=False, type='bool'),
            no_sudo=dict(required=False, type='bool'),
            fixed_primary=dict(required=False, type='bool'),
            permit=dict(required=False, type='bool'),
            no_krb5_offline_passwords=dict(required=False, type='bool'),
            no_dns_sshfp=dict(required=False, type='bool', default=False),
        ),
        supports_check_mode=True,
    )

    module._ansible_debug = True
    setup_logging()

    cli_server = module.params.get('servers')
    cli_realm = module.params.get('realm')
    hostname = module.params.get('hostname')
    cli_basedn = module.params.get('basedn')
    cli_domain = module.params.get('domain')
    options.principal = module.params.get('principal')
    subject_base = module.params.get('subject_base')
    ca_enabled = module.params.get('ca_enabled')
    options.mkhomedir = module.params.get('mkhomedir')
    options.on_master = module.params.get('on_master')
    dnsok = module.params.get('dnsok')

    fstore = sysrestore.FileStore(paths.IPA_CLIENT_SYSRESTORE)
    statestore = sysrestore.StateFile(paths.IPA_CLIENT_SYSRESTORE)

    os.environ['KRB5CCNAME'] = paths.IPA_DNS_CCACHE

    options.dns_updates = module.params.get('enable_dns_updates')
    options.all_ip_addresses = module.params.get('all_ip_addresses')
    options.ip_addresses = ansible_module_get_parsed_ip_addresses(module)
    options.request_cert = module.params.get('request_cert')
    options.hostname = hostname
    options.host_name = hostname
    options.preserve_sssd = module.params.get('preserve_sssd')
    options.no_ssh = module.params.get('no_ssh')
    options.conf_ssh = not options.no_ssh
    options.no_sshd = module.params.get('no_sshd')
    options.conf_sshd = not options.no_sshd
    options.no_sudo = module.params.get('no_sudo')
    options.conf_sudo = not options.no_sudo
    options.primary = module.params.get('fixed_primary')
    options.permit = module.params.get('permit')
    options.no_krb5_offline_passwords = module.params.get(
        'no_krb5_offline_passwords')
    options.krb5_offline_passwords = not options.no_krb5_offline_passwords
    options.no_dns_sshfp = module.params.get('no_dns_sshfp')
    options.create_sshfp = not options.no_dns_sshfp
    options.no_sssd = False
    options.sssd = not options.no_sssd
    options.no_ac = False

    CCACHE_FILE = paths.IPA_DNS_CCACHE

    api.bootstrap(context='cli_installer',
                  confdir=paths.ETC_IPA,
                  debug=False,
                  delegate=False)
    api.finalize()

    api.Backend.rpcclient.connect()
    try:
        api.Backend.rpcclient.forward('ping')
    except errors.KerberosError:
        # Cannot connect to the server due to Kerberos error, trying with
        # delegate=True
        api.Backend.rpcclient.disconnect()
        api.Backend.rpcclient.connect(delegate=True)
        api.Backend.rpcclient.forward('ping')

    ##########################################################################

    try:

        # Create IPA NSS database
        try:
            create_ipa_nssdb()
        except ipautil.CalledProcessError as e:
            raise ScriptError(
                "Failed to create IPA NSS database: %s" % e,
                rval=CLIENT_INSTALL_ERROR)

        # Get CA certificates from the certificate store
        try:
            ca_certs = get_certs_from_ldap(cli_server[0], cli_basedn,
                                           cli_realm, ca_enabled)
        except errors.NoCertificateError:
            if ca_enabled:
                ca_subject = DN(('CN', 'Certificate Authority'), subject_base)
            else:
                ca_subject = None
            ca_certs = certstore.make_compat_ca_certs(ca_certs, cli_realm,
                                                      ca_subject)
        ca_certs_trust = [(c, n,
                           certstore.key_policy_to_trust_flags(t, True, u))
                          for (c, n, t, u) in ca_certs]

        if hasattr(paths, "KDC_CA_BUNDLE_PEM"):
            x509.write_certificate_list(
                [c for c, n, t, u in ca_certs if t is not False],
                paths.KDC_CA_BUNDLE_PEM,
                # mode=0o644
            )
        if hasattr(paths, "CA_BUNDLE_PEM"):
            x509.write_certificate_list(
                [c for c, n, t, u in ca_certs if t is not False],
                paths.CA_BUNDLE_PEM,
                # mode=0o644
            )

        # Add the CA certificates to the IPA NSS database
        logger.debug("Adding CA certificates to the IPA NSS database.")
        ipa_db = certdb.NSSDatabase(paths.IPA_NSSDB_DIR)
        for cert, nickname, trust_flags in ca_certs_trust:
            try:
                ipa_db.add_cert(cert, nickname, trust_flags)
            except CalledProcessError:
                raise ScriptError(
                    "Failed to add %s to the IPA NSS database." % nickname,
                    rval=CLIENT_INSTALL_ERROR)

        # Add the CA certificates to the platform-dependant systemwide CA
        # store
        tasks.insert_ca_certs_into_systemwide_ca_store(ca_certs)

        if not options.on_master:
            client_dns(cli_server[0], hostname, options)
            configure_certmonger(fstore, subject_base, cli_realm, hostname,
                                 options, ca_enabled)

        if hasattr(paths, "SSH_CONFIG_DIR"):
            ssh_config_dir = paths.SSH_CONFIG_DIR
        else:
            ssh_config_dir = services.knownservices.sshd.get_config_dir()
        update_ssh_keys(hostname, ssh_config_dir, options.create_sshfp)

        try:
            os.remove(CCACHE_FILE)
        except Exception:
            pass

        argspec_save_state = inspect.getargspec(save_state)

        # Name Server Caching Daemon. Disable for SSSD, use otherwise
        # (if installed)
        nscd = services.knownservices.nscd
        if nscd.is_installed():
            if "statestore" in argspec_save_state.args:
                save_state(nscd, statestore)
            else:
                save_state(nscd)
            nscd_service_action = None
            try:
                if options.sssd:
                    nscd_service_action = 'stop'
                    nscd.stop()
                else:
                    nscd_service_action = 'restart'
                    nscd.restart()
            except Exception:
                logger.warning(
                    "Failed to %s the %s daemon",
                    nscd_service_action, nscd.service_name)
                if not options.sssd:
                    logger.warning(
                        "Caching of users/groups will not be available")

            try:
                if options.sssd:
                    nscd.disable()
                else:
                    nscd.enable()
            except Exception:
                if not options.sssd:
                    logger.warning(
                        "Failed to configure automatic startup of the %s "
                        "daemon",
                        nscd.service_name)
                    logger.info(
                        "Caching of users/groups will not be "
                        "available after reboot")
                else:
                    logger.warning(
                        "Failed to disable %s daemon. Disable it manually.",
                        nscd.service_name)

        else:
            # this is optional service, just log
            if not options.sssd:
                logger.info(
                    "%s daemon is not installed, skip configuration",
                    nscd.service_name)

        nslcd = services.knownservices.nslcd
        if nslcd.is_installed():
            if "statestore" in argspec_save_state.args:
                save_state(nslcd, statestore)
            else:
                save_state(nslcd)

        retcode, conf = (0, None)

        if not options.no_ac:
            # Modify nsswitch/pam stack
            argspec = inspect.getargspec(tasks.modify_nsswitch_pam_stack)
            if "sudo" in argspec.args:
                tasks.modify_nsswitch_pam_stack(
                    sssd=options.sssd,
                    mkhomedir=options.mkhomedir,
                    statestore=statestore,
                    sudo=options.conf_sudo
                )
            else:
                tasks.modify_nsswitch_pam_stack(
                    sssd=options.sssd,
                    mkhomedir=options.mkhomedir,
                    statestore=statestore
                )

            if hasattr(paths, "AUTHSELECT") and paths.AUTHSELECT is not None:
                # authselect is used
                # if mkhomedir, make sure oddjobd is enabled and started
                if options.mkhomedir:
                    oddjobd = services.service('oddjobd', api)
                    running = oddjobd.is_running()
                    enabled = oddjobd.is_enabled()
                    statestore.backup_state('oddjobd', 'running', running)
                    statestore.backup_state('oddjobd', 'enabled', enabled)
                    try:
                        if not enabled:
                            oddjobd.enable()
                        if not running:
                            oddjobd.start()
                    except Exception as e:
                        logger.critical("Unable to start oddjobd: %s", str(e))

            logger.info("%s enabled", "SSSD" if options.sssd else "LDAP")

            if options.sssd:
                sssd = services.service('sssd', api)
                try:
                    sssd.restart()
                except CalledProcessError:
                    logger.warning("SSSD service restart was unsuccessful.")

                try:
                    sssd.enable()
                except CalledProcessError as e:
                    logger.warning(
                        "Failed to enable automatic startup of the SSSD "
                        "daemon: %s", e)

            if not options.sssd:
                tasks.modify_pam_to_use_krb5(statestore)
                logger.info("Kerberos 5 enabled")

            # Update non-SSSD LDAP configuration after authconfig calls as it
            # would change its configuration otherways
            if not options.sssd:
                for configurer in [configure_ldap_conf, configure_nslcd_conf]:
                    (retcode, conf, filenames) = configurer(
                        fstore, cli_basedn, cli_realm,
                        cli_domain, cli_server, dnsok,
                        options, nosssd_files[configurer.__name__])
                    if retcode:
                        raise ScriptError(rval=CLIENT_INSTALL_ERROR)
                    if conf:
                        logger.info(
                            "%s configured using configuration file(s) %s",
                            conf, filenames)

            if configure_openldap_conf(fstore, cli_basedn, cli_server):
                logger.info("Configured /etc/openldap/ldap.conf")
            else:
                logger.info("Failed to configure /etc/openldap/ldap.conf")

            # Check that nss is working properly
            if not options.on_master:
                user = options.principal
                if user is None:
                    user = "admin@%s" % cli_domain
                    logger.info("Principal is not set when enrolling with OTP"
                                "; using principal '%s' for 'getent passwd'",
                                user)
                elif '@' not in user:
                    user = "%s@%s" % (user, cli_domain)
                n = 0
                found = False
                # Loop for up to 10 seconds to see if nss is working properly.
                # It can sometimes take a few seconds to connect to the remote
                # provider.
                # Particulary, SSSD might take longer than 6-8 seconds.
                if hasattr(paths, "GETENT"):
                    getent_cmd = paths.GETENT
                else:
                    getent_cmd = '/usr/bin/getent'
                while n < 10 and not found:
                    try:
                        ipautil.run([getent_cmd, "passwd", user])
                        found = True
                    except Exception:
                        time.sleep(1)
                        n = n + 1

                if not found:
                    logger.error("Unable to find '%s' user with 'getent "
                                 "passwd %s'!", user.split("@")[0], user)
                    if conf:
                        logger.info("Recognized configuration: %s", conf)
                    else:
                        logger.error(
                            "Unable to reliably detect "
                            "configuration. Check NSS setup manually.")

                    try:
                        hardcode_ldap_server(cli_server)
                    except Exception as e:
                        logger.error(
                            "Adding hardcoded server name to "
                            "/etc/ldap.conf failed: %s", str(e))

    except ScriptError as e:
        module.fail_json(msg=str(e))

    ##########################################################################

    module.exit_json(changed=True,
                     ca_enabled_ra=ca_enabled)


if __name__ == '__main__':
    main()

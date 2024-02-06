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
module: ipaclient_test
short_description: Tries to discover IPA server
description:
  Tries to discover IPA server using DNS or host name
options:
  domain:
    description: Primary DNS domain of the IPA deployment
    type: str
    required: no
  servers:
    description: Fully qualified name of IPA servers to enroll to
    type: list
    elements: str
    required: no
  realm:
    description: Kerberos realm name of the IPA deployment
    type: str
    required: no
  hostname:
    description: Fully qualified name of this host
    type: str
    required: no
  ntp_servers:
    description: ntp servers to use
    type: list
    elements: str
    required: no
  ntp_pool:
    description: ntp server pool to use
    type: str
    required: no
  no_ntp:
    description: Do not configure ntp
    type: bool
    required: no
    default: no
  force_ntpd:
    description:
      Stop and disable any time&date synchronization services besides ntpd
      Deprecated since 4.7
    type: bool
    required: no
    default: no
  nisdomain:
    description: The NIS domain name
    type: str
    required: no
  no_nisdomain:
    description: Do not configure NIS domain name
    type: bool
    required: no
    default: no
  kinit_attempts:
    description: Repeat the request for host Kerberos ticket X times
    type: int
    required: no
  ca_cert_files:
    description:
      List of files containing CA certificates for the service certificate
      files
    type: list
    elements: str
    required: no
  configure_firefox:
    description: Configure Firefox to use IPA domain credentials
    type: bool
    required: no
    default: no
  firefox_dir:
    description:
      Specify directory where Firefox is installed (for example
      '/usr/lib/firefox')
    type: str
    required: no
  ip_addresses:
    description: List of Master Server IP Addresses
    type: list
    elements: str
    required: no
  all_ip_addresses:
    description:
      All routable IP addresses configured on any interface will be added
      to DNS
    type: bool
    required: no
    default: no
  on_master:
    description: Whether the configuration is done on the master or not
    type: bool
    required: no
    default: no
  enable_dns_updates:
    description:
      Configures the machine to attempt dns updates when the ip address
      changes
    type: bool
    required: no
    default: no
author:
    - Thomas Woerner (@t-woerner)
'''

EXAMPLES = '''
# Complete autodiscovery, register return values as ipaclient_test
- name: IPA discovery
  ipaclient_test:
  register: register_ipaclient_test

# Discovery using servers, register return values as ipaclient_test
- name: IPA discovery
  ipaclient_test:
    servers: server1.domain.com,server2.domain.com
  register: register_ipaclient_test

# Discovery using domain name, register return values as ipaclient_test
- name: IPA discovery
  ipaclient_test:
    domain: domain.com
  register: register_ipaclient_test

# Discovery using realm, register return values as ipaclient_test
- name: IPA discovery
  ipaclient_test:
    realm: DOMAIN.COM
  register: register_ipaclient_test

# Discovery using hostname, register return values as ipaclient_test
- name: IPA discovery
  ipaclient_test:
    hostname: host.domain.com
  register: register_ipaclient_test
'''

RETURN = '''
servers:
  description: The list of detected or passed in IPA servers.
  returned: always
  type: list
  elements: str
  sample: ["server1.example.com","server2.example.com"]
domain:
  description: The DNS domain of the detected or passed in IPA deployment.
  returned: always
  type: str
  sample: example.com
realm:
  description: The Kerberos realm of the detected or passed in IPA deployment.
  returned: always
  type: str
  sample: EXAMPLE.COM
kdc:
  description: The detected KDC server name.
  returned: always
  type: str
  sample: server1.example.com
basedn:
  description: The basedn of the detected IPA server.
  returned: always
  type: str
  sample: dc=example,dc=com
hostname:
  description: The detected or passed in FQDN hostname of the client.
  returned: always
  type: str
  sample: client1.example.com
client_domain:
  description: The domain name of the client.
  returned: always
  type: str
  sample: example.com
dnsok:
  description: True if DNS discovery worked and not passed in any servers.
  returned: always
  type: bool
ntp_servers:
  description: The list of detected NTP servers.
  returned: always
  type: list
  elements: str
  sample: ["ntp.example.com"]
ipa_python_version:
  description: >
    The IPA python version as a number:
    <major version>*10000+<minor version>*100+<release>
  returned: always
  type: int
  sample: 040400
nosssd_files:
  description: >
    The dist of nss_ldap or nss-pam-ldapd files if sssd is disabled
  returned: always
  type: list
  elements: str
selinux_works:
  description: True if the selinux status check passed.
  returned: always
  type: bool
'''

import os
import socket

try:
    from ansible.module_utils.six.moves.configparser import RawConfigParser
except ImportError:
    from ConfigParser import RawConfigParser

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.ansible_ipa_client import (
    setup_logging, check_imports,
    paths, sysrestore, options, CheckedIPAddress, validate_domain_name,
    logger, x509, normalize_hostname, installer, version, ScriptError,
    CLIENT_INSTALL_ERROR, tasks, check_ldap_conf, timeconf, constants,
    validate_hostname, nssldap_exists, gssapi, remove_file,
    check_ip_addresses, ipadiscovery, print_port_conf_info,
    IPA_PYTHON_VERSION, getargspec
)


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
    Return IPA configuration read from `/etc/ipa/default.conf`.

    :returns: dict containing key,value
    """
    parser = RawConfigParser()
    parser.read(paths.IPA_DEFAULT_CONF)
    result = {}
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
        argument_spec=dict(
            # basic
            domain=dict(required=False, type='str', default=None),
            servers=dict(required=False, type='list', elements='str',
                         default=None),
            realm=dict(required=False, type='str', default=None),
            hostname=dict(required=False, type='str', default=None),
            ntp_servers=dict(required=False, type='list', elements='str',
                             default=None),
            ntp_pool=dict(required=False, type='str', default=None),
            no_ntp=dict(required=False, type='bool', default=False),
            force_ntpd=dict(required=False, type='bool', default=False),
            nisdomain=dict(required=False, type='str', default=None),
            no_nisdomain=dict(required=False, type='bool', default='no'),
            kinit_attempts=dict(required=False, type='int'),
            ca_cert_files=dict(required=False, type='list', elements='str',
                               default=None),
            configure_firefox=dict(required=False, type='bool', default=False),
            firefox_dir=dict(required=False, type='str'),
            ip_addresses=dict(required=False, type='list', elements='str',
                              default=None),
            all_ip_addresses=dict(required=False, type='bool', default=False),
            on_master=dict(required=False, type='bool', default=False),
            # sssd
            enable_dns_updates=dict(required=False, type='bool',
                                    default=False),
        ),
        supports_check_mode=False,
    )

    # module._ansible_debug = True
    check_imports(module)
    setup_logging()

    options.domain_name = module.params.get('domain')
    options.servers = module.params.get('servers')
    options.realm_name = module.params.get('realm')
    options.host_name = module.params.get('hostname')
    options.ntp_servers = module.params.get('ntp_servers')
    options.ntp_pool = module.params.get('ntp_pool')
    options.no_ntp = module.params.get('no_ntp')
    options.force_ntpd = module.params.get('force_ntpd')
    options.nisdomain = module.params.get('nisdomain')
    options.no_nisdomain = module.params.get('no_nisdomain')
    options.kinit_attempts = module.params.get('kinit_attempts')
    options.ca_cert_files = module.params.get('ca_cert_files')
    options.configure_firefox = module.params.get('configure_firefox')
    options.firefox_dir = module.params.get('firefox_dir')
    options.ip_addresses = module.params.get('ip_addresses')
    options.all_ip_addresses = module.params.get('all_ip_addresses')
    options.on_master = module.params.get('on_master')
    options.enable_dns_updates = module.params.get('enable_dns_updates')

    # Get domain from first server if domain is not set, but if there are
    # servers
    if options.domain_name is None and options.servers is not None:
        if len(options.servers) > 0:
            options.domain_name = options.servers[0][
                options.servers[0].find(".") + 1:]

    try:
        self = options

        # HostNameInstallInterface

        if options.ip_addresses is not None:
            for value in options.ip_addresses:
                try:
                    CheckedIPAddress(value)
                except Exception as e:
                    raise ValueError("invalid IP address {0}: {1}".format(
                        value, e))

        # ServiceInstallInterface

        if options.domain_name:
            validate_domain_name(options.domain_name)

        if options.realm_name:
            # pylint: disable=deprecated-method
            argspec = getargspec(validate_domain_name)
            if "entity" in argspec.args:
                # NUM_VERSION >= 40690:
                validate_domain_name(options.realm_name, entity="realm")

        # ClientInstallInterface

        if options.kinit_attempts < 1:
            raise ValueError("expects an integer greater than 0.")

        # ClientInstallInterface.__init__

        if self.servers and not self.domain_name:
            raise RuntimeError(
                "--server cannot be used without providing --domain")

        if self.force_ntpd:
            logger.warning("Option --force-ntpd has been deprecated")

        if self.ntp_servers and self.no_ntp:
            raise RuntimeError(
                "--ntp-server cannot be used together with --no-ntp")

        if self.ntp_pool and self.no_ntp:
            raise RuntimeError(
                "--ntp-pool cannot be used together with --no-ntp")

        if self.no_nisdomain and self.nisdomain:
            raise RuntimeError(
                "--no-nisdomain cannot be used together with --nisdomain")

        if self.ip_addresses:
            if self.enable_dns_updates:
                raise RuntimeError(
                    "--ip-address cannot be used together with"
                    " --enable-dns-updates")

            if self.all_ip_addresses:
                raise RuntimeError(
                    "--ip-address cannot be used together with"
                    "--all-ip-addresses")

        # SSSDInstallInterface

        self.no_sssd = False

        # ClientInstall

        if options.ca_cert_files is not None:
            for value in options.ca_cert_files:
                if not isinstance(value, list):
                    raise ValueError("Expected list, got {0!r}".format(value))
                # this is what init() does
                value = value[-1]
                if not os.path.exists(value):
                    raise ValueError("'%s' does not exist" % value)
                if not os.path.isfile(value):
                    raise ValueError("'%s' is not a file" % value)
                if not os.path.isabs(value):
                    raise ValueError("'%s' is not an absolute file path" %
                                     value)

                try:
                    x509.load_certificate_from_file(value)
                except Exception:
                    raise ValueError("'%s' is not a valid certificate file" %
                                     value)

        # self.prompt_password = self.interactive

        self.no_ac = False

        # ClientInstall.__init__

        if self.firefox_dir and not self.configure_firefox:
            raise RuntimeError(
                "--firefox-dir cannot be used without --configure-firefox "
                "option")

    except (RuntimeError, ValueError) as e:
        module.fail_json(msg=str(e))

    # ipaclient.install.client.init

    # root_logger
    options.debug = False
    if options.domain_name:
        options.domain = normalize_hostname(installer.domain_name)
    else:
        options.domain = None
    options.server = options.servers
    options.realm = options.realm_name
    # installer.primary = installer.fixed_primary
    # if installer.principal:
    #     installer.password = installer.admin_password
    # else:
    #     installer.password = installer.host_password
    installer.hostname = installer.host_name
    options.conf_ntp = not options.no_ntp
    # installer.trust_sshfp = installer.ssh_trust_dns
    # installer.conf_ssh = not installer.no_ssh
    # installer.conf_sshd = not installer.no_sshd
    # installer.conf_sudo = not installer.no_sudo
    # installer.create_sshfp = not installer.no_dns_sshfp
    if installer.ca_cert_files:
        installer.ca_cert_file = installer.ca_cert_files[-1]
    else:
        installer.ca_cert_file = None
    # installer.location = installer.automount_location
    installer.dns_updates = installer.enable_dns_updates
    # installer.krb5_offline_passwords = \
    #     not installer.no_krb5_offline_passwords
    installer.sssd = not installer.no_sssd

    selinux_works = False

    try:

        # client

        # global variables
        hostname = None
        hostname_source = None
        nosssd_files = {}
        dnsok = False
        cli_domain = None
        cli_server = None
        # subject_base = None
        cli_realm = None
        cli_kdc = None
        client_domain = None
        cli_basedn = None
        # end of global variables

        # client.install_check

        logger.info("This program will set up FreeIPA client.")
        logger.info("Version %s", version.VERSION)
        logger.info("")

        cli_domain_source = 'Unknown source'
        cli_server_source = 'Unknown source'

        # fstore = sysrestore.FileStore(paths.IPA_CLIENT_SYSRESTORE)

        if not os.getegid() == 0:
            raise ScriptError(
                "You must be root to run ipa-client-install.",
                rval=CLIENT_INSTALL_ERROR)

        selinux_works = tasks.check_selinux_status()

        # if is_ipa_client_installed(fstore, on_master=options.on_master):
        #     logger.error("IPA client is already configured on this system.")
        #     logger.info(
        #       "If you want to reinstall the IPA client, uninstall it first "
        #       "using 'ipa-client-install --uninstall'.")
        #     raise ScriptError(
        #         "IPA client is already configured on this system.",
        #         rval=CLIENT_ALREADY_CONFIGURED)

        if check_ldap_conf is not None:
            check_ldap_conf()

        if options.conf_ntp:
            try:
                timeconf.check_timedate_services()
            except timeconf.NTPConflictingService as e:
                logger.info(
                    "WARNING: conflicting time&date synchronization service "
                    "'%s' will be disabled in favor of chronyd",
                    e.conflicting_service)
                logger.info("")
            except timeconf.NTPConfigurationError:
                pass

        # password, principal and keytab are checked in tasks/install.yml
        # if options.unattended and (
        #     options.password is None and
        #     options.principal is None and
        #     options.keytab is None and
        #     options.prompt_password is False and
        #     not options.on_master
        # ):
        #     raise ScriptError(
        #         "One of password / principal / keytab is required.",
        #         rval=CLIENT_INSTALL_ERROR)

        if options.hostname:
            hostname = options.hostname
            hostname_source = 'Provided as option'
        else:
            hostname = socket.getfqdn()
            hostname_source = "Machine's FQDN"
        if hostname != hostname.lower():
            raise ScriptError(
                "Invalid hostname '{0}', must be lower-case.".format(hostname),
                rval=CLIENT_INSTALL_ERROR
            )

        if hostname in ('localhost', 'localhost.localdomain'):
            raise ScriptError(
                "Invalid hostname, '{0}' must not be used.".format(hostname),
                rval=CLIENT_INSTALL_ERROR)

        if hasattr(constants, "MAXHOSTNAMELEN"):
            try:
                validate_hostname(hostname, maxlen=constants.MAXHOSTNAMELEN)
            except ValueError as e:
                raise ScriptError(
                    'invalid hostname: {0}'.format(e),
                    rval=CLIENT_INSTALL_ERROR)

        if hasattr(tasks, "is_nosssd_supported"):
            # --no-sssd is not supported any more for rhel-based distros
            if not tasks.is_nosssd_supported() and not options.sssd:
                raise ScriptError(
                    "Option '--no-sssd' is incompatible with the 'authselect' "
                    "tool provided by this distribution for configuring "
                    "system authentication resources",
                    rval=CLIENT_INSTALL_ERROR)

            # --noac is not supported any more for rhel-based distros
            if not tasks.is_nosssd_supported() and options.no_ac:
                raise ScriptError(
                    "Option '--noac' is incompatible with the 'authselect' "
                    "tool provided by this distribution for configuring "
                    "system authentication resources",
                    rval=CLIENT_INSTALL_ERROR)

        # when installing with '--no-sssd' option, check whether nss-ldap is
        # installed
        if not options.sssd:
            if not os.path.exists(paths.PAM_KRB5_SO):
                raise ScriptError(
                    "The pam_krb5 package must be installed",
                    rval=CLIENT_INSTALL_ERROR)

            (nssldap_installed, nosssd_files) = nssldap_exists()
            if not nssldap_installed:
                raise ScriptError(
                    "One of these packages must be installed: nss_ldap or "
                    "nss-pam-ldapd",
                    rval=CLIENT_INSTALL_ERROR)

            # principal and keytab are checked in tasks/install.yml
            # if options.keytab and options.principal:
            #   raise ScriptError(
            #     "Options 'principal' and 'keytab' cannot be used together.",
            #     rval=CLIENT_INSTALL_ERROR)

            # keytab and force_join are checked in tasks/install.yml
            # if options.keytab and options.force_join:
            #   logger.warning("Option 'force-join' has no additional effect "
            #                  "when used with together with option 'keytab'.")

        # Added with freeipa-4.7.1 >>>
        # Remove invalid keytab file
        try:
            gssapi.Credentials(
                store={'keytab': paths.KRB5_KEYTAB},
                usage='accept',
            )
        except gssapi.exceptions.GSSError:
            logger.debug("Deleting invalid keytab: '%s'.", paths.KRB5_KEYTAB)
            remove_file(paths.KRB5_KEYTAB)
        # Added with freeipa-4.7.1 <<<

        # Check if old certificate exist and show warning
        if (
            not options.ca_cert_file and
            get_cert_path(options.ca_cert_file) == paths.IPA_CA_CRT
        ):
            logger.warning("Using existing certificate '%s'.",
                           paths.IPA_CA_CRT)

        if not check_ip_addresses(options):
            raise ScriptError(
                "Failed to check ip addresses, check installation log",
                rval=CLIENT_INSTALL_ERROR)

        # Create the discovery instance
        # pylint: disable=invalid-name
        ds = ipadiscovery.IPADiscovery()

        ret = ds.search(
            domain=options.domain,
            servers=options.server,
            realm=options.realm_name,
            hostname=hostname,
            ca_cert_path=get_cert_path(options.ca_cert_file)
        )

        if options.server and ret != 0:
            # There is no point to continue with installation as server list
            # was passed as a fixed list of server and thus we cannot discover
            # any better result
            logger.error(
                "Failed to verify that %s is an IPA Server.",
                ', '.join(options.server))
            logger.error(
                "This may mean that the remote server is not up "
                "or is not reachable due to network or firewall settings.")
            print_port_conf_info()
            raise ScriptError("Failed to verify that %s is an IPA Server." %
                              ', '.join(options.server),
                              rval=CLIENT_INSTALL_ERROR)

        if ret == ipadiscovery.BAD_HOST_CONFIG:
            logger.error("Can't get the fully qualified name of this host")
            logger.info("Check that the client is properly configured")
            raise ScriptError(
                "Can't get the fully qualified name of this host",
                rval=CLIENT_INSTALL_ERROR)
        if ret == ipadiscovery.NOT_FQDN:
            raise ScriptError(
                "{0} is not a fully-qualified hostname".format(hostname),
                rval=CLIENT_INSTALL_ERROR)
        if ret in (ipadiscovery.NO_LDAP_SERVER, ipadiscovery.NOT_IPA_SERVER) \
                or not ds.domain:
            if ret == ipadiscovery.NO_LDAP_SERVER:
                if ds.server:
                    logger.debug("%s is not an LDAP server", ds.server)
                else:
                    logger.debug("No LDAP server found")
            elif ret == ipadiscovery.NOT_IPA_SERVER:
                if ds.server:
                    logger.debug("%s is not an IPA server", ds.server)
                else:
                    logger.debug("No IPA server found")
            else:
                logger.debug("Domain not found")
            if options.domain:
                cli_domain = options.domain
                cli_domain_source = 'Provided as option'
            elif options.unattended:
                raise ScriptError(
                    "Unable to discover domain, not provided on command line",
                    rval=CLIENT_INSTALL_ERROR)
            else:
                raise ScriptError("No interactive installation")
            #    logger.info(
            #        "DNS discovery failed to determine your DNS domain")
            #    cli_domain = user_input(
            #        "Provide the domain name of your IPA server "
            #        "(ex: example.com)",
            #        allow_empty=False)
            #    cli_domain_source = 'Provided interactively'
            #    logger.debug(
            #        "will use interactively provided domain: %s", cli_domain)
            ret = ds.search(
                domain=cli_domain,
                servers=options.server,
                hostname=hostname,
                ca_cert_path=get_cert_path(options.ca_cert_file))

        if not cli_domain:
            if ds.domain:
                cli_domain = ds.domain
                cli_domain_source = ds.domain_source
                logger.debug("will use discovered domain: %s", cli_domain)

        client_domain = hostname[hostname.find(".") + 1:]

        if ret in (ipadiscovery.NO_LDAP_SERVER, ipadiscovery.NOT_IPA_SERVER) \
                or not ds.server:
            logger.debug("IPA Server not found")
            if options.server:
                cli_server = options.server
                cli_server_source = 'Provided as option'
            elif options.unattended:
                raise ScriptError(
                    "Unable to find IPA Server to join",
                    rval=CLIENT_INSTALL_ERROR)
            else:
                raise ScriptError("No interactive installation")
            #    logger.debug("DNS discovery failed to find the IPA Server")
            #    cli_server = [
            #        user_input(
            #            "Provide your IPA server name (ex: ipa.example.com)",
            #            allow_empty=False)
            #    ]
            #    cli_server_source = 'Provided interactively'
            #    logger.debug(
            #      "will use interactively provided server: %s", cli_server[0])
            ret = ds.search(
                domain=cli_domain,
                servers=cli_server,
                hostname=hostname,
                ca_cert_path=get_cert_path(options.ca_cert_file))

        else:
            # Only set dnsok to True if we were not passed in one or more
            # servers and if DNS discovery actually worked.
            if not options.server:
                (server, domain) = ds.check_domain(
                    ds.domain, set(), "Validating DNS Discovery")
                if server and domain:
                    logger.debug("DNS validated, enabling discovery")
                    dnsok = True
                else:
                    logger.debug("DNS discovery failed, disabling discovery")
            else:
                logger.debug(
                    "Using servers from command line, disabling DNS discovery")

        if not cli_server:
            if options.server:
                cli_server = ds.servers
                cli_server_source = 'Provided as option'
                logger.debug(
                    "will use provided server: %s", ', '.join(options.server))
            elif ds.server:
                cli_server = ds.servers
                cli_server_source = ds.server_source
                logger.debug("will use discovered server: %s", cli_server[0])

        if ret == ipadiscovery.NOT_IPA_SERVER:
            logger.error("%s is not an IPA v2 Server.", cli_server[0])
            print_port_conf_info()
            logger.debug("(%s: %s)", cli_server[0], cli_server_source)
            raise ScriptError("%s is not an IPA v2 Server." % cli_server[0],
                              rval=CLIENT_INSTALL_ERROR)

        if ret == ipadiscovery.NO_ACCESS_TO_LDAP:
            logger.warning("Anonymous access to the LDAP server is disabled.")
            logger.info("Proceeding without strict verification.")
            logger.info(
                "Note: This is not an error if anonymous access "
                "has been explicitly restricted.")
            ret = 0

        if ret == ipadiscovery.NO_TLS_LDAP:
            logger.warning(
                "The LDAP server requires TLS is but we do not have the CA.")
            logger.info("Proceeding without strict verification.")
            ret = 0

        if ret != 0:
            logger.error(
                "Failed to verify that %s is an IPA Server.",
                cli_server[0])
            logger.error(
                "This may mean that the remote server is not up "
                "or is not reachable due to network or firewall settings.")
            print_port_conf_info()
            logger.debug("(%s: %s)", cli_server[0], cli_server_source)
            raise ScriptError("Failed to verify that %s is an IPA Server." %
                              cli_server[0],
                              rval=CLIENT_INSTALL_ERROR)

        cli_kdc = ds.kdc
        if dnsok and not cli_kdc:
            logger.error(
                "DNS domain '%s' is not configured for automatic "
                "KDC address lookup.", ds.realm.lower())
            logger.debug("(%s: %s)", ds.realm, ds.realm_source)
            logger.error("KDC address will be set to fixed value.")

        if dnsok:
            logger.info("Discovery was successful!")
        elif not options.unattended:
            raise ScriptError("No interactive installation")
        # if not options.server:
        #     logger.warning(
        #       "The failure to use DNS to find your IPA "
        #       "server indicates that your resolv.conf file is not properly "
        #       "configured.")
        # logger.info(
        #     "Autodiscovery of servers for failover cannot work "
        #     "with this configuration.")
        # logger.info(
        #   "If you proceed with the installation, services "
        #   "will be configured to always access the discovered server for "
        #   "all operations and will not fail over to other servers in case "
        #   "of failure.")
        # if not user_input(
        #     "Proceed with fixed values and no DNS discovery?", False):
        #     raise ScriptError(rval=CLIENT_INSTALL_ERROR)

        # Do not ask for time source
        # if options.conf_ntp:
        #     if not options.on_master and not options.unattended and not (
        #             options.ntp_servers or options.ntp_pool):
        #         options.ntp_servers, options.ntp_pool = \
        #             timeconf.get_time_source()

        cli_realm = ds.realm
        cli_realm_source = ds.realm_source
        logger.debug("will use discovered realm: %s", cli_realm)

        if options.realm_name and options.realm_name != cli_realm:
            logger.error(
                "The provided realm name [%s] does not match discovered "
                "one [%s]",
                options.realm_name, cli_realm)
            logger.debug("(%s: %s)", cli_realm, cli_realm_source)
            raise ScriptError(
                "The provided realm name [%s] does not match discovered "
                "one [%s]" % (options.realm_name, cli_realm),
                rval=CLIENT_INSTALL_ERROR)

        cli_basedn = ds.basedn
        cli_basedn_source = ds.basedn_source
        logger.debug("will use discovered basedn: %s", cli_basedn)
        # subject_base = DN(('O', cli_realm))

        logger.info("Client hostname: %s", hostname)
        logger.debug("Hostname source: %s", hostname_source)
        logger.info("Realm: %s", cli_realm)
        logger.debug("Realm source: %s", cli_realm_source)
        logger.info("DNS Domain: %s", cli_domain)
        logger.debug("DNS Domain source: %s", cli_domain_source)
        logger.info("IPA Server: %s", ', '.join(cli_server))
        logger.debug("IPA Server source: %s", cli_server_source)
        logger.info("BaseDN: %s", cli_basedn)
        logger.debug("BaseDN source: %s", cli_basedn_source)

        if not options.on_master:
            if options.ntp_servers:
                for server in options.ntp_servers:
                    logger.info("NTP server: %s", server)

            if options.ntp_pool:
                logger.info("NTP pool: %s", options.ntp_pool)

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
                logger.warning(
                    "It seems that you are using an IP address "
                    "instead of FQDN as an argument to --server. The "
                    "installation may fail.")
                break

        # logger.info()
        # if not options.unattended and not user_input(
        #     "Continue to configure the system with these values?", False):
        #     raise ScriptError(rval=CLIENT_INSTALL_ERROR)

    except ScriptError as e:
        module.fail_json(msg=str(e))

    #########################################################################

    # client._install

    # May not happen in here at this time
    # if not options.on_master:
    #     # Try removing old principals from the keytab
    #     purge_host_keytab(cli_realm)

    # Check if ipa client is already configured
    if is_client_configured():
        client_already_configured = True

        # Check that realm and domain match
        current_config = get_ipa_conf()
        if cli_domain != current_config.get('domain'):
            module.fail_json(msg="IPA client already installed "
                             "with a conflicting domain")
        if cli_realm != current_config.get('realm'):
            module.fail_json(msg="IPA client already installed "
                             "with a conflicting realm")
    else:
        client_already_configured = False

    # Done
    module.exit_json(changed=False,
                     servers=cli_server,
                     domain=cli_domain,
                     realm=cli_realm,
                     kdc=cli_kdc,
                     basedn=str(cli_basedn),
                     hostname=hostname,
                     client_domain=client_domain,
                     dnsok=dnsok,
                     sssd=options.sssd,
                     ntp_servers=options.ntp_servers,
                     ntp_pool=options.ntp_pool,
                     client_already_configured=client_already_configured,
                     ipa_python_version=IPA_PYTHON_VERSION,
                     nosssd_files=nosssd_files,
                     selinux_works=selinux_works)


if __name__ == '__main__':
    main()

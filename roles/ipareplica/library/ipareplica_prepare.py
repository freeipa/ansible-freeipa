# -*- coding: utf-8 -*-

# Authors:
#   Thomas Woerner <twoerner@redhat.com>
#
# Based on ipa-replica-install code
#
# Copyright (C) 2018  Red Hat
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
module: ipareplica_prepare
short description: Prepare ipa replica installation
description: |
  Prepare ipa replica installation: Create IPA configuration file, run install
  checks again and also update the host name and the hosts file if needed.
  The tests and also the results from ipareplica_test are needed.
options:
  dm_password:
    description: Directory Manager password
    required: yes
  password:
    description: Admin user kerberos password
    required: yes
  ip_addresses:
    description: List of Master Server IP Addresses
    required: yes
  domain:
    description: Primary DNS domain of the IPA deployment
    required: yes
  realm:
    description: Kerberos realm name of the IPA deployment
    required: yes
  hostname:
    description: Fully qualified name of this host
    required: yes
  principal:
    description:
      User Principal allowed to promote replicas and join IPA realm
    required: no
  ca_cert_files:
    description:
      List of files containing CA certificates for the service certificate
      files
    required: yes
  no_host_dns:
    description: Do not use DNS for hostname lookup during installation
    required: yes
  setup_adtrust:
    description: Configure AD trust capability
    required: yes
  setup_ca:
    description: Configure a dogtag CA
    required: yes
  setup_kra:
    description: Configure a dogtag KRA
    required: yes
  setup_dns:
    description: Configure bind with our zone
    required: yes
  dirsrv_cert_files:
    description:
      Files containing the Directory Server SSL certificate and private key
    required: yes
  dirsrv_cert_name:
    description: Name of the Directory Server SSL certificate to install
    required: yes
  dirsrv_pin:
    description: The password to unlock the Directory Server private key
    required: yes
  http_cert_files:
    description:
      File containing the Apache Server SSL certificate and private key
    required: yes
  http_cert_name:
    description: Name of the Apache Server SSL certificate to install
    required: yes
  http_pin:
    description: The password to unlock the Apache Server private key
    required: yes
  pkinit_cert_files:
    description:
      File containing the Kerberos KDC SSL certificate and private key
    required: yes
  pkinit_cert_name:
    description: Name of the Kerberos KDC SSL certificate to install
    required: yes
  pkinit_pin:
    description: The password to unlock the Kerberos KDC private key
    required: yes
  keytab:
    description: Path to backed up keytab from previous enrollment
    required: yes
  mkhomedir:
    description: Create home directories for users on their first login
    required: yes
  force_join:
    description: Force client enrollment even if already enrolled
    required: yes
  no_ntp:
    description: Do not configure ntp
    required: yes
  ssh_trust_dns:
    description: Configure OpenSSH client to trust DNS SSHFP records
    required: yes
  no_ssh:
    description: Do not configure OpenSSH client
    required: yes
  no_sshd:
    description: Do not configure OpenSSH server
    required: yes
  no_dns_sshfp:
    description: Do not automatically create DNS SSHFP records
    required: yes
  allow_zone_overlap:
    description: Create DNS zone even if it already exists
    required: yes
  reverse_zones:
    description: The reverse DNS zones to use
    required: yes
  no_reverse:
    description: Do not create new reverse DNS zone
    required: yes
  auto_reverse:
    description: Create necessary reverse zones
    required: yes
  forwarders:
    description: Add DNS forwarders
    required: yes
  no_forwarders:
    description: Do not add any DNS forwarders, use root servers instead
    required: yes
  auto_forwarders:
    description: Use DNS forwarders configured in /etc/resolv.conf
    required: yes
  forward_policy:
    description: DNS forwarding policy for global forwarders
    required: yes
  no_dnssec_validation:
    description: Disable DNSSEC validation
    required: yes
  enable_compat:
    description: Enable support for trusted domains for old clients
    required: yes
  netbios_name:
    description: NetBIOS name of the IPA domain
    required: yes
  rid_base:
    description: Start value for mapping UIDs and GIDs to RIDs
    required: yes
  secondary_rid_base:
    description:
      Start value of the secondary range for mapping UIDs and GIDs to RIDs
    required: yes
  server:
    description: Fully qualified name of IPA server to enroll to
    required: no
  skip_conncheck:
    description: Skip connection check to remote master
    required: yes
  sid_generation_always:
    description: Enable SID generation always
    required: yes
author:
    - Thomas Woerner
'''

EXAMPLES = '''
'''

RETURN = '''
'''

import os
import tempfile
import traceback
from shutil import copyfile

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.ansible_ipa_replica import (
    AnsibleModuleLog, options, installer, DN, paths, sysrestore,
    ansible_module_get_parsed_ip_addresses, Env, ipautil, ipaldap,
    installutils, ReplicaConfig, load_pkcs12, kinit_keytab, create_api,
    rpc_client, check_remote_version, parse_version, check_remote_fips_mode,
    ReplicationManager, promotion_check_ipa_domain, current_domain_level,
    check_domain_level_is_supported, errors, ScriptError, setup_logging,
    logger, check_dns_resolution, service, find_providing_server, ca, kra,
    dns, no_matching_interface_for_ip_address_warning, adtrust,
    constants, api, redirect_stdout, replica_conn_check, tasks
)
from ansible.module_utils import six

if six.PY3:
    unicode = str


def main():
    ansible_module = AnsibleModule(
        argument_spec=dict(
            # basic
            dm_password=dict(required=False, no_log=True),
            password=dict(required=False, no_log=True),
            ip_addresses=dict(required=False, type='list', default=[]),
            domain=dict(required=False),
            realm=dict(required=False),
            hostname=dict(required=False),
            principal=dict(required=True),
            ca_cert_files=dict(required=False, type='list', default=[]),
            no_host_dns=dict(required=False, type='bool', default=False),
            # server
            setup_adtrust=dict(required=False, type='bool'),
            setup_ca=dict(required=False, type='bool'),
            setup_kra=dict(required=False, type='bool'),
            setup_dns=dict(required=False, type='bool'),
            # ssl certificate
            dirsrv_cert_files=dict(required=False, type='list', default=[]),
            dirsrv_cert_name=dict(required=False),
            dirsrv_pin=dict(required=False),
            http_cert_files=dict(required=False, type='list', default=[]),
            http_cert_name=dict(required=False),
            http_pin=dict(required=False),
            pkinit_cert_files=dict(required=False, type='list', default=[]),
            pkinit_cert_name=dict(required=False),
            pkinit_pin=dict(required=False),
            # client
            keytab=dict(required=False),
            mkhomedir=dict(required=False, type='bool'),
            force_join=dict(required=False, type='bool'),
            no_ntp=dict(required=False, type='bool'),
            ssh_trust_dns=dict(required=False, type='bool'),
            no_ssh=dict(required=False, type='bool'),
            no_sshd=dict(required=False, type='bool'),
            no_dns_sshfp=dict(required=False, type='bool'),
            # certificate system
            # subject_base=dict(required=False),
            # dns
            allow_zone_overlap=dict(required=False, type='bool',
                                    default=False),
            reverse_zones=dict(required=False, type='list', default=[]),
            no_reverse=dict(required=False, type='bool', default=False),
            auto_reverse=dict(required=False, type='bool', default=False),
            forwarders=dict(required=False, type='list', default=[]),
            no_forwarders=dict(required=False, type='bool', default=False),
            auto_forwarders=dict(required=False, type='bool', default=False),
            forward_policy=dict(default=None, choices=['first', 'only']),
            no_dnssec_validation=dict(required=False, type='bool',
                                      default=False),
            # ad trust
            enable_compat=dict(required=False, type='bool', default=False),
            netbios_name=dict(required=False),
            rid_base=dict(required=False, type='int', default=1000),
            secondary_rid_base=dict(required=False, type='int',
                                    default=100000000),
            # additional
            server=dict(required=True),
            skip_conncheck=dict(required=False, type='bool'),
            sid_generation_always=dict(required=False, type='bool',
                                       default=False),
        ),
        supports_check_mode=True,
    )

    ansible_module._ansible_debug = True
    setup_logging()
    ansible_log = AnsibleModuleLog(ansible_module)

    # get parameters #

    options.dm_password = ansible_module.params.get('dm_password')
    options.password = options.dm_password
    options.admin_password = ansible_module.params.get('password')
    options.ip_addresses = ansible_module_get_parsed_ip_addresses(
        ansible_module)
    options.domain_name = ansible_module.params.get('domain')
    options.realm_name = ansible_module.params.get('realm')
    options.host_name = ansible_module.params.get('hostname')
    options.principal = ansible_module.params.get('principal')
    options.ca_cert_files = ansible_module.params.get('ca_cert_files')
    options.no_host_dns = ansible_module.params.get('no_host_dns')
    # server
    options.setup_adtrust = ansible_module.params.get('setup_adtrust')
    options.setup_ca = ansible_module.params.get('setup_ca')
    options.setup_kra = ansible_module.params.get('setup_kra')
    options.setup_dns = ansible_module.params.get('setup_dns')
    # ssl certificate
    options.dirsrv_cert_files = ansible_module.params.get('dirsrv_cert_files')
    options.dirsrv_cert_name = ansible_module.params.get('dirsrv_cert_name')
    options.dirsrv_pin = ansible_module.params.get('dirsrv_pin')
    options.http_cert_files = ansible_module.params.get('http_cert_files')
    options.http_cert_name = ansible_module.params.get('http_cert_name')
    options.http_pin = ansible_module.params.get('http_pin')
    options.pkinit_cert_files = ansible_module.params.get('pkinit_cert_files')
    options.pkinit_cert_name = ansible_module.params.get('pkinit_cert_name')
    options.pkinit_pin = ansible_module.params.get('pkinit_pin')
    # client
    options.keytab = ansible_module.params.get('keytab')
    options.mkhomedir = ansible_module.params.get('mkhomedir')
    options.force_join = ansible_module.params.get('force_join')
    options.no_ntp = ansible_module.params.get('no_ntp')
    options.ssh_trust_dns = ansible_module.params.get('ssh_trust_dns')
    options.no_ssh = ansible_module.params.get('no_ssh')
    options.no_sshd = ansible_module.params.get('no_sshd')
    options.no_dns_sshfp = ansible_module.params.get('no_dns_sshfp')
    # certificate system
    options.external_ca = ansible_module.params.get('external_ca')
    options.external_cert_files = ansible_module.params.get(
        'external_cert_files')
    # options.subject_base = ansible_module.params.get('subject_base')
    # options.ca_subject = ansible_module.params.get('ca_subject')
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
    options.rid_base = ansible_module.params.get('rid_base')
    options.secondary_rid_base = ansible_module.params.get(
        'secondary_rid_base')

    # additional
    # options._host_name_overridden = ansible_module.params.get(
    #     '_hostname_overridden')
    options.server = ansible_module.params.get('server')
    options.skip_conncheck = ansible_module.params.get('skip_conncheck')
    sid_generation_always = ansible_module.params.get('sid_generation_always')

    # random serial numbers are master_only, therefore setting to False
    options.random_serial_numbers = False
    # options._random_serial_numbers is generated by ca.install_check and
    # later used by ca.install in the _setup_ca module.
    options._random_serial_numbers = False

    # init #

    fstore = sysrestore.FileStore(paths.SYSRESTORE)
    sstore = sysrestore.StateFile(paths.SYSRESTORE)

    # prepare (install prepare, install checks) #

    ##########################################################################
    # replica promote_check ##################################################
    ##########################################################################

    ansible_log.debug("== PROMOTE CHECK ==")

    # ansible_log.debug("-- NO_NTP --") # already done in test

    # check selinux status, http and DS ports, NTP conflicting services
    # common_check(options.no_ntp)

    installer._enrollment_performed = False
    installer._top_dir = tempfile.mkdtemp("ipa")

    # with ipautil.private_ccache():
    dir_path = tempfile.mkdtemp(prefix='krbcc')
    os.environ['KRB5CCNAME'] = os.path.join(dir_path, 'ccache')

    ansible_log.debug("-- API --")

    env = Env()
    env._bootstrap(context='installer', confdir=paths.ETC_IPA, log=None)
    env._finalize_core(**dict(constants.DEFAULT_CONFIG))

    # pylint: disable=no-member
    xmlrpc_uri = 'https://{}/ipa/xml'.format(ipautil.format_netloc(env.host))
    if hasattr(ipaldap, "realm_to_ldapi_uri"):
        realm_to_ldapi_uri = ipaldap.realm_to_ldapi_uri
    else:
        realm_to_ldapi_uri = installutils.realm_to_ldapi_uri
    api.bootstrap(in_server=True,
                  context='installer',
                  confdir=paths.ETC_IPA,
                  ldap_uri=realm_to_ldapi_uri(env.realm),
                  xmlrpc_uri=xmlrpc_uri)
    # pylint: enable=no-member
    api.finalize()

    ansible_log.debug("-- REPLICA_CONFIG --")

    config = ReplicaConfig()
    config.realm_name = api.env.realm
    config.host_name = api.env.host
    config.domain_name = api.env.domain
    config.master_host_name = api.env.server
    if not api.env.ca_host or api.env.ca_host == api.env.host:
        # ca_host has not been configured explicitly, prefer source master
        config.ca_host_name = api.env.server
    else:
        # default to ca_host from IPA config
        config.ca_host_name = api.env.ca_host
    config.kra_host_name = config.ca_host_name
    config.ca_ds_port = 389
    config.setup_ca = options.setup_ca
    config.setup_kra = options.setup_kra
    config.dir = installer._top_dir
    config.basedn = api.env.basedn
    # config.hidden_replica = options.hidden_replica

    # load and check certificates #

    ansible_log.debug("-- CERT_FILES --")

    http_pkcs12_file = None
    http_pkcs12_info = None
    http_ca_cert = None
    dirsrv_pkcs12_file = None
    dirsrv_pkcs12_info = None
    dirsrv_ca_cert = None
    pkinit_pkcs12_file = None
    pkinit_pkcs12_info = None
    pkinit_ca_cert = None

    if options.http_cert_files:
        ansible_log.debug("-- HTTP_CERT_FILES --")
        if options.http_pin is None:
            ansible_module.fail_json(
                msg="Apache Server private key unlock password required")
        http_pkcs12_file, http_pin, http_ca_cert = load_pkcs12(
            cert_files=options.http_cert_files,
            key_password=options.http_pin,
            key_nickname=options.http_cert_name,
            ca_cert_files=options.ca_cert_files,
            host_name=config.host_name)
        http_pkcs12_info = (http_pkcs12_file.name, http_pin)

    if options.dirsrv_cert_files:
        ansible_log.debug("-- DIRSRV_CERT_FILES --")
        if options.dirsrv_pin is None:
            ansible_module.fail_json(
                msg="Directory Server private key unlock password required")
        dirsrv_pkcs12_file, dirsrv_pin, dirsrv_ca_cert = load_pkcs12(
            cert_files=options.dirsrv_cert_files,
            key_password=options.dirsrv_pin,
            key_nickname=options.dirsrv_cert_name,
            ca_cert_files=options.ca_cert_files,
            host_name=config.host_name)
        dirsrv_pkcs12_info = (dirsrv_pkcs12_file.name, dirsrv_pin)

    if options.pkinit_cert_files:
        ansible_log.debug("-- PKINIT_CERT_FILES --")
        if options.pkinit_pin is None:
            ansible_module.fail_json(
                msg="Kerberos KDC private key unlock password required")
        pkinit_pkcs12_file, pkinit_pin, pkinit_ca_cert = load_pkcs12(
            cert_files=options.pkinit_cert_files,
            key_password=options.pkinit_pin,
            key_nickname=options.pkinit_cert_name,
            ca_cert_files=options.ca_cert_files,
            realm_name=config.realm_name)
        pkinit_pkcs12_info = (pkinit_pkcs12_file.name, pkinit_pin)

    if (options.http_cert_files and options.dirsrv_cert_files and
            http_ca_cert != dirsrv_ca_cert):
        ansible_module.fail_json(
            msg="Apache Server SSL certificate and Directory "
            "Server SSL certificate are not signed by the same"
            " CA certificate")

    if (options.http_cert_files and
            options.pkinit_cert_files and
            http_ca_cert != pkinit_ca_cert):
        ansible_module.fail_json(
            msg="Apache Server SSL certificate and PKINIT KDC "
            "certificate are not signed by the same CA "
            "certificate")

    # Copy pkcs12_files to make them persistent till deployment is done
    # and encode certificates for ansible compatibility
    if http_pkcs12_info is not None:
        copyfile(http_pkcs12_file.name, "/etc/ipa/.tmp_pkcs12_http")
        http_pkcs12_info = ("/etc/ipa/.tmp_pkcs12_http", http_pin)
        http_ca_cert = ""
    if dirsrv_pkcs12_info is not None:
        copyfile(dirsrv_pkcs12_file.name, "/etc/ipa/.tmp_pkcs12_dirsrv")
        dirsrv_pkcs12_info = ("/etc/ipa/.tmp_pkcs12_dirsrv", dirsrv_pin)
        dirsrv_ca_cert = ""
    if pkinit_pkcs12_info is not None:
        copyfile(pkinit_pkcs12_file.name, "/etc/ipa/.tmp_pkcs12_pkinit")
        pkinit_pkcs12_info = ("/etc/ipa/.tmp_pkcs12_pkinit", pkinit_pin)
        pkinit_ca_cert = ""

    ansible_log.debug("-- FQDN --")

    installutils.verify_fqdn(config.host_name, options.no_host_dns)
    installutils.verify_fqdn(config.master_host_name, options.no_host_dns)

    ansible_log.debug("-- KINIT_KEYTAB --")

    ccache = os.environ['KRB5CCNAME']
    kinit_keytab('host/{env.host}@{env.realm}'.format(env=api.env),
                 paths.KRB5_KEYTAB,
                 ccache)

    ansible_log.debug("-- CA_CRT --")

    cafile = paths.IPA_CA_CRT
    if not os.path.isfile(cafile):
        ansible_module.fail_json(
            msg="CA cert file is not available! Please reinstall"
            "the client and try again.")

    ansible_log.debug("-- REMOTE_API --")

    ldapuri = 'ldaps://%s' % ipautil.format_netloc(config.master_host_name)
    xmlrpc_uri = 'https://{}/ipa/xml'.format(
        ipautil.format_netloc(config.master_host_name))
    remote_api = create_api(mode=None)
    remote_api.bootstrap(in_server=True,
                         context='installer',
                         confdir=paths.ETC_IPA,
                         ldap_uri=ldapuri,
                         xmlrpc_uri=xmlrpc_uri)
    remote_api.finalize()
    installer._remote_api = remote_api

    ansible_log.debug("-- RPC_CLIENT --")

    with rpc_client(remote_api) as client:
        check_remote_version(client, parse_version(api.env.version))
        check_remote_fips_mode(client, api.env.fips_mode)

    conn = remote_api.Backend.ldap2
    replman = None
    try:
        ansible_log.debug("-- CONNECT --")
        # Try out authentication
        conn.connect(ccache=ccache)
        replman = ReplicationManager(config.realm_name,
                                     config.master_host_name, None)

        ansible_log.debug("-- CHECK IPA_DOMAIN --")

        promotion_check_ipa_domain(conn, remote_api.env.basedn)

        ansible_log.debug("-- CHECK DOMAIN_LEVEL --")

        # Make sure that domain fulfills minimal domain level
        # requirement
        domain_level = current_domain_level(remote_api)
        check_domain_level_is_supported(domain_level)
        if domain_level < constants.MIN_DOMAIN_LEVEL:
            ansible_module.fail_json(
                msg="Cannot promote this client to a replica. The domain "
                "level "
                "must be raised to {mindomainlevel} before the replica can be "
                "installed".format(
                    mindomainlevel=constants.MIN_DOMAIN_LEVEL))

        ansible_log.debug("-- CHECK AUTHORIZATION --")

        # Check authorization
        result = remote_api.Command['hostgroup_find'](
            cn=u'ipaservers',
            host=[unicode(api.env.host)]
        )['result']
        add_to_ipaservers = not result

        ansible_log.debug("-- ADD_TO_IPASERVERS --")

        if add_to_ipaservers:
            if options.password and not options.admin_password:
                raise errors.ACIError(info="Not authorized")

            if installer._ccache is None:
                del os.environ['KRB5CCNAME']
            else:
                os.environ['KRB5CCNAME'] = installer._ccache

            try:
                installutils.check_creds(options, config.realm_name)
                installer._ccache = os.environ.get('KRB5CCNAME')
            finally:
                os.environ['KRB5CCNAME'] = ccache

            conn.disconnect()
            conn.connect(ccache=installer._ccache)

            try:
                result = remote_api.Command['hostgroup_show'](
                    u'ipaservers',
                    all=True,
                    rights=True
                )['result']

                if 'w' not in result['attributelevelrights']['member']:
                    raise errors.ACIError(info="Not authorized")
            finally:
                ansible_log.debug("-- RECONNECT --")
                conn.disconnect()
                conn.connect(ccache=ccache)

        ansible_log.debug("-- CHECK FOR REPLICATION AGREEMENT --")

        # Check that we don't already have a replication agreement
        if replman.get_replication_agreement(config.host_name):
            msg = ("A replication agreement for this host already exists. "
                   "It needs to be removed.\n"
                   "Run this command:\n"
                   "    %% ipa-replica-manage del {host} --force"
                   .format(host=config.host_name))
            raise ScriptError(msg, rval=3)

        ansible_log.debug("-- DETECT REPLICATION MANAGER GROUP --")

        # Detect if the other master can handle replication managers
        # cn=replication managers,cn=sysaccounts,cn=etc,$SUFFIX
        dn = DN(('cn', 'replication managers'), ('cn', 'sysaccounts'),
                ('cn', 'etc'), ipautil.realm_to_suffix(config.realm_name))
        try:
            conn.get_entry(dn)
        except errors.NotFound:
            msg = ("The Replication Managers group is not available in "
                   "the domain. Replica promotion requires the use of "
                   "Replication Managers to be able to replicate data. "
                   "Upgrade the peer master or use the ipa-replica-prepare "
                   "command on the master and use a prep file to install "
                   "this replica.")
            logger.error("%s", msg)
            raise ScriptError(msg, rval=3)

        ansible_log.debug("-- CHECK DNS_MASTERS --")

        dns_masters = remote_api.Object['dnsrecord'].get_dns_masters()
        if dns_masters:
            if not options.no_host_dns:
                logger.debug('Check forward/reverse DNS resolution')
                resolution_ok = (
                    check_dns_resolution(config.master_host_name,
                                         dns_masters) and
                    check_dns_resolution(config.host_name, dns_masters))
                if not resolution_ok and installer.interactive:
                    if not ipautil.user_input("Continue?", False):
                        raise ScriptError(rval=0)
        else:
            logger.debug('No IPA DNS servers, '
                         'skipping forward/reverse resolution check')

        ansible_log.debug("-- GET_IPA_CONFIG --")

        entry_attrs = conn.get_ipa_config()
        subject_base = entry_attrs.get('ipacertificatesubjectbase', [None])[0]
        if subject_base is not None:
            config.subject_base = DN(subject_base)

        ansible_log.debug("-- SEARCH FOR CA --")

        # Find if any server has a CA
        if not hasattr(service, "find_providing_server"):
            _host = [config.ca_host_name]
        else:
            _host = config.ca_host_name
        ca_host = find_providing_server('CA', conn, _host)
        if ca_host is not None:
            config.ca_host_name = ca_host
            ca_enabled = True
            if options.dirsrv_cert_files:
                msg = ("Certificates could not be provided when "
                       "CA is present on some master.")
                logger.error(msg)
                raise ScriptError(msg, rval=3)
        else:
            if options.setup_ca:
                msg = ("The remote master does not have a CA "
                       "installed, can't set up CA")
                logger.error(msg)
                raise ScriptError(msg, rval=3)
            ca_enabled = False
            if not options.dirsrv_cert_files:
                msg = ("Cannot issue certificates: a CA is not "
                       "installed. Use the --http-cert-file, "
                       "--dirsrv-cert-file options to provide "
                       "custom certificates.")
                logger.error(msg)
                raise ScriptError(msg, rval=3)

        ansible_log.debug("-- SEARCH FOR KRA --")

        if not hasattr(service, "find_providing_server"):
            _host = [config.kra_host_name]
        else:
            _host = config.kra_host_name
        kra_host = find_providing_server('KRA', conn, _host)
        if kra_host is not None:
            config.kra_host_name = kra_host
            kra_enabled = True
        else:
            if options.setup_kra:
                msg = ("There is no active KRA server in the domain, "
                       "can't setup a KRA clone")
                logger.error(msg)
                raise ScriptError(msg, rval=3)
            kra_enabled = False

        ansible_log.debug("-- CHECK CA --")

        if ca_enabled:
            options.realm_name = config.realm_name
            options.host_name = config.host_name
            ca.install_check(False, config, options)

            ansible_log.debug("  ca.external_cert_file=%s" %
                              repr(ca.external_cert_file))
            ansible_log.debug("  ca.external_ca_file=%s" %
                              repr(ca.external_ca_file))

            # TODO
            # TODO
            # Save global vars external_cert_file, external_ca_file for
            # later use
            # TODO
            # TODO

        ansible_log.debug("-- CHECK KRA --")

        if kra_enabled:
            try:
                kra.install_check(remote_api, config, options)
            except RuntimeError as e:
                raise ScriptError(e)

        ansible_log.debug("-- CHECK DNS --")

        if options.setup_dns:
            dns.install_check(False, remote_api, True, options,
                              config.host_name)
            config.ips = dns.ip_addresses
        else:
            config.ips = installutils.get_server_ip_address(
                config.host_name, not installer.interactive,
                False, options.ip_addresses)

            # check addresses here, dns module is doing own check
            no_matching_interface_for_ip_address_warning(config.ips)

        ansible_log.debug("-- CHECK ADTRUST --")

        if options.setup_adtrust or sid_generation_always:
            adtrust.install_check(False, options, remote_api)

    except errors.ACIError:
        logger.debug("%s", traceback.format_exc())
        ansible_module.fail_json(
            msg=("\nInsufficient privileges to promote the server."
                 "\nPossible issues:"
                 "\n- A user has insufficient privileges"
                 "\n- This client has insufficient privileges "
                 "to become an IPA replica"))
    except errors.LDAPError:
        logger.debug("%s", traceback.format_exc())
        ansible_module.fail_json(msg="\nUnable to connect to LDAP server %s" %
                                 config.master_host_name)
    except ScriptError as e:
        ansible_module.fail_json(msg=str(e))
    finally:
        if replman and replman.conn:
            ansible_log.debug("-- UNBIND REPLMAN--")
            replman.conn.unbind()
        if conn.isconnected():
            ansible_log.debug("-- DISCONNECT --")
            conn.disconnect()

    ansible_log.debug("-- CHECK CONNECTION --")

    # check connection
    if not options.skip_conncheck:
        if add_to_ipaservers:
            # use user's credentials when the server host is not ipaservers
            if installer._ccache is None:
                del os.environ['KRB5CCNAME']
            else:
                os.environ['KRB5CCNAME'] = installer._ccache

        try:
            with redirect_stdout(ansible_log):
                replica_conn_check(
                    config.master_host_name, config.host_name,
                    config.realm_name, options.setup_ca, 389,
                    options.admin_password, principal=options.principal,
                    ca_cert_file=cafile)
        except ScriptError as e:
            ansible_module.fail_json(msg=str(e))
        finally:
            if add_to_ipaservers:
                os.environ['KRB5CCNAME'] = ccache

    if hasattr(tasks, "configure_pkcs11_modules"):
        if tasks.configure_pkcs11_modules(fstore):
            ansible_log.info("Disabled p11-kit-proxy")

    installer._ca_enabled = ca_enabled
    installer._kra_enabled = kra_enabled
    installer._ca_file = cafile
    installer._fstore = fstore
    installer._sstore = sstore
    installer._config = config
    installer._add_to_ipaservers = add_to_ipaservers

    # done #

    ansible_module.exit_json(
        changed=True,
        ccache=ccache,
        installer_ccache=installer._ccache,
        subject_base=str(config.subject_base),
        forward_policy=options.forward_policy,
        _ca_enabled=ca_enabled,
        _ca_subject=str(options._ca_subject),
        _subject_base=str(options._subject_base) if options._subject_base
        is not None else None,
        _kra_enabled=kra_enabled,
        _ca_file=cafile,
        _top_dir=installer._top_dir,
        _add_to_ipaservers=add_to_ipaservers,
        _dirsrv_pkcs12_info=dirsrv_pkcs12_info,
        _dirsrv_ca_cert=dirsrv_ca_cert,
        _http_pkcs12_info=http_pkcs12_info,
        _http_ca_cert=http_ca_cert,
        _pkinit_pkcs12_info=pkinit_pkcs12_info,
        _pkinit_ca_cert=pkinit_ca_cert,
        _random_serial_numbers=options._random_serial_numbers,
        no_dnssec_validation=options.no_dnssec_validation,
        config_setup_ca=config.setup_ca,
        config_master_host_name=config.master_host_name,
        config_ca_host_name=config.ca_host_name,
        config_kra_host_name=config.kra_host_name,
        config_ips=[str(ip) for ip in config.ips],
        # ad trust
        dns_ip_addresses=[str(ip) for ip in dns.ip_addresses],
        dns_reverse_zones=dns.reverse_zones,
        rid_base=options.rid_base,
        secondary_rid_base=options.secondary_rid_base,
        adtrust_netbios_name=adtrust.netbios_name,
        adtrust_reset_netbios_name=adtrust.reset_netbios_name)


if __name__ == '__main__':
    main()

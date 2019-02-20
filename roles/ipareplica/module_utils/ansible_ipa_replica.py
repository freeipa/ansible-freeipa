#!/usr/bin/python
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

import os
import sys
import logging
#import fcntl
from contextlib import contextmanager as contextlib_contextmanager


from ipapython.version import NUM_VERSION, VERSION

if NUM_VERSION < 30201:
    # See ipapython/version.py
    IPA_MAJOR,IPA_MINOR,IPA_RELEASE = [ int(x) for x in VERSION.split(".", 2) ]
    IPA_PYTHON_VERSION = IPA_MAJOR*10000 + IPA_MINOR*100 + IPA_RELEASE
else:
    IPA_PYTHON_VERSION = NUM_VERSION


if NUM_VERSION >= 40600:
    # IPA version >= 4.6

    import inspect

    import contextlib
    import logging

    import dns.exception as dnsexception
    import dns.name as dnsname
    import dns.resolver as dnsresolver
    import dns.reversename as dnsreversename
    import os
    import shutil
    import socket
    import tempfile
    import traceback

    from pkg_resources import parse_version
    import six

    from ipaclient.install.ipachangeconf import IPAChangeConf
    from ipalib.install import certstore, sysrestore
    from ipalib.install.kinit import kinit_keytab
    from ipapython import ipaldap, ipautil, kernel_keyring
    from ipapython.certdb import IPA_CA_TRUST_FLAGS, EXTERNAL_CA_TRUST_FLAGS
    from ipapython.dn import DN
    from ipapython.admintool import ScriptError
    from ipaplatform import services
    from ipaplatform.tasks import tasks
    from ipaplatform.paths import paths
    from ipalib import api, constants, create_api, errors, rpc, x509
    from ipalib.config import Env
    from ipalib.util import (
        validate_domain_name,
        no_matching_interface_for_ip_address_warning)
    from ipaclient.install.client import configure_krb5_conf, purge_host_keytab
    from ipaserver.install import (
        adtrust, bindinstance, ca, certs, dns, dsinstance, httpinstance,
        installutils, kra, krbinstance,
        otpdinstance, custodiainstance, service, upgradeinstance)
    from ipaserver.install.installutils import (
        create_replica_config, ReplicaConfig, load_pkcs12, is_ipa_configured)
    from ipaserver.install.replication import (
        ReplicationManager, replica_conn_check)
    from ipaserver.install.server.replicainstall import (
        make_pkcs12_info, install_replica_ds, install_krb, install_ca_cert,
        install_http, install_dns_records, create_ipa_conf, check_dirsrv,
        check_dns_resolution, configure_certmonger, remove_replica_info_dir,
        #common_cleanup,
        preserve_enrollment_state, uninstall_client,
        promote_sssd, promote_openldap_conf, rpc_client,
        check_remote_fips_mode, check_remote_version, common_check,
        current_domain_level, check_domain_level_is_supported,
        #enroll_dl0_replica,
        #ensure_enrolled,
        promotion_check_ipa_domain
    )
    import SSSDConfig
    from subprocess import CalledProcessError

    if six.PY3:
        unicode = str

    try:
        from ipaclient.install import timeconf
        time_service = "chronyd"
        ntpinstance = None
    except ImportError:
        try:
            from ipaclient.install import ntpconf as timeconf
        except ImportError:
            from ipaclient import ntpconf as timeconf
        from ipaserver.install import ntpinstance
        time_service = "ntpd"

else:
    # IPA version < 4.6

    raise Exception("freeipa version '%s' is too old" % VERSION)


logger = logging.getLogger("ipa-server-install")
logger.setLevel(logging.DEBUG)


@contextlib_contextmanager
def redirect_stdout(f):
    sys.stdout = f
    try:
        yield f
    finally:
        sys.stdout = sys.__stdout__


class AnsibleModuleLog():
    def __init__(self, module):
        self.module = module
        _ansible_module_log = self

        class AnsibleLoggingHandler(logging.Handler):
            def emit(self, record):
                _ansible_module_log.write(self.format(record))

        self.logging_handler = AnsibleLoggingHandler()
        logger.setLevel(logging.DEBUG)
        logger.root.addHandler(self.logging_handler)

    def close(self):
        self.flush()

    def flush(self):
        pass

    def log(self, msg):
        #self.write(msg+"\n")
        self.write(msg)

    def debug(self, msg):
        self.module.debug(msg)

    def write(self, msg):
        self.module.debug(msg)
        #self.module.warn(msg)


class installer_obj(object):
    def __init__(self):
        # CompatServerReplicaInstall
        self.ca_cert_files = None
        self.all_ip_addresses = False
        self.no_wait_for_dns = True
        self.nisdomain = None
        self.no_nisdomain = False
        self.no_sudo = False
        self.request_cert = False
        self.ca_file = None
        self.zonemgr = None
        self.replica_file = None
        # ServerReplicaInstall
        self.subject_base = None
        self.ca_subject = None
        # others
        self._ccache = None
        self.password = None
        self.reverse_zones = [ ]
        #def _is_promote(self):
        #    return self.replica_file is None
        #self.skip_conncheck = False
        self._replica_install = False
        #self.dnssec_master = False # future unknown
        #self.disable_dnssec_master = False # future unknown
        #self.domainlevel = MAX_DOMAIN_LEVEL # deprecated
        #self.domain_level = self.domainlevel # deprecated
        self.interactive = False
        self.unattended = not self.interactive
        #self.promote = self.replica_file is None
        self.promote = True

    #def __getattribute__(self, attr):
    #    value = super(installer_obj, self).__getattribute__(attr)
    #    if not attr.startswith("--") and not attr.endswith("--"):
    #        logger.debug(
    #            "  <-- Accessing installer.%s (%s)" % (attr, repr(value)))
    #    return value

    def __getattr__(self, attr):
        logger.info("  --> ADDING missing installer.%s" % attr)
        setattr(self, attr, None)
        return getattr(self, attr)

    #def __setattr__(self, attr, value):
    #    logger.debug("  --> Setting installer.%s to %s" % (attr, repr(value)))
    #    return super(installer_obj, self).__setattr__(attr, value)

    def knobs(self):
        for name in self.__dict__:
            yield self, name


installer = installer_obj()
options = installer


def api_Backend_ldap2(host_name, setup_ca, connect=False):
    # we are sure we have the configuration file ready.
    cfg = dict(context='installer', confdir=paths.ETC_IPA, in_server=True,
               host=host_name,
    )
    if setup_ca:
        # we have an IPA-integrated CA
        cfg['ca_host'] = host_name

    api.bootstrap(**cfg)
    api.finalize()
    if connect:
        api.Backend.ldap2.connect()


def gen_env_boostrap_finalize_core(etc_ipa, default_config):
    env = Env()
    #env._bootstrap(context='installer', confdir=paths.ETC_IPA, log=None)
    #env._finalize_core(**dict(constants.DEFAULT_CONFIG))
    env._bootstrap(context='installer', confdir=etc_ipa, log=None)
    env._finalize_core(**dict(default_config))
    return env


def api_bootstrap_finalize(env):
    # pylint: disable=no-member
    xmlrpc_uri = 'https://{}/ipa/xml'.format(ipautil.format_netloc(env.host))
    api.bootstrap(in_server=True,
                  context='installer',
                  confdir=paths.ETC_IPA,
                  ldap_uri=installutils.realm_to_ldapi_uri(env.realm),
                  xmlrpc_uri=xmlrpc_uri)
    # pylint: enable=no-member
    api.finalize()


def gen_ReplicaConfig():
    class ExtendedReplicaConfig(ReplicaConfig):
        def __init__(self, top_dir=None):
            super(ExtendedReplicaConfig, self).__init__(top_dir)

        #def __getattribute__(self, attr):
        #    value = super(ExtendedReplicaConfig, self).__getattribute__(attr)
        #    if attr not in [ "__dict__", "knobs" ]:
        #        logger.debug("  <== Accessing config.%s (%s)" % (attr, repr(value)))
        #    return value

        def __getattr__(self, attr):
            logger.info("  ==> ADDING missing config.%s" % attr)
            setattr(self, attr, None)
            return getattr(self, attr)

        #def __setattr__(self, attr, value):
        #    logger.debug("  ==> Setting config.%s to %s" % (attr, repr(value)))
        #    return super(ExtendedReplicaConfig, self).__setattr__(attr, value)

        def knobs(self):
            for name in self.__dict__:
                yield self, name

    #config = ReplicaConfig()
    config = ExtendedReplicaConfig()
    config.realm_name = api.env.realm
    config.host_name = api.env.host
    config.domain_name = api.env.domain
    config.master_host_name = api.env.server
    config.ca_host_name = api.env.ca_host
    config.kra_host_name = config.ca_host_name
    config.ca_ds_port = 389
    config.setup_ca = options.setup_ca
    config.setup_kra = options.setup_kra
    config.dir = options._top_dir
    config.basedn = api.env.basedn
    #config.subject_base = options.subject_base

    return config


def ds_init_info(ansible_log, fstore, domainlevel, dirsrv_config_file,
                 realm_name, host_name, domain_name, dm_password,
                 idstart, idmax, subject_base, ca_subject,
                 #no_hbac_allow,
                 dirsrv_pkcs12_info, no_pkinit,
                 external_cert_files, dirsrv_cert_files):

    if not external_cert_files:
        ds = dsinstance.DsInstance(fstore=fstore, domainlevel=domainlevel,
                                   config_ldif=dirsrv_config_file)
        ds.set_output(ansible_log)

        if dirsrv_cert_files:
            _dirsrv_pkcs12_info = dirsrv_pkcs12_info
        else:
            _dirsrv_pkcs12_info = None

        with redirect_stdout(ansible_log):
            ds.init_info(realm_name, host_name, domain_name, dm_password,
                         subject_base, ca_subject, idstart, idmax,
                         #hbac_allow=not no_hbac_allow,
                         _dirsrv_pkcs12_info, setup_pkinit=not no_pkinit)
    else:
        ds = dsinstance.DsInstance(fstore=fstore, domainlevel=domainlevel)
        ds.set_output(ansible_log)

        with redirect_stdout(ansible_log):
            ds.init_info(realm_name, host_name, domain_name, dm_password,
                         subject_base, ca_subject, 1101, 1100, None,
                         setup_pkinit=not no_pkinit)

    return ds


def replica_ds_init_info(ansible_log,
                         config, options, ca_is_configured, remote_api,
                         ds_ca_subject, ca_file,
                         promote=False, pkcs12_info=None):

    dsinstance.check_ports()

    # if we have a pkcs12 file, create the cert db from
    # that. Otherwise the ds setup will create the CA
    # cert
    if pkcs12_info is None:
        pkcs12_info = make_pkcs12_info(config.dir, "dscert.p12",
                                       "dirsrv_pin.txt")

    # during replica install, this gets invoked before local DS is
    # available, so use the remote api.
    #if ca_is_configured:
    #    ca_subject = ca.lookup_ca_subject(_api, config.subject_base)
    #else:
    #    ca_subject = installutils.default_ca_subject_dn(config.subject_base)
    ca_subject = ds_ca_subject

    ds = dsinstance.DsInstance(
        config_ldif=options.dirsrv_config_file)
    ds.set_output(ansible_log)

    # Source: ipaserver/install/dsinstance.py

    # idstart and idmax are configured so that the range is seen as
    # depleted by the DNA plugin and the replica will go and get a
    # new range from the master.
    # This way all servers use the initially defined range by default.
    idstart = 1101
    idmax = 1100

    with redirect_stdout(ansible_log):
        ds.init_info(
            realm_name=config.realm_name,
            fqdn=config.host_name,
            domain_name=config.domain_name,
            dm_password=config.dirman_password,
            subject_base=config.subject_base,
            ca_subject=ca_subject,
            idstart=idstart,
            idmax=idmax,
            pkcs12_info=pkcs12_info,
            ca_file=ca_file,
            setup_pkinit=not options.no_pkinit,
        )
    ds.master_fqdn = config.master_host_name
    if ca_is_configured is not None:
        ds.ca_is_configured = ca_is_configured
    ds.promote = promote
    ds.api = remote_api

    # from __setup_replica

    # Always connect to ds over ldapi
    ldap_uri = ipaldap.get_ldap_uri(protocol='ldapi', realm=ds.realm)
    conn = ipaldap.LDAPClient(ldap_uri)
    conn.external_bind()

    return ds


def krb_init_info(ansible_log, fstore, realm_name, host_name, no_pkinit,
                  subject_base):
    krb = krbinstance.KrbInstance(fstore)
    krb.set_output(ansible_log)
    with redirect_stdout(ansible_log):
        krb.init_info(realm_name, host_name, etup_pkinit=not no_pkinit,
                      subject_base=subject_base)


def replica_krb_init_info(ansible_log, fstore, realm_name, master_host_name,
                          host_name, domain_name, admin_password,
                          no_pkinit, subject_base, pkcs12_info=None):
    # promote is not needed here

    # From replicainstall.install_krb
    krb = krbinstance.KrbInstance(fstore=fstore)
    krb.set_output(ansible_log)

    # pkinit files
    if pkcs12_info is None:
        pkcs12_info = make_pkcs12_info(config.dir, "pkinitcert.p12",
                                       "pkinit_pin.txt")

    #krb.create_replica(realm_name,
    #                   master_host_name, host_name,
    #                   domain_name, dirman_password,
    #                   setup_pkinit, pkcs12_info,
    #                   subject_base=subject_base,
    #                   promote=promote)
    with redirect_stdout(ansible_log):
        krb.init_info(realm_name, host_name, setup_pkinit=not no_pkinit,
                      subject_base=subject_base)

        # From ipaserver.install.krbinstance.create_replica

        krb.pkcs12_info = pkcs12_info
        krb.subject_base = subject_base
        krb.master_fqdn = master_host_name
        krb.config_pkinit = not no_pkinit

        #krb.__common_setup(realm_name, host_name, domain_name, admin_password)
        krb.fqdn = host_name
        krb.realm = realm_name.upper()
        krb.host = host_name.split(".")[0]
        krb.ip = socket.getaddrinfo(host_name, None, socket.AF_UNSPEC, socket.SOCK_STREAM)[0][4][0]
        krb.domain = domain_name
        krb.suffix = ipautil.realm_to_suffix(krb.realm)
        krb.kdc_password = ipautil.ipa_generate_password()
        krb.admin_password = admin_password
        krb.dm_password = admin_password

        #krb.__setup_sub_dict()
        if os.path.exists(paths.COMMON_KRB5_CONF_DIR):
            includes = 'includedir {}'.format(paths.COMMON_KRB5_CONF_DIR)
        else:
            includes = ''

        krb.sub_dict = dict(FQDN=krb.fqdn,
                             IP=krb.ip,
                             PASSWORD=krb.kdc_password,
                             SUFFIX=krb.suffix,
                             DOMAIN=krb.domain,
                             HOST=krb.host,
                             SERVER_ID=installutils.realm_to_serverid(krb.realm),
                             REALM=krb.realm,
                             KRB5KDC_KADM5_ACL=paths.KRB5KDC_KADM5_ACL,
                             DICT_WORDS=paths.DICT_WORDS,
                             KRB5KDC_KADM5_KEYTAB=paths.KRB5KDC_KADM5_KEYTAB,
                             KDC_CERT=paths.KDC_CERT,
                             KDC_KEY=paths.KDC_KEY,
                             CACERT_PEM=paths.CACERT_PEM,
                             KDC_CA_BUNDLE_PEM=paths.KDC_CA_BUNDLE_PEM,
                             CA_BUNDLE_PEM=paths.CA_BUNDLE_PEM,
                             INCLUDES=includes)

        # IPA server/KDC is not a subdomain of default domain
        # Proper domain-realm mapping needs to be specified
        domain = dnsname.from_text(krb.domain)
        fqdn = dnsname.from_text(krb.fqdn)
        if not fqdn.is_subdomain(domain):
            logger.debug("IPA FQDN '%s' is not located in default domain '%s'",
                         fqdn, domain)
            server_domain = fqdn.parent().to_unicode(omit_final_dot=True)
            logger.debug("Domain '%s' needs additional mapping in krb5.conf",
                         server_domain)
            dr_map = " .%(domain)s = %(realm)s\n %(domain)s = %(realm)s\n" \
                        % dict(domain=server_domain, realm=krb.realm)
        else:
            dr_map = ""
        krb.sub_dict['OTHER_DOMAIN_REALM_MAPS'] = dr_map

        # Configure KEYRING CCACHE if supported
        if kernel_keyring.is_persistent_keyring_supported():
            logger.debug("Enabling persistent keyring CCACHE")
            krb.sub_dict['OTHER_LIBDEFAULTS'] = \
                " default_ccache_name = KEYRING:persistent:%{uid}\n"
        else:
            logger.debug("Persistent keyring CCACHE is not enabled")
            krb.sub_dict['OTHER_LIBDEFAULTS'] = ''

    return krb


def ansible_module_get_parsed_ip_addresses(ansible_module,
                                           param='ip_addresses'):
    ip_addrs = [ ]
    for ip in ansible_module.params.get(param):
        try:
            ip_parsed = ipautil.CheckedIPAddress(ip)
        except Exception as e:
            ansible_module.fail_json(msg="Invalid IP Address %s: %s" % (ip, e))
        ip_addrs.append(ip_parsed)
    return ip_addrs


def gen_remote_api(master_host_name, etc_ipa):
    ldapuri = 'ldaps://%s' % ipautil.format_netloc(master_host_name)
    xmlrpc_uri = 'https://{}/ipa/xml'.format(ipautil.format_netloc(master_host_name))
    remote_api = create_api(mode=None)
    remote_api.bootstrap(in_server=True,
                         context='installer',
                         confdir=etc_ipa,
                         ldap_uri=ldapuri,
                         xmlrpc_uri=xmlrpc_uri)
    remote_api.finalize()
    return remote_api

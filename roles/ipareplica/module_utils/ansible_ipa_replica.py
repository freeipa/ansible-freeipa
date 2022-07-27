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

__all__ = ["contextlib", "dnsexception", "dnsresolver", "dnsreversename",
           "parse_version", "IPAChangeConf",
           "certstore", "sysrestore", "ipa_generate_password", "kinit_keytab",
           "IPA_CA_TRUST_FLAGS", "EXTERNAL_CA_TRUST_FLAGS", "DN",
           "ScriptError", "services", "tasks", "constants", "errors", "rpc",
           "x509", "validate_domain_name",
           "no_matching_interface_for_ip_address_warning",
           "configure_krb5_conf", "purge_host_keytab", "adtrust",
           "bindinstance", "ca", "certs", "dns", "httpinstance", "kra",
           "otpdinstance", "custodiainstance", "service", "upgradeinstance",
           "find_providing_servers", "find_providing_server", "load_pkcs12",
           "is_ipa_configured", "ReplicationManager", "replica_conn_check",
           "install_replica_ds", "install_krb", "install_ca_cert",
           "install_http", "install_dns_records", "create_ipa_conf",
           "check_dirsrv", "check_dns_resolution", "configure_certmonger",
           "remove_replica_info_dir", "preserve_enrollment_state",
           "uninstall_client", "promote_sssd", "promote_openldap_conf",
           "rpc_client", "check_remote_fips_mode", "check_remote_version",
           "common_check", "current_domain_level",
           "check_domain_level_is_supported", "promotion_check_ipa_domain",
           "SSSDConfig", "CalledProcessError", "timeconf", "ntpinstance",
           "dnsname", "kernel_keyring", "krbinstance", "getargspec",
           "adtrustinstance"]

import sys

# HACK: workaround for Ansible 2.9
# https://github.com/ansible/ansible/issues/68361
if 'ansible.executor' in sys.modules:
    for attr in __all__:
        setattr(sys.modules[__name__], attr, None)
else:
    import logging
    from contextlib import contextmanager as contextlib_contextmanager

    # Import getargspec from inspect or provide own getargspec for
    # Python 2 compatibility with Python 3.11+.
    try:
        from inspect import getargspec
    except ImportError:
        from collections import namedtuple
        from inspect import getfullargspec

        # The code is copied from Python 3.10 inspect.py
        # Authors: Ka-Ping Yee <ping@lfw.org>
        #          Yury Selivanov <yselivanov@sprymix.com>
        ArgSpec = namedtuple('ArgSpec', 'args varargs keywords defaults')

        def getargspec(func):
            args, varargs, varkw, defaults, kwonlyargs, _kwonlydefaults, \
                ann = getfullargspec(func)
            if kwonlyargs or ann:
                raise ValueError(
                    "Function has keyword-only parameters or annotations"
                    ", use inspect.signature() API which can support them")
            return ArgSpec(args, varargs, varkw, defaults)

    from ipapython.version import NUM_VERSION, VERSION

    if NUM_VERSION < 30201:
        # See ipapython/version.py
        IPA_MAJOR, IPA_MINOR, IPA_RELEASE = [int(x) for x in
                                             VERSION.split(".", 2)]
        IPA_PYTHON_VERSION = IPA_MAJOR * 10000 + IPA_MINOR * 100 + IPA_RELEASE
    else:
        IPA_PYTHON_VERSION = NUM_VERSION

    if NUM_VERSION >= 40600:
        # IPA version >= 4.6

        import contextlib

        import dns.exception as dnsexception
        import dns.name as dnsname
        import dns.resolver as dnsresolver
        import dns.reversename as dnsreversename

        from pkg_resources import parse_version

        from ipaclient.install.ipachangeconf import IPAChangeConf
        from ipalib.install import certstore, sysrestore
        from ipapython.ipautil import ipa_generate_password
        from ipalib.install.kinit import kinit_keytab
        from ipapython import ipaldap, ipautil, kernel_keyring
        from ipapython.certdb import IPA_CA_TRUST_FLAGS, \
            EXTERNAL_CA_TRUST_FLAGS
        from ipapython.dn import DN
        from ipapython.admintool import ScriptError
        from ipapython.ipa_log_manager import standard_logging_setup
        from ipaplatform import services
        from ipaplatform.tasks import tasks
        from ipaplatform.paths import paths
        from ipalib import api, constants, create_api, errors, rpc, x509
        from ipalib.config import Env
        from ipalib.util import (
            validate_domain_name,
            no_matching_interface_for_ip_address_warning)
        from ipaclient.install.client import configure_krb5_conf, \
            purge_host_keytab
        from ipaserver.install import (
            adtrust, bindinstance, ca, certs, dns, dsinstance, httpinstance,
            installutils, kra, krbinstance,
            otpdinstance, custodiainstance, service, upgradeinstance)
        from ipaserver.install import adtrustinstance
        try:
            from ipaserver.masters import (
                find_providing_servers, find_providing_server)
        except ImportError:
            from ipaserver.install.service import (
                find_providing_servers, find_providing_server)
        from ipaserver.install.installutils import (
            ReplicaConfig, load_pkcs12)
        try:
            from ipalib.facts import is_ipa_configured
        except ImportError:
            from ipaserver.install.installutils import is_ipa_configured
        from ipaserver.install.replication import (
            ReplicationManager, replica_conn_check)
        from ipaserver.install.server.replicainstall import (
            make_pkcs12_info, install_replica_ds, install_krb, install_ca_cert,
            install_http, install_dns_records, create_ipa_conf, check_dirsrv,
            check_dns_resolution, configure_certmonger,
            remove_replica_info_dir,
            # common_cleanup,
            preserve_enrollment_state, uninstall_client,
            promote_sssd, promote_openldap_conf, rpc_client,
            check_remote_fips_mode, check_remote_version, common_check,
            current_domain_level, check_domain_level_is_supported,
            # enroll_dl0_replica,
            # ensure_enrolled,
            promotion_check_ipa_domain
        )
        import SSSDConfig
        from subprocess import CalledProcessError

        try:
            from ipaclient.install import timeconf
            time_service = "chronyd"  # pylint: disable=invalid-name
            ntpinstance = None  # pylint: disable=invalid-name
        except ImportError:
            try:
                from ipaclient.install import ntpconf as timeconf
            except ImportError:
                from ipaclient import ntpconf as timeconf
            from ipaserver.install import ntpinstance
            time_service = "ntpd"  # pylint: disable=invalid-name

    else:
        # IPA version < 4.6

        raise Exception("freeipa version '%s' is too old" % VERSION)

    logger = logging.getLogger("ipa-server-install")

    def setup_logging():
        # logger.setLevel(logging.DEBUG)
        standard_logging_setup(
            paths.IPAREPLICA_INSTALL_LOG, verbose=False, debug=False,
            filemode='a', console_format='%(message)s')

    @contextlib_contextmanager
    def redirect_stdout(stream):
        sys.stdout = stream
        try:
            yield stream
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
            # self.write(msg+"\n")
            self.write(msg)

        def debug(self, msg):
            self.module.debug(msg)

        def info(self, msg):
            self.module.debug(msg)

        def write(self, msg):
            self.module.debug(msg)
            # self.module.warn(msg)

    # pylint: disable=too-many-instance-attributes, useless-object-inheritance
    class installer_obj(object):  # pylint: disable=invalid-name
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
            self.reverse_zones = []
            # def _is_promote(self):
            #     return self.replica_file is None
            # self.skip_conncheck = False
            self._replica_install = False
            # self.dnssec_master = False # future unknown
            # self.disable_dnssec_master = False # future unknown
            # self.domainlevel = MAX_DOMAIN_LEVEL # deprecated
            # self.domain_level = self.domainlevel # deprecated
            self.interactive = False
            self.unattended = not self.interactive
            # self.promote = self.replica_file is None
            self.promote = True
            self.skip_schema_check = None

        # def __getattribute__(self, attr):
        #     value = super(installer_obj, self).__getattribute__(attr)
        #     if not attr.startswith("--") and not attr.endswith("--"):
        #         logger.debug(
        #             "  <-- Accessing installer.%s (%s)" %
        #             (attr, repr(value)))
        #     return value

        def __getattr__(self, attrname):
            logger.info("  --> ADDING missing installer.%s", attrname)
            setattr(self, attrname, None)
            return getattr(self, attrname)

        # def __setattr__(self, attr, value):
        #    logger.debug("  --> Setting installer.%s to %s" %
        #                 (attr, repr(value)))
        #    return super(installer_obj, self).__setattr__(attr, value)

        def knobs(self):
            for name in self.__dict__:
                yield self, name

    # pylint: enable=too-many-instance-attributes, useless-object-inheritance

    # pylint: disable=attribute-defined-outside-init
    installer = installer_obj()
    options = installer

    # DNSInstallInterface
    options.dnssec_master = False
    options.disable_dnssec_master = False
    options.kasp_db_file = None
    options.force = False

    # ServerMasterInstall
    options.add_sids = False
    options.add_agents = False

    # ServerReplicaInstall
    options.subject_base = None
    options.ca_subject = None
    # pylint: enable=attribute-defined-outside-init

    def gen_env_boostrap_finalize_core(etc_ipa, default_config):
        env = Env()
        # env._bootstrap(context='installer', confdir=paths.ETC_IPA, log=None)
        # env._finalize_core(**dict(constants.DEFAULT_CONFIG))
        env._bootstrap(context='installer', confdir=etc_ipa, log=None)
        env._finalize_core(**dict(default_config))
        return env

    def api_bootstrap_finalize(env):
        # pylint: disable=no-member
        xmlrpc_uri = \
            'https://{}/ipa/xml'.format(ipautil.format_netloc(env.host))
        api.bootstrap(in_server=True,
                      context='installer',
                      confdir=paths.ETC_IPA,
                      ldap_uri=installutils.realm_to_ldapi_uri(env.realm),
                      xmlrpc_uri=xmlrpc_uri)
        # pylint: enable=no-member
        api.finalize()

    def gen_ReplicaConfig():  # pylint: disable=invalid-name
        # pylint: disable=too-many-instance-attributes
        class ExtendedReplicaConfig(ReplicaConfig):
            # pylint: disable=useless-super-delegation
            def __init__(self, top_dir=None):
                # pylint: disable=super-with-arguments
                super(ExtendedReplicaConfig, self).__init__(top_dir)

            # def __getattribute__(self, attr):
            #     value = super(ExtendedReplicaConfig, self).__getattribute__(
            #         attr)
            #    if attr not in ["__dict__", "knobs"]:
            #        logger.debug("  <== Accessing config.%s (%s)" %
            #                     (attr, repr(value)))
            #    return value\
            # pylint: enable=useless-super-delegation

            def __getattr__(self, attrname):
                logger.info("  ==> ADDING missing config.%s", attrname)
                setattr(self, attrname, None)
                return getattr(self, attrname)

            # def __setattr__(self, attr, value):
            #   logger.debug("  ==> Setting config.%s to %s" %
            #                (attr, repr(value)))
            #   return super(ExtendedReplicaConfig, self).__setattr__(attr,
            #                                                         value)

            def knobs(self):
                for name in self.__dict__:
                    yield self, name
        # pylint: enable=too-many-instance-attributes

        # pylint: disable=attribute-defined-outside-init
        # config = ReplicaConfig()
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
        # config.subject_base = options.subject_base

        # pylint: enable=attribute-defined-outside-init

        return config

    def replica_ds_init_info(ansible_log,
                             config, options_, ca_is_configured, remote_api,
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
        # if ca_is_configured:
        #     ca_subject = ca.lookup_ca_subject(_api, config.subject_base)
        # else:
        #     ca_subject = installutils.default_ca_subject_dn(
        #         config.subject_base)
        ca_subject = ds_ca_subject

        ds = dsinstance.DsInstance(
            config_ldif=options_.dirsrv_config_file)
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

    def ansible_module_get_parsed_ip_addresses(ansible_module,
                                               param='ip_addresses'):
        ip_addrs = []
        for ip in ansible_module.params.get(param):
            try:
                ip_parsed = ipautil.CheckedIPAddress(ip)
            except Exception as e:
                ansible_module.fail_json(
                    msg="Invalid IP Address %s: %s" % (ip, e))
            ip_addrs.append(ip_parsed)
        return ip_addrs

    def gen_remote_api(master_host_name, etc_ipa):
        ldapuri = 'ldaps://%s' % ipautil.format_netloc(master_host_name)
        xmlrpc_uri = 'https://{}/ipa/xml'.format(
            ipautil.format_netloc(master_host_name))
        remote_api = create_api(mode=None)
        remote_api.bootstrap(in_server=True,
                             context='installer',
                             confdir=etc_ipa,
                             ldap_uri=ldapuri,
                             xmlrpc_uri=xmlrpc_uri)
        remote_api.finalize()
        return remote_api

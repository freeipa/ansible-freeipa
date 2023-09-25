# -*- coding: utf-8 -*-

# Authors:
#   Thomas Woerner <twoerner@redhat.com>
#
# Based on ipa-server-install code
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

__metaclass__ = type  # pylint: disable=invalid-name

__all__ = ["IPAChangeConf", "certmonger", "sysrestore", "root_logger",
           "ipa_generate_password", "run", "ScriptError", "services",
           "tasks", "errors", "x509", "DOMAIN_LEVEL_0", "MIN_DOMAIN_LEVEL",
           "MAX_DOMAIN_LEVEL", "validate_domain_name",
           "no_matching_interface_for_ip_address_warning",
           "check_zone_overlap", "timeconf", "ntpinstance", "adtrust",
           "bindinstance", "ca", "dns", "httpinstance", "installutils",
           "kra", "krbinstance", "otpdinstance", "custodiainstance",
           "replication", "service", "sysupgrade", "IPA_MODULES",
           "BadHostError", "get_fqdn", "get_server_ip_address",
           "is_ipa_configured", "load_pkcs12", "read_password", "verify_fqdn",
           "update_hosts_file", "check_dirsrv", "validate_admin_password",
           "validate_dm_password", "read_cache", "write_cache",
           "adtrustinstance", "IPAAPI_USER", "sync_time", "PKIIniLoader",
           "default_subject_base", "default_ca_subject_dn",
           "check_ldap_conf", "encode_certificate", "decode_certificate",
           "check_available_memory", "getargspec", "get_min_idstart",
           "paths", "api", "ipautil", "adtrust_imported", "NUM_VERSION",
           "time_service", "kra_imported", "dsinstance", "IPA_PYTHON_VERSION",
           "NUM_VERSION", "SerialNumber"]

import sys
import logging

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


try:
    from contextlib import contextmanager as contextlib_contextmanager
    from ansible.module_utils import six
    import base64

    from ipapython.version import NUM_VERSION, VERSION

    if NUM_VERSION < 30201:
        # See ipapython/version.py
        IPA_MAJOR, IPA_MINOR, IPA_RELEASE = [int(x) for x in
                                             VERSION.split(".", 2)]
        IPA_PYTHON_VERSION = IPA_MAJOR * 10000 + IPA_MINOR * 100 + IPA_RELEASE
    else:
        IPA_PYTHON_VERSION = NUM_VERSION

    if NUM_VERSION >= 40500:
        # IPA version >= 4.5

        from ipaclient.install.ipachangeconf import IPAChangeConf
        from ipalib.install import certmonger
        try:
            from ipalib import sysrestore
        except ImportError:
            from ipalib.install import sysrestore
        from ipapython import ipautil
        from ipapython.ipa_log_manager import standard_logging_setup
        try:
            from ipapython.ipa_log_manager import root_logger
        except ImportError:
            root_logger = None
        from ipapython.ipautil import (
            ipa_generate_password, run)
        from ipapython.admintool import ScriptError
        from ipaplatform import services
        from ipaplatform.paths import paths
        from ipaplatform.tasks import tasks
        from ipalib import api, errors, x509
        from ipalib.constants import DOMAIN_LEVEL_0, MIN_DOMAIN_LEVEL, \
            MAX_DOMAIN_LEVEL
        try:
            from ipalib.constants import IPAAPI_USER
        except ImportError:
            IPAAPI_USER = None
        from ipalib.util import (
            validate_domain_name,
            no_matching_interface_for_ip_address_warning,
        )
        from ipapython.dnsutil import check_zone_overlap
        from ipapython.dn import DN
        try:
            from ipaclient.install import timeconf
            from ipaclient.install.client import sync_time
            time_service = "chronyd"  # pylint: disable=invalid-name
            ntpinstance = None  # pylint: disable=invalid-name
        except ImportError:
            try:
                from ipaclient.install import ntpconf as timeconf
            except ImportError:
                from ipaclient import ntpconf as timeconf
            from ipaserver.install import ntpinstance
            time_service = "ntpd"  # pylint: disable=invalid-name
            sync_time = None  # pylint: disable=invalid-name
        from ipaserver.install import (
            adtrust, bindinstance, ca, dns, dsinstance,
            httpinstance, installutils, kra, krbinstance,
            otpdinstance, custodiainstance, replication, service,
            sysupgrade)
        adtrust_imported = True  # pylint: disable=invalid-name
        kra_imported = True  # pylint: disable=invalid-name
        from ipaserver.install.installutils import (
            BadHostError, get_fqdn, get_server_ip_address,
            load_pkcs12, read_password, verify_fqdn,
            update_hosts_file)
        try:
            from ipalib.facts import is_ipa_configured
        except ImportError:
            from ipaserver.install.installutils import is_ipa_configured
        from ipaserver.install.server.install import (
            check_dirsrv, validate_admin_password, validate_dm_password,
            read_cache, write_cache)
        try:
            from ipaserver.install.dogtaginstance import PKIIniLoader
        except ImportError:
            PKIIniLoader = None
        try:
            from ipaserver.install.installutils import default_subject_base
        except ImportError:
            def default_subject_base(realm_name):
                return DN(('O', realm_name))
        try:
            from ipalib.facts import IPA_MODULES
        except ImportError:
            from ipaserver.install.installutils import IPA_MODULES
        try:
            from ipaserver.install.installutils import default_ca_subject_dn
        except ImportError:
            def default_ca_subject_dn(subject_base):
                return DN(('CN', 'Certificate Authority'), subject_base)
        try:
            from ipaserver.install.installutils import check_available_memory
        except ImportError:
            check_available_memory = None

        try:
            from ipaserver.install import adtrustinstance
            _server_trust_ad_installed = True  # pylint: disable=invalid-name
        except ImportError:
            _server_trust_ad_installed = False  # pylint: disable=invalid-name

        try:
            from ipaclient.install.client import check_ldap_conf
        except ImportError:
            check_ldap_conf = None

        try:
            from ipalib.x509 import Encoding
        except ImportError:
            from cryptography.hazmat.primitives.serialization import Encoding

        try:
            from ipalib.x509 import load_pem_x509_certificate
            certificate_loader = load_pem_x509_certificate
        except ImportError:
            from ipalib.x509 import load_certificate
            certificate_loader = load_certificate

        try:
            from ipaserver.install.server.install import get_min_idstart
        except ImportError:
            get_min_idstart = None

        # SerialNumber is defined in versions 4.10 and later and is
        # used by Random Serian Number v3.
        try:
            from ipalib.parameters import SerialNumber
        except ImportError:
            SerialNumber = None

    else:
        # IPA version < 4.5
        raise RuntimeError("freeipa version '%s' is too old" % VERSION)

except ImportError as _err:
    ANSIBLE_IPA_SERVER_MODULE_IMPORT_ERROR = str(_err)

    for attr in __all__:
        setattr(sys.modules[__name__], attr, None)
else:
    ANSIBLE_IPA_SERVER_MODULE_IMPORT_ERROR = None


logger = logging.getLogger("ipa-server-install")


def setup_logging():
    # logger.setLevel(logging.DEBUG)
    standard_logging_setup(
        paths.IPASERVER_INSTALL_LOG, verbose=False, debug=False,
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

    @staticmethod
    def isatty():
        return False

    def write(self, msg):
        self.module.debug(msg)
        # self.module.warn(msg)


# pylint: disable=too-few-public-methods, useless-object-inheritance
# pylint: disable=too-many-instance-attributes
class options_obj(object):  # pylint: disable=invalid-name
    def __init__(self):
        self._replica_install = False
        self.dnssec_master = False  # future unknown
        self.disable_dnssec_master = False  # future unknown
        self.domainlevel = MAX_DOMAIN_LEVEL  # deprecated
        self.domain_level = self.domainlevel  # deprecated
        self.interactive = False
        self.unattended = not self.interactive

    # def __getattribute__(self, attr):
    #    logger.info(" <-- Accessing options.%s" % attr)
    #    return super(options_obj, self).__getattribute__(attr)

    # def __getattr__(self, attr):
    #    logger.info(" --> Adding missing options.%s" % attr)
    #    setattr(self, attr, None)
    #    return getattr(self, attr)

    def knobs(self):
        for name in self.__dict__:
            yield self, name


# pylint: enable=too-few-public-methods, useless-object-inheritance


# pylint: enable=too-many-instance-attributes
options = options_obj()
installer = options

# pylint: disable=attribute-defined-outside-init

# ServerMasterInstall
options.add_sids = True
options.add_agents = False

# Installable
options.uninstalling = False

# ServerInstallInterface
options.description = "Server"

options.kinit_attempts = 1
options.fixed_primary = True
options.permit = False
options.enable_dns_updates = False
options.no_krb5_offline_passwords = False
options.preserve_sssd = False
options.no_sssd = False

# ServerMasterInstall
options.force_join = False
options.servers = None
options.no_wait_for_dns = True
options.host_password = None
options.keytab = None
options.setup_ca = True
# always run sidgen task and do not allow adding agents on first master
options.add_sids = True
options.add_agents = False

# ADTrustInstallInterface
# no_msdcs is deprecated
options.no_msdcs = False

# For pylint
options.external_cert_files = None
options.dirsrv_cert_files = None

# Uninstall
options.ignore_topology_disconnect = False
options.ignore_last_of_role = False

# pylint: enable=attribute-defined-outside-init


# pylint: disable=invalid-name
def api_Backend_ldap2(host_name, setup_ca, connect=False):
    # we are sure we have the configuration file ready.
    cfg = dict(context='installer', confdir=paths.ETC_IPA, in_server=True,
               host=host_name)
    if setup_ca:
        # we have an IPA-integrated CA
        cfg['ca_host'] = host_name

    api.bootstrap(**cfg)
    api.finalize()
    if connect:
        api.Backend.ldap2.connect()


# pylint: enable=invalid-name


def ds_init_info(ansible_log, fstore, domainlevel, dirsrv_config_file,
                 realm_name, host_name, domain_name, dm_password,
                 idstart, idmax, subject_base, ca_subject,
                 _no_hbac_allow, dirsrv_pkcs12_info, no_pkinit):

    if not options.external_cert_files:
        _ds = dsinstance.DsInstance(fstore=fstore, domainlevel=domainlevel,
                                    config_ldif=dirsrv_config_file)
        _ds.set_output(ansible_log)

        if options.dirsrv_cert_files:
            _dirsrv_pkcs12_info = dirsrv_pkcs12_info
        else:
            _dirsrv_pkcs12_info = None

        with redirect_stdout(ansible_log):
            _ds.init_info(realm_name, host_name, domain_name, dm_password,
                          subject_base, ca_subject, idstart, idmax,
                          # hbac_allow=not no_hbac_allow,
                          _dirsrv_pkcs12_info, setup_pkinit=not no_pkinit)
    else:
        _ds = dsinstance.DsInstance(fstore=fstore, domainlevel=domainlevel)
        _ds.set_output(ansible_log)

        with redirect_stdout(ansible_log):
            _ds.init_info(realm_name, host_name, domain_name, dm_password,
                          subject_base, ca_subject, 1101, 1100, None,
                          setup_pkinit=not no_pkinit)

    return _ds


def ansible_module_get_parsed_ip_addresses(ansible_module,
                                           param='ip_addresses'):
    ip_addrs = []
    for _ip in ansible_module.params.get(param):
        try:
            ip_parsed = ipautil.CheckedIPAddress(_ip)
        except Exception as err:
            ansible_module.fail_json(
                msg="Invalid IP Address %s: %s" % (_ip, err))
        ip_addrs.append(ip_parsed)
    return ip_addrs


def encode_certificate(cert):
    """
    Encode a certificate using base64.

    It also takes FreeIPA and Python versions into account.
    """
    if isinstance(cert, (str, bytes)):
        encoded = base64.b64encode(cert)
    else:
        encoded = base64.b64encode(cert.public_bytes(Encoding.DER))
    if not six.PY2:
        encoded = encoded.decode('ascii')
    return encoded


def decode_certificate(cert):
    """
    Decode a certificate using base64.

    It also takes FreeIPA versions into account and returns a
    IPACertificate for newer IPA versions.
    """
    if hasattr(x509, "IPACertificate"):
        cert = cert.strip()
        if not cert.startswith("-----BEGIN CERTIFICATE-----"):
            cert = "-----BEGIN CERTIFICATE-----\n" + cert
        if not cert.endswith("-----END CERTIFICATE-----"):
            cert += "\n-----END CERTIFICATE-----"

        cert = certificate_loader(cert.encode('utf-8'))
    else:
        cert = base64.b64decode(cert)
    return cert


def check_imports(module):
    if ANSIBLE_IPA_SERVER_MODULE_IMPORT_ERROR is not None:
        module.fail_json(msg=ANSIBLE_IPA_SERVER_MODULE_IMPORT_ERROR)

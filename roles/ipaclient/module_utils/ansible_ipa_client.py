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

__all__ = ["gssapi", "version", "discovery", "api", "errors", "x509",
           "constants", "sysrestore", "certmonger", "certstore",
           "delete_persistent_client_session_data", "ScriptError",
           "CheckedIPAddress", "validate_domain_name", "normalize_hostname",
           "validate_hostname", "services", "tasks", "CalledProcessError",
           "write_tmp_file", "ipa_generate_password", "DN", "kinit_keytab",
           "kinit_password", "GSSError", "CLIENT_INSTALL_ERROR",
           "is_ipa_client_installed", "CLIENT_ALREADY_CONFIGURED",
           "nssldap_exists", "remove_file", "check_ip_addresses",
           "print_port_conf_info", "configure_ipa_conf", "purge_host_keytab",
           "configure_sssd_conf", "realm_to_suffix", "run", "timeconf",
           "serialization", "configure_krb5_conf", "get_ca_certs",
           "SECURE_PATH", "get_server_connection_interface",
           "disable_ra", "client_dns",
           "configure_certmonger", "update_ssh_keys",
           "configure_openldap_conf", "hardcode_ldap_server",
           "get_certs_from_ldap", "save_state", "create_ipa_nssdb",
           "configure_nisdomain", "configure_ldap_conf",
           "configure_nslcd_conf", "configure_ssh_config",
           "configure_sshd_config", "configure_automount",
           "configure_firefox", "sync_time", "check_ldap_conf",
           "sssd_enable_ifp", "configure_selinux_for_client",
           "getargspec", "paths", "options",
           "IPA_PYTHON_VERSION", "NUM_VERSION", "certdb",
           "ipalib", "logger", "ipautil", "installer"]

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
    from ipapython.version import NUM_VERSION, VERSION

    if NUM_VERSION < 30201:
        # See ipapython/version.py
        IPA_MAJOR, IPA_MINOR, IPA_RELEASE = [int(x) for x in
                                             VERSION.split(".", 2)]
        IPA_PYTHON_VERSION = IPA_MAJOR * 10000 + IPA_MINOR * 100 + IPA_RELEASE
    else:
        IPA_PYTHON_VERSION = NUM_VERSION

    # Minimal IPA version check
    if NUM_VERSION < 40608:
        raise RuntimeError("freeipa version '%s' is too old" % VERSION)

    import gssapi

    from ipapython import version
    try:
        # IPA >= 4.8.0
        from ipaclient import discovery
    except ImportError:
        from ipaclient.install import ipadiscovery as discovery
    import ipalib
    from ipalib import api, errors, x509
    from ipalib import constants
    try:
        from ipalib import sysrestore  # IPA >= 4.8.9
    except ImportError:
        from ipalib.install import sysrestore  # IPA >= 4.5.0
    from ipalib.install import certmonger  # IPA >= 4.5.0
    from ipalib.install import certstore   # IPA >= 4.5.0
    from ipalib.rpc import delete_persistent_client_session_data
    from ipapython import certdb, ipautil
    from ipapython.admintool import ScriptError
    from ipapython.ipautil import CheckedIPAddress
    from ipalib.util import validate_domain_name, normalize_hostname, \
        validate_hostname
    from ipaplatform import services
    from ipaplatform.paths import paths
    from ipaplatform.tasks import tasks
    try:
        from cryptography.hazmat.primitives import serialization
    except ImportError:
        serialization = None
    from ipapython.ipautil import CalledProcessError, write_tmp_file, \
        ipa_generate_password
    from ipapython.dn import DN
    try:
        # IPA >= 4.12.0
        from ipalib.kinit import kinit_password, kinit_keytab
    except ImportError:
        # IPA >= 4.5.0
        from ipalib.install.kinit import kinit_keytab, kinit_password
    from ipapython.ipa_log_manager import standard_logging_setup
    from gssapi.exceptions import GSSError
    from ipaclient.install.client import configure_krb5_conf, \
        get_ca_certs, SECURE_PATH, get_server_connection_interface, \
        disable_ra, client_dns, \
        configure_certmonger, update_ssh_keys, \
        configure_openldap_conf, \
        hardcode_ldap_server, get_certs_from_ldap, save_state, \
        create_ipa_nssdb, configure_ssh_config, \
        configure_sshd_config, \
        configure_automount, configure_firefox, configure_nisdomain, \
        CLIENT_INSTALL_ERROR, is_ipa_client_installed, \
        CLIENT_ALREADY_CONFIGURED, nssldap_exists, remove_file, \
        check_ip_addresses, print_port_conf_info, configure_ipa_conf, \
        purge_host_keytab, configure_sssd_conf, configure_ldap_conf, \
        configure_nslcd_conf

    from ipapython.ipautil import realm_to_suffix, run

    try:
        # IPA >= 4.6.90.pre2
        from ipaclient.install import timeconf
        time_service = "chronyd"
    except ImportError:
        # IPA >= 4.5.0
        from ipaclient.install import ntpconf as timeconf
        time_service = "ntpd"

    try:
        # IPA >= 4.6.90.pre2
        from ipaclient.install.client import sync_time
    except ImportError:
        sync_time = None

    try:
        # IPA >= 4.7.0
        from ipaclient.install.client import check_ldap_conf
    except ImportError:
        check_ldap_conf = None

    from ipaclient.install.client import sssd_enable_ifp  # IPA >= 4.6.5

    try:
        # IPA >= 4.11.0
        from ipaclient.install.client import configure_selinux_for_client
    except ImportError:
        configure_selinux_for_client = None

    from ipaclient.install.client import ClientInstallInterface  # IPA >= 4.5.0
    CLIENT_SUPPORTS_NO_DNSSEC_VALIDATION = False
    if hasattr(ClientInstallInterface, "no_dnssec_validation"):
        # IPA >= 4.13.0
        CLIENT_SUPPORTS_NO_DNSSEC_VALIDATION = True

except ImportError as _err:
    ANSIBLE_IPA_CLIENT_MODULE_IMPORT_ERROR = str(_err)

    for attr in __all__:
        setattr(sys.modules[__name__], attr, None)

else:
    ANSIBLE_IPA_CLIENT_MODULE_IMPORT_ERROR = None


def setup_logging():
    standard_logging_setup(
        paths.IPACLIENT_INSTALL_LOG, verbose=False, debug=False,
        filemode='a', console_format='%(message)s')


def ansible_module_get_parsed_ip_addresses(ansible_module,
                                           param='ip_addresses'):
    ip_addresses = ansible_module.params.get(param)
    if ip_addresses is None:
        return None

    ip_addrs = []
    for ip in ip_addresses:
        try:
            ip_parsed = ipautil.CheckedIPAddress(ip)
        except Exception as e:
            ansible_module.fail_json(msg="Invalid IP Address %s: %s" % (ip, e))
        ip_addrs.append(ip_parsed)
    return ip_addrs


def check_imports(module):
    if ANSIBLE_IPA_CLIENT_MODULE_IMPORT_ERROR is not None:
        module.fail_json(msg=ANSIBLE_IPA_CLIENT_MODULE_IMPORT_ERROR)


# pylint: disable=invalid-name,useless-object-inheritance
class installer_obj(object):
    def __init__(self):
        self.interactive = False
        self.unattended = not self.interactive

    # pylint: disable=attribute-defined-outside-init
    def set_logger(self, _logger):
        self.logger = _logger

    # def __getattribute__(self, attr):
    #    value = super(installer_obj, self).__getattribute__(attr)
    #    if not attr.startswith("--") and not attr.endswith("--"):
    #        logger.debug(
    #            "  <-- Accessing installer.%s (%s)" % (attr, repr(value)))
    #    return value

    # def __getattr__(self, attr):
    #    # logger.info("  --> ADDING missing installer.%s" % attr)
    #    self.logger.warn("  --> ADDING missing installer.%s" % attr)
    #    setattr(self, attr, None)
    #    return getattr(self, attr)

    # def __setattr__(self, attr, value):
    #    logger.debug("  --> Setting installer.%s to %s" %
    #                 (attr, repr(value)))
    #    return super(installer_obj, self).__setattr__(attr, value)

    def knobs(self):
        for name in self.__dict__:
            yield self, name
# pylint: enable=too-few-public-methods, useless-object-inheritance


# Initialize installer and options
installer = installer_obj()
options = installer

# Initialize logger
logger = logging.getLogger("ipa-client-install")
root_logger = logger

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

__all__ = ["gssapi", "version", "ipadiscovery", "api", "errors", "x509",
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
           "configure_nslcd_conf", "nosssd_files", "configure_ssh_config",
           "configure_sshd_config", "configure_automount",
           "configure_firefox", "sync_time", "check_ldap_conf",
           "sssd_enable_ifp"]

from ipapython.version import NUM_VERSION, VERSION

if NUM_VERSION < 30201:
    # See ipapython/version.py
    IPA_MAJOR, IPA_MINOR, IPA_RELEASE = [int(x) for x in VERSION.split(".", 2)]
    IPA_PYTHON_VERSION = IPA_MAJOR*10000 + IPA_MINOR*100 + IPA_RELEASE
else:
    IPA_PYTHON_VERSION = NUM_VERSION


class installer_obj(object):
    def __init__(self):
        pass

    def set_logger(self, logger):
        self.logger = logger

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
    #    logger.debug("  --> Setting installer.%s to %s" % (attr, repr(value)))
    #    return super(installer_obj, self).__setattr__(attr, value)

    def knobs(self):
        for name in self.__dict__:
            yield self, name


# Initialize installer settings
installer = installer_obj()
# Create options
options = installer
options.interactive = False
options.unattended = not options.interactive

if NUM_VERSION >= 40400:
    # IPA version >= 4.4

    import sys
    import inspect
    import gssapi
    import logging

    from ipapython import version
    try:
        from ipaclient.install import ipadiscovery
    except ImportError:
        from ipaclient import ipadiscovery
    from ipalib import api, errors, x509
    from ipalib import constants
    try:
        from ipalib import sysrestore
    except ImportError:
        try:
            from ipalib.install import sysrestore
        except ImportError:
            from ipapython import sysrestore
    try:
        from ipalib.install import certmonger
    except ImportError:
        from ipapython import certmonger
    try:
        from ipalib.install import certstore
    except ImportError:
        from ipalib import certstore
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
        from ipalib.install.kinit import kinit_keytab, kinit_password
    except ImportError:
        from ipapython.ipautil import kinit_keytab, kinit_password
    from ipapython.ipa_log_manager import standard_logging_setup
    from gssapi.exceptions import GSSError
    try:
        from ipaclient.install.client import configure_krb5_conf, \
            get_ca_certs, SECURE_PATH, get_server_connection_interface, \
            disable_ra, client_dns, \
            configure_certmonger, update_ssh_keys, configure_openldap_conf, \
            hardcode_ldap_server, get_certs_from_ldap, save_state, \
            create_ipa_nssdb, configure_ssh_config, configure_sshd_config, \
            configure_automount, configure_firefox, configure_nisdomain, \
            CLIENT_INSTALL_ERROR, is_ipa_client_installed, \
            CLIENT_ALREADY_CONFIGURED, nssldap_exists, remove_file, \
            check_ip_addresses, print_port_conf_info, configure_ipa_conf, \
            purge_host_keytab, configure_sssd_conf, configure_ldap_conf, \
            configure_nslcd_conf, nosssd_files
        get_ca_cert = None
    except ImportError:
        # Create temporary copy of ipa-client-install script (as
        # ipa_client_install.py) to be able to import the script easily
        # and also to remove the global finally clause in which the
        # generated ccache file gets removed. The ccache file will be
        # needed in the next step.
        # This is done in a temporary directory that gets removed right
        # after ipa_client_install has been imported.
        import shutil
        import tempfile
        temp_dir = tempfile.mkdtemp(dir="/tmp")
        sys.path.append(temp_dir)
        temp_file = "%s/ipa_client_install.py" % temp_dir

        with open("/usr/sbin/ipa-client-install", "r") as f_in:
            with open(temp_file, "w") as f_out:
                for line in f_in:
                    if line.startswith("finally:"):
                        break
                    f_out.write(line)
        import ipa_client_install

        shutil.rmtree(temp_dir, ignore_errors=True)
        sys.path.remove(temp_dir)

        argspec = inspect.getargspec(ipa_client_install.configure_krb5_conf)
        if argspec.keywords is None:
            def configure_krb5_conf(
                    cli_realm, cli_domain, cli_server, cli_kdc, dnsok,
                    filename, client_domain, client_hostname, force=False,
                    configure_sssd=True):
                global options
                options.force = force
                options.sssd = configure_sssd
                return ipa_client_install.configure_krb5_conf(
                    cli_realm, cli_domain, cli_server, cli_kdc, dnsok, options,
                    filename, client_domain, client_hostname)
        else:
            configure_krb5_conf = ipa_client_install.configure_krb5_conf
        if NUM_VERSION < 40100:
            get_ca_cert = ipa_client_install.get_ca_cert
            get_ca_certs = None
        else:
            get_ca_cert = None
            get_ca_certs = ipa_client_install.get_ca_certs
        SECURE_PATH = ("/bin:/sbin:/usr/kerberos/bin:/usr/kerberos/sbin:"
                       "/usr/bin:/usr/sbin")

        get_server_connection_interface = \
            ipa_client_install.get_server_connection_interface
        disable_ra = ipa_client_install.disable_ra
        client_dns = ipa_client_install.client_dns
        configure_certmonger = ipa_client_install.configure_certmonger
        update_ssh_keys = ipa_client_install.update_ssh_keys
        configure_openldap_conf = ipa_client_install.configure_openldap_conf
        hardcode_ldap_server = ipa_client_install.hardcode_ldap_server
        get_certs_from_ldap = ipa_client_install.get_certs_from_ldap
        save_state = ipa_client_install.save_state

        create_ipa_nssdb = certdb.create_ipa_nssdb

        argspec = inspect.getargspec(ipa_client_install.configure_nisdomain)
        if len(argspec.args) == 3:
            configure_nisdomain = ipa_client_install.configure_nisdomain
        else:
            def configure_nisdomain(options, domain, statestore=None):
                return ipa_client_install.configure_nisdomain(options, domain)

        configure_ldap_conf = ipa_client_install.configure_ldap_conf
        configure_nslcd_conf = ipa_client_install.configure_nslcd_conf
        nosssd_files = ipa_client_install.nosssd_files

        configure_ssh_config = ipa_client_install.configure_ssh_config
        configure_sshd_config = ipa_client_install.configure_sshd_config
        configure_automount = ipa_client_install.configure_automount
        configure_firefox = ipa_client_install.configure_firefox

    from ipapython.ipautil import realm_to_suffix, run

    try:
        from ipaclient.install import timeconf
        time_service = "chronyd"
    except ImportError:
        try:
            from ipaclient.install import ntpconf as timeconf
        except ImportError:
            from ipaclient import ntpconf as timeconf
        time_service = "ntpd"

    try:
        from ipaclient.install.client import sync_time
    except ImportError:
        sync_time = None

    try:
        from ipaclient.install.client import check_ldap_conf
    except ImportError:
        check_ldap_conf = None

    try:
        from ipaclient.install.client import sssd_enable_ifp
    except ImportError:
        sssd_enable_ifp = None

    logger = logging.getLogger("ipa-client-install")
    root_logger = logger

else:
    # IPA version < 4.4

    raise Exception("freeipa version '%s' is too old" % VERSION)


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

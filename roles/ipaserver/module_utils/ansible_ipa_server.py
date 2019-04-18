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

import os
import sys
import logging
#import fcntl
import inspect
from contextlib import contextmanager as contextlib_contextmanager


from ipapython.version import NUM_VERSION, VERSION

if NUM_VERSION < 30201:
    # See ipapython/version.py
    IPA_MAJOR,IPA_MINOR,IPA_RELEASE = [ int(x) for x in VERSION.split(".", 2) ]
    IPA_PYTHON_VERSION = IPA_MAJOR*10000 + IPA_MINOR*100 + IPA_RELEASE
else:
    IPA_PYTHON_VERSION = NUM_VERSION


if NUM_VERSION >= 40500:
    # IPA version >= 4.5

    import errno
    import pickle
    import shutil
    import tempfile
    import textwrap
    import random

    import six

    if NUM_VERSION >= 40690:
        from ipaclient.install.ipachangeconf import IPAChangeConf
    from ipalib.install import certmonger, sysrestore
    from ipapython import ipautil
    from ipapython.ipa_log_manager import standard_logging_setup
    if NUM_VERSION < 40600:
        from ipapython.ipa_log_manager import root_logger
    from ipapython.ipautil import (
        ipa_generate_password, run)
    from ipapython.admintool import ScriptError
    from ipaplatform import services
    from ipaplatform.paths import paths
    from ipaplatform.tasks import tasks
    from ipalib import api, errors, x509
    from ipalib.constants import DOMAIN_LEVEL_0, MIN_DOMAIN_LEVEL, MAX_DOMAIN_LEVEL
    if NUM_VERSION == 40504:
        from ipalib.constants import IPAAPI_USER
    from ipalib.util import (
        validate_domain_name,
        no_matching_interface_for_ip_address_warning,
    )
    from ipapython.dnsutil import check_zone_overlap
    from ipapython.dn import DN
    try:
        from ipaclient.install import timeconf
        from ipaclient.install.client import sync_time
        time_service = "chronyd"
        ntpinstance = None
    except ImportError:
        try:
            from ipaclient.install import ntpconf as timeconf
        except ImportError:
            from ipaclient import ntpconf as timeconf
        from ipaserver.install import ntpinstance
        time_service = "ntpd"
    from ipaserver.install import (
        adtrust, bindinstance, ca, dns, dsinstance,
        httpinstance, installutils, kra, krbinstance,
        otpdinstance, custodiainstance, replication, service,
        sysupgrade)
    adtrust_imported = True
    kra_imported = True
    from ipaserver.install.installutils import (
        IPA_MODULES, BadHostError, get_fqdn, get_server_ip_address,
        is_ipa_configured, load_pkcs12, read_password, verify_fqdn,
        update_hosts_file)
    from ipaserver.install.server.install import (
        check_dirsrv, validate_admin_password, validate_dm_password,
        write_cache)
    try:
        from ipaserver.install.installutils import default_subject_base
    except ImportError:
        def default_subject_base(realm_name):
            return DN(('O', realm_name))
    try:
        from ipaserver.install.installutils import default_ca_subject_dn
    except ImportError:
        def default_ca_subject_dn(subject_base):
            return DN(('CN', 'Certificate Authority'), subject_base)

    if six.PY3:
        unicode = str

    try:
        from ipaserver.install import adtrustinstance
        _server_trust_ad_installed = True
    except ImportError:
        _server_trust_ad_installed = False

    try:
        from ipaclient.install.client import check_ldap_conf
    except ImportError:
        check_ldap_conf = None

else:
    # IPA version < 4.5

    raise Exception("freeipa version '%s' is too old" % VERSION)


logger = logging.getLogger("ipa-server-install")
#logger.setLevel(logging.DEBUG)
standard_logging_setup(
    paths.IPASERVER_INSTALL_LOG, verbose=False, debug=False,
    filemode='a', console_format='%(message)s')


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

    def write(self, msg):
        self.module.debug(msg)
        #self.module.warn(msg)


class options_obj(object):
    def __init__(self):
        self._replica_install = False
        self.dnssec_master = False # future unknown
        self.disable_dnssec_master = False # future unknown
        self.domainlevel = MAX_DOMAIN_LEVEL # deprecated
        self.domain_level = self.domainlevel # deprecated
        self.interactive = False
        self.unattended = not self.interactive

    #def __getattribute__(self, attr):
    #    logger.info(" <-- Accessing options.%s" % attr)
    #    return super(options_obj, self).__getattribute__(attr)

    #def __getattr__(self, attr):
    #    logger.info(" --> Adding missing options.%s" % attr)
    #    setattr(self, attr, None)
    #    return getattr(self, attr)

    def knobs(self):
        for name in self.__dict__:
            yield self, name


options = options_obj()
installer = options

# ServerMasterInstall
options.add_sids = True
options.add_agents = False


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


def ds_init_info(ansible_log, fstore, domainlevel, dirsrv_config_file,
                 realm_name, host_name, domain_name, dm_password,
                 idstart, idmax, subject_base, ca_subject,
                 no_hbac_allow, dirsrv_pkcs12_info, no_pkinit):

    if not options.external_cert_files:
        ds = dsinstance.DsInstance(fstore=fstore, domainlevel=domainlevel,
                                   config_ldif=dirsrv_config_file)
        ds.set_output(ansible_log)

        if options.dirsrv_cert_files:
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

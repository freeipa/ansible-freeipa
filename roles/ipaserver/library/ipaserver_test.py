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
module: ipaserver_test
short description:
description:
options:
author:
    - Thomas Woerner
'''

EXAMPLES = '''
'''

RETURN = '''
'''

import os
import sys
import logging
import tempfile, shutil

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.ansible_ipa_server import *

def main():
    ansible_module = AnsibleModule(
        argument_spec = dict(
            ### basic ###
            force=dict(required=False, type='bool', default=False),
            dm_password=dict(required=True, no_log=True),
            password=dict(required=True, no_log=True),
            master_password=dict(required=False, no_log=True),
            ip_addresses=dict(required=False, type='list', default=[]),
            domain=dict(required=False),
            realm=dict(required=False),
            hostname=dict(required=False),
            ca_cert_files=dict(required=False, type='list', default=[]),
            no_host_dns=dict(required=False, type='bool', default=False),
            ### server ###
            setup_adtrust=dict(required=False, type='bool', default=False),
            setup_kra=dict(required=False, type='bool', default=False),
            setup_dns=dict(required=False, type='bool', default=False),
            idstart=dict(required=False, type='int'),
            idmax=dict(required=False, type='int'),
            # no_hbac_allow
            no_pkinit=dict(required=False, type='bool', default=False),
            # no_ui_redirect
            dirsrv_config_file=dict(required=False),
            ### ssl certificate ###
            dirsrv_cert_files=dict(required=False, type='list', default=[]),
            http_cert_files=dict(required=False, type='list', default=[]),
            pkinit_cert_files=dict(required=False, type='list', default=[]),
            # dirsrv_pin
            # http_pin
            # pkinit_pin
            # dirsrv_name
            # http_name
            # pkinit_name
            ### client ###
            # mkhomedir
            no_ntp=dict(required=False, type='bool', default=False),
            # ssh_trust_dns
            # no_ssh
            # no_sshd
            # no_dns_sshfp
            ### certificate system ###
            external_ca=dict(required=False, type='bool', default=False),
            external_ca_type=dict(required=False),
            external_cert_files=dict(required=False, type='list', default=[]),
            subject_base=dict(required=False),
            ca_subject=dict(required=False),
            # ca_signing_algorithm
            ### dns ###
            allow_zone_overlap=dict(required=False, type='bool', default=False),
            reverse_zones=dict(required=False, type='list', default=[]),
            no_reverse=dict(required=False, type='bool', default=False),
            auto_reverse=dict(required=False, type='bool', default=False),
            zonemgr=dict(required=False),
            forwarders=dict(required=False, type='list', default=[]),
            no_forwarders=dict(required=False, type='bool', default=False),
            auto_forwarders=dict(required=False, type='bool', default=False),
            forward_policy=dict(default=None, choices=['first', 'only']),
            no_dnssec_validation=dict(required=False, type='bool',
                                      default=False),
            ### ad trust ###
            enable_compat=dict(required=False, type='bool', default=False),
            netbios_name=dict(required=False),
            rid_base=dict(required=False, type='int', default=1000),
            secondary_rid_base=dict(required=False, type='int',
                                    default=100000000),

            ### additional ###
        ),
        supports_check_mode = True,
    )

    ansible_module._ansible_debug = True
    ansible_log = AnsibleModuleLog(ansible_module)

    # set values ############################################################

    ### basic ###
    options.force = ansible_module.params.get('force')
    options.dm_password = ansible_module.params.get('dm_password')
    options.admin_password = ansible_module.params.get('password')
    options.master_password = ansible_module.params.get('master_password')
    options.ip_addresses = ansible_module_get_parsed_ip_addresses(
        ansible_module)
    options.domain_name = ansible_module.params.get('domain')
    options.realm_name = ansible_module.params.get('realm')
    options.host_name = ansible_module.params.get('hostname')
    options.ca_cert_files = ansible_module.params.get('ca_cert_files')
    options.no_host_dns = ansible_module.params.get('no_host_dns')
    ### server ###
    options.setup_adtrust = ansible_module.params.get('setup_adtrust')
    options.setup_dns = ansible_module.params.get('setup_dns')
    options.setup_kra = ansible_module.params.get('setup_kra')
    options.idstart = ansible_module.params.get('idstart')
    options.idmax = ansible_module.params.get('idmax')
    # no_hbac_allow
    options.no_pkinit = ansible_module.params.get('no_pkinit')
    # no_ui_redirect
    options.dirsrv_config_file = ansible_module.params.get('dirsrv_config_file')
    ### ssl certificate ###
    options.dirsrv_cert_files = ansible_module.params.get('dirsrv_cert_files')
    options.http_cert_files = ansible_module.params.get('http_cert_files')
    options.pkinit_cert_files = ansible_module.params.get('pkinit_cert_files')
    # dirsrv_pin
    # http_pin
    # pkinit_pin
    # dirsrv_name
    # http_name
    # pkinit_name
    ### client ###
    # mkhomedir
    options.no_ntp = ansible_module.params.get('no_ntp')
    # ssh_trust_dns
    # no_ssh
    # no_sshd
    # no_dns_sshfp
    ### certificate system ###
    options.external_ca = ansible_module.params.get('external_ca')
    options.external_ca_type = ansible_module.params.get('external_ca_type')
    options.external_cert_files = ansible_module.params.get(
        'external_cert_files')
    options.subject_base = ansible_module.params.get('subject_base')
    options.ca_subject = ansible_module.params.get('ca_subject')
    # ca_signing_algorithm
    ### dns ###
    options.allow_zone_overlap = ansible_module.params.get('allow_zone_overlap')
    options.reverse_zones = ansible_module.params.get('reverse_zones')
    options.no_reverse = ansible_module.params.get('no_reverse')
    options.auto_reverse = ansible_module.params.get('auto_reverse')
    options.zonemgr = ansible_module.params.get('zonemgr')
    options.forwarders = ansible_module.params.get('forwarders')
    options.no_forwarders = ansible_module.params.get('no_forwarders')
    options.auto_forwarders = ansible_module.params.get('auto_forwarders')
    options.forward_policy = ansible_module.params.get('forward_policy')
    options.no_dnssec_validation = ansible_module.params.get(
        'no_dnssec_validation')
    ### ad trust ###
    options.enable_compat = ansible_module.params.get('enable_compat')
    options.netbios_name = ansible_module.params.get('netbios_name')
    options.rid_base = ansible_module.params.get('rid_base')
    options.secondary_rid_base = ansible_module.params.get('secondary_rid_base')

    ### additional ###
    options.kasp_db_file = None

    # version specific ######################################################

    if options.setup_adtrust and not adtrust_imported:
        #if "adtrust" not in options._allow_missing:
        ansible_module.fail_json(msg="adtrust can not be imported")
        #else:
        #  options.setup_adtrust = False
        #  ansible_module.warn(msg="adtrust is not supported, disabling")

    if options.setup_kra and not kra_imported:
        #if "kra" not in options._allow_missing:
        ansible_module.fail_json(msg="kra can not be imported")
        #else:
        #  options.setup_kra = False
        #  ansible_module.warn(msg="kra is not supported, disabling")

    # validation #############################################################

    if options.dm_password is None:
        ansible_module.fail_json(msg="Directory Manager password required")

    if options.admin_password is None:
        ansible_module.fail_json(msg="IPA admin password required")

    # This will override any settings passed in on the cmdline
    if os.path.isfile(paths.ROOT_IPA_CACHE):
        # dm_password check removed, checked already
        try:
            cache_vars = read_cache(options.dm_password)
            options.__dict__.update(cache_vars)
            if cache_vars.get('external_ca', False):
                options.external_ca = False
                options.interactive = False
        except Exception as e:
            ansible_module.fail_json(msg="Cannot process the cache file: %s" % str(e))
    # default values ########################################################

    # idstart and idmax
    if options.idstart is None:
        options.idstart = random.randint(1, 10000) * 200000
    if options.idmax is None or options.idmax == 0:
        options.idmax = options.idstart + 199999

    # validation ############################################################

    # domain_level
    if options.domain_level < MIN_DOMAIN_LEVEL:
        ansible_module.fail_json(
            msg="Domain Level cannot be lower than %d" % MIN_DOMAIN_LEVEL)
    elif options.domain_level > MAX_DOMAIN_LEVEL:
        ansible_module.fail_json(
            msg="Domain Level cannot be higher than %d" % MAX_DOMAIN_LEVEL)

    # dirsrv_config_file
    if options.dirsrv_config_file is not None:
        if not os.path.exists(options.dirsrv_config_file):
            ansible_module.fail_json(
                msg="File %s does not exist." % options.dirsrv_config_file)

    # domain_name
    if (options.setup_dns and not options.allow_zone_overlap and \
        options.domain_name is not None):
        try:
            check_zone_overlap(options.domain_name, False)
        except ValueError as e:
            ansible_module.fail_json(msg=str(e))

    # dm_password
    with redirect_stdout(ansible_log):
        validate_dm_password(options.dm_password)

    # admin_password
    with redirect_stdout(ansible_log):
        validate_admin_password(options.admin_password)

    # pkinit is not supported on DL0, don't allow related options

    # replica install: if not self.replica_file is None:
    if (not options._replica_install and \
        not options.domain_level > DOMAIN_LEVEL_0) or \
        (options._replica_install and self.replica_file is not None):
        if (options.no_pkinit or options.pkinit_cert_files is not None or
                options.pkinit_pin is not None):
            ansible_module.fail_json(
                msg="pkinit on domain level 0 is not supported. Please "
                "don't use any pkinit-related options.")
        options.no_pkinit = True

    # If any of the key file options are selected, all are required.
    cert_file_req = (options.dirsrv_cert_files, options.http_cert_files)
    cert_file_opt = (options.pkinit_cert_files,)
    if not options.no_pkinit:
        cert_file_req += cert_file_opt
    if options.no_pkinit and options.pkinit_cert_files:
        ansible_module.fail_json(
            msg="no-pkinit and pkinit-cert-file cannot be specified together"
        )
    if any(cert_file_req + cert_file_opt) and not all(cert_file_req):
        ansible_module.fail_json(
            msg="dirsrv-cert-file, http-cert-file, and pkinit-cert-file "
            "or no-pkinit are required if any key file options are used."
        )

    if not options.interactive:
        if options.dirsrv_cert_files and options.dirsrv_pin is None:
            ansible_module.fail_json(
                msg="You must specify dirsrv-pin with dirsrv-cert-file")
        if options.http_cert_files and options.http_pin is None:
            ansible_module.fail_json(
                msg="You must specify http-pin with http-cert-file")
        if options.pkinit_cert_files and options.pkinit_pin is None:
            ansible_module.fail_json(
                msg="You must specify pkinit-pin with pkinit-cert-file")

    if not options.setup_dns:
        # lists
        for x in [ "forwarders", "reverse_zones" ]:
            if len(getattr(options, x)) > 1:
                ansible_module.fail_json(
                    msg="You cannot specify %s without setting setup-dns" % x)
        # bool and str values
        for x in [ "auto_forwarders", "no_forwarders",
                   "auto_reverse", "no_reverse", "no_dnssec_validation",
                   "forward_policy" ]:
            if getattr(options, x) == True:
                ansible_module.fail_json(
                    msg="You cannot specify %s without setting setup-dns" % x)

    elif len(options.forwarders) > 0 and options.no_forwarders:
        ansible_module.fail_json(
            msg="You cannot specify forwarders together with no-forwarders")
    elif options.auto_forwarders and options.no_forwarders:
        ansible_module.fail_json(
            msg="You cannot specify auto-forwarders together with no-forwarders")
    elif len(options.reverse_zones) > 0 and options.no_reverse:
        ansible_module.fail_json(
            msg="You cannot specify reverse-zones together with no-reverse")
    elif options.auto_reverse and options.no_reverse:
        ansible_module.fail_json(
            msg="You cannot specify auto-reverse together with no-reverse")

    if not options._replica_install:
        if options.external_cert_files and options.dirsrv_cert_files:
            ansible_module.fail_json(
                msg="Service certificate file options cannot be used with the "
                "external CA options.")

        if options.external_ca_type and not options.external_ca:
            ansible_module.fail_json(
                msg="You cannot specify external-ca-type without external-ca")

        #if options.uninstalling:
        #    if (options.realm_name or options.admin_password or
        #            options.master_password):
        #        ansible_module.fail_json(
        #            msg="In uninstall mode, -a, -r and -P options are not "
        #            "allowed")
        #elif not options.interactive:
        #    if (not options.realm_name or not options.dm_password or
        #            not options.admin_password):
        #        ansible_module.fail_json(msg=
        #            "In unattended mode you need to provide at least -r, "
        #            "-p and -a options")
        #    if options.setup_dns:
        #        if (not options.forwarders and
        #                not options.no_forwarders and
        #                not options.auto_forwarders):
        #            ansible_module.fail_json(msg=
        #                "You must specify at least one of --forwarder, "
        #                "--auto-forwarders, or --no-forwarders options")
        if (not options.realm_name or not options.dm_password or
                not options.admin_password):
            ansible_module.fail_json(
                msg="You need to provide at least realm_name, dm_password "
                "and admin_password")
        if options.setup_dns:
            if len(options.forwarders) < 1 and not options.no_forwarders and \
               not options.auto_forwarders:
                ansible_module.fail_json(
                    msg="You must specify at least one of forwarders, "
                    "auto-forwarders or no-forwarders")

        #any_ignore_option_true = any(
        #    [options.ignore_topology_disconnect, options.ignore_last_of_role])
        #if any_ignore_option_true and not options.uninstalling:
        #    ansible_module.fail_json(
        #        msg="ignore-topology-disconnect and ignore-last-of-role "
        #        "can be used only during uninstallation")

        if options.idmax < options.idstart:
            ansible_module.fail_json(
                msg="idmax (%s) cannot be smaller than idstart (%s)" %
                (options.idmax, options.idstart))
    else:
        # replica install
        if options.replica_file is None:
            if options.servers and not options.domain_name:
                ansible_module.fail_json(
                    msg="servers cannot be used without providing domain")

        else:
            if not os.path.isfile(options.replica_file):
                ansible_module.fail_json(
                    msg="Replica file %s does not exist" % options.replica_file)

            if any(cert_file_req + cert_file_opt):
                ansible_module.fail_json(
                    msg="You cannot specify dirsrv-cert-file, http-cert-file, "
                    "or pkinit-cert-file together with replica file")

            conflicting = { "realm": options.realm_name,
                            "domain": options.domain_name,
                            "hostname": options.host_name,
                            "servers": options.servers,
                            "principal": options.principal }
            conflicting_names = [ name for name in conflicting
                                  if conflicting[name] is not None ]
            if len(conflicting_names) > 0:
                ansible_module.fail_json(
                    msg="You cannot specify %s option(s) with replica file." % \
                    ", ".join(conflicting_names))

    if options.setup_dns:
        if len(options.forwarders) < 1 and not options.no_forwarders and \
           not options.auto_forwarders:
            ansible_module.fail_json(
                msg="You must specify at least one of forwarders, "
                "auto-forwarders or no-forwarders")

    if NUM_VERSION >= 40200 and options.master_password:
        ansible_module.warn("Specifying master-password is deprecated")

    options._installation_cleanup = True
    if not options.external_ca and len(options.external_cert_files) < 1 and \
       is_ipa_configured():
        options._installation_cleanup = False
        ansible_module.log(
            "IPA server is already configured on this system. If you want "
            "to reinstall the IPA server, please uninstall it first.")
        ansible_module.exit_json(changed=False,
                                 server_already_configured=True)

    client_fstore = sysrestore.FileStore(paths.IPA_CLIENT_SYSRESTORE)
    if client_fstore.has_files():
        options._installation_cleanup = False
        ansible_module.log(
            "IPA client is already configured on this system. "
            "Please uninstall it before configuring the IPA server.")
        ansible_module.exit_json(changed=False,
                                 client_already_configured=True)

    # validate reverse_zones
    if not options.allow_zone_overlap:
        for zone in options.reverse_zones:
            with redirect_stdout(ansible_log):
                check_zone_overlap(zone)

    # validate zonemgr
    if options.zonemgr:
        try:
            # IDNA support requires unicode
            encoding = getattr(sys.stdin, 'encoding', None)
            if encoding is None:
                encoding = 'utf-8'
            value = options.zonemgr.decode(encoding)
            with redirect_stdout(ansible_log):
                bindinstance.validate_zonemgr_str(value)
        except ValueError as e:
            # FIXME we can do this in better way
            # https://fedorahosted.org/freeipa/ticket/4804
            # decode to proper stderr encoding
            stderr_encoding = getattr(sys.stderr, 'encoding', None)
            if stderr_encoding is None:
                stderr_encoding = 'utf-8'
            error = unicode(e).encode(stderr_encoding)
            ansible_module.fail_json(msg=error)

    # external cert file paths are absolute
    for path in options.external_cert_files:
        if not os.path.isabs(path):
            ansible_module.fail_json(
                msg="External cert file '%s' must use an absolute path" % path)

    options.setup_ca = True
    # We only set up the CA if the PKCS#12 options are not given.
    if options.dirsrv_cert_files and len(options.dirsrv_cert_files) > 0:
        options.setup_ca = False
    else:
        options.setup_ca = True

    if not options.setup_ca and options.ca_subject:
        ansible_module.fail_json(msg=
            "--ca-subject cannot be used with CA-less installation")
    if not options.setup_ca and options.subject_base:
        ansible_module.fail_json(msg=
            "--subject-base cannot be used with CA-less installation")
    if not options.setup_ca and options.setup_kra:
        ansible_module.fail_json(msg=
            "--setup-kra cannot be used with CA-less installation")

    # ca_subject
    if options.ca_subject:
        ca.subject_validator(ca.VALID_SUBJECT_ATTRS, options.ca_subject)

    # IPv6 and SELinux check

    tasks.check_ipv6_stack_enabled()
    tasks.check_selinux_status()
    if check_ldap_conf is not None:
        check_ldap_conf()

    _installation_cleanup = True
    if not options.external_ca and not options.external_cert_files and \
       is_ipa_configured():
        _installation_cleanup = False
        ansible_module.fail_json(msg="IPA server is already configured on this system.")

    if not options.no_ntp:
        try:
            timeconf.check_timedate_services()
        except timeconf.NTPConflictingService as e:
            ansible_module.log("Conflicting time&date synchronization service '%s'"
                       " will be disabled in favor of %s" % \
                       (e.conflicting_service, time_service))
        except timeconf.NTPConfigurationError:
            pass

    if hasattr(httpinstance, "httpd_443_configured"):
        # Check to see if httpd is already configured to listen on 443
        if httpinstance.httpd_443_configured():
            ansible_module.fail_json(msg="httpd is already configured to listen on 443.")

    if not options.external_cert_files:
        # Make sure the 389-ds ports are available
        try:
            check_dirsrv(True)
        except ScriptError as e:
            ansible_module.fail_json(msg=e)

    # check bind packages are installed
    if options.setup_dns:
        # Don't require an external DNS to say who we are if we are
        # setting up a local DNS server.
        options.no_host_dns = True

    # host name
    if options.host_name:
        options.host_default = options.host_name
    else:
        options.host_default = get_fqdn()

    try:
        verify_fqdn(options.host_default, options.no_host_dns)
        options.host_name = options.host_default
    except BadHostError as e:
        ansible_module.fail_json(msg=e)
    options.host_name = options.host_name.lower()

    if not options.domain_name:
        options.domain_name = options.host_name[options.host_name.find(".")+1:]
        try:
            validate_domain_name(options.domain_name)
        except ValueError as e:
            ansible_module.fail_json(msg="Invalid domain name: %s" % unicode(e))
    options.domain_name = options.domain_name.lower()

    if not options.realm_name:
        options.realm_name = options.domain_name
    options.realm_name = options.realm_name.upper()
    argspec = inspect.getargspec(validate_domain_name)
    if "entity" in argspec.args:
        # NUM_VERSION >= 40690:
        try:
            validate_domain_name(options.realm_name, entity="realm")
        except ValueError as e:
            raise ScriptError("Invalid realm name: {}".format(unicode(e)))

    if not options.setup_adtrust:
        # If domain name and realm does not match, IPA server will not be able
        # to establish trust with Active Directory. Fail.

        if options.domain_name.upper() != options.realm_name:
            ansible_module.warn(
                "Realm name does not match the domain name: "
                "You will not be able to establish trusts with Active "
                "Directory.")

    #########################################################################

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
        if options.http_pin is None:
            ansible_module.fail_json(msg=
                "Apache Server private key unlock password required")
        http_pkcs12_file, http_pin, http_ca_cert = load_pkcs12(
            cert_files=options.http_cert_files,
            key_password=options.http_pin,
            key_nickname=options.http_cert_name,
            ca_cert_files=options.ca_cert_files,
            host_name=options.host_name)
        http_pkcs12_info = (http_pkcs12_file.name, options.http_pin)

    if options.dirsrv_cert_files:
        if options.dirsrv_pin is None:
            ansible_module.fail_json(msg=
                "Directory Server private key unlock password required")
        dirsrv_pkcs12_file, dirsrv_pin, dirsrv_ca_cert = load_pkcs12(
            cert_files=options.dirsrv_cert_files,
            key_password=options.dirsrv_pin,
            key_nickname=options.dirsrv_cert_name,
            ca_cert_files=options.ca_cert_files,
            host_name=options.host_name)
        dirsrv_pkcs12_info = (dirsrv_pkcs12_file.name, options.dirsrv_pin)

    if options.pkinit_cert_files:
        if options.pkinit_pin is None:
            ansible_module.fail_json(msg=
                "Kerberos KDC private key unlock password required")
        pkinit_pkcs12_file, pkinit_pin, pkinit_ca_cert = load_pkcs12(
            cert_files=options.pkinit_cert_files,
            key_password=options.pkinit_pin,
            key_nickname=options.pkinit_cert_name,
            ca_cert_files=options.ca_cert_files,
            realm_name=options.realm_name)
        pkinit_pkcs12_info = (pkinit_pkcs12_file.name, options.pkinit_pin)

    if (options.http_cert_files and options.dirsrv_cert_files and
        http_ca_cert != dirsrv_ca_cert):
        ansible_module.fail_json(msg=
            "Apache Server SSL certificate and Directory Server SSL "
            "certificate are not signed by the same CA certificate")

    if (options.http_cert_files and options.pkinit_cert_files and
        http_ca_cert != pkinit_ca_cert):
        ansible_module.fail_json(msg=
            "Apache Server SSL certificate and PKINIT KDC "
            "certificate are not signed by the same CA certificate")

    # subject_base
    if not options.subject_base:
        options.subject_base = str(default_subject_base(options.realm_name))
        # set options.subject for old ipa releases
        options.subject = options.subject_base

    if not options.ca_subject:
        options.ca_subject = str(default_ca_subject_dn(options.subject_base))

    # temporary ipa configuration ###########################################

    ipa_tempdir = tempfile.mkdtemp(prefix="ipaconf")
    try:
        # Configuration for ipalib, we will bootstrap and finalize later, after
        # we are sure we have the configuration file ready.
        cfg = dict(
            context='installer',
            confdir=ipa_tempdir,
            in_server=True,
            # make sure host name specified by user is used instead of default
            host=options.host_name,
        )
        if options.setup_ca:
            # we have an IPA-integrated CA
            cfg['ca_host'] = options.host_name

        # Create the management framework config file and finalize api
        target_fname = "%s/default.conf" % ipa_tempdir
        fd = open(target_fname, "w")
        fd.write("[global]\n")
        fd.write("host=%s\n" % options.host_name)
        fd.write("basedn=%s\n" % ipautil.realm_to_suffix(options.realm_name))
        fd.write("realm=%s\n" % options.realm_name)
        fd.write("domain=%s\n" % options.domain_name)
        fd.write("xmlrpc_uri=https://%s/ipa/xml\n" % ipautil.format_netloc(options.host_name))
        fd.write("ldap_uri=ldapi://%%2fvar%%2frun%%2fslapd-%s.socket\n" %
                 installutils.realm_to_serverid(options.realm_name))
        if options.setup_ca:
            fd.write("enable_ra=True\n")
            fd.write("ra_plugin=dogtag\n")
            fd.write("dogtag_version=10\n")
        else:
            fd.write("enable_ra=False\n")
            fd.write("ra_plugin=none\n")
        fd.write("mode=production\n")
        fd.close()

        # Must be readable for everyone
        os.chmod(target_fname, 0o644)

        api.bootstrap(**cfg)
        api.finalize()

        # install checks ####################################################

        if options.setup_ca:
            ca.install_check(False, None, options)

        if options.setup_kra:
            kra.install_check(api, None, options)

        if options.setup_dns:
            with redirect_stdout(ansible_log):
                dns.install_check(False, api, False, options, options.host_name)
            ip_addresses = dns.ip_addresses
        else:
            ip_addresses = get_server_ip_address(options.host_name,
                                                 False, False,
                                                 options.ip_addresses)

            # check addresses here, dns ansible_module is doing own check
            no_matching_interface_for_ip_address_warning(ip_addresses)

        options.ip_addresses = ip_addresses
        options.reverse_zones = dns.reverse_zones
        instance_name = "-".join(options.realm_name.split("."))
        dirsrv = services.knownservices.dirsrv
        if (options.external_cert_files
               and dirsrv.is_installed(instance_name)
               and not dirsrv.is_running(instance_name)):
            logger.debug('Starting Directory Server')
            services.knownservices.dirsrv.start(instance_name)

        if options.setup_adtrust:
            adtrust.install_check(False, options, api)

    except (RuntimeError, ValueError, ScriptError) as e:
        ansible_module.fail_json(msg=str(e))

    finally:
        try:
            shutil.rmtree(ipa_tempdir, ignore_errors=True)
        except OSError:
            ansible_module.fail_json(msg="Could not remove %s" % ipa_tempdir)

    # Always set _host_name_overridden
    options._host_name_overridden = bool(options.host_name)

    # done ##################################################################

    ansible_module.exit_json(changed=False,
                             ipa_python_version=IPA_PYTHON_VERSION,
                             ### basic ###
                             domain=options.domain_name,
                             realm=options.realm_name,
                             ip_addresses=[ str(ip) for ip in ip_addresses ],
                             hostname=options.host_name,
                             _hostname_overridden=options._host_name_overridden,
                             no_host_dns=options.no_host_dns,
                             ### server ###
                             setup_adtrust=options.setup_adtrust,
                             setup_kra=options.setup_kra,
                             setup_ca=options.setup_ca,
                             idstart=options.idstart,
                             idmax=options.idmax,
                             no_pkinit=options.no_pkinit,
                             ### ssl certificate ###
                             _dirsrv_pkcs12_file=dirsrv_pkcs12_file,
                             _dirsrv_pkcs12_info=dirsrv_pkcs12_info,
                             _dirsrv_ca_cert=dirsrv_ca_cert,
                             _http_pkcs12_file=http_pkcs12_file,
                             _http_pkcs12_info=http_pkcs12_info,
                             _http_ca_cert=http_ca_cert,
                             _pkinit_pkcs12_file=pkinit_pkcs12_file,
                             _pkinit_pkcs12_info=pkinit_pkcs12_info,
                             _pkinit_ca_cert=pkinit_ca_cert,
                             ### certificate system ###
                             subject_base=options.subject_base,
                             _subject_base=options._subject_base,
                             ca_subject=options.ca_subject,
                             _ca_subject=options._ca_subject,
                             ### dns ###
                             reverse_zones=options.reverse_zones,
                             forward_policy=options.forward_policy,
                             forwarders=options.forwarders,
                             no_dnssec_validation=options.no_dnssec_validation,
                             ### ad trust ###
                             rid_base=options.rid_base,
                             secondary_rid_base=options.secondary_rid_base,
                             ### additional ###
                             _installation_cleanup=_installation_cleanup,
                             domainlevel=options.domainlevel,
                             dns_ip_addresses=[ str(ip) for ip
                                                in dns.ip_addresses ],
                             dns_reverse_zones=dns.reverse_zones,
                             adtrust_netbios_name=adtrust.netbios_name,
                             adtrust_reset_netbios_name=adtrust.reset_netbios_name)

if __name__ == '__main__':
    main()

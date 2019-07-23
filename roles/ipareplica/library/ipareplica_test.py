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

ANSIBLE_METADATA = {
    'metadata_version': '1.0',
    'supported_by': 'community',
    'status': ['preview'],
}

DOCUMENTATION = '''
---
module: ipareplica_test
short description: IPA replica deployment tests
description: IPA replica deployment tests
options:
  ip_addresses:
    description: List of Master Server IP Addresses
    required: yes
  domain:
    description: Primary DNS domain of the IPA deployment
    required: yes
  servers:
    description: Fully qualified name of IPA servers to enroll to
    required: yes
  realm:
    description: Kerberos realm name of the IPA deployment
    required: yes
  hostname:
    description: Fully qualified name of this host
    required: yes
  ca_cert_files:
    description:
      List of files containing CA certificates for the service certificate
      files
    required: yes
  hidden_replica:
    description: Install a hidden replica
    required: yes
  setup_adtrust:
    description: Configure AD trust capability
    required: yes
  setup_kra:
    description: Configure a dogtag KRA
    required: yes
  setup_dns:
    description: Configure bind with our zone
    required: yes
  no_pkinit:
    description: Disable pkinit setup steps
    required: yes
  dirsrv_config_file:
    description:
      The path to LDIF file that will be used to modify configuration of
      dse.ldif during installation of the directory server instance
    required: yes
  dirsrv_cert_files:
    description:
      Files containing the Directory Server SSL certificate and private key
    required: yes
  http_cert_files:
    description:
      File containing the Apache Server SSL certificate and private key
    required: yes
  pkinit_cert_files:
    description:
      File containing the Kerberos KDC SSL certificate and private key
    required: yes
  no_ntp:
    description: Do not configure ntp
    required: yes
  ntp_servers:
    description: ntp servers to use
    required: yes
  ntp_pool:
    description: ntp server pool to use
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
author:
    - Thomas Woerner
'''

EXAMPLES = '''
'''

RETURN = '''
'''

import os
import inspect

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.ansible_ipa_replica import (
    AnsibleModuleLog, options, installer, paths, sysrestore,
    ansible_module_get_parsed_ip_addresses, service,
    redirect_stdout, create_ipa_conf, ipautil,
    x509, validate_domain_name, common_check,
    IPA_PYTHON_VERSION
)


def main():
    ansible_module = AnsibleModule(
        argument_spec=dict(
            # basic
            # dm_password=dict(required=False, no_log=True),
            # password=dict(required=False, no_log=True),
            ip_addresses=dict(required=False, type='list', default=[]),
            domain=dict(required=False),
            servers=dict(required=False, type='list', default=[]),
            realm=dict(required=False),
            hostname=dict(required=False),
            ca_cert_files=dict(required=False, type='list', default=[]),
            hidden_replica=dict(required=False, type='bool', default=False),
            # server
            setup_adtrust=dict(required=False, type='bool', default=False),
            setup_kra=dict(required=False, type='bool', default=False),
            setup_dns=dict(required=False, type='bool', default=False),
            no_pkinit=dict(required=False, type='bool', default=False),
            dirsrv_config_file=dict(required=False),
            # ssl certificate
            dirsrv_cert_files=dict(required=False, type='list', default=[]),
            http_cert_files=dict(required=False, type='list', default=[]),
            pkinit_cert_files=dict(required=False, type='list', default=[]),
            # client
            no_ntp=dict(required=False, type='bool', default=False),
            ntp_servers=dict(required=False, type='list', default=[]),
            ntp_pool=dict(required=False),
            # dns
            no_reverse=dict(required=False, type='bool', default=False),
            auto_reverse=dict(required=False, type='bool', default=False),
            forwarders=dict(required=False, type='list', default=[]),
            no_forwarders=dict(required=False, type='bool', default=False),
            auto_forwarders=dict(required=False, type='bool', default=False),
            forward_policy=dict(default=None, choices=['first', 'only']),
            no_dnssec_validation=dict(required=False, type='bool',
                                      default=False),
        ),
    )

    ansible_module._ansible_debug = True
    ansible_log = AnsibleModuleLog(ansible_module)

    # get parameters #

    # basic
    # options.dm_password = ansible_module.params.get('dm_password')
    # # options.password = ansible_module.params.get('password')
    # options.password = options.dm_password
    options.ip_addresses = ansible_module_get_parsed_ip_addresses(
        ansible_module)
    options.domain_name = ansible_module.params.get('domain')
    options.servers = ansible_module.params.get('servers')
    options.realm_name = ansible_module.params.get('realm')
    options.host_name = ansible_module.params.get('hostname')
    options.ca_cert_files = ansible_module.params.get('ca_cert_files')
    options.hidden_replica = ansible_module.params.get('hidden_replica')
    # server
    options.setup_adtrust = ansible_module.params.get('setup_adtrust')
    options.setup_kra = ansible_module.params.get('setup_kra')
    options.setup_dns = ansible_module.params.get('setup_dns')
    options.no_pkinit = ansible_module.params.get('no_pkinit')
    options.dirsrv_config_file = ansible_module.params.get(
        'dirsrv_config_file')
    # ssl certificate
    options.dirsrv_cert_files = ansible_module.params.get('dirsrv_cert_files')
    options.http_cert_files = ansible_module.params.get('http_cert_files')
    options.pkinit_cert_files = ansible_module.params.get('pkinit_cert_files')
    # client
    options.no_ntp = ansible_module.params.get('no_ntp')
    options.ntp_servers = ansible_module.params.get('ntp_servers')
    options.ntp_pool = ansible_module.params.get('ntp_pool')
    # dns
    options.no_reverse = ansible_module.params.get('no_reverse')
    options.auto_reverse = ansible_module.params.get('auto_reverse')
    options.forwarders = ansible_module.params.get('forwarders')
    options.no_forwarders = ansible_module.params.get('no_forwarders')
    options.auto_forwarders = ansible_module.params.get('auto_forwarders')
    options.forward_policy = ansible_module.params.get('forward_policy')
    options.no_dnssec_validation = ansible_module.params.get(
        'no_dnssec_validation')

    ##########################################################################
    # replica init ###########################################################
    ##########################################################################

    if installer.servers:
        installer.server = installer.servers[0]
    else:
        installer.server = None
    # TODO: Kills ipa-client-install
    # if installer.replica_file is None:
    #     installer.password = installer.admin_password
    # else:
    #     installer.password = installer.dm_password

    # installer._ccache = os.environ.get('KRB5CCNAME')

    # If not defined, set domain from server name
    if installer.domain_name is None and installer.server is not None:
        installer.domain_name = installer.server[installer.server.find(".")+1:]
    # If not defined, set realm from domain name
    if installer.realm_name is None and installer.domain_name is not None:
        installer.realm_name = installer.domain_name.upper()

    ##########################################################################
    # other checks ###########################################################
    ##########################################################################

    # version specific tests #

    # if options.setup_adtrust and not adtrust_imported:
    #    # if "adtrust" not in options._allow_missing:
    #    ansible_module.fail_json(msg="adtrust can not be imported")
    #    # else:
    #    #  options.setup_adtrust = False
    #    #  ansible_module.warn(msg="adtrust is not supported, disabling")

    # if options.setup_kra and not kra_imported:
    #    # if "kra" not in options._allow_missing:
    #    ansible_module.fail_json(msg="kra can not be imported")
    #    # else:
    #    #  options.setup_kra = False
    #    #  ansible_module.warn(msg="kra is not supported, disabling")

    if options.hidden_replica and not hasattr(service, "hide_services"):
        ansible_module.fail_json(
            msg="Hidden replica is not supported in this version.")

    # We need to point to the master in ipa default conf when certmonger
    # asks for HTTP certificate in newer ipa versions. In these versions
    # create_ipa_conf has the additional master argument.
    change_master_for_certmonger = False
    argspec = inspect.getargspec(create_ipa_conf)
    if "master" in argspec.args:
        change_master_for_certmonger = True

    # From ipa installer classes

    # pkinit is not supported on DL0, don't allow related options
    if installer.replica_file is not None:
        ansible_module.fail_json(
            msg="Replica installation using a replica file is not supported")

    # If any of the key file options are selected, all are required.
    cert_file_req = (installer.dirsrv_cert_files, installer.http_cert_files)
    cert_file_opt = (installer.pkinit_cert_files,)
    if not installer.no_pkinit:
        cert_file_req += cert_file_opt
    if installer.no_pkinit and installer.pkinit_cert_files:
        ansible_module.fail_json(
            msg="--no-pkinit and --pkinit-cert-file cannot be specified "
            "together")
    if any(cert_file_req + cert_file_opt) and not all(cert_file_req):
        ansible_module.fail_json(
            msg="--dirsrv-cert-file, --http-cert-file, and --pkinit-cert-file "
            "or --no-pkinit are required if any key file options are used.")

    if not installer.setup_dns:
        if installer.forwarders:
            ansible_module.fail_json(
                msg="You cannot specify a --forwarder option without the "
                "--setup-dns option")
        if installer.auto_forwarders:
            ansible_module.fail_json(
                msg="You cannot specify a --auto-forwarders option without "
                "the --setup-dns option")
        if installer.no_forwarders:
            ansible_module.fail_json(
                msg="You cannot specify a --no-forwarders option without the "
                "--setup-dns option")
        if installer.forward_policy:
            ansible_module.fail_json(
                msg="You cannot specify a --forward-policy option without the "
                "--setup-dns option")
        if installer.reverse_zones:
            ansible_module.fail_json(
                msg="You cannot specify a --reverse-zone option without the "
                "--setup-dns option")
        if installer.auto_reverse:
            ansible_module.fail_json(
                msg="You cannot specify a --auto-reverse option without the "
                "--setup-dns option")
        if installer.no_reverse:
            ansible_module.fail_json(
                msg="You cannot specify a --no-reverse option without the "
                "--setup-dns option")
        if installer.no_dnssec_validation:
            ansible_module.fail_json(
                msg="You cannot specify a --no-dnssec-validation option "
                "without the --setup-dns option")
    elif installer.forwarders and installer.no_forwarders:
        ansible_module.fail_json(
            msg="You cannot specify a --forwarder option together with "
            "--no-forwarders")
    elif installer.auto_forwarders and installer.no_forwarders:
        ansible_module.fail_json(
            msg="You cannot specify a --auto-forwarders option together with "
            "--no-forwarders")
    elif installer.reverse_zones and installer.no_reverse:
        ansible_module.fail_json(
            msg="You cannot specify a --reverse-zone option together with "
            "--no-reverse")
    elif installer.auto_reverse and installer.no_reverse:
        ansible_module.fail_json(
            msg="You cannot specify a --auto-reverse option together with "
            "--no-reverse")

    # replica installers
    if installer.servers and not installer.domain_name:
        ansible_module.fail_json(
            msg="The --server option cannot be used without providing "
            "domain via the --domain option")

    if installer.setup_dns:
        if (not installer.forwarders and
                not installer.no_forwarders and
                not installer.auto_forwarders):
            ansible_module.fail_json(
                msg="You must specify at least one of --forwarder, "
                "--auto-forwarders, or --no-forwarders options")

    if installer.dirsrv_config_file is not None and \
       not os.path.exists(installer.dirsrv_config_file):
        ansible_module.fail_json(
            msg="File %s does not exist." % installer.dirsrv_config_file)

    if installer.ca_cert_files is not None:
        if not isinstance(installer.ca_cert_files, list):
            ansible_module.fail_json(
                msg="Expected list, got {!r}".format(installer.ca_cert_files))
        for cert in installer.ca_cert_files:
            if not os.path.exists(cert):
                ansible_module.fail_json(msg="'%s' does not exist" % cert)
            if not os.path.isfile(cert):
                ansible_module.fail_json(msg="'%s' is not a file" % cert)
            if not os.path.isabs(cert):
                ansible_module.fail_json(
                    msg="'%s' is not an absolute file path" % cert)

            try:
                x509.load_certificate_from_file(cert)
            except Exception:
                ansible_module.fail_json(
                    msg="'%s' is not a valid certificate file" % cert)

    if installer.ip_addresses is not None:
        for value in installer.ip_addresses:
            try:
                ipautil.CheckedIPAddress(value)
            except Exception as e:
                ansible_module.fail_json(
                    msg="invalid IP address {0}: {1}".format(
                        value, e))

    if installer.domain_name is not None:
        validate_domain_name(installer.domain_name)

    ##########################################################################
    # replica promote_check excerpts #########################################
    ##########################################################################

    # check selinux status, http and DS ports, NTP conflicting services
    try:
        with redirect_stdout(ansible_log):
            common_check(options.no_ntp)
    except Exception as msg:  # ScriptError as msg:
        _msg = str(msg)
        if "server is already configured" in _msg:
            ansible_module.exit_json(changed=False,
                                     server_already_configured=True)
        else:
            ansible_module.fail_json(msg=_msg)

    # TODO: Check ntp_servers and ntp_pool

    # client enrolled?

    client_fstore = sysrestore.FileStore(paths.IPA_CLIENT_SYSRESTORE)
    client_enrolled = client_fstore.has_files()

    if not client_enrolled:
        # # One-step replica installation
        # if options.dm_password and options.password:
        #    ansible_module.fail_json(
        #        msg="--password and --admin-password options are "
        #        "mutually exclusive")
        pass
    else:
        # The NTP configuration can not be touched on pre-installed client:
        if options.no_ntp or options.ntp_servers or options.ntp_pool:
            ansible_module.fail_json(
                msg="NTP configuration cannot be updated during promotion")

    # done #

    ansible_module.exit_json(
        changed=False,
        ipa_python_version=IPA_PYTHON_VERSION,
        # basic
        domain=options.domain_name,
        realm=options.realm_name,
        hostname=options.host_name,
        # server
        setup_adtrust=options.setup_adtrust,
        setup_kra=options.setup_kra,
        server=options.server,
        # additional
        client_enrolled=client_enrolled,
        change_master_for_certmonger=change_master_for_certmonger,
    )


if __name__ == '__main__':
    main()

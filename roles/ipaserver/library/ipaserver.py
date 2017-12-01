#!/usr/bin/python
# -*- coding: utf-8 -*-

# Authors:
#   Florence Blanc-Renaud <frenaud@redhat.com>
#   Thomas Woerner <twoerner@redhat.com>
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

ANSIBLE_METADATA = {'metadata_version': '1.0',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
---
module: ipaserver
short description: Configures a server machine as IPA server
description:
  Configures a server machine to use IPA for authentication and
  identity services.
  The enrollment requires one authentication method among the 3 following:
  - Kerberos principal and password (principal/password)
  - Kerberos keytab file (keytab)
  - One-Time-Password (otp)
options:
  state:
    description: the server state
    required: false
    default: present
    choices: [ "present", "absent" ]
  domain:
    description: The primary DNS domain of an existing IPA deployment
    required: true
  realm:
    description:  The Kerberos realm of an existing IPA deployment
    required: true
  password:
    description: The password for the kerberos admin
    required: true
  dm_password:
    description: The password for the Directory Manager
    required: true

#  ip_addresses:
#    description: Master Server IP Addresses
#    required: false
#  hostname:
#    description: Fully qualified name of this host
#    required: false

  mkhomedir:
    description: Create home directories for users on their first login
    required: false
    default: no
  setup_dns:
    description: Configure bind with our zone
    required: false
    default: no
  no_host_dns:
    description: Do not use DNS for hostname lookup during installation
    required: false
    default: no
  no_ntp:
    description: Do not configure ntp
    required: false
    default: no

  idstart:
    description: The starting value for the IDs range (default random)
    required: false
  idmax:
    description: The max value for the IDs range (default: idstart+199999)
    required: false
  no_hbac_allow:
    description: Don't install allow_all HBAC rule
    required: false
    default: no
#  ignore_topology_disconnect:
#    description: Do not check whether server uninstall disconnects the topology (domain level 1+)
#    required: false
#    default: no
#  ignore_last_of_role:
#    description: Do not check whether server uninstall removes last CA/DNS server or DNSSec master (domain level 1+)
#    required: false
  no_pkinit:
    description: Disables pkinit setup steps
    required: false
  no_ui_redirect:
    description: Do not automatically redirect to the Web UI
    required: false

  ssh_trust_dns:
    description: Configure OpenSSH client to trust DNS SSHFP records
    required: false
  no_ssh:
    description: Do not configure OpenSSH client
    required: false
  no_sshd:
    description: Do not configure OpenSSH server
    required: false
  no_dns_sshfp:
    description: Do not automatically create DNS SSHFP records
    required: false
  dirsrv_config_file:
    description: The path to LDIF file that will be used to modify configuration of dse.ldif during installation of the directory server instance
    required: false

  external_ca:
    description: Generate a CSR for the IPA CA certificate to be signed by an external CA
    required: false
  external_ca_type:
    description: Type of the external CA
    required: false
  external_cert_files:
    description: File containing the IPA CA certificate and the external CA certificate chain
    required: false

  dirsrv_cert_files:
    description: File containing the Directory Server SSL certificate and private key
    required: false
  dirsrv_pin:
    description: The password to unlock the Directory Server private key
    required: false
  dirsrv_cert_name:
    description: Name of the Directory Server SSL certificate to install
    required: false

  http_cert_files:
    description: File containing the Apache Server SSL certificate and private key
    required: false
  http_pin:
    description: The password to unlock the Apache Server private key
    required: false
  http_cert_name:
    description: Name of the Apache Server SSL certificate to install
    required: false

  pkinit_cert_files:
    description: File containing the Kerberos KDC SSL certificate and private key
    required: false
  pkinit_pin:
    description: The password to unlock the Kerberos KDC private key
    required: false
  pkinit_cert_name:
    description: Name of the Kerberos KDC SSL certificate to install
    required: false

  ca_cert_files:
    description: File containing CA certificates for the service certificate files
    required: false
  subject:
    description: The certificate subject base (default O=<realm-name>)
    required: false
  ca_signing_algorithm:
    description: Signing algorithm of the IPA CA certificate
    required: false

  forwarders:
    description: Add DNS forwarders
    required: false



author:
    - Florence Blanc-Renaud
    - Thomas Woerner
'''

EXAMPLES = '''
# Example from Ansible Playbooks
# Unenroll server
- ipaserver:
  state: absent

# Enroll server using admin credentials, with auto-discovery
- ipaserver:
    password: MySecretPassword
    dm_password: MySecretPassword
'''

RETURN = '''
tbd
'''

import os
from six.moves.configparser import RawConfigParser
from ansible.module_utils.basic import AnsibleModule
try:
    from ipalib.install.sysrestore import SYSRESTORE_STATEFILE
except ImportError:
    from ipapython.sysrestore import SYSRESTORE_STATEFILE
from ipaplatform.paths import paths


def is_server_configured():
    """
    Check if ipa server is configured.

    IPA server is configured when /etc/ipa/default.conf exists and
    /var/lib/ipa/sysrestore/sysrestore.state exists.

    :returns: boolean
    """

    return (os.path.isfile(paths.IPA_DEFAULT_CONF) and
            os.path.isfile(os.path.join(paths.SYSRESTORE,
                                        SYSRESTORE_STATEFILE)))


def get_ipa_conf():
    """
    Return IPA configuration read from /etc/ipa/default.conf

    :returns: dict containing key,value
    """

    parser = RawConfigParser()
    parser.read(paths.IPA_DEFAULT_CONF)
    result = dict()
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
        supports_check_mode=True,
        argument_spec=dict(
            state=dict(default='present', choices=['present', 'absent']),
            # basic
            dm_password=dict(required=False, no_log=True),
            password=dict(required=False, no_log=True),
#            ip_addresses=dict(required=False, type='list'),
            domain=dict(required=True),
            realm=dict(required=True),
#            hostname=dict(required=False),
            ca_cert_files=dict(required=False, type='list'),
            no_host_dns=dict(required=False, type='bool', default=False),
            # server
#            setup_adtrust=dict(required=False, type='bool', default=F#alse),
#            setup_kra=dict(required=False, type='bool', default=False),
            setup_dns=dict(required=False, type='bool', default=False),
            idstart=dict(required=False, type='int', default=0),
            idmax=dict(required=False, type='int', default=0),
            no_hbac_allow=dict(required=False, type='bool', default=False),
            no_pkinit=dict(required=False, type='bool', default=False),
            no_ui_redirect=dict(required=False, type='bool', default=False),
            dirsrv_config_file=dict(required=False),
            # ssl certificate
            dirsrv_cert_files=dict(required=False, type='list'),
            dirsrv_pin=dict(required=False),
            dirsrv_cert_name=dict(required=False),
            http_cert_files=dict(required=False, type='list'),
            http_pin=dict(required=False),
            http_cert_name=dict(required=False),
            pkinit_cert_files=dict(required=False, type='list'),
            pkinit_pin=dict(required=False),
            pkinit_cert_name=dict(required=False),
            # client
            mkhomedir=dict(required=False, type='bool', default=False),
            no_ntp=dict(required=False, type='bool', default=False),
            ssh_trust_dns=dict(required=False, type='bool', default=False),
            no_ssh=dict(required=False, type='bool', default=False),
            no_sshd=dict(required=False, type='bool', default=False),
            no_dns_sshfp=dict(required=False, type='bool', default=False),
            # certificate system
            external_ca=dict(required=False),
            external_ca_type=dict(default='generic',
                                  choices=['generic', 'ms-cs']),
            external_cert_files=dict(required=False, type='list'),
            subject_base=dict(required=False),
            ca_signing_algorithm=dict(required=False),

            # dns
            allow_zone_overlap=dict(required=False, type='bool', default=False),
            reverse_zones=dict(required=False, type='list'),
            no_reverse=dict(required=False, type='bool', default=False),
            auto_reverse=dict(required=False, type='bool', default=False),
            zone_manager=dict(required=False),
            forwarders=dict(required=False, type='list'),
            no_forwarders=dict(required=False, type='bool', default=False),
            auto_forwarders=dict(required=False, type='bool', default=False),
            forward_policy=dict(default='first', choices=['first', 'only']),
            no_dnssec_validation=dict(required=False, type='bool', default=False),
            # ad trust
            enable_compat=dict(required=False, type='bool', default=False),
            netbios_name=dict(required=False),
            rid_base=dict(required=False),
            secondary_rid_base=dict(required=False),
        ),
    )

    module._ansible_debug = True
    state = module.params.get('state')

    domain = module.params.get('domain')
    realm = module.params.get('realm')
    password = module.params.get('password')
    dm_password = module.params.get('dm_password')

    #ip_addresses = module.params.get('ip_addresses')
    #hostname = module.params.get('hostname')

    mkhomedir = module.params.get('mkhomedir')
    setup_dns = module.params.get('setup_dns')
    no_host_dns = module.params.get('no_host_dns')
    no_ntp = module.params.get('no_ntp')

    idstart = module.params.get('idstart')
    idmax = module.params.get('idmax')
    no_hbac_allow = module.params.get('no_hbac_allow')
    ignore_topology_disconnect = module.params.get('ignore_topology_disconnect')
    ignore_last_of_role = module.params.get('ignore_last_of_role')
    no_pkinit = module.params.get('no_pkinit')
    no_ui_redirect = module.params.get('no_ui_redirect')

    ssh_trust_dns = module.params.get('ssh_trust_dns')
    no_ssh = module.params.get('no_ssh')
    no_sshd = module.params.get('no_sshd')
    no_dns_sshfp = module.params.get('no_dns_sshfp')
    dirsrv_config_file = module.params.get('dirsrv_config_file')

    external_ca = module.params.get('external_ca')
    external_ca_type = module.params.get('external_ca_type')
    external_cert_files = module.params.get('external_cert_files')

    dirsrv_cert_files=module.params.get('dirsrv_cert_files')
    dirsrv_pin=module.params.get('dirsrv_pin')
    dirsrv_cert_name=module.params.get('dirsrv_cert_name')

    http_cert_files=module.params.get('http_cert_files')
    http_pin=module.params.get('http_pin')
    http_cert_name=module.params.get('http_cert_name')

    pkinit_cert_files=module.params.get('pkinit_cert_files')
    pkinit_pin=module.params.get('pkinit_pin')
    pkinit_cert_name=module.params.get('pkinit_cert_name')

    ca_cert_files=module.params.get('ca_cert_files')
    subject=module.params.get('subject')
    ca_signing_algorithm=module.params.get('ca_signing_algorithm')
    
    forwarders = module.params.get('forwarders')

    if state == 'present':
        if not password or not dm_password:
            module.fail_json(
                msg="Password and dm password need to be specified")

        # Check if ipa server is already configured
        if is_server_configured():
            # Check that realm and domain match
            current_config = get_ipa_conf()
            if domain and domain != current_config.get('domain'):
                module.fail_json(msg="IPA server already installed "
                                 "with a conflicting domain")
            if realm and realm != current_config.get('realm'):
                module.fail_json(msg="IPA server already installed "
                                 "with a conflicting realm")

            # server is already configured and no inconsistency
            # detected
            return module.exit_json(changed=False, domain=domain, realm=realm)

        # ipa server not installed
        if module.check_mode:
            # Do nothing, just return changed=True
            return module.exit_json(changed=True)

        # basic options
        cmd = [
            module.get_bin_path("ipa-server-install"),
            "-U",
            "--ds-password", dm_password,
            "--admin-password", password,
            "--domain", domain,
            "--realm", realm,
        ]

        #for ip in ip_addresses:
        #    cmd.append("--ip-address=%s" % ip)
        #if hostname:
        #    cmd.append("--hostname=%s" % hostname)

        for cert_file in ca_cert_files:
            cmd.append("--ca-cert-file=%s" % cert_file)
        if no_host_dns:
            cmd.append("--no-host-dns")

        # server options
        #if setup_adtrust:
        #    cmd.append("--setup-adtrust")
        #if setup_kra:
        #    cmd.append("--setup-kra")
        if setup_dns:
            cmd.append("--setup-dns")
        if idstart:
            cmd.append("--idstart=%d", idstart)
        if idmax:
            cmd.append("--idstart=%d", idmax)
        if no_hbac_allow:
            cmd.append("--no_hbac_allow")
        if no_pkinit:
            cmd.append("--no-pkinit")
        if no_ui_redirect:
            cmd.append("--no-ui-redirect")
        if dirsrv_config_file:
            cmd.append("--dirsrv-config-file=%s" % dirsrv_config_file)

        # ssl certificate options
        for cert_file in dirsrv_cert_files:
            cmd.append("--dirsrv-cert-file=%s" % cert_file)
        if dirsrv_pin:
            cmd.append("--dirsrv-pin=%s" % dirserv_pin)
        if dirsrv_cert_name:
            cmd.append("--dirsrv-cert-name=%s" % dirsrv_cert_name)
        for cert_file in http_cert_files:
            cmd.append("--http-cert-file=%s" % cert_file)
        if http_pin:
            cmd.append("--http-pin=%s" % http_pin)
        if http_cert_name:
            cmd.append("--http-cert-name=%s" % http_cert_name)
        for cert_file in pkinit_cert_files:
            cmd.append("--pkinit-cert-file=%s" % cert_file)
        if pkinit_pin:
            cmd.append("--pkinit-pin=%s" % pkinit_pin)
        if pkinit_cert_name:
            cmd.append("--pkinit-cert-name=%s" % pkinit_cert_name)

        # client options
        if mkhomedir:
            cmd.append("--mkhomedir")
        if no_ntp:
            cmd.append("--no-ntp")
        if ssh_trust_dns:
            cmd.append("--ssh-trust-dns")
        if no_ssh:
            cmd.append("--no-ssh")
        if no_sshd:
            cmd.append("--no-sshd")
        if no_dns_sshfp:
            cmd.append("--no-dns-sshfp")

        # certificate system options
        if external_ca:
            cmd.append("--external-ca")
        if external_ca_type:
            cmd.append("--external-ca-type=%s" % external_ca_type)
        for cert_file in external_cert_files:
            cmd.append("--external-cert-file=%s" % cert_file)
        if subject_base:
            cmd.append("--subject=%s" % subject)
        if ca_signing_algorithm:
            cmd.append("--ca-signing-algorithm=%s" % ca_signing_algorithm)

        # dns options
        if allow_zone_overlop:
            cmd.append("--allow-zone-overlap")
        for reverse_zone in reverse_zones:
            cmd.append("--reverse-zone=%s" % reverse_zone)
        if no_reverse:
            cmd.append("--no-reverse")
        if auto_reverse:
            cmd.append("--auto-reverse")
        if zonemgr:
            cmd.append("--zonemgr=%s" % zonemgr)
        for forwarder in forwarders:
            cmd.append("--forwarder=%s" % forwarder)
        if no_forwarders:
            cmd.append("--no-forwarders")
        if auto_forwarders:
            cmd.append("--auto-forwarders")
        if forward_policy:
            cmd.append("--forward-policy=%s" % forward_policy)
        if no_dnssec_validation:
            cmd.append("--no-dnssec-validation")

        # ad trust options
        #if enable_compat:
        #    cmd.append("--enable-compat")
        #if netbios_name:
        #    cmd.append("--netbios-name=%s" % netbios_name)
        #if rid_base:
        #    cmd.append("--rid-base=%s" % rid_base)
        #if secondary_rid_base:
        #    cmd.append("--secondary-rid-base=%s" % rid_base)

    else: # state == adsent
        if not is_server_configured():
            # Nothing to do
            module.exit_json(changed=False)

        # Server is configured
        # If in check mode, do nothing but return changed=True
        if module.check_mode:
            module.exit_json(changed=True)

        cmd = [
            module.get_bin_path('ipa-server-install'),
            "--uninstall",
            "-U",
        ]

        if ignore_topology_disconnect:
            cmd.append("--ignore-topology-disconnect")
        if ignore_last_of_role:
            cmd.append("--ignore-last-of-role")

    retcode, stdout, stderr = module.run_command(cmd)
    if retcode != 0:
        module.fail_json(msg="Failed to uninstall IPA server: %s" % stderr)

    module.exit_json(changed=True)

if __name__ == '__main__':
    main()

#!/usr/bin/python
# -*- coding: utf-8 -*-

# Authors:
#   Florence Blanc-Renaud <frenaud@redhat.com>
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
module: ipaclient
short description: Configures a client machine as IPA client
description:
  Configures a client machine to use IPA for authentication and
  identity services.
  The enrollment requires one authentication method among the 3 following:
  - Kerberos principal and password (principal/password)
  - Kerberos keytab file (keytab)
  - One-Time-Password (otp)
options:
  state:
    description: the client state
    required: false
    default: present
    choices: [ "present", "absent" ]
  domain:
    description: The primary DNS domain of an existing IPA deployment.
    required: false
  realm:
    description:  The Kerberos realm of an existing IPA deployment.
    required: false
  servers:
    description: The FQDN of the IPA servers to connect to.
    required: false
  principal:
    description: The authorized kerberos principal used to join the IPA realm.
    required: false
    default: admin
  password:
    description: The password for the kerberos principal.
    required: false
  keytab:
    description: The path to a backed-up host keytab from previous enrollment.
    required: false
  otp:
    description: The One-Time-Password used to join the IPA realm.
    required: false
  force_join:
    description: Set force_join to yes to join the host even if it is already enrolled.
    required: false
    choices: [ "yes", "force" ]
    default: yes
  kinit_attempts:
    description: Repeat the request for host Kerberos ticket X times.
    required: false
  ntp:
    description: Set to no to not configure and enable NTP
    required: false
    default: yes
  mkhomedir:
    description: Set to yes to configure PAM to create a users home directory if it does not exist.
    required: false
    default: no
  extr_args:
    description: The list of extra arguments to provide to ipa-client-install.
    required: false
    type: list
author:
    - Florence Blanc-Renaud
    - Thomas Woerner
'''

EXAMPLES = '''
# Example from Ansible Playbooks
# Unenroll client
- ipaclient:
  state: absent

# Enroll client using admin credentials, with auto-discovery
- ipaclient:
    principal: admin
    password: MySecretPassword
    ntp: no
    kinit_attempts: 5

# Enroll client using admin credentials, with specified domain and
# autodiscovery of the IPA server
- ipaclient:
    principal: admin
    password: MySecretPassword
    domain: ipa.domain.com
    ntp: no
    kinit_attempts: 5

# Enroll client using admin credentials, with specified server
- ipaclient:
    principal: admin
    password: MySecretPassword
    domain: ipa.domain.com
    servers: ipaserver.ipa.domain.com
    ntp: no
    kinit_attempts: 5

# Enroll client using One-Time-Password, with specified domain and realm
- ipaclient:
    domain: ipa.domain.com
    realm: IPA.DOMAIN.com
    otp: 9Mn*Jm8z[%n]|:CJeu>Y~K

# Re-enroll client using keytab stored on the managed node
- ipaclient:
    domain: ipa.domain.com
    realm: IPA.DOMAIN.com
    keytab: /path/to/host.keytab
'''

RETURN = '''
tbd
'''

import os
from six.moves.configparser import RawConfigParser

from ansible.module_utils.basic import AnsibleModule

from ipalib.install.sysrestore import SYSRESTORE_STATEFILE
from ipaplatform.paths import paths


def is_client_configured():
    """
    Check if ipa client is configured.

    IPA client is configured when /etc/ipa/default.conf exists and
    /var/lib/ipa-client/sysrestore/sysrestore.state exists.

    :returns: boolean
    """

    return (os.path.isfile(paths.IPA_DEFAULT_CONF) and
            os.path.isfile(os.path.join(paths.IPA_CLIENT_SYSRESTORE,
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


def ensure_not_ipa_client(module):
    """
    Module for client uninstallation

    If IPA client is installed, calls ipa-client-install --uninstall -U
    :param module: AnsibleModule
    """

    # Check if IPA client is already configured
    if not is_client_configured():
        # Nothing to do
        module.exit_json(changed=False)

    # Client is configured
    # If in check mode, do nothing but return changed=True
    if module.check_mode:
        module.exit_json(changed=True)

    # Client is configured and we want to remove it
    cmd = [
        module.get_bin_path('ipa-client-install'),
        "--uninstall",
        "-U",
        ]
    retcode, stdout, stderr = module.run_command(cmd)
    if retcode != 0:
        module.fail_json(msg="Failed to uninstall IPA client: %s" % stderr)

    module.exit_json(changed=True)


def ensure_ipa_client(module):
    """
    Module for client installation

    If IPA client is not installed, calls ipa-client-install
    :param module: AnsibleModule
    """

    domain = module.params.get('domain')
    realm = module.params.get('realm')
    servers = module.params.get('servers')
    principal = module.params.get('principal')
    password = module.params.get('password')
    keytab = module.params.get('keytab')
    otp = module.params.get('otp')
    force_join = module.params.get('force_join')
    kinit_attempts = module.params.get('kinit_attempts')
    ntp = module.params.get('ntp')
    mkhomedir = module.params.get('mkhomedir')
    extra_args = module.params.get('extra_args')

    # Ensure that at least one auth method is specified
    if not (password or keytab or otp):
        module.fail_json(msg="At least one of password, keytab or otp "
                             "must be specified")

    # Check if ipa client is already configured
    if is_client_configured():
        # Check that realm and domain match
        current_config = get_ipa_conf()
        if domain and domain != current_config.get('domain'):
            return module.fail_json(msg="IPA client already installed "
                                        "with a conflicting domain")
        if realm and realm != current_config.get('realm'):
            return module.fail_json(msg="IPA client already installed "
                                        "with a conflicting realm")

        # client is already configured and no inconsistency detected
        return module.exit_json(changed=False, domain=domain, realm=realm)

    # ipa client not installed
    if module.check_mode:
        # Do nothing, just return changed=True
        return module.exit_json(changed=True)

    cmd = [
        module.get_bin_path("ipa-client-install"),
        "-U",
        ]
    if domain:
        cmd.append("--domain")
        cmd.append(domain)
    if realm:
        cmd.append("--realm")
        cmd.append(realm)
    if servers:
        for server in servers:
            cmd.append("--server")
            cmd.append(server)
    if password:
        cmd.append("--password")
        cmd.append(password)
        cmd.append("--principal")
        cmd.append(principal)
    if keytab:
        cmd.append("--keytab")
        cmd.append(keytab)
        cmd.append("-d")
    if otp:
        cmd.append("--password")
        cmd.append(otp)
    if force_join:
        cmd.append("--force-join")
    if kinit_attempts:
        cmd.append("--kinit-attempts")
        cmd.append(str(kinit_attempts))
    if not ntp:
        cmd.append("--no-ntp")
    if mkhomedir:
        cmd.append("--mkhomedir")
    if extra_args:
        for extra_arg in extra_args:
            cmd.append(extra_arg)

    retcode, stdout, stderr = module.run_command(cmd)
    if retcode != 0:
        module.fail_json(msg="Failed to install IPA client: %s" % stderr)

    # If autodiscovery was used, need to read /etc/ipa/default.conf to
    # find domain and realm
    new_config = get_ipa_conf()
    module.exit_json(changed=True,
                     domain=new_config.get('domain'),
                     realm=new_config.get('realm'))


def main():
    module = AnsibleModule(
        supports_check_mode=True,
        argument_spec=dict(
            state=dict(default='present', choices=['present', 'absent']),
            domain=dict(required=False),
            realm=dict(required=False),
            servers=dict(required=False, type='list'),
            principal=dict(default='admin'),
            password=dict(required=False, no_log=True),
            keytab=dict(required=False, type='path'),
            otp=dict(required=False),
            force_join=dict(required=False, type='bool', default=False),
            kinit_attempts=dict(required=False, type='int'),
            ntp=dict(required=False, type='bool', default=True),
            mkhomedir=dict(required=False, type='bool', default=False),
            extra_args=dict(default=None, type='list')
            ),
        )

    module._ansible_debug = True
    state = module.params.get('state')

    if state == 'present':
        ensure_ipa_client(module)
    else:
        ensure_not_ipa_client(module)

if __name__ == '__main__':
    main()

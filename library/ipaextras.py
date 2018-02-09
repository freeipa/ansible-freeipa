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
module: ipaextras
short description: Configure IPA extras
description:
Configure IPA extras
options:
  servers:
    description: The FQDN of the IPA servers to connect to.
    required: true
    type: list
  domain:
    description: The primary DNS domain of an existing IPA deployment.
    required: true
  ntp:
    description: Set to no to not configure and enable NTP
    required: false
    type: bool
    default: no
  force_ntpd:
    description: Stop and disable any time&date synchronization services besides ntpd.
    required: false
    type: bool
    default: no
  ntp_servers:
    description: The ntp servers to configure if ntp is enabled.
    required: false
    type: list
  ssh:
    description: Configure OpenSSH client
    required: false
    type: bool
    default: yes
  sssd:
    description: Configure the client to use SSSD for authentication
    required: false
    type: bool
    default: yes
  trust_sshfp:
    description: Configure OpenSSH client to trust DNS SSHFP records
    required: false
    type: bool
    default: yes
  sshd:
    description: Configure OpenSSH server
    required: false
    type: bool
    default: yes
  automount_location:
    description: Automount location
    required: false
  firefox:
    description: Configure Firefox to use IPA domain credentials
    required: false
    type: bool
    default: no
  firefox_dir:
    description: Specify directory where Firefox is installed (for example: '/usr/lib/firefox')
    required: false
  no_nisdomain:
    description: Do not configure NIS domain name
    required: false
    type: bool
    default: no
  nisdomain:
    description: NIS domain name
    required: false
  on_master:
    description: Whether the configuration is done on the master or not.
    required: false
    type: bool
    default: no
author:
    - Thomas Woerner
'''

EXAMPLES = '''
- name: IPA extras configurations
  ipaextras:
    servers: ["server1.example.com","server2.example.com"]
    domain: example.com
'''

RETURN = '''
'''

import os

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.ansible_ipa_client import *

def main():
    module = AnsibleModule(
        argument_spec = dict(
            servers=dict(required=True, type='list'),
            domain=dict(required=True),
            ntp=dict(required=False, type='bool', default='no'),
            force_ntpd=dict(required=False, type='bool', default='no'),
            ntp_servers=dict(required=False, type='list'),
            ssh=dict(required=False, type='bool', default='yes'),
            sssd=dict(required=False, type='bool', default='yes'),
            trust_sshfp=dict(required=False, type='bool', default='yes'),
            sshd=dict(required=False, type='bool', default='yes'),
            automount_location=dict(required=False),
            firefox=dict(required=False, type='bool', default='no'),
            firefox_dir=dict(required=False),
            no_nisdomain=dict(required=False, type='bool', default='no'),
            nisdomain=dict(required=False),
            on_master=dict(required=False, type='bool', default='no'),
        ),
        supports_check_mode = True,
    )

    module._ansible_debug = True
    servers = module.params.get('servers')
    domain = module.params.get('domain')
    ntp = module.params.get('ntp')
    force_ntpd = module.params.get('force_ntpd')
    ntp_servers = module.params.get('ntp_servers')
    ssh = module.params.get('ssh')
    sssd = module.params.get('sssd')
    trust_sshfp = module.params.get('trust_sshfp')
    sshd = module.params.get('sshd')
    automount_location = module.params.get('automount_location')
    firefox = module.params.get('firefox')
    firefox_dir = module.params.get('firefox_dir')
    no_nisdomain = module.params.get('no_nisdomain')
    nisdomain = module.params.get('nisdomain')
    on_master = module.params.get('on_master')
    
    fstore = sysrestore.FileStore(paths.IPA_CLIENT_SYSRESTORE)
    statestore = sysrestore.StateFile(paths.IPA_CLIENT_SYSRESTORE)

    os.environ['KRB5CCNAME'] = paths.IPA_DNS_CCACHE
    
    options.sssd = sssd
    options.trust_sshfp = trust_sshfp
    options.location = automount_location
    options.server = servers
    options.firefox_dir = firefox_dir
    options.nisdomain = nisdomain

    if ntp and not on_master:
        # disable other time&date services first
        if force_ntpd:
            ntpconf.force_ntpd(statestore)

        ntpconf.config_ntp(ntp_servers, fstore, statestore)
        module.log("NTP enabled")

    if ssh:
        configure_ssh_config(fstore, options)

    if sshd:
        configure_sshd_config(fstore, options)

    if automount_location:
        configure_automount(options)

    if firefox:
        configure_firefox(options, statestore, domain)

    if not no_nisdomain:
        if NUM_VERSION < 40500:
            configure_nisdomain(options=options, domain=domain)
        else:
            configure_nisdomain(options=options, domain=domain,
                                statestore=statestore)

    # Cleanup: Remove CCACHE_FILE
    try:
        os.remove(paths.IPA_DNS_CCACHE)
    except Exception:
        pass

    module.exit_json(changed=True)

if __name__ == '__main__':
    main()

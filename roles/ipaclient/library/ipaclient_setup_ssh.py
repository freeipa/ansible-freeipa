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
module: ipaclient_setup_ssh
short description: Configure ssh and sshd for IPA client
description:
  Configure ssh and sshd for IPA client
options:
  servers:
    description: The FQDN of the IPA servers to connect to.
    required: true
    type: list
  ssh:
    description: Configure OpenSSH client
    required: false
    type: bool
    default: no
  trust_sshfp:
    description: Configure OpenSSH client to trust DNS SSHFP records
    required: false
    type: bool
    default: no
  sshd:
    description: Configure OpenSSH server
    required: false
    type: bool
    default: no
  sssd:
    description: Configure SSSD server
    required: false
    type: bool
    default: no
author:
    - Thomas Woerner
'''

EXAMPLES = '''
- name: Configure ssh and sshd for IPA client
  ipaclient_setup_ssh:
    servers: ["server1.example.com","server2.example.com"]
    ssh: yes
    sshd: yes
    sssd: yes
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
            ssh=dict(required=False, type='bool', default='no'),
            trust_sshfp=dict(required=False, type='bool', default='no'),
            sshd=dict(required=False, type='bool', default='no'),
            sssd=dict(required=False, type='bool', default='no'),
        ),
        supports_check_mode = True,
    )

    module._ansible_debug = True
    options.servers = module.params.get('servers')
    options.server = options.servers
    options.conf_ssh = module.params.get('ssh')
    options.trust_sshfp = module.params.get('trust_sshfp')
    options.conf_sshd = module.params.get('sshd')
    options.sssd = module.params.get('sssd')

    fstore = sysrestore.FileStore(paths.IPA_CLIENT_SYSRESTORE)

    #os.environ['KRB5CCNAME'] = paths.IPA_DNS_CCACHE

    changed = False
    if options.conf_ssh:
        configure_ssh_config(fstore, options)
        changed = True

    if options.conf_sshd:
        configure_sshd_config(fstore, options)
        changed = True

    module.exit_json(changed=changed)

if __name__ == '__main__':
    main()

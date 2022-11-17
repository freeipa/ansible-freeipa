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

ANSIBLE_METADATA = {
    'metadata_version': '1.0',
    'supported_by': 'community',
    'status': ['preview'],
}

DOCUMENTATION = '''
---
module: ipaclient_setup_ssh
short_description: Configure ssh and sshd for IPA client
description:
  Configure ssh and sshd for IPA client
options:
  servers:
    description: Fully qualified name of IPA servers to enroll to
    type: list
    elements: str
    required: yes
  no_ssh:
    description: Do not configure OpenSSH client
    type: bool
    required: no
    default: no
  ssh_trust_dns:
    description: Configure OpenSSH client to trust DNS SSHFP records
    type: bool
    required: no
    default: no
  no_sshd:
    description: Do not configure OpenSSH server
    type: bool
    required: no
    default: no
  sssd:
    description: The installer sssd setting
    type: bool
    required: no
    default: no
author:
    - Thomas Woerner (@t-woerner)
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

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.ansible_ipa_client import (
    setup_logging, check_imports,
    options, sysrestore, paths, configure_ssh_config, configure_sshd_config
)


def main():
    module = AnsibleModule(
        argument_spec=dict(
            servers=dict(required=True, type='list', elements='str'),
            no_ssh=dict(required=False, type='bool', default='no'),
            ssh_trust_dns=dict(required=False, type='bool', default='no'),
            no_sshd=dict(required=False, type='bool', default='no'),
            sssd=dict(required=False, type='bool', default='no'),
        ),
        supports_check_mode=False,
    )

    module._ansible_debug = True
    check_imports(module)
    setup_logging()

    options.servers = module.params.get('servers')
    options.server = options.servers
    options.no_ssh = module.params.get('no_ssh')
    options.conf_ssh = not options.no_ssh
    options.trust_sshfp = module.params.get('ssh_trust_dns')
    options.no_sshd = module.params.get('no_sshd')
    options.conf_sshd = not options.no_sshd
    options.sssd = module.params.get('sssd')

    fstore = sysrestore.FileStore(paths.IPA_CLIENT_SYSRESTORE)

    # os.environ['KRB5CCNAME'] = paths.IPA_DNS_CCACHE

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

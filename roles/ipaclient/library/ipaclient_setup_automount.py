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
module: ipaclient_setup_automount
short description: Setup automount for IPA client
description:
  Setup automount for IPA client
options:
  servers:
    description: Fully qualified name of IPA servers to enroll to
    required: no
  sssd:
    description: The installer sssd setting
    required: yes
  automount_location:
    description: The automount location
    required: yes
author:
    - Thomas Woerner
'''

EXAMPLES = '''
- name: IPA extras configurations
  ipaclient_setup_automount:
    servers: ["server1.example.com","server2.example.com"]
'''

RETURN = '''
'''


from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.ansible_ipa_client import (
    setup_logging, options, configure_automount
)


def main():
    module = AnsibleModule(
        argument_spec=dict(
            servers=dict(required=True, type='list'),
            sssd=dict(required=False, type='bool', default='yes'),
            automount_location=dict(required=False, default=None),
        ),
        supports_check_mode=True,
    )

    # os.environ['KRB5CCNAME'] = paths.IPA_DNS_CCACHE

    module._ansible_debug = True
    setup_logging()

    options.servers = module.params.get('servers')
    options.server = options.servers
    options.sssd = module.params.get('sssd')
    options.automount_location = module.params.get('automount_location')
    options.location = options.automount_location

    if options.automount_location:
        configure_automount(options)

    module.exit_json(changed=True)


if __name__ == '__main__':
    main()

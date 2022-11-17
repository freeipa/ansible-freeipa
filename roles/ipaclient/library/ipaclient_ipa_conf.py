# -*- coding: utf-8 -*-

# Authors:
#   Thomas Woerner <twoerner@redhat.com>
#
# Based on ipa-client-install code
#
# Copyright (C) 2018-2022  Red Hat
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
module: ipaclient_ipa_conf
short_description: Configure ipa.conf
description:
  Configure ipa.conf
options:
  domain:
    description: Primary DNS domain of the IPA deployment
    type: str
    required: yes
  servers:
    description: Fully qualified name of IPA servers to enroll to
    type: list
    elements: str
    required: yes
  realm:
    description: Kerberos realm name of the IPA deployment
    type: str
    required: yes
  hostname:
    description: Fully qualified name of this host
    type: str
    required: yes
  basedn:
    description: The basedn of the IPA server (of the form dc=example,dc=com)
    type: str
    required: yes
author:
    - Thomas Woerner (@t-woerner)
'''

EXAMPLES = '''
# Backup and set hostname
- name: Backup and set hostname
  ipaclient_ipa_conf:
    server: server.example.com
    domain: example.com
    realm: EXAMPLE.COM
    hostname: client1.example.com
    basedn: dc=example,dc=com
'''

RETURN = '''
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.ansible_ipa_client import (
    setup_logging, check_imports, paths, sysrestore, configure_ipa_conf
)


def main():
    module = AnsibleModule(
        argument_spec=dict(
            domain=dict(required=True, type='str'),
            servers=dict(required=True, type='list', elements='str'),
            realm=dict(required=True, type='str'),
            hostname=dict(required=True, type='str'),
            basedn=dict(required=True, type='str'),
        ),
        supports_check_mode=False,
    )

    module._ansible_debug = True
    check_imports(module)
    setup_logging()

    servers = module.params.get('servers')
    domain = module.params.get('domain')
    realm = module.params.get('realm')
    hostname = module.params.get('hostname')
    basedn = module.params.get('basedn')

    fstore = sysrestore.FileStore(paths.IPA_CLIENT_SYSRESTORE)

    configure_ipa_conf(fstore, basedn, realm, domain, servers, hostname)

    module.exit_json(changed=True)


if __name__ == '__main__':
    main()

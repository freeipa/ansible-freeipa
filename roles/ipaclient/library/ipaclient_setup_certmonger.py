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
module: ipaclient_setup_certmonger
short_description: Setup certmonger for IPA client
description: Setup certmonger for IPA client
options:
  realm:
    description: Kerberos realm name of the IPA deployment
    type: str
    required: yes
  hostname:
    description: Fully qualified name of this host
    type: str
    required: yes
  subject_base:
    description: |
      The certificate subject base (default O=<realm-name>).
      RDNs are in LDAP order (most specific RDN first).
    type: str
    required: yes
  ca_enabled:
    description: Whether the Certificate Authority is enabled or not
    type: bool
    required: yes
  request_cert:
    description: Request certificate for the machine
    type: bool
    required: yes
author:
    - Thomas Woerner (@t-woerner)
'''

EXAMPLES = '''
- name: Setup certmonger for IPA client
  ipaclient_setup_certmonger:
    realm: EXAMPLE.COM
    hostname: client1.example.com
    subject_base: O=EXAMPLE.COM
    ca_enabled: true
    request_cert: false
'''

RETURN = '''
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.ansible_ipa_client import (
    setup_logging, check_imports,
    options, sysrestore, paths, ScriptError, configure_certmonger
)


def main():
    module = AnsibleModule(
        argument_spec=dict(
            realm=dict(required=True, type='str'),
            hostname=dict(required=True, type='str'),
            subject_base=dict(required=True, type='str'),
            ca_enabled=dict(required=True, type='bool'),
            request_cert=dict(required=True, type='bool'),
        ),
        supports_check_mode=False,
    )

    module._ansible_debug = True
    check_imports(module)
    setup_logging()

    cli_realm = module.params.get('realm')
    hostname = module.params.get('hostname')
    subject_base = module.params.get('subject_base')
    ca_enabled = module.params.get('ca_enabled')

    fstore = sysrestore.FileStore(paths.IPA_CLIENT_SYSRESTORE)

    options.request_cert = module.params.get('request_cert')
    options.hostname = hostname

    try:
        configure_certmonger(fstore, subject_base, cli_realm, hostname,
                             options, ca_enabled)

    except ScriptError as e:
        module.fail_json(msg=str(e))

    module.exit_json(changed=True)


if __name__ == '__main__':
    main()

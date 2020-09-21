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

ANSIBLE_METADATA = {'metadata_version': '1.0',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
---
module: ipaclient_fix_ca
short description: Fix IPA ca certificate
description: Repair Fix IPA ca certificate
options:
  servers:
    description: Fully qualified name of IPA servers to enroll to
    required: no
  realm:
    description: Kerberos realm name of the IPA deployment
    required: no
  basedn:
    description: The basedn of the IPA server (of the form dc=example,dc=com)
    required: no
  allow_repair:
    description: |
      Allow repair of already joined hosts. Contrary to ipaclient_force_join
      the host entry will not be changed on the server
    required: no
author:
    - Thomas Woerner
'''

EXAMPLES = '''
- name: Fix IPA ca certificate
  ipaclient_fix_ca:
    servers: ["server1.example.com","server2.example.com"]
    realm: EXAMPLE.COM
    basedn: dc=example,dc=com
    allow_repair: yes
'''

RETURN = '''
'''

import os

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.ansible_ipa_client import (
    setup_logging,
    SECURE_PATH, paths, sysrestore, options, NUM_VERSION, get_ca_cert,
    get_ca_certs, errors
)


def main():
    module = AnsibleModule(
        argument_spec=dict(
            servers=dict(required=True, type='list'),
            realm=dict(required=True),
            basedn=dict(required=True),
            allow_repair=dict(required=True, type='bool'),
        ),
    )

    module._ansible_debug = True
    setup_logging()

    servers = module.params.get('servers')
    realm = module.params.get('realm')
    basedn = module.params.get('basedn')
    allow_repair = module.params.get('allow_repair')

    env = {'PATH': SECURE_PATH}
    fstore = sysrestore.FileStore(paths.IPA_CLIENT_SYSRESTORE)
    os.environ['KRB5CCNAME'] = paths.IPA_DNS_CCACHE

    options.ca_cert_file = None
    options.principal = None
    options.force = False
    options.password = None

    changed = False
    if not os.path.exists(paths.IPA_CA_CRT):
        if not allow_repair:
            module.fail_json(
                msg="%s missing, enable allow_repair to fix it." %
                paths.IPA_CA_CRT)

        # Repair missing ca.crt file
        try:
            os.environ['KRB5_CONFIG'] = env['KRB5_CONFIG'] = "/etc/krb5.conf"
            env['KRB5CCNAME'] = os.environ['KRB5CCNAME']
            if NUM_VERSION < 40100:
                get_ca_cert(fstore, options, servers[0], basedn)
            else:
                get_ca_certs(fstore, options, servers[0], basedn, realm)
            changed = True
            del os.environ['KRB5_CONFIG']
        except errors.FileError as e:
            module.fail_json(msg='%s' % e)
        except Exception as e:
            module.fail_json(msg="Cannot obtain CA certificate\n%s" % e)

    module.exit_json(changed=changed)


if __name__ == '__main__':
    main()

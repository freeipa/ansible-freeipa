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
module: ipaclient_temp_krb5
short_description:
  Create temporary krb5 configuration.
description:
  Create temporary krb5 configuration for deferring the creation of the final
  krb5.conf on clients
options:
  servers:
    description: Fully qualified name of IPA servers to enroll to
    type: list
    elements: str
    required: yes
  domain:
    description: Primary DNS domain of the IPA deployment
    type: str
    required: yes
  realm:
    description: Kerberos realm name of the IPA deployment
    type: str
    required: yes
  hostname:
    description: Fully qualified name of this host
    type: str
    required: yes
  kdc:
    description: The name or address of the host running the KDC
    type: str
    required: yes
  on_master:
    description: Whether the configuration is done on the master or not
    type: bool
    required: no
    default: no
author:
    - Thomas Woerner (@t-woerner)
'''

EXAMPLES = '''
# Test IPA with local keytab
- name: Test IPA in force mode with maximum 5 kinit attempts
  ipaclient_test_keytab:
    servers: ["server1.example.com","server2.example.com"]
    domain: example.com
    realm: EXAMPLE.COM
    kdc: server1.example.com
    hostname: client1.example.com

# Test IPA with ipadiscovery return values
- name: Join IPA
  ipaclient_test_keytab:
    servers: "{{ ipadiscovery.servers }}"
    domain: "{{ ipadiscovery.domain }}"
    realm: "{{ ipadiscovery.realm }}"
    kdc: "{{ ipadiscovery.kdc }}"
    hostname: "{{ ipadiscovery.hostname }}"
'''

RETURN = '''
krb_name:
  description: The krb5 config file name
  returned: always
  type: str
'''

import os
import tempfile

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.ansible_ipa_client import (
    setup_logging, check_imports, configure_krb5_conf
)


def main():
    module = AnsibleModule(
        argument_spec=dict(
            servers=dict(required=True, type='list', elements='str'),
            domain=dict(required=True, type='str'),
            realm=dict(required=True, type='str'),
            hostname=dict(required=True, type='str'),
            kdc=dict(required=True, type='str'),
            on_master=dict(required=False, type='bool', default=False),
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
    kdc = module.params.get('kdc')
    client_domain = hostname[hostname.find(".") + 1:]

    krb_name = None
    # Create temporary krb5 configuration
    try:
        (krb_fd, krb_name) = tempfile.mkstemp()
        os.close(krb_fd)
        configure_krb5_conf(
            cli_realm=realm,
            cli_domain=domain,
            cli_server=servers,
            cli_kdc=kdc,
            dnsok=False,
            filename=krb_name,
            client_domain=client_domain,
            client_hostname=hostname,
            configure_sssd=True,
            force=False)
    except Exception as ex:
        if krb_name:
            try:
                os.remove(krb_name)
            except OSError:
                module.fail_json(msg="Could not remove %s" % krb_name)
        module.fail_json(
            msg="Failed to create temporary krb5 configuration: %s" % str(ex))

    module.exit_json(changed=False,
                     krb_name=krb_name)


if __name__ == '__main__':
    main()

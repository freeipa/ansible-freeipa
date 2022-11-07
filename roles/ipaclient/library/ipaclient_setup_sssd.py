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
module: ipaclient_setup_sssd
short_description: Setup sssd for IPA client
description:
  Setup sssd for IPA client
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
  on_master:
    description: Whether the configuration is done on the master or not
    type: bool
    required: no
  no_ssh:
    description: Do not configure OpenSSH client
    type: bool
    required: no
  no_sshd:
    description: Do not configure OpenSSH server
    type: bool
    required: no
  no_sudo:
    description: Do not configure SSSD as data source for sudo
    type: bool
    required: no
  all_ip_addresses:
    description:
      All routable IP addresses configured on any interface will be added
      to DNS
    type: bool
    required: no
  fixed_primary:
    description: Configure sssd to use fixed server as primary IPA server
    type: bool
    required: no
  permit:
    description: Disable access rules by default, permit all access
    type: bool
    required: no
  enable_dns_updates:
    description:
      Configures the machine to attempt dns updates when the ip address
      changes
    type: bool
    required: no
  preserve_sssd:
    description: Preserve old SSSD configuration if possible
    type: bool
    required: no
  no_krb5_offline_passwords:
    description:
      Configure SSSD not to store user password when the server is offline
    type: bool
    required: no
author:
    - Thomas Woerner (@t-woerner)
'''

EXAMPLES = '''
- name: Configure SSSD
  ipaclient_setup_sssd:
    servers: ["server1.example.com","server2.example.com"]
    domain: example.com
    realm: EXAMPLE.COM
    hostname: client1.example.com
    no_krb5_offline_passwords: yes
'''

RETURN = '''
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.ansible_ipa_client import (
    setup_logging, check_imports, options, sysrestore, paths,
    configure_sssd_conf, logger
)


def main():
    module = AnsibleModule(
        argument_spec=dict(
            servers=dict(required=True, type='list', elements='str'),
            domain=dict(required=True, type='str'),
            realm=dict(required=True, type='str'),
            hostname=dict(required=True, type='str'),
            on_master=dict(required=False, type='bool'),
            no_ssh=dict(required=False, type='bool'),
            no_sshd=dict(required=False, type='bool'),
            no_sudo=dict(required=False, type='bool'),
            all_ip_addresses=dict(required=False, type='bool'),

            fixed_primary=dict(required=False, type='bool'),
            permit=dict(required=False, type='bool'),
            enable_dns_updates=dict(required=False, type='bool'),
            preserve_sssd=dict(required=False, type='bool'),
            no_krb5_offline_passwords=dict(required=False, type='bool'),
        ),
        supports_check_mode=False,
    )
    # ansible_log = AnsibleModuleLog(module, logger)
    # options.set_logger(ansible_log)

    module._ansible_debug = True
    check_imports(module)
    setup_logging()

    cli_server = module.params.get('servers')
    cli_domain = module.params.get('domain')
    cli_realm = module.params.get('realm')
    hostname = module.params.get('hostname')
    options.on_master = module.params.get('on_master')

    options.no_ssh = module.params.get('no_ssh')
    options.conf_ssh = not options.no_ssh
    options.no_sshd = module.params.get('no_sshd')
    options.conf_sshd = not options.no_sshd
    options.no_sudo = module.params.get('no_sudo')
    options.conf_sudo = not options.no_sudo
    options.all_ip_addresses = module.params.get('all_ip_addresses')

    options.primary = module.params.get('fixed_primary')
    options.permit = module.params.get('permit')
    options.dns_updates = module.params.get('enable_dns_updates')
    options.preserve_sssd = module.params.get('preserve_sssd')

    options.no_krb5_offline_passwords = module.params.get(
        'no_krb5_offline_passwords')
    options.krb5_offline_passwords = not options.no_krb5_offline_passwords

    fstore = sysrestore.FileStore(paths.IPA_CLIENT_SYSRESTORE)
    client_domain = hostname[hostname.find(".") + 1:]

    if configure_sssd_conf(fstore, cli_realm, cli_domain, cli_server,
                           options, client_domain, hostname):
        module.fail_json("configure_sssd_conf failed")
    logger.info("Configured /etc/sssd/sssd.conf")

    module.exit_json(changed=True)


if __name__ == '__main__':
    main()

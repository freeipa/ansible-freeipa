#!/usr/bin/python
# -*- coding: utf-8 -*-

# Authors:
#   Thomas Woerner <twoerner@redhat.com>
#
# Based on ipa-client-install code
#
# Copyright (C) 2018  Red Hat
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
module: ipaclient_setup_krb5
short description: Setup krb5 for IPA client
description:
  Setup krb5 for IPA client
options:
  domain:
    description: Primary DNS domain of the IPA deployment
    required: yes
  servers:
    description: Fully qualified name of IPA servers to enroll to
    required: yes
  realm:
    description: Kerberos realm name of the IPA deployment
    required: yes
  hostname:
    description: Fully qualified name of this host
    required: yes
  kdc:
    description: The name or address of the host running the KDC
    required: yes
  dnsok:
    description: The installer dnsok setting
    required: yes
  client_domain:
    description: Primary DNS domain of the IPA deployment
    required: yes
  sssd:
    description: The installer sssd setting
    required: yes
  force:
    description: Installer force parameter
    required: yes
author:
    - Thomas Woerner
'''

EXAMPLES = '''
# Backup and set hostname
- name: Backup and set hostname
  ipaclient_setup_krb5:
    server:
    domain:
    realm:
    hostname: client1.example.com
'''

RETURN = '''
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.ansible_ipa_client import (
    setup_logging, sysrestore, paths, configure_krb5_conf, logger
)


def main():
    module = AnsibleModule(
        argument_spec=dict(
            domain=dict(required=False, default=None),
            servers=dict(required=False, type='list', default=None),
            realm=dict(required=False, default=None),
            hostname=dict(required=False, default=None),
            kdc=dict(required=False, default=None),
            dnsok=dict(required=False, type='bool', default=False),
            client_domain=dict(required=False, default=None),
            sssd=dict(required=False, type='bool', default=False),
            force=dict(required=False, type='bool', default=False),
            # on_master=dict(required=False, type='bool', default=False),
        ),
        supports_check_mode=True,
    )

    module._ansible_debug = True
    setup_logging()

    servers = module.params.get('servers')
    domain = module.params.get('domain')
    realm = module.params.get('realm')
    hostname = module.params.get('hostname')
    kdc = module.params.get('kdc')
    dnsok = module.params.get('dnsok')
    client_domain = module.params.get('client_domain')
    sssd = module.params.get('sssd')
    force = module.params.get('force')
    # on_master = module.params.get('on_master')

    fstore = sysrestore.FileStore(paths.IPA_CLIENT_SYSRESTORE)

    # if options.on_master:
    #     # If on master assume kerberos is already configured properly.
    #     # Get the host TGT.
    #     try:
    #         kinit_keytab(host_principal, paths.KRB5_KEYTAB, CCACHE_FILE,
    #                      attempts=options.kinit_attempts)
    #         os.environ['KRB5CCNAME'] = CCACHE_FILE
    #     except gssapi.exceptions.GSSError as e:
    #         logger.error("Failed to obtain host TGT: %s", e)
    #         raise ScriptError(rval=CLIENT_INSTALL_ERROR)
    # else:

    # Configure krb5.conf
    fstore.backup_file(paths.KRB5_CONF)
    configure_krb5_conf(
        cli_realm=realm,
        cli_domain=domain,
        cli_server=servers,
        cli_kdc=kdc,
        dnsok=dnsok,
        filename=paths.KRB5_CONF,
        client_domain=client_domain,
        client_hostname=hostname,
        configure_sssd=sssd,
        force=force)

    logger.info(
        "Configured /etc/krb5.conf for IPA realm %s", realm)

    module.exit_json(changed=True)


if __name__ == '__main__':
    main()

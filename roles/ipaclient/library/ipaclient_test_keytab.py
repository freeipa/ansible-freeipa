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
module: ipaclient_test_keytab
short_description:
  Test if the krb5.keytab on the machine is valid and can be used.
description:
  Test if the krb5.keytab on the machine is valid and can be used.
  A temporary krb5.conf file will be generated to not fail on an invalid one.
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
  kinit_attempts:
    description: Repeat the request for host Kerberos ticket X times
    type: int
    default: 5
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
    kinit_attempts: 5

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
krb5_keytab_ok:
  description: The flag describes if krb5.keytab on the host is usable.
  returned: always
  type: bool
ca_crt_exists:
  description: The flag describes if ca.crt exists.
  returned: always
  type: str
krb5_conf_ok:
  description: The flag describes if krb5.conf on the host is usable.
  returned: always
  type: bool
ping_test_ok:
  description: The flag describes if ipa ping test succeded.
  returned: always
  type: bool
'''

import os
import tempfile

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.ansible_ipa_client import (
    setup_logging, check_imports,
    SECURE_PATH, paths, kinit_keytab, run, GSSError, configure_krb5_conf
)


def main():
    module = AnsibleModule(
        argument_spec=dict(
            servers=dict(required=True, type='list', elements='str'),
            domain=dict(required=True, type='str'),
            realm=dict(required=True, type='str'),
            hostname=dict(required=True, type='str'),
            kdc=dict(required=True, type='str'),
            kinit_attempts=dict(required=False, type='int', default=5),
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
    kinit_attempts = module.params.get('kinit_attempts')

    client_domain = hostname[hostname.find(".") + 1:]
    host_principal = 'host/%s@%s' % (hostname, realm)
    sssd = True

    # Remove IPA_DNS_CCACHE remain if it exists
    try:
        os.remove(paths.IPA_DNS_CCACHE)
    except OSError:
        pass

    krb5_keytab_ok = False
    krb5_conf_ok = False
    ping_test_ok = False
    ca_crt_exists = os.path.exists(paths.IPA_CA_CRT)
    env = {'PATH': SECURE_PATH, 'KRB5CCNAME': paths.IPA_DNS_CCACHE}

    # First try: Validate with temporary test krb5.conf that forces
    # 1) no DNS lookups and
    # 2) to load /etc/krb5.conf:
    #
    # [libdefaults]
    # dns_lookup_realm = false
    # dns_lookup_kdc = false
    # include /etc/krb5.conf
    #
    try:
        (krb_fd, krb_name) = tempfile.mkstemp()
        os.close(krb_fd)
        content = "\n".join([
            "[libdefaults]",
            "dns_lookup_realm = false",
            "dns_lookup_kdc = false",
            "include /etc/krb5.conf"
        ])
        with open(krb_name, "w") as outf:
            outf.write(content)
        kinit_keytab(host_principal, paths.KRB5_KEYTAB,
                     paths.IPA_DNS_CCACHE,
                     config=krb_name,
                     attempts=kinit_attempts)
        krb5_keytab_ok = True
        krb5_conf_ok = True

        # Test IPA
        try:
            result = run(["/usr/bin/ipa", "ping"], raiseonerr=False, env=env)
            if result.returncode == 0:
                ping_test_ok = True
        except OSError:
            pass
    except GSSError:
        pass
    finally:
        try:
            os.remove(krb_name)
        except OSError:
            module.fail_json(msg="Could not remove %s" % krb_name)

    # Second try: Validate krb5 keytab with temporary krb5
    # configuration
    if not krb5_conf_ok:
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
                configure_sssd=sssd,
                force=False)

            try:
                kinit_keytab(host_principal, paths.KRB5_KEYTAB,
                             paths.IPA_DNS_CCACHE,
                             config=krb_name,
                             attempts=kinit_attempts)
                krb5_keytab_ok = True

                # Test IPA
                env['KRB5_CONFIG'] = krb_name
                try:
                    result = run(["/usr/bin/ipa", "ping"], raiseonerr=False,
                                 env=env)
                    if result.returncode == 0:
                        ping_test_ok = True
                except OSError:
                    pass

            except GSSError:
                pass

        finally:
            try:
                os.remove(krb_name)
            except OSError:
                module.fail_json(msg="Could not remove %s" % krb_name)
            if os.path.exists(krb_name + ".ipabkp"):
                try:
                    os.remove(krb_name + ".ipabkp")
                except OSError:
                    module.fail_json(
                        msg="Could not remove %s.ipabkp" % krb_name)

    module.exit_json(changed=False,
                     krb5_keytab_ok=krb5_keytab_ok,
                     krb5_conf_ok=krb5_conf_ok,
                     ca_crt_exists=ca_crt_exists,
                     ping_test_ok=ping_test_ok)


if __name__ == '__main__':
    main()

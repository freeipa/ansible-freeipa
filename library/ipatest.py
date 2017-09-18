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
module: ipatest
short description: Test if the krb5.keytab on the machine is valid and can be used.
description:
  Test if the krb5.keytab on the machine is valid and can be used.
  A temporary krb5.conf file will be generated to not fail on an invalid one.
options:
  servers:
    description: The FQDN of the IPA servers to connect to.
    required: true
  domain:
    description: The primary DNS domain of an existing IPA deployment.
    required: true
  realm:
    description: The Kerberos realm of an existing IPA deployment.
    required: true
  hostname:
    description: The hostname of the machine to join (FQDN).
    required: true
  kdc:
    description: The name or address of the host running the KDC.
    required: true
  principal:
    description: The authorized kerberos principal used to join the IPA realm.
    required: false
  kinit_attempts:
    description: Repeat the request for host Kerberos ticket X times.
    required: false
    default: 5
author:
    - Thomas Woerner
'''

EXAMPLES = '''
# Join IPA to get the keytab
- name: Test IPA in force mode with maximum 5 kinit attempts
  ipatest:
    servers: ["server1.example.com","server2.example.com"]
    domain: example.com
    realm: EXAMPLE.COM
    kdc: server1.example.com
    hostname: client1.example.com
    principal: admin
    kinit_attempts: 5

# Join IPA to get the keytab using ipadiscovery return values
- name: Join IPA
  ipajoin:
    servers: "{{ ipadiscovery.servers }}"
    domain: "{{ ipadiscovery.domain }}"
    realm: "{{ ipadiscovery.realm }}"
    kdc: "{{ ipadiscovery.kdc }}"
    hostname: "{{ ipadiscovery.hostname }}"
    principal: admin
'''

RETURN = '''
krb5_keytab_ok:
  description: The flag describes if krb5.keytab on the host is usable.
  returned: always
  type: bool
'''

class Object(object):
    pass
options = Object()

import os
import sys
import gssapi
import tempfile
import inspect

from ansible.module_utils.basic import AnsibleModule
from ipapython.version import NUM_VERSION, VERSION
if NUM_VERSION < 40400:
    raise Exception, "freeipa version '%s' is too old" % VERSION
from ipaplatform.paths import paths
try:
    from ipalib.install.kinit import kinit_keytab
except ImportError:
    from ipapython.ipautil import kinit_keytab
try:
    from ipaclient.install.client import configure_krb5_conf
except ImportError:
    # Create temporary copy of ipa-client-install script (as
    # ipa_client_install.py) to be able to import the script easily and also
    # to remove the global finally clause in which the generated ccache file
    # gets removed. The ccache file will be needed in the next step.
    # This is done in a temporary directory that gets removed right after
    # ipa_client_install has been imported.
    import shutil
    temp_dir = tempfile.mkdtemp(dir="/tmp")
    sys.path.append(temp_dir)
    temp_file = "%s/ipa_client_install.py" % temp_dir

    with open("/usr/sbin/ipa-client-install", "r") as f_in:
        with open(temp_file, "w") as f_out:
            for line in f_in:
                if line.startswith("finally:"):
                    break
                f_out.write(line)
    import ipa_client_install

    shutil.rmtree(temp_dir, ignore_errors=True)
    sys.path.remove(temp_dir)

    argspec = inspect.getargspec(ipa_client_install.configure_krb5_conf)
    if argspec.keywords is None:
        def configure_krb5_conf(
                cli_realm, cli_domain, cli_server, cli_kdc, dnsok,
                filename, client_domain, client_hostname, force,
                configure_sssd):
            global options
            options.force = force
            options.sssd = configure_sssd
            return ipa_client_install.configure_krb5_conf(
                cli_realm, cli_domain, cli_server, cli_kdc, dnsok, options,
                filename, client_domain, client_hostname)
    else:
        configure_krb5_conf = ipa_client_install.configure_krb5_conf
from ipapython.ipautil import realm_to_suffix, run


import logging
logger = logging.getLogger("ipa-client-install")

def main():
    module = AnsibleModule(
        argument_spec = dict(
            servers=dict(required=True, type='list'),
            domain=dict(required=True),
            realm=dict(required=True),
            hostname=dict(required=True),
            kdc=dict(required=True),
            principal=dict(required=False),
            kinit_attempts=dict(required=False, type='int', default=5),
        ),
        supports_check_mode = True,
    )

    module._ansible_debug = True
    servers = module.params.get('servers')
    domain = module.params.get('domain')
    realm = module.params.get('realm')
    hostname = module.params.get('hostname')
    kdc = module.params.get('kdc')
    principal = module.params.get('principal')
    kinit_attempts = module.params.get('kinit_attempts')

    client_domain = hostname[hostname.find(".")+1:]
    host_principal = 'host/%s@%s' % (hostname, realm)
    sssd = True

    krb5_keytab_ok = True
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

        # Obtain the TGT. We do it with the temporary krb5.conf, so that
        # only the KDC we're installing under is contacted.
        # Other KDCs might not have replicated the principal yet.
        # Once we have the TGT, it's usable on any server.
        try:
            kinit_keytab(host_principal, paths.KRB5_KEYTAB,
                         paths.IPA_DNS_CCACHE,
                         config=krb_name,
                         attempts=kinit_attempts)
        except gssapi.exceptions.GSSError as e:
            # failure to get ticket makes it impossible to login and bind
            # from sssd to LDAP, abort installation and rollback changes
            krb5_keytab_ok = False

    finally:
        try:
            os.remove(krb_name)
        except OSError:
            module.fail_json(msg="Could not remove %s" % krb_name)

    module.exit_json(changed=False, krb5_keytab_ok=krb5_keytab_ok)

if __name__ == '__main__':
    main()

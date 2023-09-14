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
module: ipaclient_join
short_description:
  Join a machine to an IPA realm and get a keytab for the host service
  principal
description:
  Join a machine to an IPA realm and get a keytab for the host service
  principal
options:
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
  principal:
    description:
      User Principal allowed to promote replicas and join IPA realm
    type: str
    required: no
  password:
    description: Admin user kerberos password
    type: str
    required: no
  keytab:
    description: Path to backed up keytab from previous enrollment
    type: str
    required: no
  admin_keytab:
    description: The path to a local admin keytab
    type: str
    required: no
  ca_cert_file:
    description:
      A CA certificate to use. Do not acquire the IPA CA certificate via
      automated means
    type: str
    required: no
  force_join:
    description: Force client enrollment even if already enrolled
    type: bool
    required: no
  kinit_attempts:
    description: Repeat the request for host Kerberos ticket X times
    type: int
    required: no
    default: 5
  debug:
    description: Turn on extra debugging
    type: bool
    required: no
  krb_name:
    description: The krb5 config file name
    type: str
    required: yes
author:
    - Thomas Woerner (@t-woerner)
'''

EXAMPLES = '''
# Join IPA to get the keytab
- name: Join IPA in force mode with maximum 5 kinit attempts
  ipaclient_join:
    servers: ["server1.example.com","server2.example.com"]
    realm: EXAMPLE.COM
    basedn: dc=example,dc=com
    hostname: client1.example.com
    principal: admin
    password: MySecretPassword
    force_join: yes
    kinit_attempts: 5
    krb_name: /tmp/tmpkrb5.conf

# Join IPA to get the keytab using ipadiscovery return values
- name: Join IPA
  ipaclient_join:
    servers: "{{ ipadiscovery.servers }}"
    realm: "{{ ipadiscovery.realm }}"
    basedn: "{{ ipadiscovery.basedn }}"
    hostname: "{{ ipadiscovery.hostname }}"
    principal: admin
    password: MySecretPassword
    krb_name: /tmp/tmpkrb5.conf
'''

RETURN = '''
already_joined:
  description: The flag describes if the host is arelady joined.
  returned: always
  type: bool
'''

import os
import tempfile

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.ansible_ipa_client import (
    setup_logging, check_imports,
    SECURE_PATH, sysrestore, paths, options, realm_to_suffix, kinit_keytab,
    GSSError, kinit_password, NUM_VERSION, get_ca_cert, get_ca_certs, errors,
    run
)


def main():
    module = AnsibleModule(
        argument_spec=dict(
            servers=dict(required=True, type='list', elements='str'),
            realm=dict(required=True, type='str'),
            hostname=dict(required=True, type='str'),
            basedn=dict(required=True, type='str'),
            principal=dict(required=False, type='str'),
            password=dict(required=False, type='str', no_log=True),
            keytab=dict(required=False, type='str', no_log=False),
            admin_keytab=dict(required=False, type='str', no_log=False),
            ca_cert_file=dict(required=False, type='str'),
            force_join=dict(required=False, type='bool'),
            kinit_attempts=dict(required=False, type='int', default=5),
            debug=dict(required=False, type='bool'),
            krb_name=dict(required=True, type='str'),
        ),
        supports_check_mode=False,
    )

    module._ansible_debug = True
    check_imports(module)
    setup_logging()

    servers = module.params.get('servers')
    realm = module.params.get('realm')
    hostname = module.params.get('hostname')
    basedn = module.params.get('basedn')
    force_join = module.params.get('force_join')
    principal = module.params.get('principal')
    password = module.params.get('password')
    keytab = module.params.get('keytab')
    admin_keytab = module.params.get('admin_keytab')
    ca_cert_file = module.params.get('ca_cert_file')
    kinit_attempts = module.params.get('kinit_attempts')
    debug = module.params.get('debug')
    krb_name = module.params.get('krb_name')

    if password is not None and keytab is not None:
        module.fail_json(msg="Password and keytab cannot be used together")

    if password is None and admin_keytab is None:
        module.fail_json(msg="Password or admin_keytab is needed")

    nolog = tuple()
    env = {'PATH': SECURE_PATH}
    fstore = sysrestore.FileStore(paths.IPA_CLIENT_SYSRESTORE)
    host_principal = 'host/%s@%s' % (hostname, realm)

    options.ca_cert_file = ca_cert_file
    options.principal = principal
    options.force = False
    options.password = password

    ccache_dir = None
    changed = False
    already_joined = False
    try:
        env['KRB5_CONFIG'] = krb_name
        ccache_dir = tempfile.mkdtemp(prefix='krbcc')
        ccache_name = os.path.join(ccache_dir, 'ccache')
        join_args = [paths.SBIN_IPA_JOIN,
                     "-s", servers[0],
                     "-b", str(realm_to_suffix(realm)),
                     "-h", hostname]
        if debug:
            join_args.append("-d")
            env['XMLRPC_TRACE_CURL'] = 'yes'
        if force_join:
            join_args.append("-f")
        if principal is not None:
            if principal.find('@') == -1:
                principal = '%s@%s' % (principal, realm)
            if admin_keytab:
                join_args.append("-f")
                if not os.path.exists(admin_keytab):
                    module.fail_json(
                        msg="Keytab file could not be found: %s" %
                        admin_keytab)
                try:
                    kinit_keytab(principal,
                                 admin_keytab,
                                 ccache_name,
                                 config=krb_name,
                                 attempts=kinit_attempts)
                except GSSError as e:
                    module.fail_json(
                        msg="Kerberos authentication failed: %s" % str(e))
            else:
                try:
                    kinit_password(principal, password, ccache_name,
                                   config=krb_name)
                except RuntimeError as e:
                    module.fail_json(
                        msg="Kerberos authentication failed: {0}".format(e))

        elif keytab:
            join_args.append("-f")
            if os.path.exists(keytab):
                try:
                    kinit_keytab(host_principal,
                                 keytab,
                                 ccache_name,
                                 config=krb_name,
                                 attempts=kinit_attempts)
                except GSSError as e:
                    module.fail_json(
                        msg="Kerberos authentication failed: {0}".format(e))
            else:
                module.fail_json(
                    msg="Keytab file could not be found: {0}".format(keytab))

        elif password:
            join_args.append("-w")
            join_args.append(password)
            nolog = (password,)

        env['KRB5CCNAME'] = os.environ['KRB5CCNAME'] = ccache_name
        # Get the CA certificate
        try:
            os.environ['KRB5_CONFIG'] = env['KRB5_CONFIG']
            if NUM_VERSION < 40100:
                get_ca_cert(fstore, options, servers[0], basedn)
            else:
                get_ca_certs(fstore, options, servers[0], basedn, realm)
            os.environ.pop('KRB5_CONFIG', None)
        except errors.FileError as e:
            module.fail_json(msg='%s' % e)
        except Exception as e:
            module.fail_json(msg="Cannot obtain CA certificate\n%s" % e)

        # Now join the domain
        result = run(
            join_args, raiseonerr=False, env=env, nolog=nolog,
            capture_error=True)
        stderr = result.error_output

        if result.returncode != 0:
            if result.returncode == 13:
                already_joined = True
                module.log("Host is already joined")
            else:
                if principal:
                    run([paths.KDESTROY], raiseonerr=False, env=env)
                module.fail_json(msg="Joining realm failed: %s" % stderr)
        else:
            changed = True
            module.log("Enrolled in IPA realm %s" % realm)

        # Fail for missing krb5.keytab on already joined host
        if already_joined and not os.path.exists(paths.KRB5_KEYTAB):
            module.fail_json(msg="krb5.keytab missing! Retry with "
                             "ipaclient_force_join=yes to generate a new one.")

        if principal:
            run([paths.KDESTROY], raiseonerr=False, env=env)

        # Obtain the TGT. We do it with the temporary krb5.conf, sot
        # tha only the KDC we're installing under is contacted.
        # Other KDCs might not have replicated the principal yet.
        # Once we have the TGT, it's usable on any server.
        try:
            kinit_keytab(host_principal, paths.KRB5_KEYTAB,
                         paths.IPA_DNS_CCACHE,
                         config=krb_name,
                         attempts=kinit_attempts)
        except GSSError as e:
            # failure to get ticket makes it impossible to login and
            # bind from sssd to LDAP, abort installation
            module.fail_json(msg="Failed to obtain host TGT: %s" % e)

    finally:
        if ccache_dir is not None:
            try:
                os.rmdir(ccache_dir)
            except OSError:
                pass

    module.exit_json(changed=changed,
                     already_joined=already_joined)


if __name__ == '__main__':
    main()

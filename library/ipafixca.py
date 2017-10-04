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
module: ipaapi
short description: Fix IPA ca certificate
description:
Repair Fix IPA ca certificate
options:
  servers:
    description: The FQDN of the IPA servers to connect to.
    required: false
  realm:
    description: The Kerberos realm of an existing IPA deployment.
    required: true
  basedn:
    description: The basedn of the IPA server (of the form dc=example,dc=com).
    required: true
  allow_repair:
    deescription: Allow repair of already joined hosts. Contrary to ipaclient_force_join the host entry will not be changed on the server.
    required: true
    type: boolean
author:
    - Thomas Woerner
'''

EXAMPLES = '''
- name: Fix IPA ca certificate
  ipafixca:
    servers: ["server1.example.com","server2.example.com"]
    realm: EXAMPLE.COM
    basedn: dc=example,dc=com
    allow_repair: yes
'''

RETURN = '''
'''

iclass Object(object):
    pass
options = Object()

import os
import sys
import tempfile
import inspect

from ansible.module_utils.basic import AnsibleModule
from ipapython.version import NUM_VERSION, VERSION
if NUM_VERSION < 40400:
    raise Exception("freeipa version '%s' is too old" % VERSION)
from ipalib import errors
from ipaplatform.paths import paths
try:
    from ipalib.install import sysrestore
except ImportError:
    from ipapython import sysrestore
try:
    from ipaclient.install.client import get_ca_certs, SECURE_PATH
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

    if NUM_VERSION < 40100:
        get_ca_cert = ipa_client_install.get_ca_cert
    else:
        get_ca_certs = ipa_client_install.get_ca_certs
    SECURE_PATH = ("/bin:/sbin:/usr/kerberos/bin:/usr/kerberos/sbin:/usr/bin:/usr/sbin")

    
def main():
    module = AnsibleModule(
        argument_spec = dict(
            servers=dict(required=True, type='list'),
            realm=dict(required=True),
            basedn=dict(required=True),
            allow_repair=dict(required=True, type='bool'),
        ),
    )

    module._ansible_debug = True
    servers = module.params.get('servers')
    realm = module.params.get('realm')
    basedn = module.params.get('basedn')
    allow_repair = module.params.get('allow_repair')

    env = {'PATH': SECURE_PATH}
    fstore = sysrestore.FileStore(paths.IPA_CLIENT_SYSRESTORE)
    os.environ['KRB5CCNAME'] = paths.IPA_DNS_CCACHE

    options.ca_cert_file = None
    options.unattended = True
    options.principal = None
    options.force = False
    options.password = None

    changed = False
    if not os.path.exists(paths.IPA_CA_CRT):
        if not allow_repair:
            module.fail_json(msg="%s missing, enable allow_repair to fix it." % paths.IPA_CA_CRT)
        
        # Repair missing ca.crt file

        from ipaclient.install.client import get_ca_certs

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

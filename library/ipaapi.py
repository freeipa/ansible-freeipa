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
short description: Create temporary NSS database, call IPA API for remaining enrollment parts
description:
Create temporary NSS database, call IPA API for remaining enrollment parts
options:
  servers:
    description: The FQDN of the IPA servers to connect to.
    required: false
  realm:
    description: The Kerberos realm of an existing IPA deployment.
    required: true
  hostname:
    description: The hostname of the machine to join (FQDN).
    required: true
  debug:
    description: Turn on extra debugging
    required: false
author:
    - Thomas Woerner
'''

EXAMPLES = '''
- name: IPA API calls for remaining enrollment parts
  ipaapi:
    servers: ["server1.example.com","server2.example.com"]
    domain: example.com
    hostname: client1.example.com
  register: ipaapi
'''

RETURN = '''
ca_enabled:
  description: Wheter the Certificate Authority is enabled or not.
  returned: always
  type: bool
subject_base:
  description: The subject base, needed for certmonger
  returned: always
  type: string
  sample: O=EXAMPLE.COM
'''

import os
import sys
import time
import gssapi
import tempfile
import inspect

from ansible.module_utils.basic import AnsibleModule
from ipapython.version import NUM_VERSION, VERSION
if NUM_VERSION < 40400:
    raise Exception, "freeipa version '%s' is too old" % VERSION
from ipaplatform.paths import paths
if NUM_VERSION >= 40500 and NUM_VERSION < 40590:
    from cryptography.hazmat.primitives import serialization
from ipalib import api, errors, x509
try:
    from ipalib.install import sysrestore
except ImportError:
    from ipapython import sysrestore
from ipalib.rpc import delete_persistent_client_session_data
from ipapython import certdb
from ipapython.ipautil import CalledProcessError, write_tmp_file, \
    ipa_generate_password
from ipapython.dn import DN
ipa_client_install = None
try:
    from ipaclient.install.client import SECURE_PATH, disable_ra
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

    SECURE_PATH = ("/bin:/sbin:/usr/kerberos/bin:/usr/kerberos/sbin:/usr/bin:/usr/sbin")
    disable_ra = ipa_client_install.disable_ra


def main():
    module = AnsibleModule(
        argument_spec = dict(
            servers=dict(required=True, type='list'),
            realm=dict(required=True),
            hostname=dict(required=True),
            debug=dict(required=False, type='bool', default="false")
        ),
        supports_check_mode = True,
    )

    module._ansible_debug = True
    realm = module.params.get('realm')
    hostname = module.params.get('hostname')
    servers = module.params.get('servers')
    debug = module.params.get('debug')

    fstore = sysrestore.FileStore(paths.IPA_CLIENT_SYSRESTORE)
    statestore = sysrestore.StateFile(paths.IPA_CLIENT_SYSRESTORE)
    host_principal = 'host/%s@%s' % (hostname, realm)
    os.environ['KRB5CCNAME'] = paths.IPA_DNS_CCACHE
    
    ca_certs = x509.load_certificate_list_from_file(paths.IPA_CA_CRT)
    if NUM_VERSION >= 40500 and NUM_VERSION < 40590:
        ca_certs = [ cert.public_bytes(serialization.Encoding.DER)
                     for cert in ca_certs ]
    elif NUM_VERSION < 40500:
        ca_certs = [ cert.der_data for cert in ca_certs ]

    with certdb.NSSDatabase() as tmp_db:
        api.bootstrap(context='cli_installer',
                      confdir=paths.ETC_IPA,
                      debug=debug,
                      delegate=False,
                      nss_dir=tmp_db.secdir)

        if 'config_loaded' not in api.env:
            module.fail_json(msg="Failed to initialize IPA API.")

        # Clear out any current session keyring information
        try:
            delete_persistent_client_session_data(host_principal)
        except ValueError:
            pass

        # Add CA certs to a temporary NSS database
        argspec = inspect.getargspec(tmp_db.create_db)
        try:
            if NUM_VERSION > 40400:
                tmp_db.create_db()

                for i, cert in enumerate(ca_certs):
                    tmp_db.add_cert(cert,
                                    'CA certificate %d' % (i + 1),
                                    certdb.EXTERNAL_CA_TRUST_FLAGS)
            else:
                pwd_file = write_tmp_file(ipa_generate_password())
                tmp_db.create_db(pwd_file.name)

                for i, cert in enumerate(ca_certs):
                    tmp_db.add_cert(cert, 'CA certificate %d' % (i + 1), 'C,,')
        except CalledProcessError as e:
            module.fail_json(msg="Failed to add CA to temporary NSS database.")

        api.finalize()

        # Now, let's try to connect to the server's RPC interface
        connected = False
        try:
            api.Backend.rpcclient.connect()
            connected = True
            module.debug("Try RPC connection")
            api.Backend.rpcclient.forward('ping')
        except errors.KerberosError as e:
            if connected:
                api.Backend.rpcclient.disconnect()
            module.log(
                "Cannot connect to the server due to Kerberos error: %s. "
                "Trying with delegate=True" % e)
            try:
                api.Backend.rpcclient.connect(delegate=True)
                module.debug("Try RPC connection")
                api.Backend.rpcclient.forward('ping')

                module.log("Connection with delegate=True successful")

                # The remote server is not capable of Kerberos S4U2Proxy
                # delegation. This features is implemented in IPA server
                # version 2.2 and higher
                module.warn(
                    "Target IPA server has a lower version than the enrolled "
                    "client")
                module.warn(
                    "Some capabilities including the ipa command capability "
                    "may not be available")
            except errors.PublicError as e2:
                module.fail_json(
                    msg="Cannot connect to the IPA server RPC interface: %s" % e2)
        except errors.PublicError as e:
            module.fail_json(
                msg="Cannot connect to the server due to generic error: %s" % e)
    # Use the RPC directly so older servers are supported
    try:
        result = api.Backend.rpcclient.forward(
            'ca_is_enabled',
            version=u'2.107',
        )
        ca_enabled = result['result']
    except (errors.CommandError, errors.NetworkError):
        result = api.Backend.rpcclient.forward(
            'env',
            server=True,
            version=u'2.0',
        )
        ca_enabled = result['result']['enable_ra']
    if not ca_enabled:
        disable_ra()

    # Get subject base from ipa server
    try:
        config = api.Command['config_show']()['result']
        subject_base = str(DN(config['ipacertificatesubjectbase'][0]))
    except errors.PublicError as e:
        module.fail_json(msg="Cannot get subject base from server: %s" % e)

    module.exit_json(changed=True,
                     ca_enabled=ca_enabled,
                     subject_base=subject_base)

if __name__ == '__main__':
    main()

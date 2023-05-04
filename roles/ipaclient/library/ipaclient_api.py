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

ANSIBLE_METADATA = {'metadata_version': '1.0',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
---
module: ipaclient_api
short_description:
  Create temporary NSS database, call IPA API for remaining enrollment parts
description:
  Create temporary NSS database, call IPA API for remaining enrollment parts
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
  debug:
    description: Turn on extra debugging
    type: bool
    required: no
    default: no
  krb_name:
    description: The krb5 config file name
    type: str
    required: yes
author:
    - Thomas Woerner (@t-woerner)
'''

EXAMPLES = '''
- name: IPA API calls for remaining enrollment parts
  ipaclient_api:
    servers: ["server1.example.com","server2.example.com"]
    domain: example.com
    hostname: client1.example.com
    krb_name: /tmp/tmpkrb5.conf
  register: result_ipaclient_api
'''

RETURN = '''
ca_enabled:
  description: Wheter the Certificate Authority is enabled or not.
  returned: always
  type: bool
subject_base:
  description: The subject base, needed for certmonger
  returned: always
  type: str
  sample: O=EXAMPLE.COM
'''

import os

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.ansible_ipa_client import (
    setup_logging, check_imports,
    paths, x509, NUM_VERSION, serialization, certdb, api,
    delete_persistent_client_session_data, write_tmp_file,
    ipa_generate_password, CalledProcessError, errors, disable_ra, DN,
    CLIENT_INSTALL_ERROR, logger, getargspec
)


def main():
    module = AnsibleModule(
        argument_spec=dict(
            servers=dict(required=True, type='list', elements='str'),
            realm=dict(required=True, type='str'),
            hostname=dict(required=True, type='str'),
            debug=dict(required=False, type='bool', default="false"),
            krb_name=dict(required=True, type='str'),
        ),
        supports_check_mode=False,
    )

    module._ansible_debug = True
    check_imports(module)
    setup_logging()

    realm = module.params.get('realm')
    hostname = module.params.get('hostname')
    debug = module.params.get('debug')
    krb_name = module.params.get('krb_name')

    host_principal = 'host/%s@%s' % (hostname, realm)
    os.environ['KRB5CCNAME'] = paths.IPA_DNS_CCACHE
    os.environ['KRB5_CONFIG'] = krb_name

    ca_certs = x509.load_certificate_list_from_file(paths.IPA_CA_CRT)
    if 40500 <= NUM_VERSION < 40590:
        ca_certs = [cert.public_bytes(serialization.Encoding.DER)
                    for cert in ca_certs]
    elif NUM_VERSION < 40500:
        ca_certs = [cert.der_data for cert in ca_certs]

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
        try:
            # pylint: disable=deprecated-method
            argspec = getargspec(tmp_db.create_db)
            # pylint: enable=deprecated-method
            if "password_filename" not in argspec.args:
                tmp_db.create_db()
            else:
                pwd_file = write_tmp_file(ipa_generate_password())
                tmp_db.create_db(pwd_file.name)
            for i, cert in enumerate(ca_certs):
                if hasattr(certdb, "EXTERNAL_CA_TRUST_FLAGS"):
                    tmp_db.add_cert(cert,
                                    'CA certificate %d' % (i + 1),
                                    certdb.EXTERNAL_CA_TRUST_FLAGS)
                else:
                    tmp_db.add_cert(cert, 'CA certificate %d' % (i + 1),
                                    'C,,')
        except CalledProcessError:
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
            except errors.PublicError as e2:  # pylint: disable=invalid-name
                module.fail_json(
                    msg="Cannot connect to the IPA server RPC interface: "
                    "%s" % e2)
        except errors.PublicError as e:
            module.fail_json(
                msg="Cannot connect to the server due to generic error: "
                "%s" % e)
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
    except errors.PublicError:
        try:
            config = api.Backend.rpcclient.forward(
                'config_show',
                raw=True,  # so that servroles are not queried
                version=u'2.0'
            )['result']
        except Exception as e:
            logger.debug("config_show failed %s", e, exc_info=True)
            module.fail_json(
                "Failed to retrieve CA certificate subject base: "
                "{0}".format(e),
                rval=CLIENT_INSTALL_ERROR)
        else:
            subject_base = str(DN(config['ipacertificatesubjectbase'][0]))

    module.exit_json(changed=True,
                     ca_enabled=ca_enabled,
                     subject_base=subject_base)


if __name__ == '__main__':
    main()

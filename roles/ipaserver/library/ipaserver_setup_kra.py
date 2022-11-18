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
module: ipaserver_setup_kra
short_description: Setup KRA
description: Setup KRA
options:
  dm_password:
    description: Directory Manager password
    type: str
    required: yes
  hostname:
    description: Fully qualified name of this host
    type: str
    required: yes
  setup_ca:
    description: Configure a dogtag CA
    type: bool
    required: yes
  setup_kra:
    description: Configure a dogtag KRA
    type: bool
    required: yes
  realm:
    description: Kerberos realm name of the IPA deployment
    type: str
    required: yes
  pki_config_override:
    description: Path to ini file with config overrides
    type: str
    required: no
author:
    - Thomas Woerner (@t-woerner)
'''

EXAMPLES = '''
'''

RETURN = '''
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.ansible_ipa_server import (
    check_imports, AnsibleModuleLog, setup_logging, options,
    api_Backend_ldap2, redirect_stdout, api, custodiainstance, kra
)


def main():
    ansible_module = AnsibleModule(
        argument_spec=dict(
            # basic
            dm_password=dict(required=True, type='str', no_log=True),
            hostname=dict(required=True, type='str'),
            setup_ca=dict(required=True, type='bool'),
            setup_kra=dict(required=True, type='bool'),
            realm=dict(required=True, type='str'),
            pki_config_override=dict(required=False, type='str'),
        ),
    )

    ansible_module._ansible_debug = True
    check_imports(ansible_module)
    setup_logging()
    ansible_log = AnsibleModuleLog(ansible_module)

    # set values ####################################################

    options.dm_password = ansible_module.params.get('dm_password')
    options.host_name = ansible_module.params.get('hostname')
    options.setup_ca = ansible_module.params.get('setup_ca')
    options.setup_kra = ansible_module.params.get('setup_kra')
    options.realm_name = ansible_module.params.get('realm')
    options.pki_config_override = ansible_module.params.get(
        'pki_config_override')
    options.promote = False  # first master, no promotion

    # init ##########################################################

    api_Backend_ldap2(options.host_name, options.setup_ca, connect=True)

    # setup kra #####################################################

    with redirect_stdout(ansible_log):
        if hasattr(custodiainstance, "get_custodia_instance"):
            if hasattr(custodiainstance.CustodiaModes, "FIRST_MASTER"):
                mode = custodiainstance.CustodiaModes.FIRST_MASTER
            else:
                mode = custodiainstance.CustodiaModes.MASTER_PEER
            custodia = custodiainstance.get_custodia_instance(options, mode)

            kra.install(api, None, options, custodia=custodia)
        else:
            kra.install(api, None, options)

    # done ##########################################################

    ansible_module.exit_json(changed=True)


if __name__ == '__main__':
    main()

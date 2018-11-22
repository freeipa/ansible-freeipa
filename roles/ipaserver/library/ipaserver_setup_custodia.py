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

from __future__ import print_function

ANSIBLE_METADATA = {
    'metadata_version': '1.0',
    'supported_by': 'community',
    'status': ['preview'],
}

DOCUMENTATION = '''
---
module: ipaserver_setup_custodia
short description: 
description:
options:
  realm:
  hostname:
  setup_ca:
author:
    - Thomas Woerner
'''

EXAMPLES = '''
'''

RETURN = '''
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.ansible_ipa_server import *

def main():
    ansible_module = AnsibleModule(
        argument_spec = dict(
            # basic
            realm=dict(required=True),
            hostname=dict(required=False),
            setup_ca=dict(required=False, type='bool', default=False),
        ),
    )

    ansible_module._ansible_debug = True
    ansible_log = AnsibleModuleLog(ansible_module)

    # set values ############################################################

    options.realm_name = ansible_module.params.get('realm')
    options.host_name = ansible_module.params.get('hostname')
    options.setup_ca = ansible_module.params.get('setup_ca')
    options.promote = False

    # init ##################################################################

    fstore = sysrestore.FileStore(paths.SYSRESTORE)

    api_Backend_ldap2(options.host_name, options.setup_ca, connect=True)

    # setup custodia ########################################################

    if hasattr(custodiainstance, "get_custodia_instance"):
        if hasattr(custodiainstance.CustodiaModes, "FIRST_MASTER"):
            mode = custodiainstance.CustodiaModes.FIRST_MASTER
        else:
            mode = custodiainstance.CustodiaModes.MASTER_PEER
        custodia = custodiainstance.get_custodia_instance(options, mode)
    else:
        custodia = custodiainstance.CustodiaInstance(options.host_name,
                                                     options.realm_name)
    custodia.set_output(ansible_log)
    with redirect_stdout(ansible_log):
        custodia.create_instance()

    # done ##################################################################

    ansible_module.exit_json(changed=True)

if __name__ == '__main__':
    main()

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
module: setup_adtrust
short description: 
description:
options:
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
            hostname=dict(required=False),
            setup_ca=dict(required=True, type='bool', default=False),
            setup_adtrust=dict(required=True, type='bool', default=False),
        ),
    )

    ansible_module._ansible_debug = True
    ansible_log = AnsibleModuleLog(ansible_module)

    # set values ####################################################

    options.host_name = ansible_module.params.get('hostname')
    options.setup_ca = ansible_module.params.get('setup_ca')
    options.setup_adtrust = ansible_module.params.get('setup_adtrust')

    # init ##########################################################

    fstore = sysrestore.FileStore(paths.SYSRESTORE)
    sstore = sysrestore.StateFile(paths.SYSRESTORE)

    api_Backend_ldap2_connect(options.host_name, options.setup_ca)

    # setup ds ######################################################

    with redirect_stdout(ansible_log):
        adtrust.install(False, options, fstore, api)

    # done ##########################################################

    ansible_module.exit_json(changed=True)

if __name__ == '__main__':
    main()

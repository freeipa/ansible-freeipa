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
module: ipaserver_setup_adtrust
short_description: Setup trust ad
description: Setup trust ad
options:
  hostname:
    description: Fully qualified name of this host
    type: str
    required: no
  setup_ca:
    description: Configure a dogtag CA
    type: bool
    default: no
    required: no
  setup_adtrust:
    description: Configure AD trust capability
    type: bool
    default: no
    required: no
  enable_compat:
    description: Enable support for trusted domains for old clients
    type: bool
    default: no
    required: no
  rid_base:
    description: Start value for mapping UIDs and GIDs to RIDs
    type: int
    required: no
  secondary_rid_base:
    description:
      Start value of the secondary range for mapping UIDs and GIDs to RIDs
    type: int
    required: no
  adtrust_netbios_name:
    description: The adtrust netbios_name setting
    type: str
    required: yes
  adtrust_reset_netbios_name:
    description: The adtrust reset_netbios_name setting
    type: bool
    required: yes
author:
    - Thomas Woerner (@t-woerner)
'''

EXAMPLES = '''
'''

RETURN = '''
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.ansible_ipa_server import (
    check_imports, AnsibleModuleLog, setup_logging, options, sysrestore, paths,
    api_Backend_ldap2, redirect_stdout, adtrust, api
)


def main():
    ansible_module = AnsibleModule(
        argument_spec=dict(
            # basic
            hostname=dict(required=False, type='str'),
            setup_ca=dict(required=False, type='bool', default=False),
            setup_adtrust=dict(required=False, type='bool', default=False),
            # ad trust
            enable_compat=dict(required=False, type='bool', default=False),
            rid_base=dict(required=False, type='int'),
            secondary_rid_base=dict(required=False, type='int'),
            # additional
            adtrust_netbios_name=dict(required=True, type='str'),
            adtrust_reset_netbios_name=dict(required=True, type='bool'),
        ),
    )

    ansible_module._ansible_debug = True
    check_imports(ansible_module)
    setup_logging()
    ansible_log = AnsibleModuleLog(ansible_module)

    # set values ####################################################

    options.host_name = ansible_module.params.get('hostname')
    options.setup_ca = ansible_module.params.get('setup_ca')
    options.setup_adtrust = ansible_module.params.get('setup_adtrust')
    # ad trust
    options.enable_compat = ansible_module.params.get('enable_compat')
    options.rid_base = ansible_module.params.get('rid_base')
    options.secondary_rid_base = ansible_module.params.get(
        'secondary_rid_base')
    # additional
    adtrust.netbios_name = ansible_module.params.get('adtrust_netbios_name')
    adtrust.reset_netbios_name = ansible_module.params.get(
        'adtrust_reset_netbios_name')

    # init ##########################################################

    fstore = sysrestore.FileStore(paths.SYSRESTORE)

    api_Backend_ldap2(options.host_name, options.setup_ca, connect=True)

    # setup ds ######################################################

    with redirect_stdout(ansible_log):
        adtrust.install(False, options, fstore, api)

    # done ##########################################################

    ansible_module.exit_json(changed=True)


if __name__ == '__main__':
    main()

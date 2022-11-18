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
module: ipaserver_setup_otpd
short_description: Setup OTPD
description: Setup OTPD
options:
  realm:
    description: Kerberos realm name of the IPA deployment
    type: str
    required: yes
  hostname:
    description: Fully qualified name of this host
    type: str
    required: no
  setup_ca:
    description: Configure a dogtag CA
    type: bool
    default: no
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
    api_Backend_ldap2, redirect_stdout, otpdinstance, ipautil
)


def main():
    ansible_module = AnsibleModule(
        argument_spec=dict(
            # basic
            realm=dict(required=True, type='str'),
            hostname=dict(required=False, type='str'),
            setup_ca=dict(required=False, type='bool', default=False),
        ),
    )

    ansible_module._ansible_debug = True
    check_imports(ansible_module)
    setup_logging()
    ansible_log = AnsibleModuleLog(ansible_module)

    # set values ####################################################

    options.realm_name = ansible_module.params.get('realm')
    options.host_name = ansible_module.params.get('hostname')
    options.setup_ca = ansible_module.params.get('setup_ca')

    # init ##########################################################

    api_Backend_ldap2(options.host_name, options.setup_ca, connect=True)

    # setup ds ######################################################

    otpd = otpdinstance.OtpdInstance()
    otpd.set_output(ansible_log)
    with redirect_stdout(ansible_log):
        otpd.create_instance('OTPD', options.host_name,
                             ipautil.realm_to_suffix(options.realm_name))

    # done ##########################################################

    ansible_module.exit_json(changed=True)


if __name__ == '__main__':
    main()

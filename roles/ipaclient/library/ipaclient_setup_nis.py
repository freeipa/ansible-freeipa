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
module: ipaclient_setup_nis
short description: Setup NIS for IPA client
description:
  Setup NIS for IPA client
options:
  domain:
    description: Primary DNS domain of the IPA deployment
    required: no
  nisdomain:
    description: The NIS domain name
    required: yes
author:
    - Thomas Woerner
'''

EXAMPLES = '''
- name: Setup NIS for IPA client
  ipaclient_setup_nis:
    domain: example.com
'''

RETURN = '''
'''

import inspect

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.ansible_ipa_client import (
    setup_logging, options, sysrestore, paths, configure_nisdomain
)


def main():
    module = AnsibleModule(
        argument_spec=dict(
            domain=dict(required=True),
            nisdomain=dict(required=False),
        ),
        supports_check_mode=True,
    )

    module._ansible_debug = True
    setup_logging()

    domain = module.params.get('domain')
    options.nisdomain = module.params.get('nisdomain')

    statestore = sysrestore.StateFile(paths.IPA_CLIENT_SYSRESTORE)

    argspec = inspect.getargspec(configure_nisdomain)
    if "statestore" not in argspec.args:
        # NUM_VERSION < 40500:
        configure_nisdomain(options=options, domain=domain)
    else:
        configure_nisdomain(options=options, domain=domain,
                            statestore=statestore)

    module.exit_json(changed=True)


if __name__ == '__main__':
    main()

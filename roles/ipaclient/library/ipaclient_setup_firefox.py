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
module: ipaclient_setup_firefox
short_description: Setup firefox for IPA client
description:
  Setup firefox for IPA client
options:
  domain:
    description: Primary DNS domain of the IPA deployment
    type: str
    required: yes
  firefox_dir:
    description:
      Specify directory where Firefox is installed (for example
      '/usr/lib/firefox')
    type: str
    required: no
author:
    - Thomas Woerner (@t-woerner)
'''

EXAMPLES = '''
- name: Setup firefox for IPA client
  ipaclient_setup_firefox:
    servers: ["server1.example.com","server2.example.com"]
    domain: example.com
    firefox_dir: /usr/lib/firefox
'''

RETURN = '''
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.ansible_ipa_client import (
    setup_logging, check_imports, sysrestore, paths, options, configure_firefox
)


def main():
    module = AnsibleModule(
        argument_spec=dict(
            domain=dict(required=True, type='str'),
            firefox_dir=dict(required=False, type='str'),
        ),
        supports_check_mode=False,
    )

    module._ansible_debug = True
    check_imports(module)
    setup_logging()

    domain = module.params.get('domain')
    options.firefox_dir = module.params.get('firefox_dir')

    statestore = sysrestore.StateFile(paths.IPA_CLIENT_SYSRESTORE)

    configure_firefox(options, statestore, domain)

    module.exit_json(changed=True)


if __name__ == '__main__':
    main()

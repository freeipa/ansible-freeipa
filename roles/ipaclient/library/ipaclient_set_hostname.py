#!/usr/bin/python
# -*- coding: utf-8 -*-

# Authors:
#   Thomas Woerner <twoerner@redhat.com>
#
# Based on ipa-client-install code
#
# Copyright (C) 2018  Red Hat
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
module: ipaclient_set_hostname
short description: Backup and set hostname
description:
  Backup and set hostname
options:
  hostname:
    description: Fully qualified name of this host
    required: no
author:
    - Thomas Woerner
'''

EXAMPLES = '''
# Backup and set hostname
- name: Backup and set hostname
  ipaclient_set_hostname:
    hostname: client1.example.com
'''

RETURN = '''
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.ansible_ipa_client import (
    setup_logging, sysrestore, paths, tasks
)


def main():
    module = AnsibleModule(
        argument_spec=dict(
            hostname=dict(required=True),
        ),
        supports_check_mode=True,
    )

    module._ansible_debug = True
    setup_logging()

    hostname = module.params.get('hostname')

    fstore = sysrestore.FileStore(paths.IPA_CLIENT_SYSRESTORE)
    statestore = sysrestore.StateFile(paths.IPA_CLIENT_SYSRESTORE)

    tasks.backup_hostname(fstore, statestore)
    tasks.set_hostname(hostname)

    module.exit_json(changed=True)


if __name__ == '__main__':
    main()

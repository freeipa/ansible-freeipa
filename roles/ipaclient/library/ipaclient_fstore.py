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
module: ipaclient_fstore
short_description: Backup files using IPA client sysrestore
description: Backup files using IPA client sysrestore
options:
  backup:
    description: File to backup
    type: str
    required: yes
author:
    - Thomas Woerner (@t-woerner)
'''

EXAMPLES = '''
- name: Backup /etc/krb5.conf
  ipaclient_fstore:
    backup: "/etc/krb5.conf"
'''

RETURN = '''
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.ansible_ipa_client import (
    setup_logging, check_imports, paths, sysrestore
)


def main():
    module = AnsibleModule(
        argument_spec=dict(
            backup=dict(required=True, type='str'),
        ),
    )

    module._ansible_debug = True
    check_imports(module)
    setup_logging()

    backup = module.params.get('backup')

    fstore = sysrestore.FileStore(paths.IPA_CLIENT_SYSRESTORE)
    if not fstore.has_file(backup):
        fstore.backup_file(backup)
        module.exit_json(changed=True)

    module.exit_json(changed=False)


if __name__ == '__main__':
    main()

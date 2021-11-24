#!/usr/bin/python
# -*- coding: utf-8 -*-

# Authors:
#   Thomas Woerner <twoerner@redhat.com>
#
# Copyright (C) 2021  Red Hat
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
module: ipabackup_get_backup_dir
short description:
  Get IPA_BACKUP_DIR from ipaplatform
description:
  Get IPA_BACKUP_DIR from ipaplatform
options:
author:
    - Thomas Woerner
'''

EXAMPLES = '''
# Get IPA_BACKUP_DIR from ipaplatform
- name: ipabackup_get_backup_dir:
  register result
'''

RETURN = '''
backup_dir:
  description: IPA_BACKUP_DIR from ipaplatform
  returned: always
  type: str
'''

from ansible.module_utils.basic import AnsibleModule
from ipaplatform.paths import paths


def main():
    module = AnsibleModule(
        argument_spec=dict(),
        supports_check_mode=True,
    )

    module.exit_json(changed=False,
                     backup_dir=paths.IPA_BACKUP_DIR)


if __name__ == '__main__':
    main()

# -*- coding: utf-8 -*-

# Authors:
#   Thomas Woerner <twoerner@redhat.com>
#
# Copyright (C) 2022  Red Hat
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
module: ipasmartcard_client_get_vars
short_description:
  Get variables from ipaplatform and python interpreter used for the module.
description:
  Get variables from ipaplatform and python interpreter used for the module.
author:
    - Thomas Woerner (@t-woerner)
'''

EXAMPLES = '''
- name: Get VARS from IPA
  ipasmartcard_client_get_vars:
  register: ipasmartcard_client_vars
'''

RETURN = '''
NSS_DB_DIR:
  description: paths.NSS_DB_DIR from ipaplatform
  returned: always
  type: str
USE_AUTHSELECT:
  description: True if "AUTHSELECT" is defined in paths
  returned: always
  type: bool
python_interpreter:
  description: Python interpreter from sys.executable
  returned: always
  type: str
'''

import sys
from ansible.module_utils.basic import AnsibleModule
try:
    from ipaplatform.paths import paths
except ImportError as _err:
    MODULE_IMPORT_ERROR = str(_err)
    paths = None
else:
    MODULE_IMPORT_ERROR = None


def main():
    ansible_module = AnsibleModule(
        argument_spec={},
        supports_check_mode=False,
    )

    if MODULE_IMPORT_ERROR is not None:
        ansible_module.fail_json(msg=MODULE_IMPORT_ERROR)

    ansible_module.exit_json(changed=False,
                             NSS_DB_DIR=paths.NSS_DB_DIR,
                             USE_AUTHSELECT=hasattr(paths, "AUTHSELECT"),
                             python_interpreter=sys.executable)


if __name__ == '__main__':
    main()

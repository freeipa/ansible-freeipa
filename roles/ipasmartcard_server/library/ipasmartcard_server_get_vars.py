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
module: ipasmartcard_server_get_vars
short_description:
  Get variables from ipaplatform and ipaserver and python interpreter.
description:
  Get variables from ipaplatform and ipaserver and python interpreter.
author:
    - Thomas Woerner (@t-woerner)
'''

EXAMPLES = '''
- name: Get VARS from IPA
  ipasmartcard_server_get_vars:
  register: ipasmartcard_server_vars
'''

RETURN = '''
NSS_OCSP_ENABLED:
  description:
    Empty string for newer systems using ssl.conf and not nss.conf for
    HTTP instance where OCSP_ENABLED and OCSP_DIRECTIVE are defined in
    ipaserver.install.httpinstance, else NSS_OCSP_ENABLED imported from
    ipaserver.install.httpinstance.
  returned: always
  type: str
NSS_OCSP_DIRECTIVE:
  description:
    Empty string for newer systems using ssl.conf and not nss.conf for
    HTTP instance where OCSP_ENABLED and OCSP_DIRECTIVE are defined in
    ipaserver.install.httpinstance, else NSSOCSP.
  returned: always
  type: str
NSS_NICKNAME_DIRECTIVE:
  description:
    Empty string for newer systems using ssl.conf and not nss.conf for
    HTTP instance where OCSP_ENABLED and OCSP_DIRECTIVE are defined in
    ipaserver.install.httpinstance, else NSSNickname
  returned: always
  type: str
OCSP_ENABLED:
  description:
    OCSP_ENABLED imported from ipaserver.install.httpinstance, if import
    succeeds, else ""
  returned: always
  type: str
OCSP_DIRECTIVE:
  description:
    OCSP_DIRECTIVE imported from ipaserver.install.httpinstance, if import
    succeeds, else ""
  returned: always
  type: str
HTTPD_SSL_CONF:
  description: paths.HTTPD_SSL_CONF from ipaplatform
  returned: always
  type: str
HTTPD_NSS_CONF:
  description: paths.HTTPD_NSS_CONF from ipaplatform
  returned: always
  type: str
HTTPD_ALIAS_DIR:
  description: paths.HTTPD_ALIAS_DIR from ipaplatform
  returned: always
  type: str
allow_httpd_ifp:
  description:
    True if sssd_enable_ifp can be imported from ipaclient.install.client,
    else false.
  returned: always
  type: bool
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
    try:
        from ipaserver.install.httpinstance import OCSP_ENABLED, OCSP_DIRECTIVE
        NSS_OCSP_ENABLED = ""
        NSS_OCSP_DIRECTIVE = ""
        NSS_NICKNAME_DIRECTIVE = ""
    except ImportError:
        from ipaserver.install.httpinstance import NSS_OCSP_ENABLED
        NSS_OCSP_DIRECTIVE = "NSSOCSP"
        NSS_NICKNAME_DIRECTIVE = "NSSNickname"
        OCSP_ENABLED = ""
        OCSP_DIRECTIVE = ""
    try:
        from ipaclient.install.client import sssd_enable_ifp
    except ImportError:
        sssd_enable_ifp = None
except ImportError as _err:
    MODULE_IMPORT_ERROR = str(_err)
    paths = None
    sssd_enable_ifp = None
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
                             NSS_OCSP_ENABLED=NSS_OCSP_ENABLED,
                             NSS_OCSP_DIRECTIVE=NSS_OCSP_DIRECTIVE,
                             NSS_NICKNAME_DIRECTIVE=NSS_NICKNAME_DIRECTIVE,
                             OCSP_ENABLED=OCSP_ENABLED,
                             OCSP_DIRECTIVE=OCSP_DIRECTIVE,
                             HTTPD_SSL_CONF=paths.HTTPD_SSL_CONF,
                             HTTPD_NSS_CONF=paths.HTTPD_NSS_CONF,
                             HTTPD_ALIAS_DIR=paths.HTTPD_ALIAS_DIR,
                             allow_httpd_ifp=sssd_enable_ifp is not None,
                             NSS_DB_DIR=paths.NSS_DB_DIR,
                             USE_AUTHSELECT=hasattr(paths, "AUTHSELECT"),
                             python_interpreter=sys.executable)


if __name__ == '__main__':
    main()

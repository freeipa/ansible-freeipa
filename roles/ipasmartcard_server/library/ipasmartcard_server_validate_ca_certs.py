# -*- coding: utf-8 -*-

# Authors:
#   Thomas Woerner <twoerner@redhat.com>
#
# Based on ipa-replica-install code
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
module: ipasmartcard_server_validate_ca_certs
short_description: Validate CA certs
description: Validate CA certs
options:
  ca_cert_files:
    description:
      List of files containing CA certificates for the service certificate
      files
    type: list
    elements: str
    required: no
author:
    - Thomas Woerner (@t-woerner)
'''

EXAMPLES = '''
'''

RETURN = '''
'''

import os.path
from ansible.module_utils.basic import AnsibleModule
try:
    from ipalib import x509
except ImportError:
    x509 = None


def main():
    ansible_module = AnsibleModule(
        argument_spec=dict(
            ca_cert_files=dict(required=False, type='list', elements='str',
                               default=[]),
        ),
        supports_check_mode=False,
    )

    # get parameters #

    ca_cert_files = ansible_module.params.get('ca_cert_files')

    # import check #

    if x509 is None:
        ansible_module.fail_json(msg="Failed to import x509 from ipalib")

    # validate ca certs #

    if ca_cert_files is not None:
        if not isinstance(ca_cert_files, list):
            ansible_module.fail_json(
                msg="Expected list, got %s" % repr(ca_cert_files))
        # remove duplicates
        ca_cert_files = list(dict.fromkeys(ca_cert_files))
        # validate
        for cert in ca_cert_files:
            if not os.path.exists(cert):
                ansible_module.fail_json(msg="'%s' does not exist" % cert)
            if not os.path.isfile(cert):
                ansible_module.fail_json(msg="'%s' is not a file" % cert)
            if not os.path.isabs(cert):
                ansible_module.fail_json(
                    msg="'%s' is not an absolute file path" % cert)
            try:
                x509.load_certificate_from_file(cert)
            except Exception:
                ansible_module.fail_json(
                    msg="'%s' is not a valid certificate file" % cert)

    # exit #

    ansible_module.exit_json(changed=False,
                             ca_cert_files=ca_cert_files)


if __name__ == '__main__':
    main()

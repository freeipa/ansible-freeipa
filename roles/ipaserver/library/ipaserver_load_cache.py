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

from __future__ import print_function

ANSIBLE_METADATA = {
    'metadata_version': '1.0',
    'supported_by': 'community',
    'status': ['preview'],
}

DOCUMENTATION = '''
---
module: ipaserver_load_cache
short description: 
description:
options:
  dm_password:
author:
    - Thomas Woerner
'''

EXAMPLES = '''
'''

RETURN = '''
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.ansible_ipa_server import *

def main():
    ansible_module = AnsibleModule(
        argument_spec = dict(
            ### basic ###
            dm_password=dict(required=True, no_log=True),
        ),
    )

    ansible_module._ansible_debug = True
    ansible_log = AnsibleModuleLog(ansible_module)

    # set values ############################################################

    ### basic ###
    options.dm_password = ansible_module.params.get('dm_password')

    # restore cache #########################################################

    if os.path.isfile(paths.ROOT_IPA_CACHE):
        if options.dm_password is None:
            ansible_module.fail_json(msg="Directory Manager password required")
        try:
            cache_vars = read_cache(dm_password)
            options.__dict__.update(cache_vars)
            if cache_vars.get('external_ca', False):
                options.external_ca = False
                options.interactive = False
        except Exception as e:
            ansible_module.fail_json(
                msg="Cannot process the cache file: %s" % str(e))

        kwargs = { "changed": True }
        for name in options.__dict__:
            kwargs[name] = options.__dict__[name]
        ansible_module.exit_json(kwargs)

    # done ##################################################################

    ansible_module.exit_json(changed=False)

if __name__ == '__main__':
    main()

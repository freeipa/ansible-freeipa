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
module: setup_ntp
short description: 
description:
options:
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
        argument_spec = dict(),
    )

    ansible_module._ansible_debug = True
    ansible_log = AnsibleModuleLog(ansible_module)

    # init ##########################################################

    fstore = sysrestore.FileStore(paths.SYSRESTORE)
    sstore = sysrestore.StateFile(paths.SYSRESTORE)

    # setup NTP #####################################################

    if time_service == "chronyd":
        # We have to sync time before certificate handling on master.
        # As chrony configuration is moved from client here, unconfiguration of
        # chrony will be handled here in uninstall() method as well by invoking
        # the ipa-server-install --uninstall
        ansible_module.log("Synchronizing time")
        options.ntp_servers = None
        options.ntp_pool = None
        if sync_time(options, fstore, sstore):
            ansible_module.log("Time synchronization was successful.")
        else:
            ansible_module.warn("IPA was unable to sync time with chrony!")
            ansible_module.warn("Time synchronization is required for IPA "
                                "to work correctly")
    else:
        # Configure ntpd
        timeconf.force_ntpd(sstore)
        ntp = ntpinstance.NTPInstance(fstore)
        ntp.set_output(ansible_log)
        with redirect_stdout(ansible_log):
            if not ntp.is_configured():
                ntp.create_instance()

    # done ##########################################################

    ansible_module.exit_json(changed=True)

if __name__ == '__main__':
    main()

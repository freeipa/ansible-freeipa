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
module: ipaserver_setup_ntp
short_description: Setup NTP
description: Setup NTP
options:
  ntp_servers:
    description: ntp servers to use
    type: list
    elements: str
    required: no
  ntp_pool:
    description: ntp server pool to use
    type: str
    required: no
author:
    - Thomas Woerner (@t-woerner)
'''

EXAMPLES = '''
'''

RETURN = '''
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.ansible_ipa_server import (
    check_imports, AnsibleModuleLog, setup_logging, options, sysrestore, paths,
    redirect_stdout, time_service, sync_time, ntpinstance, timeconf,
    getargspec
)


def main():
    ansible_module = AnsibleModule(
        argument_spec=dict(
            ntp_servers=dict(required=False, type='list', elements='str',
                             default=None),
            ntp_pool=dict(required=False, type='str', default=None),
        ),
    )

    ansible_module._ansible_debug = True
    check_imports(ansible_module)
    setup_logging()
    ansible_log = AnsibleModuleLog(ansible_module)

    # set values ############################################################

    options.ntp_servers = ansible_module.params.get('ntp_servers')
    options.ntp_pool = ansible_module.params.get('ntp_pool')

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

        # pylint: disable=deprecated-method
        argspec = getargspec(sync_time)
        # pylint: enable=deprecated-method
        if "options" not in argspec.args:
            synced_ntp = sync_time(options.ntp_servers, options.ntp_pool,
                                   fstore, sstore)
        else:
            synced_ntp = sync_time(options, fstore, sstore)
        if not synced_ntp:
            ansible_module.log(
                "Warning: IPA was unable to sync time with chrony!")
            ansible_module.log(
                "         Time synchronization is required for IPA "
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

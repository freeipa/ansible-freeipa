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
module: ipaclient_setup_ntp
short_description: Setup NTP for IPA client
description:
  Setup NTP for IPA client
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
  no_ntp:
    description: Do not configure ntp
    type: bool
    required: no
    default: no
  on_master:
    description: Whether the configuration is done on the master or not
    type: bool
    required: no
    default: no
  servers:
    description: Fully qualified name of IPA servers to enroll to
    type: list
    elements: str
    required: no
  domain:
    description: Primary DNS domain of the IPA deployment
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
from ansible.module_utils.ansible_ipa_client import (
    setup_logging, check_imports,
    options, sysrestore, paths, sync_time, logger, ipadiscovery,
    timeconf, getargspec
)


def main():
    module = AnsibleModule(
        argument_spec=dict(
            # basic
            ntp_servers=dict(required=False, type='list', elements='str',
                             default=None),
            ntp_pool=dict(required=False, type='str', default=None),
            no_ntp=dict(required=False, type='bool', default=False),
            # force_ntpd=dict(required=False, type='bool', default=False),
            on_master=dict(required=False, type='bool', default=False),
            # additional
            servers=dict(required=False, type='list', elements='str',
                         default=None),
            domain=dict(required=False, type='str', default=None),
        ),
        supports_check_mode=False,
    )

    # module._ansible_debug = True
    check_imports(module)
    setup_logging()

    options.ntp_servers = module.params.get('ntp_servers')
    options.ntp_pool = module.params.get('ntp_pool')
    options.no_ntp = module.params.get('no_ntp')
    # options.force_ntpd = module.params.get('force_ntpd')
    options.on_master = module.params.get('on_master')
    cli_server = module.params.get('servers')
    cli_domain = module.params.get('domain')

    options.conf_ntp = not options.no_ntp
    options.debug = False

    fstore = sysrestore.FileStore(paths.IPA_CLIENT_SYSRESTORE)
    statestore = sysrestore.StateFile(paths.IPA_CLIENT_SYSRESTORE)

    synced_ntp = False
    if sync_time is not None:
        if options.conf_ntp:
            # Attempt to configure and sync time with NTP server (chrony).
            # pylint: disable=deprecated-method
            argspec = getargspec(sync_time)
            # pylint: enable=deprecated-method
            if "options" not in argspec.args:
                synced_ntp = sync_time(options.ntp_servers, options.ntp_pool,
                                       fstore, statestore)
            else:
                synced_ntp = sync_time(options, fstore, statestore)
        elif options.on_master:
            # If we're on master skipping the time sync here because it was
            # done in ipa-server-install
            logger.info(
                "Skipping attempt to configure and synchronize time with"
                " chrony server as it has been already done on master.")
        else:
            logger.info("Skipping chrony configuration")

    else:
        ntp_srv_servers = []
        if not options.on_master and options.conf_ntp:
            # Attempt to sync time with IPA server.
            # If we're skipping NTP configuration, we also skip the time sync
            # here.
            # We assume that NTP servers are discoverable through SRV records
            # in the DNS.
            # If that fails, we try to sync directly with IPA server,
            # assuming it runs NTP
            logger.info('Synchronizing time with KDC...')
            ds = ipadiscovery.IPADiscovery()
            ntp_srv_servers = ds.ipadns_search_srv(cli_domain, '_ntp._udp',
                                                   None, break_on_first=False)
            synced_ntp = False
            ntp_servers = ntp_srv_servers

            # use user specified NTP servers if there are any
            if options.ntp_servers:
                ntp_servers = options.ntp_servers

            for _ntp_server in ntp_servers:
                synced_ntp = timeconf.synconce_ntp(_ntp_server, options.debug)
                if synced_ntp:
                    break

            if not synced_ntp and not options.ntp_servers:
                synced_ntp = timeconf.synconce_ntp(cli_server[0],
                                                   options.debug)
            if not synced_ntp:
                module.warn(
                    "Unable to sync time with NTP "
                    "server, assuming the time is in sync. Please check "
                    "that 123 UDP port is opened.")
        else:
            logger.info('Skipping synchronizing time with NTP server.')

    # Done
    module.exit_json(changed=synced_ntp)


if __name__ == '__main__':
    main()

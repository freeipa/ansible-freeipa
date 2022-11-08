# -*- coding: utf-8 -*-

# Authors:
#   Thomas Woerner <twoerner@redhat.com>
#
# Based on ipa-server-install code
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
module: ipaserver_enable_ipa
short_description: Enable IPA
description: Enable IPA
options:
  hostname:
    description: Fully qualified name of this host
    type: str
    required: no
  setup_dns:
    description: Configure bind with our zone
    type: bool
    required: yes
  setup_ca:
    description: Configure a dogtag CA
    type: bool
    required: yes
author:
    - Thomas Woerner (@t-woerner)
'''

EXAMPLES = '''
'''

RETURN = '''
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.ansible_ipa_server import (
    check_imports,
    AnsibleModuleLog, setup_logging, options, paths, api, sysrestore, tasks,
    service, bindinstance, redirect_stdout, services
)


def main():
    ansible_module = AnsibleModule(
        argument_spec=dict(
            hostname=dict(required=False, type='str'),
            setup_dns=dict(required=True, type='bool'),
            setup_ca=dict(required=True, type='bool'),
        ),
    )

    ansible_module._ansible_debug = True
    check_imports(ansible_module)
    setup_logging()
    ansible_log = AnsibleModuleLog(ansible_module)

    # set values #############################################################

    options.host_name = ansible_module.params.get('hostname')
    options.setup_dns = ansible_module.params.get('setup_dns')
    options.setup_ca = ansible_module.params.get('setup_ca')

    # Configuration for ipalib, we will bootstrap and finalize later, after
    # we are sure we have the configuration file ready.
    cfg = dict(
        context='installer',
        confdir=paths.ETC_IPA,
        in_server=True,
        # make sure host name specified by user is used instead of default
        host=options.host_name,
    )
    if options.setup_ca:
        # we have an IPA-integrated CA
        cfg['ca_host'] = options.host_name

    api.bootstrap(**cfg)
    api.finalize()
    api.Backend.ldap2.connect()

    # setup ds ######################################################

    fstore = sysrestore.FileStore(paths.SYSRESTORE)

    if hasattr(tasks, "configure_tmpfiles"):
        # Make sure the files we crated in /var/run are recreated at startup
        tasks.configure_tmpfiles()

    if hasattr(service, "enable_services"):
        # Enable configured services and update DNS SRV records
        service.enable_services(options.host_name)
        api.Command.dns_update_system_records()

        if not options.setup_dns:
            # After DNS and AD trust are configured and services are
            # enabled, create a dummy instance to dump DNS configuration.
            bind = bindinstance.BindInstance(fstore)
            bind.create_file_with_system_records()

    with redirect_stdout(ansible_log):
        services.knownservices.ipa.enable()

    ansible_module.exit_json(changed=True)


if __name__ == '__main__':
    main()

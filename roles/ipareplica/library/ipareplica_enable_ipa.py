# -*- coding: utf-8 -*-

# Authors:
#   Thomas Woerner <twoerner@redhat.com>
#
# Based on ipa-replica-install code
#
# Copyright (C) 2018-2022  Red Hat
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
module: ipareplica_enable_ipa
short_description: Enable IPA
description: Enable IPA
  Enable IPA
options:
  hostname:
    description: Fully qualified name of this host
    type: str
    required: no
  hidden_replica:
    description: Install a hidden replica
    type: bool
    default: no
    required: no
  subject_base:
    description:
      The certificate subject base (default O=<realm-name>).
      RDNs are in LDAP order (most specific RDN first).
    type: str
    required: yes
  ccache:
    description: The local ccache
    type: str
    required: yes
  _top_dir:
    description: The installer _top_dir setting
    type: str
    required: yes
  setup_ca:
    description: Configure a dogtag CA
    type: bool
    required: yes
  setup_kra:
    description: Configure a dogtag KRA
    type: bool
    required: yes
  config_master_host_name:
    description: The config master_host_name setting
    type: str
    required: yes
author:
    - Thomas Woerner (@t-woerner)
'''

EXAMPLES = '''
'''

RETURN = '''
'''

import os

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.ansible_ipa_replica import (
    check_imports, AnsibleModuleLog, setup_logging, installer, DN, paths,
    gen_env_boostrap_finalize_core, constants, api_bootstrap_finalize,
    gen_ReplicaConfig, gen_remote_api, api, redirect_stdout, service,
    find_providing_servers, services
)


def main():
    ansible_module = AnsibleModule(
        argument_spec=dict(
            hostname=dict(required=False, type='str'),
            hidden_replica=dict(required=False, type='bool', default=False),
            # server
            # certificate system
            subject_base=dict(required=True, type='str'),
            # additional
            ccache=dict(required=True, type='str'),
            _top_dir=dict(required=True, type='str'),
            setup_ca=dict(required=True, type='bool'),
            setup_kra=dict(required=True, type='bool'),
            config_master_host_name=dict(required=True, type='str'),
        ),
        supports_check_mode=False,
    )

    ansible_module._ansible_debug = True
    check_imports(ansible_module)
    setup_logging()
    ansible_log = AnsibleModuleLog(ansible_module)

    # get parameters #

    options = installer
    options.host_name = ansible_module.params.get('hostname')
    options.hidden_replica = ansible_module.params.get('hidden_replica')
    # server
    # certificate system
    options.subject_base = ansible_module.params.get('subject_base')
    if options.subject_base is not None:
        options.subject_base = DN(options.subject_base)
    # additional
    ccache = ansible_module.params.get('ccache')
    os.environ['KRB5CCNAME'] = ccache
    options._top_dir = ansible_module.params.get('_top_dir')
    options.setup_ca = ansible_module.params.get('setup_ca')
    options.setup_kra = ansible_module.params.get('setup_kra')
    config_master_host_name = ansible_module.params.get(
        'config_master_host_name')

    # init #

    ansible_log.debug("== INSTALL ==")

    env = gen_env_boostrap_finalize_core(paths.ETC_IPA,
                                         constants.DEFAULT_CONFIG)
    api_bootstrap_finalize(env)
    config = gen_ReplicaConfig()

    remote_api = gen_remote_api(config_master_host_name, paths.ETC_IPA)
    installer._remote_api = remote_api

    ccache = os.environ['KRB5CCNAME']

    api.Backend.ldap2.connect()

    with redirect_stdout(ansible_log):
        if options.hidden_replica:
            # Set services to hidden
            service.hide_services(config.host_name)
        else:
            # Enable configured services
            service.enable_services(config.host_name)
        # update DNS SRV records. Although it's only really necessary in
        # enabled-service case, also perform update in hidden replica case.
        api.Command.dns_update_system_records()
        ca_servers = find_providing_servers('CA', api.Backend.ldap2, api=api)
        api.Backend.ldap2.disconnect()

        # Everything installed properly, activate ipa service.
        services.knownservices.ipa.enable()

        # Print a warning if CA role is only installed on one server
        if len(ca_servers) == 1:
            msg = u'''
                WARNING: The CA service is only installed on one server ({0}).
                It is strongly recommended to install it on another server.
                Run ipa-ca-install(1) on another master to accomplish this.
            '''.format(ca_servers[0])
            ansible_module.debug(msg)

    # done #

    ansible_module.exit_json(changed=True)


if __name__ == '__main__':
    main()

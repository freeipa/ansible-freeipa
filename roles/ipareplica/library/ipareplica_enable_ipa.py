#!/usr/bin/python
# -*- coding: utf-8 -*-

# Authors:
#   Thomas Woerner <twoerner@redhat.com>
#
# Based on ipa-replica-install code
#
# Copyright (C) 2018  Red Hat
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
module: ipareplica_enable_ipa
short description:
description: Enable IPA
  Enable IPA
options:
  subject_base:
    description: The certificate subject base (default O=<realm-name>).
    required: yes
  ccache:
    description: The installation specific ccache file.
    required: yes
  _top_dir:
    description: The temporary top directory used for the installation.
    required: yes
  setup_ca:
    description: Configure a dogtag CA
    required: yes
  config_master_host_name:
    description: The master host name
    required: yes
author:
    - Thomas Woerner
'''

EXAMPLES = '''
'''

RETURN = '''
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.ansible_ipa_replica import *

def main():
    ansible_module = AnsibleModule(
        argument_spec = dict(
            hostname=dict(required=False),
            ### server ###
            ### certificate system ###
            subject_base=dict(required=True),
            ### additional ###
            ccache=dict(required=True),
            _top_dir = dict(required=True),
            setup_ca=dict(required=True, type='bool'),
            config_master_host_name=dict(required=True),
        ),
        supports_check_mode = True,
    )

    ansible_module._ansible_debug = True
    ansible_log = AnsibleModuleLog(ansible_module)

    # get parameters #

    options = installer
    options.host_name = ansible_module.params.get('hostname')
    ### server ###
    ### certificate system ###
    options.subject_base = ansible_module.params.get('subject_base')
    if options.subject_base is not None:
        options.subject_base = DN(options.subject_base)
    ### additional ###
    ccache = ansible_module.params.get('ccache')
    os.environ['KRB5CCNAME'] = ccache
    options._top_dir = ansible_module.params.get('_top_dir')
    options.setup_ca = ansible_module.params.get('setup_ca')
    config_master_host_name = ansible_module.params.get('config_master_host_name')

    # init #

    fstore = sysrestore.FileStore(paths.SYSRESTORE)
    sstore = sysrestore.StateFile(paths.SYSRESTORE)

    ansible_log.debug("== INSTALL ==")

    promote = installer.promote

    env = gen_env_boostrap_finalize_core(paths.ETC_IPA,
                                         constants.DEFAULT_CONFIG)
    api_bootstrap_finalize(env)

    remote_api = gen_remote_api(config_master_host_name, paths.ETC_IPA)
    installer._remote_api = remote_api

    conn = remote_api.Backend.ldap2
    ccache = os.environ['KRB5CCNAME']

    api.Backend.ldap2.connect()

    with redirect_stdout(ansible_log):
        # Enable configured services and update DNS SRV records
        service.enable_services(options.host_name)
        api.Command.dns_update_system_records()
        ca_servers = service.find_providing_servers('CA', api.Backend.ldap2,
                                                    api)
        api.Backend.ldap2.disconnect()

        # Everything installed properly, activate ipa service.
        services.knownservices.ipa.enable()

        # Print a warning if CA role is only installed on one server
        if len(ca_servers) == 1:
            msg = textwrap.dedent(u'''
                WARNING: The CA service is only installed on one server ({}).
                It is strongly recommended to install it on another server.
                Run ipa-ca-install(1) on another master to accomplish this.
            '''.format(ca_servers[0]))
            ansible_module.warn(msg)

    # done #

    ansible_module.exit_json(changed=True)

if __name__ == '__main__':
    main()

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

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

ANSIBLE_METADATA = {
    'metadata_version': '1.0',
    'supported_by': 'community',
    'status': ['preview'],
}

DOCUMENTATION = '''
---
module: ipareplica_promote_openldap_conf
short description: Promote openldap.conf
description:
  Promote openldap.conf
options:
  setup_kra:
    description: Configure a dogtag KRA
    required: yes
  subject_base:
    description:
      The certificate subject base (default O=<realm-name>).
      RDNs are in LDAP order (most specific RDN first).
    required: no
  ccache:
    description: The local ccache
    required: no
  _top_dir:
    description: The installer _top_dir setting
    required: no
  config_setup_ca:
    description: The config setup_ca setting
    required: no
  config_master_host_name:
    description: The config master_host_name setting
    required: no
author:
    - Thomas Woerner
'''

EXAMPLES = '''
'''

RETURN = '''
'''

import os

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.ansible_ipa_replica import (
    AnsibleModuleLog, setup_logging, installer, DN, paths,
    gen_env_boostrap_finalize_core, constants, api_bootstrap_finalize,
    gen_ReplicaConfig, gen_remote_api, redirect_stdout, promote_openldap_conf
)


def main():
    ansible_module = AnsibleModule(
        argument_spec=dict(
            # server
            setup_kra=dict(required=False, type='bool'),
            # certificate system
            subject_base=dict(required=True),
            # additional
            ccache=dict(required=True),
            _top_dir=dict(required=True),
            config_setup_ca=dict(required=True, type='bool'),
            config_master_host_name=dict(required=True),
        ),
        supports_check_mode=True,
    )

    ansible_module._ansible_debug = True
    setup_logging()
    ansible_log = AnsibleModuleLog(ansible_module)

    # get parameters #

    options = installer
    # server
    options.setup_kra = ansible_module.params.get('setup_kra')
    # certificate system
    options.subject_base = ansible_module.params.get('subject_base')
    if options.subject_base is not None:
        options.subject_base = DN(options.subject_base)
    # additional
    ccache = ansible_module.params.get('ccache')
    os.environ['KRB5CCNAME'] = ccache
    options._top_dir = ansible_module.params.get('_top_dir')
    config_setup_ca = ansible_module.params.get('config_setup_ca')
    installer.setup_ca = config_setup_ca
    config_master_host_name = ansible_module.params.get(
        'config_master_host_name')

    # init #

    ansible_log.debug("== INSTALL ==")

    env = gen_env_boostrap_finalize_core(paths.ETC_IPA,
                                         constants.DEFAULT_CONFIG)
    api_bootstrap_finalize(env)
    config = gen_ReplicaConfig()
    config.subject_base = options.subject_base
    config.setup_ca = config_setup_ca
    config.master_host_name = config_master_host_name

    remote_api = gen_remote_api(config.master_host_name, paths.ETC_IPA)
    installer._remote_api = remote_api

    ccache = os.environ['KRB5CCNAME']

    with redirect_stdout(ansible_log):
        ansible_log.debug("-- PROMOTE OPENLDAP_CONF--")

        promote_openldap_conf(config.host_name, config.master_host_name)

    # done #

    ansible_module.exit_json(changed=True)


if __name__ == '__main__':
    main()

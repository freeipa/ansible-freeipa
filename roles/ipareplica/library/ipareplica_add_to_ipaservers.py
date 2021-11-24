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
module: ipareplica_add_to_ipaservers
short description: Add to ipaservers
description:
  Add to ipaservers
options:
  setup_kra:
    description: Configure a dogtag KRA
    required: no
  config_master_host_name:
    description: The config master_host_name setting
    required: no
  ccache:
    description: The local ccache
    required: no
  installer_ccache:
    description: The installer ccache setting
    required: no
  _top_dir:
    description: The installer _top_dir setting
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
    AnsibleModuleLog, setup_logging, installer, paths,
    gen_env_boostrap_finalize_core, constants, api_bootstrap_finalize,
    gen_remote_api, api
)

from ansible.module_utils import six

if six.PY3:
    unicode = str


def main():
    ansible_module = AnsibleModule(
        argument_spec=dict(
            # server
            setup_kra=dict(required=True, type='bool'),
            # additional
            config_master_host_name=dict(required=True),
            ccache=dict(required=True),
            installer_ccache=dict(required=True),
            _top_dir=dict(required=True),
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
    # additional
    config_master_host_name = ansible_module.params.get(
        'config_master_host_name')
    ccache = ansible_module.params.get('ccache')
    os.environ['KRB5CCNAME'] = ccache
    options._ccache = ansible_module.params.get('installer_ccache')
    # os.environ['KRB5CCNAME'] = ansible_module.params.get('installer_ccache')
    options._top_dir = ansible_module.params.get('_top_dir')

    # init #

    ansible_log.debug("== INSTALLER ==")

    options = installer

    env = gen_env_boostrap_finalize_core(paths.ETC_IPA,
                                         constants.DEFAULT_CONFIG)
    api_bootstrap_finalize(env)
    # config = gen_ReplicaConfig()

    remote_api = gen_remote_api(config_master_host_name, paths.ETC_IPA)
    # installer._remote_api = remote_api

    conn = remote_api.Backend.ldap2
    ccache = os.environ['KRB5CCNAME']

    ansible_log.debug("-- HOSTGROUP_ADD_MEMBER --")
    try:
        ansible_log.debug("-- CONNECT --")
        conn.connect(ccache=installer._ccache)
        remote_api.Command['hostgroup_add_member'](
            u'ipaservers',
            host=[unicode(api.env.host)],
        )
    finally:
        if conn.isconnected():
            ansible_log.debug("-- DISCONNECT --")
            conn.disconnect()
        os.environ['KRB5CCNAME'] = ccache

    # done #

    ansible_module.exit_json(changed=True)


if __name__ == '__main__':
    main()

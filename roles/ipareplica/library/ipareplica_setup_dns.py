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
module: ipareplica_setup_dns
short description: Setup DNS
description:
  Setup DNS
options:
  setup_kra:
    description: Configure a dogtag KRA
    required: yes
  setup_dns:
    description: Configure bind with our zone
    required: yes
  subject_base:
    description:
      The certificate subject base (default O=<realm-name>).
      RDNs are in LDAP order (most specific RDN first).
    required: no
  zonemgr:
    description: DNS zone manager e-mail address. Defaults to hostmaster@DOMAIN
    required: yes
  forwarders:
    description: Add DNS forwarders
    required: yes
  forward_policy:
    description: DNS forwarding policy for global forwarders
    required: yes
  no_dnssec_validation:
    description: Disable DNSSEC validation
    required: yes
  dns_ip_addresses:
    description: The dns ip_addresses setting
    required: no
  dns_reverse_zones:
    description: The dns reverse_zones setting
    required: no
  ccache:
    description: The local ccache
    required: no
  _top_dir:
    description: The installer _top_dir setting
    required: no
  setup_ca:
    description: Configure a dogtag CA
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
    gen_ReplicaConfig, gen_remote_api, api, redirect_stdout, dns,
    ansible_module_get_parsed_ip_addresses
)


def main():
    ansible_module = AnsibleModule(
        argument_spec=dict(
            # server
            setup_kra=dict(required=False, type='bool'),
            setup_dns=dict(required=False, type='bool'),
            # certificate system
            subject_base=dict(required=True),
            # dns
            zonemgr=dict(required=False),
            forwarders=dict(required=False, type='list', default=[]),
            forward_policy=dict(default=None, choices=['first', 'only']),
            no_dnssec_validation=dict(required=False, type='bool',
                                      default=False),
            # additional
            dns_ip_addresses=dict(required=True, type='list'),
            dns_reverse_zones=dict(required=True, type='list'),
            ccache=dict(required=True),
            _top_dir=dict(required=True),
            setup_ca=dict(required=True, type='bool'),
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
    options.setup_dns = ansible_module.params.get('setup_dns')
    # certificate system
    options.subject_base = ansible_module.params.get('subject_base')
    if options.subject_base is not None:
        options.subject_base = DN(options.subject_base)
    # dns
    options.zonemgr = ansible_module.params.get('zonemgr')
    options.forwarders = ansible_module.params.get('forwarders')
    options.forward_policy = ansible_module.params.get('forward_policy')
    options.no_dnssec_validation = ansible_module.params.get(
        'no_dnssec_validation')
    # additional
    dns.ip_addresses = ansible_module_get_parsed_ip_addresses(
        ansible_module, 'dns_ip_addresses')
    dns.reverse_zones = ansible_module.params.get('dns_reverse_zones')
    ccache = ansible_module.params.get('ccache')
    os.environ['KRB5CCNAME'] = ccache
    options._top_dir = ansible_module.params.get('_top_dir')
    options.setup_ca = ansible_module.params.get('setup_ca')
    config_master_host_name = ansible_module.params.get(
        'config_master_host_name')

    # init #

    ansible_log.debug("== INSTALL ==")

    env = gen_env_boostrap_finalize_core(paths.ETC_IPA,
                                         constants.DEFAULT_CONFIG)
    api_bootstrap_finalize(env)
    config = gen_ReplicaConfig()
    config.subject_base = options.subject_base
    config.master_host_name = config_master_host_name

    remote_api = gen_remote_api(config.master_host_name, paths.ETC_IPA)
    installer._remote_api = remote_api

    ccache = os.environ['KRB5CCNAME']

    # There is a api.Backend.ldap2.connect call somewhere in ca, ds, dns or
    # ntpinstance
    api.Backend.ldap2.connect()

    with redirect_stdout(ansible_log):
        if options.setup_dns:
            ansible_log.debug("-- INSTALL DNS --")
            dns.install(False, True, options, api)
        else:
            ansible_log.debug("-- DNS UPDATE_SYSTEM_RECORDS --")
            api.Command.dns_update_system_records()

    # done #

    ansible_module.exit_json(changed=True)


if __name__ == '__main__':
    main()

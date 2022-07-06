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
module: ipareplica_setup_http
short description: Setup HTTP
description:
  Setup HTTP
options:
  setup_ca:
    description: Configure a dogtag CA
    required: yes
  setup_kra:
    description: Configure a dogtag KRA
    required: yes
  no_pkinit:
    description: Disable pkinit setup steps
    required: yes
  no_ui_redirect:
    description: Do not automatically redirect to the Web UI
    required: yes
  subject_base:
    description:
      The certificate subject base (default O=<realm-name>).
      RDNs are in LDAP order (most specific RDN first).
    required: no
  config_master_host_name:
    description: The config master_host_name setting
    required: no
  config_ca_host_name:
    description: The config ca_host_name setting
    required: no
  ccache:
    description: The local ccache
    required: no
  _ca_enabled:
    description: The installer _ca_enabled setting
    required: yes
  _ca_file:
    description: The installer _ca_file setting
    required: yes
  _http_pkcs12_info:
    description: The installer _http_pkcs12_info setting
    required: yes
  _top_dir:
    description: The installer _top_dir setting
    required: no
  dirman_password:
    description: Directory Manager (master) password
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
    AnsibleModuleLog, setup_logging, installer, DN, paths, sysrestore,
    gen_env_boostrap_finalize_core, constants, api_bootstrap_finalize,
    gen_ReplicaConfig, gen_remote_api, api, redirect_stdout, create_ipa_conf,
    install_http, getargspec
)


def main():
    ansible_module = AnsibleModule(
        argument_spec=dict(
            # server
            setup_ca=dict(required=False, type='bool'),
            setup_kra=dict(required=False, type='bool'),
            no_pkinit=dict(required=False, type='bool'),
            no_ui_redirect=dict(required=False, type='bool'),
            # certificate system
            subject_base=dict(required=True),
            config_master_host_name=dict(required=True),
            config_ca_host_name=dict(required=True),
            ccache=dict(required=True),
            _ca_enabled=dict(required=False, type='bool'),
            _ca_file=dict(required=False),
            _http_pkcs12_info=dict(required=False, type='list'),
            _top_dir=dict(required=True),
            dirman_password=dict(required=True, no_log=True),
        ),
        supports_check_mode=True,
    )

    ansible_module._ansible_debug = True
    setup_logging()
    ansible_log = AnsibleModuleLog(ansible_module)

    # get parameters #

    options = installer
    options.setup_ca = ansible_module.params.get('setup_ca')
    options.setup_kra = ansible_module.params.get('setup_kra')
    options.no_pkinit = ansible_module.params.get('no_pkinit')
    options.no_ui_redirect = ansible_module.params.get('no_ui_redirect')
    # certificate system
    options.subject_base = ansible_module.params.get('subject_base')
    if options.subject_base is not None:
        options.subject_base = DN(options.subject_base)
    # additional
    master_host_name = ansible_module.params.get('config_master_host_name')
    ca_host_name = ansible_module.params.get('config_master_host_name')
    ccache = ansible_module.params.get('ccache')
    os.environ['KRB5CCNAME'] = ccache
    # os.environ['KRB5CCNAME'] = ansible_module.params.get('installer_ccache')
    # installer._ccache = ansible_module.params.get('installer_ccache')
    ca_enabled = ansible_module.params.get('_ca_enabled')
    http_pkcs12_info = ansible_module.params.get('_http_pkcs12_info')
    options._top_dir = ansible_module.params.get('_top_dir')
    dirman_password = ansible_module.params.get('dirman_password')

    # init #

    fstore = sysrestore.FileStore(paths.SYSRESTORE)

    ansible_log.debug("== INSTALL ==")

    promote = installer.promote

    env = gen_env_boostrap_finalize_core(paths.ETC_IPA,
                                         constants.DEFAULT_CONFIG)
    api_bootstrap_finalize(env)
    config = gen_ReplicaConfig()
    config.subject_base = options.subject_base
    config.dirman_password = dirman_password
    config.setup_ca = options.setup_ca
    config.master_host_name = master_host_name
    config.ca_host_name = ca_host_name
    config.promote = installer.promote

    remote_api = gen_remote_api(master_host_name, paths.ETC_IPA)
    # installer._remote_api = remote_api

    conn = remote_api.Backend.ldap2
    ccache = os.environ['KRB5CCNAME']

    # There is a api.Backend.ldap2.connect call somewhere in ca, ds, dns or
    # ntpinstance
    api.Backend.ldap2.connect()
    conn.connect(ccache=ccache)

    cafile = paths.IPA_CA_CRT
    with redirect_stdout(ansible_log):
        ansible_log.debug("-- INSTALL_HTTP --")

        # We need to point to the master when certmonger asks for
        # HTTP certificate.
        # During http installation, the HTTP/hostname principal is created
        # locally then the installer waits for the entry to appear on the
        # master selected for the installation.
        # In a later step, the installer requests a SSL certificate through
        # Certmonger (and the op adds the principal if it does not exist yet).
        # If xmlrpc_uri points to the soon-to-be replica,
        # the httpd service is not ready yet to handle certmonger requests
        # and certmonger tries to find another master. The master can be
        # different from the one selected for the installation, and it is
        # possible that the principal has not been replicated yet. This
        # may lead to a replication conflict.
        # This is why we need to force the use of the same master by
        # setting xmlrpc_uri
        create_ipa_conf(fstore, config, ca_enabled,
                        master=config.master_host_name)

        # pylint: disable=deprecated-method
        argspec = getargspec(install_http)
        # pylint: enable=deprecated-method
        if "promote" in argspec.args:
            install_http(
                config,
                auto_redirect=not options.no_ui_redirect,
                promote=promote,
                pkcs12_info=http_pkcs12_info,
                ca_is_configured=ca_enabled,
                ca_file=cafile)
        else:
            if "fstore" not in argspec.args:
                install_http(
                    config,
                    auto_redirect=not options.no_ui_redirect,
                    pkcs12_info=http_pkcs12_info,
                    ca_is_configured=ca_enabled,
                    ca_file=cafile)
            else:
                install_http(
                    config,
                    auto_redirect=not options.no_ui_redirect,
                    pkcs12_info=http_pkcs12_info,
                    ca_is_configured=ca_enabled,
                    ca_file=cafile,
                    fstore=fstore)

        # Need to point back to ourself after the cert for HTTP is obtained
        create_ipa_conf(fstore, config, ca_enabled)

    # done #

    ansible_module.exit_json(changed=True)


if __name__ == '__main__':
    main()

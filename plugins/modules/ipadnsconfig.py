# -*- coding: utf-8 -*-

# Authors:
#   Rafael Guterres Jeffman <rjeffman@redhat.com>
#
# Copyright (C) 2019 Red Hat
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
    "metadata_version": "1.0",
    "supported_by": "community",
    "status": ["preview"],
}

DOCUMENTATION = """
---
module: ipadnsconfig
short description: Manage FreeIPA dnsconfig
description: Manage FreeIPA dnsconfig
extends_documentation_fragment:
  - ipamodule_base_docs
options:
  forwarders:
    description: The list of global DNS forwarders.
    required: false
    options:
      ip_address:
        description: The forwarder nameserver IP address list (IPv4 and IPv6).
        required: true
      port:
        description: The port to forward requests to.
        required: false
  forward_policy:
    description:
      Global forwarding policy. Set to "none" to disable any configured
      global forwarders.
    required: false
    choices: ['only', 'first', 'none']
  allow_sync_ptr:
    description:
      Allow synchronization of forward (A, AAAA) and reverse (PTR) records.
    required: false
    type: bool
  state:
    description: State to ensure
    default: present
    choices: ["present", "absent"]
"""

EXAMPLES = """
# Ensure global DNS forward configuration, allowing PTR record synchronization.
- ipadnsconfig:
    ipaadmin_password: SomeADMINpassword
    forwarders:
      - ip_address: 8.8.4.4
      - ip_address: 2001:4860:4860::8888
        port: 53
    forward_policy: only
    allow_sync_ptr: yes

# Ensure forwarder is absent.
- ipadnsconfig:
    ipaadmin_password: SomeADMINpassword
    forwarders:
      - ip_address: 2001:4860:4860::8888
        port: 53
    state: absent

# Disable PTR record synchronization.
- ipadnsconfig:
    ipaadmin_password: SomeADMINpassword
    allow_sync_ptr: no

# Disable global forwarders.
- ipadnsconfig:
    ipaadmin_password: SomeADMINpassword
    forward_policy: none
"""

RETURN = """
"""

from ansible.module_utils.ansible_freeipa_module import \
    IPAAnsibleModule, compare_args_ipa, is_ipv4_addr, is_ipv6_addr


def find_dnsconfig(module):
    _args = {
        "all": True,
    }

    _result = module.ipa_command_no_name("dnsconfig_show", _args)

    if "result" in _result:
        if _result["result"].get('idnsforwarders', None) is None:
            _result["result"]['idnsforwarders'] = ['']
        return _result["result"]

    module.fail_json(msg="Could not retrieve current DNS configuration.")
    return None


def gen_args(module, state, dnsconfig, forwarders, forward_policy,
             allow_sync_ptr):
    _args = {}

    if forwarders:
        _forwarders = []
        for forwarder in forwarders:
            ip_address = forwarder.get('ip_address')
            port = forwarder.get('port')
            if not (is_ipv4_addr(ip_address) or is_ipv6_addr(ip_address)):
                module.fail_json(
                    msg="Invalid IP for DNS forwarder: %s" % ip_address)
            if port is None:
                _forwarders.append(ip_address)
            else:
                _forwarders.append('%s port %d' % (ip_address, port))

        global_forwarders = dnsconfig.get('idnsforwarders', [])
        if state == 'absent':
            _args['idnsforwarders'] = [
                fwd for fwd in global_forwarders if fwd not in _forwarders]
            # When all forwarders should be excluded, use an empty string ('').
            if not _args['idnsforwarders']:
                _args['idnsforwarders'] = ['']

        elif state == 'present':
            _args['idnsforwarders'] = [
                fwd for fwd in _forwarders if fwd not in global_forwarders]
            # If no forwarders should be added, remove argument.
            if not _args['idnsforwarders']:
                del _args['idnsforwarders']

        else:
            # shouldn't happen, but let's be paranoid.
            module.fail_json(msg="Invalid state: %s" % state)

    if forward_policy is not None:
        _args['idnsforwardpolicy'] = forward_policy

    if allow_sync_ptr is not None:
        _args['idnsallowsyncptr'] = 'TRUE' if allow_sync_ptr else 'FALSE'

    return _args


def main():
    forwarder_spec = dict(
       ip_address=dict(type=str, required=True),
       port=dict(type=int, required=False, default=None)
    )

    ansible_module = IPAAnsibleModule(
       argument_spec=dict(
           # dnsconfig
           forwarders=dict(type='list', default=None, required=False,
                           options=dict(**forwarder_spec)),
           forward_policy=dict(type='str', required=False, default=None,
                               choices=['only', 'first', 'none']),
           allow_sync_ptr=dict(type='bool', required=False, default=None),

           # general
           state=dict(type="str", default="present",
                      choices=["present", "absent"]),

       )
    )

    ansible_module._ansible_debug = True

    # dnsconfig
    forwarders = ansible_module.params_get('forwarders') or []
    forward_policy = ansible_module.params_get('forward_policy')
    allow_sync_ptr = ansible_module.params_get('allow_sync_ptr')

    state = ansible_module.params_get('state')

    # Check parameters.
    invalid = []
    if state == 'absent':
        invalid = ['forward_policy', 'allow_sync_ptr']

    ansible_module.params_fail_used_invalid(invalid, state)

    # Init

    changed = False

    # Connect to IPA API
    with ansible_module.ipa_connect():

        res_find = find_dnsconfig(ansible_module)
        args = gen_args(ansible_module, state, res_find, forwarders,
                        forward_policy, allow_sync_ptr)

        # Execute command only if configuration changes.
        if not compare_args_ipa(ansible_module, args, res_find):
            try:
                if not ansible_module.check_mode:
                    ansible_module.ipa_command_no_name('dnsconfig_mod', args)
                # If command did not fail, something changed.
                changed = True

            except Exception as e:
                msg = str(e)
                ansible_module.fail_json(msg="dnsconfig_mod: %s" % msg)

    # Done

    ansible_module.exit_json(changed=changed)


if __name__ == "__main__":
    main()

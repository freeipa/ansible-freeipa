#!/usr/bin/python
# -*- coding: utf-8 -*-

# Authors:
#   Florence Blanc-Renaud <frenaud@redhat.com>
#
# Copyright (C) 2017  Red Hat
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

ANSIBLE_METADATA = {'metadata_version': '1.0',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
---
module: ipahost
short description: Manage IPA hosts
description:
  Manage hosts in a IPA domain.
  The operation needs to be authenticated with Kerberos either by providing
  a password or a keytab corresponding to a principal allowed to perform
  host operations.
options:
  principal:
    description: Kerberos principal used to manage the host
    required: true
    default: admin
  password:
    description: Password for the kerberos principal
    required: false
  keytab:
    description: Keytab file containing the Kerberos principal and encrypted key
    required: false
  lifetime:
    description: Sets the default lifetime for initial ticket requests
    required: false
    default: 1h
  fqdn:
    description: the fully-qualified hostname of the host to add/modify/remove
    required: true
  random:
    description: generate a random password to be used in bulk enrollment
    required: false
    type: bool
    default: no
  state:
    description: the host state
    required: false
    default: present
    choices: [ "present", "absent" ]
  certificates:
    description: a list of host certificates
    required: false
    type: list
  sshpubkey:
    description: the SSH public key for the host
    required: false
  ipaddress:
    description: the IP address for the host
    required: false
  ansible_python_interpreter:
    desciption: The ansible python interpreter used in the action plugin part, ignored here
    required: false

requirements:
    - gssapi on the Ansible controller
author:
    - "Florence Blanc-Renaud"
'''

EXAMPLES = '''
# Example from Ansible Playbooks
# Add a new host with a random OTP, authenticate using principal/password
- ipahost:
    principal: admin
    password: MySecretPassword
    fqdn: ipaclient.ipa.domain.com
    ipaddress: 192.168.100.23
    random: True
  register: ipahost

# Add a new host, authenticate with a keytab stored on the controller node
- ipahost:
    keytab: admin.keytab
    fqdn: ipaclient.ipa.domain.com

# Remove a host, authenticate using principal/password
- ipahost:
    principal: admin
    password: MySecretPassword
    fqdn: ipaclient.ipa.domain.com
    state: absent

# Modify a host, add ssh public key:
- ipahost:
    principal: admin
    password: MySecretPassword
    fqdn: ipaclient.ipa.domain.com
    sshpubkey: ssh-rsa AAAA...

'''

RETURN = '''
host:
  description: the host structure as returned from IPA API
  returned: always
  type: complex
  contains:
    dn:
      description: the DN of the host entry
      type: string
      returned: always
    fqdn:
      description: the fully qualified host name
      type: string
      returned: always
    has_keytab:
      description: whether the host entry contains a keytab
      type: bool
      returned: always
    has_password:
      description: whether the host entry contains a password
      type: bool
      returned: always
    managedby_host:
      description: the list of hosts managing the host
      type: list
      returned: always
    randompassword:
      description: the OneTimePassword generated for this host
      type: string
      returned: changed
    certificates:
      description: the list of host certificates
      type: list
      returned: when present
    sshpubkey:
      description: the SSH public key for the host
      type: string
      returned: when present
    ipaddress:
      description: the IP address for the host
      type: string
      returned: when present
'''

import os
import six

from ansible.module_utils.basic import AnsibleModule

from ipalib import api, errors
from ipaplatform.paths import paths
from ipapython.ipautil import run

if six.PY3:
    unicode = str

def get_host_diff(ipa_host, module_host):
    """
    Compares two dictionaries containing host attributes and builds a dict
    of differences.

    :param ipa_host: the host structure seen from IPA
    :param module_host: the target host structure seen from the module params

    :return: a dict representing the host attributes to apply
    """
    non_updateable_keys = ['ip_address']
    data = dict()
    for key in non_updateable_keys:
        if key in module_host:
            del module_host[key]

    for key in module_host.keys():
        ipa_value = ipa_host.get(key, None)
        module_value = module_host.get(key, None)
        if isinstance(ipa_value, list) and not isinstance(module_value, list):
            module_value = [module_value]
        if isinstance(ipa_value, list) and isinstance(module_value, list):
            ipa_value = sorted(ipa_value)
            module_value = sorted(module_value)
        if ipa_value != module_value:
            data[key]=unicode(module_value)
    return data


def get_module_host(module):
    """
    Creates a structure representing the host information

    Reads the module parameters and builds the host structure as expected from
    the module
    :param module: the ansible module
    :returns: a dict representing the host attributes
    """
    data = dict()
    certificates = module.params.get('certificates')
    if certificates:
        data['usercertificate'] = certificates
    sshpubkey = module.params.get('sshpubkey')
    if sshpubkey:
        data['ipasshpubkey'] = unicode(sshpubkey)
    ipaddress = module.params.get('ipaddress')
    if ipaddress:
        data['ip_address'] = unicode(ipaddress)
    random = module.params.get('random')
    if random:
        data['random'] = random
    return data


def ensure_host_present(module, api, ipahost):
    """
    Ensures that the host exists in IPA and has the same attributes.

    :param module: the ansible module
    :param api: IPA api handle
    :param ipahost: the host information present in IPA, can be none if the
                    host does not exist
    """
    fqdn = unicode(module.params.get('fqdn'))
    if ipahost:
        # Host already present, need to compare the attributes
        module_host = get_module_host(module)
        diffs = get_host_diff(ipahost, module_host)

        if not diffs:
            # Same attributes, success
            module.exit_json(changed=False, host=ipahost)

        # Need to modify the host - only if not in check_mode
        if module.check_mode:
            module.exit_json(changed=True)

        # If we want to create a random password, and the host
        # already has Keytab: true, then we need first to run
        # ipa host-disable in order to remove OTP and keytab
        if module.params.get('random') and ipahost['has_keytab'] == True:
            api.Command.host_disable(fqdn)

        result = api.Command.host_mod(fqdn, **diffs)
        # Save random password as it is not displayed by host-show
        if module.params.get('random'):
            randompassword = result['result']['randompassword']
        result = api.Command.host_show(fqdn)
        if module.params.get('random'):
            result['result']['randompassword'] = randompassword
        module.exit_json(changed=True, host=result['result'])

    if not ipahost:
        # Need to add the user, only if not in check_mode
        if module.check_mode:
            module.exit_json(changed=True)

        # Must add the user
        module_host = get_module_host(module)
        result = api.Command.host_add(fqdn, **module_host)
        # Save random password as it is not displayed by host-show
        if module.params.get('random'):
            randompassword = result['result']['randompassword']
        result = api.Command.host_show(fqdn)
        if module.params.get('random'):
            result['result']['randompassword'] = randompassword
        module.exit_json(changed=True, host=result['result'])


def ensure_host_absent(module, api, host):
    """
    Ensures that the host does not exist in IPA

    :param module: the ansible module
    :param api: the IPA API handle
    :param host: the host information present in IPA, can be none if the
                 host does not exist
    """
    if not host:
        # Nothing to do, host already removed
        module.exit_json(changed=False)

    # Need to remove the host - only if not in check_mode
    if module.check_mode:
        module.exit_json(changed=True, host=host)

    fqdn = unicode(module.params.get('fqdn'))
    try:
        api.Command.host_del(fqdn)
    except Exception as e:
        module.fail_json(msg="Failed to remove host: %s" % e)

    module.exit_json(changed=True)


def main():
    """
    Main routine for the ansible module.
    """
    module = AnsibleModule(
        argument_spec=dict(
            principal = dict(default='admin'),
            ccache = dict(required=False, type='path'),
            fqdn = dict(required=True),
            certificates = dict(required=False, type='list'),
            sshpubkey= dict(required=False),
            ipaddress = dict(required=False),
            random = dict(default=False, type='bool'),
            state = dict(default='present', choices=[ 'present', 'absent' ]),
            ansible_python_interpreter = dict(required=False),
        ),
        supports_check_mode=True,
    )

    principal = module.params.get('principal', 'admin')
    ccache = module.params.get('ccache')
    fqdn = unicode(module.params.get('fqdn'))
    state = module.params.get('state')

    try:
        os.environ['KRB5CCNAME']=ccache

        cfg = dict(
            context='ansible_module',
            confdir=paths.ETC_IPA,
            in_server=False,
            debug=False,
            verbose=0,
        )
        api.bootstrap(**cfg)
        api.finalize()
        api.Backend.rpcclient.connect()

        changed = False
        try:
            result = api.Command.host_show(fqdn, all=True)
            host = result['result']
        except errors.NotFound:
            host = None

        if state == 'present' or state == 'disabled':
            changed = ensure_host_present(module, api, host)
        elif state == 'absent':
            changed = ensure_host_absent(module, api, host)

    except Exception as e:
        module.fail_json(msg="ipahost module failed : %s" % str(e))
    finally:
        run([paths.KDESTROY], raiseonerr=False, env=os.environ)

    module.exit_json(changed=changed, host=host)

if __name__ == '__main__':
    main()

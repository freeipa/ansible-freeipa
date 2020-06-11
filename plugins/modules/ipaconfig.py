#!/usr/bin/python
# -*- coding: utf-8 -*-

# Authors:
#   Chris Procter <cprocter@redhat.com>
#
# Copyright (C) 2020 Red Hat
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

ANSIBLE_METADATA = {
    "metadata_version": "1.0",
    "supported_by": "community",
    "status": ["preview"],
}


DOCUMENTATION = '''
---
module: ipa_config
author: chris procter
short_description: Modify IPA global config options
description:
- Modify IPA global config options
options:
    ipaadmin_principal:
        description: The admin principal
        default: admin
    ipaadmin_password:
        description: The admin password
        required: false
    maxusername:
        description: Set the maximum username length between 1-255
        required: false
        aliases: ['ipamaxusernamelength']
    maxhostname:
        description: Set the maximum hostname length between 64-255
        required: false
        aliases: ['ipamaxhostnamelength']
    homedirectory:
        description: Set the default location of home directories
        required: false
        aliases: ['ipahomesrootdir']
    defaultshell:
        description: Set the default shell for new users
        required: false
        aliases: ['ipadefaultloginshell', 'loginshell']
    defaultgroup:
        description: Set the default group for new users
        required: false
        aliases: ['ipadefaultprimarygroup']
    emaildomain:
        description: Set the default e-mail domain
        required: false
        aliases: ['ipadefaultemaildomain']
    searchtimelimit:
        description:
        - Set maximum amount of time (seconds) for a search
        - values -1 to 2147483647 (-1 or 0 is unlimited)
        required: false
        aliases: ['ipasearchtimelimit']
    searchrecordslimit:
        description:
        - Set maximum number of records to search
        - values -1 to 2147483647 (-1 or 0 is unlimited)
        required: false
        aliases: ['ipasearchrecordslimit']
    usersearch:
        description:
        - Set comma-separated list of fields to search for user search
        required: false
        aliases: ['ipausersearchfields']
    groupsearch:
        description:
        - Set comma-separated list of fields to search for group search
        required: false
        aliases: ['ipagroupsearchfields']
    enable_migration:
        description: Enable migration mode
        type: bool
        required: false
        aliases: ['ipamigrationenabled']
    groupobjectclasses:
        description: Set default group objectclasses (comma-separated list)
        required: false
        type: list
        aliases: ['ipagroupobjectclasses']
    userobjectclasses:
        description: Set default user objectclasses (comma-separated list)
        required: false
        type: list
        aliases: ['ipauserobjectclasses']
    pwdexpnotify:
        description:
        - Set number of days's notice of impending password expiration
        - values 0 to 2147483647
        required: false
        aliases: ['ipapwdexpadvnotify']
    configstring:
        description: Set extra hashes to generate in password plug-in
        required: false
        type: list
        choices:
        - "AllowNThash"
        - "KDC:Disable Last Success"
        - "KDC:Disable Lockout"
        - "KDC:Disable Default Preauth for SPNs"
        - ""
        aliases: ['ipaconfigstring']
    selinuxusermaporder:
        description: Set order in increasing priority of SELinux users
        required: false
        type: list
        aliases: ['ipaselinuxusermaporder']
    selinuxusermapdefault:
        description: Set default SELinux user when no match found in map rule
        required: false
        aliases: ['ipaselinuxusermapdefault']
    pac_type:
        description: set default types of PAC supported for services
        required: false
        type: list
        choices: ["MS-PAC", "PAD", "nfs:NONE", ""]
        aliases: ["ipakrbauthzdata"]
    user_auth_type:
        description: set default types of supported user authentication
        required: false
        type: list
        choices: ["password", "radius", "otp", "disabled", ""]
        aliases: ["ipauserauthtype"]
    ca_renewal_master_server:
        description: Renewal master for IPA certificate authority.
        required: false
        type: string
    domain_resolution_order:
        description: set list of domains used for short name qualification
        required: false
        type: list
        aliases: ["ipadomainresolutionorder"]
'''

EXAMPLES = '''
---
- name: Playbook to handle global configuration options
  hosts: ipaserver
  become: true
  tasks:
    - name: return current values of the global configuration options
      ipaconfig:
        ipaadmin_password: password
      register: result
    - name: display default login shell
      debug:
        msg: '{{result.config.defaultshell[0] }}'

    - name: set defaultshell and maxusername
      ipaconfig:
        ipaadmin_password: password
        defaultshell: /bin/bash
        maxusername: 64
'''

RETURN = '''
config:
  description: Dict of all global config options
  returned: When no options are set
  type: dict
  options:
    maxusername:
        description: maximum username length
        returned: always
    maxhostname:
        description: maximum hostname length
        returned: always
    homedirectory:
        description: default location of home directories
        returned: always
    defaultshell:
        description: default shell for new users
        returned: always
    defaultgroup:
        description: default group for new users
        returned: always
    emaildomain:
        description: default e-mail domain
        returned: always
    searchtimelimit:
        description: maximum amount of time (seconds) for a search
        returned: always
    searchrecordslimit:
        description: maximum number of records to search
        returned: always
    usersearch:
        description: comma-separated list of fields to search in user search
        type: list
        returned: always
    groupsearch:
        description: comma-separated list of fields to search in group search
        type: list
        returned: always
    enable_migration:
        description: Enable migration mode
        type: bool
        returned: always
    groupobjectclasses:
        description: default group objectclasses (comma-separated list)
        type: list
        returned: always
    userobjectclasses:
        description: default user objectclasses (comma-separated list)
        type: list
        returned: always
    pwdexpnotify:
        description: number of days's notice of impending password expiration
        returned: always
    configstring:
        description: extra hashes to generate in password plug-in
        type: list
        returned: always
    selinuxusermaporder:
        description: order in increasing priority of SELinux users
        returned: always
    selinuxusermapdefault:
        description: default SELinux user when no match is found in map rule
        returned: always
    pac_type:
        description: default types of PAC supported for services
        type: list
        returned: always
    user_auth_type:
        description: default types of supported user authentication
        returned: always
    ca_renewal_master_server:
        description: master for IPA certificate authority.
        returned: always
    domain_resolution_order:
        description: list of domains used for short name qualification
        returned: always
'''


from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.ansible_freeipa_module import temp_kinit, \
    temp_kdestroy, valid_creds, api_connect, api_command_no_name, \
    compare_args_ipa, module_params_get
import ipalib.errors


def config_show(module):
    _result = api_command_no_name(module, "config_show", {})

    return _result["result"]


def gen_args(params):
    _args = {}
    for k, v in params.items():
        if v is not None:
            _args[k] = v

    return _args


def main():
    ansible_module = AnsibleModule(
        argument_spec=dict(
            # general
            ipaadmin_principal=dict(type="str", default="admin"),
            ipaadmin_password=dict(type="str", required=False, no_log=True),
            maxusername=dict(type="int", required=False,
                             aliases=['ipamaxusernamelength']),
            maxhostname=dict(type="int", required=False,
                             aliases=['ipamaxhostnamelength']),
            homedirectory=dict(type="str", required=False,
                               aliases=['ipahomesrootdir']),
            defaultshell=dict(type="str", required=False,
                              aliases=['ipadefaultloginshell',
                                       'loginshell']),
            defaultgroup=dict(type="str", required=False,
                              aliases=['ipadefaultprimarygroup']),
            emaildomain=dict(type="str", required=False,
                             aliases=['ipadefaultemaildomain']),
            searchtimelimit=dict(type="int", required=False,
                                 aliases=['ipasearchtimelimit']),
            searchrecordslimit=dict(type="int", required=False,
                                    aliases=['ipasearchrecordslimit']),
            usersearch=dict(type="list", required=False,
                            aliases=['ipausersearchfields']),
            groupsearch=dict(type="list", required=False,
                             aliases=['ipagroupsearchfields']),
            enable_migration=dict(type="bool", required=False,
                                  aliases=['ipamigrationenabled']),
            groupobjectclasses=dict(type="list", required=False,
                                    aliases=['ipagroupobjectclasses']),
            userobjectclasses=dict(type="list", required=False,
                                   aliases=['ipauserobjectclasses']),
            pwdexpnotify=dict(type="int", required=False,
                              aliases=['ipapwdexpadvnotify']),
            configstring=dict(type="list", required=False,
                              aliases=['ipaconfigstring'],
                              choices=["AllowNThash",
                                       "KDC:Disable Last Success",
                                       "KDC:Disable Lockout",
                                       "KDC:Disable Default Preauth for SPNs",
                                       ""]), # noqa E128
            selinuxusermaporder=dict(type="list", required=False,
                                     aliases=['ipaselinuxusermaporder']),
            selinuxusermapdefault=dict(type="str", required=False,
                                       aliases=['ipaselinuxusermapdefault']),
            pac_type=dict(type="list", required=False,
                          aliases=["ipakrbauthzdata"],
                          choices=["MS-PAC", "PAD", "nfs:NONE", ""]),
            user_auth_type=dict(type="list", required=False,
                                choices=["password", "radius", "otp",
                                         "disabled", ""],
                                aliases=["ipauserauthtype"]),
            ca_renewal_master_server=dict(type="str", required=False),
            domain_resolution_order=dict(type="list", required=False,
                                         aliases=["ipadomainresolutionorder"])
        ),
        supports_check_mode=True,
    )

    ansible_module._ansible_debug = True

    # Get parameters

    # general
    ipaadmin_principal = module_params_get(ansible_module,
                                           "ipaadmin_principal")
    ipaadmin_password = module_params_get(ansible_module,
                                          "ipaadmin_password")

    field_map = {
        "maxusername": "ipamaxusernamelength",
        "maxhostname": "ipamaxhostnamelength",
        "homedirectory": "ipahomesrootdir",
        "defaultshell": "ipadefaultloginshell",
        "defaultgroup": "ipadefaultprimarygroup",
        "emaildomain": "ipadefaultemaildomain",
        "searchtimelimit": "ipasearchtimelimit",
        "searchrecordslimit": "ipasearchrecordslimit",
        "usersearch": "ipausersearchfields",
        "groupsearch": "ipagroupsearchfields",
        "enable_migration": "ipamigrationenabled",
        "groupobjectclasses": "ipagroupobjectclasses",
        "userobjectclasses": "ipauserobjectclasses",
        "pwdexpnotify": "ipapwdexpadvnotify",
        "configstring": "ipaconfigstring",
        "selinuxusermaporder": "ipaselinuxusermaporder",
        "selinuxusermapdefault": "ipaselinuxusermapdefault",
        "pac_type": "ipakrbauthzdata",
        "user_auth_type": "ipauserauthtype",
        "ca_renewal_master_server": "ca_renewal_master_server",
        "domain_resolution_order": "ipadomainresolutionorder"
    }
    reverse_field_map = {v: k for k, v in field_map.items()}

    params = {}
    for x in field_map.keys():
        val = module_params_get(ansible_module, x)

        if val is not None:
            params[field_map.get(x, x)] = val

    if params.get("ipamigrationenabled") is not None:
        params["ipamigrationenabled"] = \
            str(params["ipamigrationenabled"]).upper()

    if params.get("ipaselinuxusermaporder", None):
        params["ipaselinuxusermaporder"] = \
            "$".join(params["ipaselinuxusermaporder"])

    if params.get("ipadomainresolutionorder", None):
        params["ipadomainresolutionorder"] = \
             ":".join(params["ipadomainresolutionorder"])

    if params.get("ipausersearchfields", None):
        params["ipausersearchfields"] = \
             ",".join(params["ipausersearchfields"])

    if params.get("ipagroupsearchfields", None):
        params["ipagroupsearchfields"] = \
             ",".join(params["ipagroupsearchfields"])

    # verify limits on INT values.
    args_with_limits = [
        ("ipamaxusernamelength", 1, 255),
        ("ipamaxhostnamelength", 64, 255),
        ("ipasearchtimelimit", -1, 2147483647),
        ("ipasearchrecordslimit", -1, 2147483647),
        ("ipapwdexpadvnotify", 0, 2147483647),
    ]
    for arg, min, max in args_with_limits:
        if arg in params and (params[arg] > max or params[arg] < min):
            ansible_module.fail_json(
                msg="Argument '%s' must be between %d and %d."
                    % (arg, min, max))

    changed = False
    exit_args = {}
    ccache_dir = None
    ccache_name = None
    res_show = None
    try:
        if not valid_creds(ansible_module, ipaadmin_principal):
            ccache_dir, ccache_name = temp_kinit(ipaadmin_principal,
                                                 ipaadmin_password)
        api_connect()
        if params:
            res_show = config_show(ansible_module)
            params = {
                k: v for k, v in params.items()
                if k not in res_show or res_show[k] != v
            }
            if params \
               and not compare_args_ipa(ansible_module, params, res_show):
                changed = True
                api_command_no_name(ansible_module, "config_mod", params)

        else:
            rawresult = api_command_no_name(ansible_module, "config_show", {})
            result = rawresult['result']
            del result['dn']
            for key, v in result.items():
                k = reverse_field_map.get(key, key)
                if ansible_module.argument_spec.get(k):
                    if k == 'ipaselinuxusermaporder':
                        exit_args['ipaselinuxusermaporder'] = \
                            result.get(key)[0].split('$')
                    elif k == 'domain_resolution_order':
                        exit_args['domain_resolution_order'] = \
                           result.get(key)[0].split('$')
                    elif k == 'usersearch':
                        exit_args['usersearch'] = \
                            result.get(key)[0].split(',')
                    elif k == 'groupsearch':
                        exit_args['groupsearch'] = \
                            result.get(key)[0].split(',')
                    elif isinstance(v, str) and \
                            ansible_module.argument_spec[k]['type'] == "list":
                        exit_args[k] = [v]
                    elif isinstance(v, list) and \
                            ansible_module.argument_spec[k]['type'] == "str":
                        exit_args[k] = ",".join(v)
                    elif isinstance(v, list) and \
                            ansible_module.argument_spec[k]['type'] == "int":
                        exit_args[k] = ",".join(v)
                    elif isinstance(v, list) and \
                            ansible_module.argument_spec[k]['type'] == "bool":
                        exit_args[k] = (v[0] == "TRUE")
                    else:
                        exit_args[k] = v
    except ipalib.errors.EmptyModlist:
        changed = False
    except Exception as e:
        ansible_module.fail_json(msg="%s %s" % (params, str(e)))

    finally:
        temp_kdestroy(ccache_dir, ccache_name)

    # Done
    ansible_module.exit_json(changed=changed, config=exit_args)


if __name__ == "__main__":
    main()

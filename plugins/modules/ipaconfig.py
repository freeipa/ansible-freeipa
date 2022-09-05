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

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

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
extends_documentation_fragment:
  - ipamodule_base_docs
options:
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
    enable_sid:
        description: >
          New users and groups automatically get a SID assigned.
          Requires IPA 4.9.8+.
        required: false
        type: bool
    netbios_name:
        description: >
          NetBIOS name of the IPA domain.
          Requires IPA 4.9.8+ and 'enable_sid: yes'.
        required: false
        type: string
    add_sids:
        description: >
          Add SIDs for existing users and groups.
          Requires IPA 4.9.8+ and 'enable_sid: yes'.
        required: false
        type: bool
'''

EXAMPLES = '''
---
- name: Playbook to handle global configuration options
  hosts: ipaserver
  become: true
  tasks:
    - name: return current values of the global configuration options
      ipaconfig:
        ipaadmin_password: SomeADMINpassword
      register: result
    - name: display default login shell
      debug:
        msg: '{{ result.config.defaultshell[0] }}'

    - name: set defaultshell and maxusername
      ipaconfig:
        ipaadmin_password: SomeADMINpassword
        defaultshell: /bin/bash
        maxusername: 64

- name: Playbook to enable SID and generate users and groups SIDs
  hosts: ipaserver
  tasks:
    - name: Enable SID and generate users and groups SIDS
      ipaconfig:
        ipaadmin_password: SomeADMINpassword
        enable_sid: yes
        add_sids: yes

- name: Playbook to change IPA domain netbios name
  hosts: ipaserver
  tasks:
    - name: Enable SID and generate users and groups SIDS
      ipaconfig:
        ipaadmin_password: SomeADMINpassword
        enable_sid: yes
        netbios_name: IPADOM
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
    enable_sid:
        description: >
          new users and groups automatically get a SID assigned.
          Requires IPA 4.9.8+.
        returned: always
    netbios_name:
        description: NetBIOS name of the IPA domain. Requires IPA 4.9.8+.
        returned: if enable_sid is True
'''


from ansible.module_utils.ansible_freeipa_module import \
    IPAAnsibleModule, compare_args_ipa, ipalib_errors


def config_show(module):
    _result = module.ipa_command_no_name("config_show", {"all": True})

    return _result["result"]


def get_netbios_name(module):
    try:
        _result = module.ipa_command_no_name("trustconfig_show", {"all": True})
    except Exception:  # pylint: disable=broad-except
        return None
    else:
        return _result["result"]["ipantflatname"][0]


def is_enable_sid(module):
    """When 'enable-sid' is true admin user and admins group have SID set."""
    _result = module.ipa_command("user_show", "admin", {"all": True})
    sid = _result["result"].get("ipantsecurityidentifier", [""])
    if not sid[0].endswith("-500"):
        return False
    _result = module.ipa_command("group_show", "admins", {"all": True})
    sid = _result["result"].get("ipantsecurityidentifier", [""])
    if not sid[0].endswith("-512"):
        return False
    return True


def main():
    ansible_module = IPAAnsibleModule(
        argument_spec=dict(
            # general
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
                                       ""]),  # noqa E128
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
                                         aliases=["ipadomainresolutionorder"]),
            enable_sid=dict(type="bool", required=False),
            add_sids=dict(type="bool", required=False),
            netbios_name=dict(type="str", required=False),
        ),
        supports_check_mode=True,
    )

    ansible_module._ansible_debug = True

    # Get parameters

    # general
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
        "domain_resolution_order": "ipadomainresolutionorder",
        "enable_sid": "enable_sid",
        "netbios_name": "netbios_name",
        "add_sids": "add_sids",
    }
    allow_empty_string = ["pac_type", "user_auth_type", "configstring"]
    reverse_field_map = {v: k for k, v in field_map.items()}

    params = {}
    for x in field_map:
        val = ansible_module.params_get(
            x, allow_empty_string=(x in allow_empty_string))

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
    for arg, minimum, maximum in args_with_limits:
        if arg in params and (params[arg] > maximum or params[arg] < minimum):
            ansible_module.fail_json(
                msg="Argument '%s' must be between %d and %d."
                    % (arg, minimum, maximum))

    changed = False
    exit_args = {}

    # Connect to IPA API (enable-sid requires context == 'client')
    with ansible_module.ipa_connect(context="client"):
        has_enable_sid = ansible_module.ipa_command_param_exists(
            "config_mod", "enable_sid")

        result = config_show(ansible_module)

        if params:
            netbios_name = params.get("netbios_name")
            if netbios_name:
                netbios_name = netbios_name.upper()
            add_sids = params.get("add_sids")
            enable_sid = params.get("enable_sid")
            required_sid = any([netbios_name, add_sids])
            if required_sid and not enable_sid:
                ansible_module.fail_json(
                    "'enable-sid: yes' required for 'netbios_name' "
                    "and 'add-sids'."
                )
            if enable_sid:
                if not has_enable_sid:
                    ansible_module.fail_json(
                        "This version of IPA does not support 'enable-sid'.")
                if (
                    netbios_name
                    and netbios_name == get_netbios_name(ansible_module)
                ):
                    del params["netbios_name"]
                    netbios_name = None
                if not add_sids and "add_sids" in params:
                    del params["add_sids"]
                if (
                    not any([netbios_name, add_sids])
                    and is_enable_sid(ansible_module)
                ):
                    del params["enable_sid"]
            else:
                for param in ["enable_sid", "netbios_name", "add_sids"]:
                    if param in params:
                        del params[params]

            params = {
                k: v for k, v in params.items()
                if k not in result or result[k] != v
            }
            # Remove empty string args from params if result arg is not set
            for k in ["ipakrbauthzdata", "ipauserauthtype", "ipaconfigstring"]:
                if k not in result and k in params and params[k] == [""]:
                    del params[k]
            if params \
               and not compare_args_ipa(ansible_module, params, result):
                changed = True
                if not ansible_module.check_mode:
                    try:
                        ansible_module.ipa_command_no_name("config_mod",
                                                           params)
                    except ipalib_errors.EmptyModlist:
                        changed = False
        else:
            del result['dn']
            type_map = {"str": str, "int": int, "list": list, "bool": bool}
            for key, value in result.items():
                k = reverse_field_map.get(key, key)
                if ansible_module.argument_spec.get(k):
                    arg_type = ansible_module.argument_spec[k]['type']
                    if k in (
                        'ipaselinuxusermaporder', 'domain_resolution_order'
                    ):
                        exit_args[k] = result.get(key)[0].split('$')
                    elif k in (
                        'usersearch', 'groupsearch'
                    ):
                        exit_args[k] = result.get(key)[0].split(',')
                    elif isinstance(value, str) and arg_type == "list":
                        exit_args[k] = [value]
                    elif (
                        isinstance(value, (tuple, list))
                        and arg_type in ("str", "int")
                    ):
                        exit_args[k] = type_map[arg_type](value[0])
                    elif (
                        isinstance(value, (tuple, list)) and arg_type == "bool"
                    ):
                        # FreeIPA 4.9.10+ and 4.10 use proper mapping for
                        # boolean values, so we need to convert it to str
                        # for comparison.
                        # See: https://github.com/freeipa/freeipa/pull/6294
                        exit_args[k] = (str(value[0]).upper() == "TRUE")
                    else:
                        if arg_type not in type_map:
                            raise ValueError(
                                "Unexpected attribute type: %s" % arg_type)
                        exit_args[k] = type_map[arg_type](value)
            # Add empty pac_type and user_auth_type if they are not set
            for key in ["pac_type", "user_auth_type"]:
                if key not in exit_args:
                    exit_args[key] = ""
            # Add empty domain_resolution_order if it is not set
            if "domain_resolution_order" not in exit_args:
                exit_args["domain_resolution_order"] = []
            # Set enable_sid
            if has_enable_sid:
                exit_args["enable_sid"] = is_enable_sid(ansible_module)
                exit_args["netbios_name"] = get_netbios_name(ansible_module)

    # Done
    ansible_module.exit_json(changed=changed, config=exit_args)


if __name__ == "__main__":
    main()

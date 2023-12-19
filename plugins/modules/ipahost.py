# -*- coding: utf-8 -*-

# Authors:
#   Thomas Woerner <twoerner@redhat.com>
#
# Copyright (C) 2019-2022 Red Hat
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
module: ipahost
short_description: Manage FreeIPA hosts
description: Manage FreeIPA hosts
extends_documentation_fragment:
  - ipamodule_base_docs
options:
  name:
    description: The full qualified domain name.
    type: list
    elements: str
    aliases: ["fqdn"]
    required: false
  hosts:
    description: The list of host dicts
    required: false
    type: list
    elements: dict
    suboptions:
      name:
        description: The host (internally uid).
        type: str
        aliases: ["fqdn"]
        required: true
      description:
        description: The host description
        type: str
        required: false
      locality:
        description: Host locality (e.g. "Baltimore, MD")
        type: str
        required: false
      location:
        description: Host physical location hist (e.g. "Lab 2")
        type: str
        aliases: ["ns_host_location"]
        required: false
      platform:
        description: Host hardware platform (e.g. "Lenovo T61")
        type: str
        aliases: ["ns_hardware_platform"]
        required: false
      os:
        description: Host operating system and version (e.g. "Fedora 9")
        type: str
        aliases: ["ns_os_version"]
        required: false
      password:
        description: Password used in bulk enrollment
        type: str
        aliases: ["user_password", "userpassword"]
        required: false
      random:
        description:
          Initiate the generation of a random password to be used in bulk
          enrollment
        type: bool
        aliases: ["random_password"]
        required: false
      certificate:
        description: List of base-64 encoded host certificates
        type: list
        elements: str
        aliases: ["usercertificate"]
        required: false
      managedby_host:
        description: List of hosts that can manage this host
        type: list
        elements: str
        required: false
      principal:
        description: List of principal aliases for this host
        type: list
        elements: str
        aliases: ["principalname", "krbprincipalname"]
        required: false
      allow_create_keytab_user:
        description: Users allowed to create a keytab of this host
        type: list
        elements: str
        aliases: ["ipaallowedtoperform_write_keys_user"]
        required: false
      allow_create_keytab_group:
        description: Groups allowed to create a keytab of this host
        type: list
        elements: str
        aliases: ["ipaallowedtoperform_write_keys_group"]
        required: false
      allow_create_keytab_host:
        description: Hosts allowed to create a keytab of this host
        type: list
        elements: str
        aliases: ["ipaallowedtoperform_write_keys_host"]
        required: false
      allow_create_keytab_hostgroup:
        description: Hostgroups allowed to create a keytab of this host
        type: list
        elements: str
        aliases: ["ipaallowedtoperform_write_keys_hostgroup"]
        required: false
      allow_retrieve_keytab_user:
        description: Users allowed to retrieve a keytab of this host
        type: list
        elements: str
        aliases: ["ipaallowedtoperform_read_keys_user"]
        required: false
      allow_retrieve_keytab_group:
        description: Groups allowed to retrieve a keytab of this host
        type: list
        elements: str
        aliases: ["ipaallowedtoperform_read_keys_group"]
        required: false
      allow_retrieve_keytab_host:
        description: Hosts allowed to retrieve a keytab of this host
        type: list
        elements: str
        aliases: ["ipaallowedtoperform_read_keys_host"]
        required: false
      allow_retrieve_keytab_hostgroup:
        description: Hostgroups allowed to retrieve a keytab of this host
        type: list
        elements: str
        aliases: ["ipaallowedtoperform_read_keys_hostgroup"]
        required: false
      mac_address:
        description: List of hardware MAC addresses.
        type: list
        elements: str
        aliases: ["macaddress"]
        required: false
      sshpubkey:
        description: List of SSH public keys
        type: list
        elements: str
        aliases: ["ipasshpubkey"]
        required: false
      userclass:
        description:
          Host category (semantics placed on this attribute are for local
          interpretation)
        type: list
        elements: str
        aliases: ["class"]
        required: false
      auth_ind:
        description:
          Defines an allow list for Authentication Indicators. Use 'otp'
          to allow OTP-based 2FA authentications. Use 'radius' to allow
          RADIUS-based 2FA authentications. Other values may be used
          for custom configurations. Use empty string to reset auth_ind
          to the initial value.
        type: list
        elements: str
        aliases: ["krbprincipalauthind"]
        choices: ["radius", "otp", "pkinit", "hardened", "idp", ""]
        required: false
      requires_pre_auth:
        description: Pre-authentication is required for the service
        type: bool
        aliases: ["ipakrbrequirespreauth"]
        required: false
      ok_as_delegate:
        description: Client credentials may be delegated to the service
        type: bool
        aliases: ["ipakrbokasdelegate"]
        required: false
      ok_to_auth_as_delegate:
        description:
          The service is allowed to authenticate on behalf of a client
        type: bool
        aliases: ["ipakrboktoauthasdelegate"]
        required: false
      force:
        description: Force host name even if not in DNS
        type: bool
        required: false
      reverse:
        description: Reverse DNS detection
        type: bool
        required: false
      ip_address:
        description:
          The host IP address list (IPv4 and IPv6). No IP address conflict
          check will be done.
        type: list
        elements: str
        aliases: ["ipaddress"]
        required: false
      update_dns:
        description:
          Controls the update of the DNS SSHFP records for existing hosts and
          the removal of all DNS entries if a host gets removed with state
          absent.
        type: bool
        aliases: ["updatedns"]
        required: false
  description:
    description: The host description
    type: str
    required: false
  locality:
    description: Host locality (e.g. "Baltimore, MD")
    type: str
    required: false
  location:
    description: Host location (e.g. "Lab 2")
    type: str
    aliases: ["ns_host_location"]
    required: false
  platform:
    description: Host hardware platform (e.g. "Lenovo T61")
    type: str
    aliases: ["ns_hardware_platform"]
    required: false
  os:
    description: Host operating system and version (e.g. "Fedora 9")
    type: str
    aliases: ["ns_os_version"]
    required: false
  password:
    description: Password used in bulk enrollment
    type: str
    aliases: ["user_password", "userpassword"]
    required: false
  random:
    description:
      Initiate the generation of a random password to be used in bulk
      enrollment
    type: bool
    aliases: ["random_password"]
    required: false
  certificate:
    description: List of base-64 encoded host certificates
    type: list
    elements: str
    aliases: ["usercertificate"]
    required: false
  managedby_host:
    description: List of hosts that can manage this host
    type: list
    elements: str
    required: false
  principal:
    description: List of principal aliases for this host
    type: list
    elements: str
    aliases: ["principalname", "krbprincipalname"]
    required: false
  allow_create_keytab_user:
    description: Users allowed to create a keytab of this host
    type: list
    elements: str
    aliases: ["ipaallowedtoperform_write_keys_user"]
    required: false
  allow_create_keytab_group:
    description: Groups allowed to create a keytab of this host
    type: list
    elements: str
    aliases: ["ipaallowedtoperform_write_keys_group"]
    required: false
  allow_create_keytab_host:
    description: Hosts allowed to create a keytab of this host
    type: list
    elements: str
    aliases: ["ipaallowedtoperform_write_keys_host"]
    required: false
  allow_create_keytab_hostgroup:
    description: Hostgroups allowed to create a keytab of this host
    type: list
    elements: str
    aliases: ["ipaallowedtoperform_write_keys_hostgroup"]
    required: false
  allow_retrieve_keytab_user:
    description: Users allowed to retrieve a keytab of this host
    type: list
    elements: str
    aliases: ["ipaallowedtoperform_read_keys_user"]
    required: false
  allow_retrieve_keytab_group:
    description: Groups allowed to retrieve a keytab of this host
    type: list
    elements: str
    aliases: ["ipaallowedtoperform_read_keys_group"]
    required: false
  allow_retrieve_keytab_host:
    description: Hosts allowed to retrieve a keytab of this host
    type: list
    elements: str
    aliases: ["ipaallowedtoperform_read_keys_host"]
    required: false
  allow_retrieve_keytab_hostgroup:
    description: Hostgroups allowed to retrieve a keytab of this host
    type: list
    elements: str
    aliases: ["ipaallowedtoperform_read_keys_hostgroup"]
    required: false
  mac_address:
    description: List of hardware MAC addresses.
    type: list
    elements: str
    aliases: ["macaddress"]
    required: false
  sshpubkey:
    description: List of SSH public keys
    type: list
    elements: str
    aliases: ["ipasshpubkey"]
    required: false
  userclass:
    description:
      Host category (semantics placed on this attribute are for local
      interpretation)
    type: list
    elements: str
    aliases: ["class"]
    required: false
  auth_ind:
    description:
      Defines an allow list for Authentication Indicators. Use 'otp'
      to allow OTP-based 2FA authentications. Use 'radius' to allow
      RADIUS-based 2FA authentications. Other values may be used
      for custom configurations. Use empty string to reset auth_ind
      to the initial value.
    type: list
    elements: str
    aliases: ["krbprincipalauthind"]
    choices: ["radius", "otp", "pkinit", "hardened", "idp", ""]
    required: false
  requires_pre_auth:
    description: Pre-authentication is required for the service
    type: bool
    aliases: ["ipakrbrequirespreauth"]
    required: false
  ok_as_delegate:
    description: Client credentials may be delegated to the service
    type: bool
    aliases: ["ipakrbokasdelegate"]
    required: false
  ok_to_auth_as_delegate:
    description:
      The service is allowed to authenticate on behalf of a client
    type: bool
    aliases: ["ipakrboktoauthasdelegate"]
    required: false
  force:
    description: Force host name even if not in DNS
    type: bool
    required: false
  reverse:
    description: Reverse DNS detection
    type: bool
    required: false
  ip_address:
    description:
      The host IP address list (IPv4 and IPv6). No IP address conflict
      check will be done.
    type: list
    elements: str
    aliases: ["ipaddress"]
    required: false
  update_dns:
    description:
      Controls the update of the DNS SSHFP records for existing hosts and
      the removal of all DNS entries if a host gets removed with state
      absent.
    type: bool
    aliases: ["updatedns"]
    required: false
  update_password:
    description:
      Set password for a host in present state only on creation or always
    type: str
    choices: ["always", "on_create"]
  action:
    description: Work on host or member level
    type: str
    default: "host"
    choices: ["member", "host"]
  state:
    description: State to ensure
    type: str
    default: present
    choices: ["present", "absent",
              "disabled"]
author:
  - Thomas Woerner (@t-woerner)
"""

EXAMPLES = """
# Ensure host is present
- ipahost:
    ipaadmin_password: SomeADMINpassword
    name: host01.example.com
    description: Example host
    ip_address: 192.168.0.123
    locality: Lab
    ns_host_location: Lab
    ns_os_version: CentOS 7
    ns_hardware_platform: Lenovo T61
    mac_address:
    - "08:00:27:E3:B1:2D"
    - "52:54:00:BD:97:1E"
    state: present

# Ensure host is present without DNS
- ipahost:
    ipaadmin_password: SomeADMINpassword
    name: host02.example.com
    description: Example host
    force: yes

# Ensure multiple hosts are present with random passwords
- ipahost:
    ipaadmin_password: SomeADMINpassword
    hosts:
    - name: host01.example.com
      random: yes
    - name: host02.example.com
      random: yes

# Initiate generation of a random password for the host
- ipahost:
    ipaadmin_password: SomeADMINpassword
    name: host01.example.com
    description: Example host
    ip_address: 192.168.0.123
    random: yes

# Ensure multiple hosts are present with principals
- ipahost:
    ipaadmin_password: SomeADMINpassword
    hosts:
    - name: host01.example.com
      principal:
      - host/testhost01.example.com
    - name: host02.example.com
      principal:
      - host/myhost01.example.com
    action: member

# Ensure host is disabled
- ipahost:
    ipaadmin_password: SomeADMINpassword
    name: host01.example.com
    update_dns: yes
    state: disabled

# Ensure host is absent
- ipahost:
    ipaadmin_password: SomeADMINpassword
    name: host01.example.com
    state: absent
"""

RETURN = """
host:
  description: Host dict with random password
  returned: If random is yes and host did not exist or update_password is yes
  type: dict
  contains:
    randompassword:
      description: The generated random password
      type: str
      returned: |
        If only one host is handled by the module without using hosts parameter
    name:
      description: The host name of the host that got a new random password
      returned: |
        If several hosts are handled by the module with the hosts parameter
      type: dict
      contains:
        randompassword:
          description: The generated random password
          type: str
          returned: always
"""

from ansible.module_utils.ansible_freeipa_module import \
    IPAAnsibleModule, compare_args_ipa, gen_add_del_lists, \
    encode_certificate, is_ipv4_addr, is_ipv6_addr, ipalib_errors
from ansible.module_utils import six
if six.PY3:
    unicode = str


def find_host(module, name):
    _args = {
        "all": True,
    }

    try:
        _result = module.ipa_command("host_show", name, _args)
    except ipalib_errors.NotFound as e:
        msg = str(e)
        if "host not found" in msg:
            return None
        module.fail_json(msg="host_show failed: %s" % msg)

    _res = _result["result"]
    certs = _res.get("usercertificate")
    if certs is not None:
        _res["usercertificate"] = [encode_certificate(cert) for
                                   cert in certs]
    return _res


def find_dnsrecord(module, name):
    """
    Search for a DNS record.

    This function may raise ipalib_errors.NotFound in some cases,
    and it should be handled by the caller.
    """
    domain_name = name[name.find(".") + 1:]
    host_name = name[:name.find(".")]

    _args = {
        "all": True,
        "idnsname": host_name
    }

    _result = module.ipa_command("dnsrecord_show", domain_name, _args)

    return _result["result"]


def show_host(module, name):
    _result = module.ipa_command("host_show", name, {})
    return _result["result"]


def gen_args(description, locality, location, platform, os, password, random,
             mac_address, sshpubkey, userclass, auth_ind, requires_pre_auth,
             ok_as_delegate, ok_to_auth_as_delegate, force, _reverse,
             ip_address, update_dns):
    # certificate, managedby_host, principal, create_keytab_* and
    # allow_retrieve_keytab_* are not handled here
    _args = {}
    if description is not None:
        _args["description"] = description
    if locality is not None:
        _args["l"] = locality
    if location is not None:
        _args["nshostlocation"] = location
    if platform is not None:
        _args["nshardwareplatform"] = platform
    if os is not None:
        _args["nsosversion"] = os
    if password is not None:
        _args["userpassword"] = password
    if random is not None:
        _args["random"] = random
    if mac_address is not None:
        _args["macaddress"] = mac_address
    if sshpubkey is not None:
        _args["ipasshpubkey"] = sshpubkey
    if userclass is not None:
        _args["userclass"] = userclass
    if auth_ind is not None:
        _args["krbprincipalauthind"] = auth_ind
    if requires_pre_auth is not None:
        _args["ipakrbrequirespreauth"] = requires_pre_auth
    if ok_as_delegate is not None:
        _args["ipakrbokasdelegate"] = ok_as_delegate
    if ok_to_auth_as_delegate is not None:
        _args["ipakrboktoauthasdelegate"] = ok_to_auth_as_delegate
    if force is not None:
        _args["force"] = force
    if ip_address is not None:
        # IP addresses are handed extra, therefore it is needed to set
        # the force option here to make sure that host-add is able to
        # add a host without IP address.
        _args["force"] = True
    if update_dns is not None:
        _args["updatedns"] = update_dns

    return _args


def gen_dnsrecord_args(module, ip_address, reverse):
    _args = {}
    if reverse is not None:
        _args["a_extra_create_reverse"] = reverse
        _args["aaaa_extra_create_reverse"] = reverse
    if ip_address is not None:
        for ip in ip_address:
            if is_ipv4_addr(ip):
                _args.setdefault("arecord", []).append(ip)
            elif is_ipv6_addr(ip):
                _args.setdefault("aaaarecord", []).append(ip)
            else:
                module.fail_json(msg="'%s' is not a valid IP address." % ip)

    return _args


def check_parameters(   # pylint: disable=unused-argument
        module, state, action,
        description, locality, location, platform, os, password, random,
        certificate, managedby_host, principal, allow_create_keytab_user,
        allow_create_keytab_group, allow_create_keytab_host,
        allow_create_keytab_hostgroup, allow_retrieve_keytab_user,
        allow_retrieve_keytab_group, allow_retrieve_keytab_host,
        allow_retrieve_keytab_hostgroup, mac_address, sshpubkey,
        userclass, auth_ind, requires_pre_auth, ok_as_delegate,
        ok_to_auth_as_delegate, force, reverse, ip_address, update_dns,
        update_password):
    invalid = []
    if state == "present":
        if action == "member":
            # certificate, managedby_host, principal,
            # allow_create_keytab_*, allow_retrieve_keytab_*,
            invalid = ["description", "locality", "location", "platform",
                       "os", "password", "random", "mac_address", "sshpubkey",
                       "userclass", "auth_ind", "requires_pre_auth",
                       "ok_as_delegate", "ok_to_auth_as_delegate", "force",
                       "reverse", "update_dns", "update_password"]

    if state == "absent":
        invalid = ["description", "locality", "location", "platform", "os",
                   "password", "random", "mac_address", "sshpubkey",
                   "userclass", "auth_ind", "requires_pre_auth",
                   "ok_as_delegate", "ok_to_auth_as_delegate", "force",
                   "reverse", "update_password"]
        if action == "host":
            invalid = [
                "certificate", "managedby_host", "principal",
                "allow_create_keytab_user", "allow_create_keytab_group",
                "allow_create_keytab_host", "allow_create_keytab_hostgroup",
                "allow_retrieve_keytab_user", "allow_retrieve_keytab_group",
                "allow_retrieve_keytab_host",
                "allow_retrieve_keytab_hostgroup"
            ]

    module.params_fail_used_invalid(invalid, state, action)


def check_authind(module, auth_ind):
    _invalid = module.ipa_command_invalid_param_choices(
        "host_add", "krbprincipalauthind", auth_ind)
    if _invalid:
        module.fail_json(
            msg="The use of krbprincipalauthind '%s' is not supported "
            "by your IPA version" % "','".join(_invalid))


# pylint: disable=unused-argument
def result_handler(module, result, command, name, args, errors, exit_args,
                   single_host):
    if "random" in args and command in ["host_add", "host_mod"] \
       and "randompassword" in result["result"]:
        if single_host:
            exit_args["randompassword"] = \
                result["result"]["randompassword"]
        else:
            exit_args.setdefault(name, {})["randompassword"] = \
                result["result"]["randompassword"]

    # All "already a member" and "not a member" failures in the
    # result are ignored. All others are reported.
    if "failed" in result and len(result["failed"]) > 0:
        for item in result["failed"]:
            failed_item = result["failed"][item]
            for member_type in failed_item:
                for member, failure in failed_item[member_type]:
                    if "already a member" in failure \
                       or "not a member" in failure:
                        continue
                    errors.append("%s: %s %s: %s" % (
                        command, member_type, member, failure))


# pylint: disable=unused-argument
def exception_handler(module, ex, errors, exit_args, single_host):
    msg = str(ex)
    if "already contains" in msg \
       or "does not contain" in msg:
        return True

    #  The canonical principal name may not be removed
    if "equal to the canonical principal name must" in msg:
        return True

    # Host is already disabled, ignore error
    if "This entry is already disabled" in msg:
        return True

    # Ignore no modification error.
    if "no modifications to be performed" in msg:
        return True

    return False


def main():
    host_spec = dict(
        # present
        description=dict(type="str", default=None),
        locality=dict(type="str", default=None),
        location=dict(type="str", aliases=["ns_host_location"],
                      default=None),
        platform=dict(type="str", aliases=["ns_hardware_platform"],
                      default=None),
        os=dict(type="str", aliases=["ns_os_version"], default=None),
        password=dict(type="str",
                      aliases=["user_password", "userpassword"],
                      default=None, no_log=True),
        random=dict(type="bool", aliases=["random_password"],
                    default=None),
        certificate=dict(type="list", elements="str",
                         aliases=["usercertificate"], default=None),
        managedby_host=dict(type="list", elements="str", default=None),
        principal=dict(type="list", elements="str",
                       aliases=["principalname", "krbprincipalname"],
                       default=None),
        allow_create_keytab_user=dict(
            type="list", elements="str",
            aliases=["ipaallowedtoperform_write_keys_user"],
            default=None, no_log=False),
        allow_create_keytab_group=dict(
            type="list", elements="str",
            aliases=["ipaallowedtoperform_write_keys_group"],
            default=None, no_log=False),
        allow_create_keytab_host=dict(
            type="list", elements="str",
            aliases=["ipaallowedtoperform_write_keys_host"],
            default=None, no_log=False),
        allow_create_keytab_hostgroup=dict(
            type="list", elements="str",
            aliases=["ipaallowedtoperform_write_keys_hostgroup"],
            default=None, no_log=False),
        allow_retrieve_keytab_user=dict(
            type="list", elements="str",
            aliases=["ipaallowedtoperform_read_keys_user"],
            default=None, no_log=False),
        allow_retrieve_keytab_group=dict(
            type="list", elements="str",
            aliases=["ipaallowedtoperform_read_keys_group"],
            default=None, no_log=False),
        allow_retrieve_keytab_host=dict(
            type="list", elements="str",
            aliases=["ipaallowedtoperform_read_keys_host"],
            default=None, no_log=False),
        allow_retrieve_keytab_hostgroup=dict(
            type="list", elements="str",
            aliases=["ipaallowedtoperform_read_keys_hostgroup"],
            default=None, no_log=False),
        mac_address=dict(type="list", elements="str", aliases=["macaddress"],
                         default=None),
        sshpubkey=dict(type="list", elements="str", aliases=["ipasshpubkey"],
                       default=None),
        userclass=dict(type="list", elements="str", aliases=["class"],
                       default=None),
        auth_ind=dict(type='list', elements="str",
                      aliases=["krbprincipalauthind"], default=None,
                      choices=["radius", "otp", "pkinit", "hardened", "idp",
                               ""]),
        requires_pre_auth=dict(type="bool", aliases=["ipakrbrequirespreauth"],
                               default=None),
        ok_as_delegate=dict(type="bool", aliases=["ipakrbokasdelegate"],
                            default=None),
        ok_to_auth_as_delegate=dict(type="bool",
                                    aliases=["ipakrboktoauthasdelegate"],
                                    default=None),
        force=dict(type='bool', default=None),
        reverse=dict(type='bool', default=None),
        ip_address=dict(type="list", elements="str", aliases=["ipaddress"],
                        default=None),
        update_dns=dict(type="bool", aliases=["updatedns"],
                        default=None),
        # no_members

        # for update:
        # krbprincipalname
    )

    ansible_module = IPAAnsibleModule(
        argument_spec=dict(
            # general
            name=dict(type="list", elements="str", aliases=["fqdn"],
                      default=None, required=False),

            hosts=dict(type="list", default=None,
                       options=dict(
                           # Here name is a simple string
                           name=dict(type="str", aliases=["fqdn"],
                                     required=True),
                           # Add host specific parameters
                           **host_spec
                       ),
                       elements='dict', required=False),

            # mod
            update_password=dict(type='str', default=None, no_log=False,
                                 choices=['always', 'on_create']),

            # general
            action=dict(type="str", default="host",
                        choices=["member", "host"]),
            state=dict(type="str", default="present",
                       choices=["present", "absent", "disabled"]),

            # Add host specific parameters for simple use case
            **host_spec
        ),
        mutually_exclusive=[["name", "hosts"]],
        required_one_of=[["name", "hosts"]],
        supports_check_mode=True,
    )

    ansible_module._ansible_debug = True

    # Get parameters

    # general
    names = ansible_module.params_get("name")
    hosts = ansible_module.params_get("hosts")

    # present
    description = ansible_module.params_get("description")
    locality = ansible_module.params_get("locality")
    location = ansible_module.params_get("location")
    platform = ansible_module.params_get("platform")
    os = ansible_module.params_get("os")
    password = ansible_module.params_get("password")
    random = ansible_module.params_get("random")
    certificate = ansible_module.params_get("certificate")
    managedby_host = ansible_module.params_get("managedby_host")
    principal = ansible_module.params_get("principal")
    allow_create_keytab_user = ansible_module.params_get(
        "allow_create_keytab_user")
    allow_create_keytab_group = ansible_module.params_get(
        "allow_create_keytab_group")
    allow_create_keytab_host = ansible_module.params_get(
        "allow_create_keytab_host")
    allow_create_keytab_hostgroup = ansible_module.params_get(
        "allow_create_keytab_hostgroup")
    allow_retrieve_keytab_user = ansible_module.params_get(
        "allow_retrieve_keytab_user")
    allow_retrieve_keytab_group = ansible_module.params_get(
        "allow_retrieve_keytab_group")
    allow_retrieve_keytab_host = ansible_module.params_get(
        "allow_retrieve_keytab_host")
    allow_retrieve_keytab_hostgroup = ansible_module.params_get(
        "allow_retrieve_keytab_hostgroup")
    mac_address = ansible_module.params_get("mac_address")
    sshpubkey = ansible_module.params_get(
        "sshpubkey", allow_empty_list_item=True)
    userclass = ansible_module.params_get("userclass")
    auth_ind = ansible_module.params_get(
        "auth_ind", allow_empty_list_item=True)
    requires_pre_auth = ansible_module.params_get("requires_pre_auth")
    ok_as_delegate = ansible_module.params_get("ok_as_delegate")
    ok_to_auth_as_delegate = ansible_module.params_get(
        "ok_to_auth_as_delegate")
    force = ansible_module.params_get("force")
    reverse = ansible_module.params_get("reverse")
    ip_address = ansible_module.params_get("ip_address")
    update_dns = ansible_module.params_get("update_dns")
    update_password = ansible_module.params_get("update_password")
    # general
    action = ansible_module.params_get("action")
    state = ansible_module.params_get("state")

    # Check parameters

    if (names is None or len(names) < 1) and \
       (hosts is None or len(hosts) < 1):
        ansible_module.fail_json(msg="One of name and hosts is required")

    if state == "present":
        if names is not None and len(names) != 1:
            ansible_module.fail_json(
                msg="Only one host can be added at a time.")

    check_parameters(
        ansible_module, state, action,
        description, locality, location, platform, os, password, random,
        certificate, managedby_host, principal, allow_create_keytab_user,
        allow_create_keytab_group, allow_create_keytab_host,
        allow_create_keytab_hostgroup, allow_retrieve_keytab_user,
        allow_retrieve_keytab_group, allow_retrieve_keytab_host,
        allow_retrieve_keytab_hostgroup, mac_address, sshpubkey, userclass,
        auth_ind, requires_pre_auth, ok_as_delegate, ok_to_auth_as_delegate,
        force, reverse, ip_address, update_dns, update_password)

    # Use hosts if names is None
    if hosts is not None:
        names = hosts

    # Init

    changed = False
    exit_args = {}

    # Connect to IPA API
    with ansible_module.ipa_connect():

        # Check version specific settings

        check_authind(ansible_module, auth_ind)

        server_realm = ansible_module.ipa_get_realm()

        commands = []
        host_set = set()

        for host in names:
            if isinstance(host, dict):
                name = host.get("name")
                if name in host_set:
                    ansible_module.fail_json(
                        msg="host '%s' is used more than once" % name)
                host_set.add(name)
                description = host.get("description")
                locality = host.get("locality")
                location = host.get("location")
                platform = host.get("platform")
                os = host.get("os")
                password = host.get("password")
                random = host.get("random")
                certificate = host.get("certificate")
                managedby_host = host.get("managedby_host")
                principal = host.get("principal")
                allow_create_keytab_user = host.get(
                    "allow_create_keytab_user")
                allow_create_keytab_group = host.get(
                    "allow_create_keytab_group")
                allow_create_keytab_host = host.get(
                    "allow_create_keytab_host")
                allow_create_keytab_hostgroup = host.get(
                    "allow_create_keytab_hostgroup")
                allow_retrieve_keytab_user = host.get(
                    "allow_retrieve_keytab_user")
                allow_retrieve_keytab_group = host.get(
                    "allow_retrieve_keytab_group")
                allow_retrieve_keytab_host = host.get(
                    "allow_retrieve_keytab_host")
                allow_retrieve_keytab_hostgroup = host.get(
                    "allow_retrieve_keytab_hostgroup")
                mac_address = host.get("mac_address")
                sshpubkey = host.get("sshpubkey")
                userclass = host.get("userclass")
                auth_ind = host.get("auth_ind")
                check_authind(ansible_module, auth_ind)
                requires_pre_auth = host.get("requires_pre_auth")
                ok_as_delegate = host.get("ok_as_delegate")
                ok_to_auth_as_delegate = host.get("ok_to_auth_as_delegate")
                force = host.get("force")
                reverse = host.get("reverse")
                ip_address = host.get("ip_address")
                update_dns = host.get("update_dns")
                # update_password is not part of hosts structure
                # action is not part of hosts structure
                # state is not part of hosts structure

                check_parameters(
                    ansible_module, state, action,
                    description, locality, location, platform, os, password,
                    random, certificate, managedby_host, principal,
                    allow_create_keytab_user, allow_create_keytab_group,
                    allow_create_keytab_host, allow_create_keytab_hostgroup,
                    allow_retrieve_keytab_user, allow_retrieve_keytab_group,
                    allow_retrieve_keytab_host,
                    allow_retrieve_keytab_hostgroup, mac_address, sshpubkey,
                    userclass, auth_ind, requires_pre_auth, ok_as_delegate,
                    ok_to_auth_as_delegate, force, reverse, ip_address,
                    update_dns, update_password)

            elif isinstance(host, (str, unicode)):
                name = host
            else:
                ansible_module.fail_json(msg="Host '%s' is not valid" %
                                         repr(host))

            # Make sure host exists
            res_find = find_host(ansible_module, name)
            try:
                res_find_dnsrecord = find_dnsrecord(ansible_module, name)
            except ipalib_errors.NotFound as e:
                msg = str(e)
                dns_not_configured = "DNS is not configured" in msg
                dns_zone_not_found = "DNS zone not found" in msg
                dns_res_not_found = "DNS resource record not found" in msg
                if (
                    dns_res_not_found
                    or ip_address is None
                    and (dns_not_configured or dns_zone_not_found)
                ):
                    # IP address(es) not given and no DNS support in IPA
                    # -> Ignore failure
                    # IP address(es) not given and DNS zone is not found
                    # -> Ignore failure
                    res_find_dnsrecord = None
                else:
                    ansible_module.fail_json(msg="%s: %s" % (host, msg))

            # Create command
            if state == "present":
                # Generate args
                args = gen_args(
                    description, locality, location, platform, os, password,
                    random, mac_address, sshpubkey, userclass, auth_ind,
                    requires_pre_auth, ok_as_delegate, ok_to_auth_as_delegate,
                    force, reverse, ip_address, update_dns)
                dnsrecord_args = gen_dnsrecord_args(
                    ansible_module, ip_address, reverse)

                if action == "host":
                    # Found the host
                    if res_find is not None:
                        # Ignore password with update_password == on_create
                        if update_password == "on_create":
                            # Ignore userpassword and random for existing
                            # host if update_password is "on_create"
                            if "userpassword" in args:
                                del args["userpassword"]
                            if "random" in args:
                                del args["random"]
                        elif "userpassword" in args or "random" in args:
                            # Allow an existing OTP to be reset but don't
                            # allow a OTP or to be added to an enrolled host.
                            # Also do not allow to change the password for an
                            # enrolled host.

                            if not res_find["has_password"] and \
                               res_find["has_keytab"]:
                                ansible_module.fail_json(
                                    msg="%s: Password cannot be set on "
                                    "enrolled host." % host
                                )

                        # Ignore force, ip_address and no_reverse for mod
                        for x in ["force", "ip_address", "no_reverse"]:
                            if x in args:
                                del args[x]

                        # Ignore auth_ind if it is empty (for resetting)
                        # and not set in for the host
                        if "krbprincipalauthind" not in res_find and \
                           "krbprincipalauthind" in args and \
                           args["krbprincipalauthind"] == ['']:
                            del args["krbprincipalauthind"]

                        # For all settings is args, check if there are
                        # different settings in the find result.
                        # If yes: modify
                        if not compare_args_ipa(ansible_module, args,
                                                res_find):
                            commands.append([name, "host_mod", args])
                        elif random and "userpassword" in res_find:
                            # Host exists and random is set, return
                            # userpassword
                            if len(names) == 1:
                                exit_args["userpassword"] = \
                                    res_find["userpassword"]
                            else:
                                exit_args.setdefault("hosts", {})[name] = {
                                    "userpassword": res_find["userpassword"]
                                }

                    else:
                        # Remove update_dns as it is not supported by host_add
                        if "updatedns" in args:
                            del args["updatedns"]
                        commands.append([name, "host_add", args])

                    # Handle members: certificate, managedby_host, principal,
                    # allow_create_keytab and allow_retrieve_keytab
                    if res_find is not None:
                        certificate_add, certificate_del = gen_add_del_lists(
                            certificate, res_find.get("usercertificate"))
                        managedby_host_add, managedby_host_del = \
                            gen_add_del_lists(managedby_host,
                                              res_find.get("managedby_host"))
                        principal_add, principal_del = gen_add_del_lists(
                            principal, res_find.get("principal"))
                        # Principals are not returned as utf8 for IPA using
                        # python2 using host_show, therefore we need to
                        # convert the principals that we should remove.
                        principal_del = [unicode(x) for x in principal_del]

                        (allow_create_keytab_user_add,
                         allow_create_keytab_user_del) = \
                            gen_add_del_lists(
                                allow_create_keytab_user,
                                res_find.get(
                                    "ipaallowedtoperform_write_keys_user"))
                        (allow_create_keytab_group_add,
                         allow_create_keytab_group_del) = \
                            gen_add_del_lists(
                                allow_create_keytab_group,
                                res_find.get(
                                    "ipaallowedtoperform_write_keys_group"))
                        (allow_create_keytab_host_add,
                         allow_create_keytab_host_del) = \
                            gen_add_del_lists(
                                allow_create_keytab_host,
                                res_find.get(
                                    "ipaallowedtoperform_write_keys_host"))
                        (allow_create_keytab_hostgroup_add,
                         allow_create_keytab_hostgroup_del) = \
                            gen_add_del_lists(
                                allow_create_keytab_hostgroup,
                                res_find.get(
                                    "ipaallowedtoperform_write_keys_"
                                    "hostgroup"))
                        (allow_retrieve_keytab_user_add,
                         allow_retrieve_keytab_user_del) = \
                            gen_add_del_lists(
                                allow_retrieve_keytab_user,
                                res_find.get(
                                    "ipaallowedtoperform_read_keys_user"))
                        (allow_retrieve_keytab_group_add,
                         allow_retrieve_keytab_group_del) = \
                            gen_add_del_lists(
                                allow_retrieve_keytab_group,
                                res_find.get(
                                    "ipaallowedtoperform_read_keys_group"))
                        (allow_retrieve_keytab_host_add,
                         allow_retrieve_keytab_host_del) = \
                            gen_add_del_lists(
                                allow_retrieve_keytab_host,
                                res_find.get(
                                    "ipaallowedtoperform_read_keys_host"))
                        (allow_retrieve_keytab_hostgroup_add,
                         allow_retrieve_keytab_hostgroup_del) = \
                            gen_add_del_lists(
                                allow_retrieve_keytab_hostgroup,
                                res_find.get(
                                    "ipaallowedtoperform_read_keys_hostgroup"))

                        # IP addresses are not really a member of hosts, but
                        # we will simply treat it as this to enable the
                        # addition and removal of IPv4 and IPv6 addresses in
                        # a simple way.
                        _dnsrec = res_find_dnsrecord or {}
                        dnsrecord_a_add, dnsrecord_a_del = gen_add_del_lists(
                            dnsrecord_args.get("arecord"),
                            _dnsrec.get("arecord"))
                        dnsrecord_aaaa_add, dnsrecord_aaaa_del = \
                            gen_add_del_lists(
                                dnsrecord_args.get("aaaarecord"),
                                _dnsrec.get("aaaarecord"))

                else:
                    if res_find is None:
                        ansible_module.fail_json(
                            msg="No host '%s'" % name)

                if action != "host" or (action == "host" and res_find is None):
                    certificate_add = certificate or []
                    certificate_del = []
                    managedby_host_add = managedby_host or []
                    managedby_host_del = []
                    principal_add = principal or []
                    principal_del = []
                    allow_create_keytab_user_add = \
                        allow_create_keytab_user or []
                    allow_create_keytab_user_del = []
                    allow_create_keytab_group_add = \
                        allow_create_keytab_group or []
                    allow_create_keytab_group_del = []
                    allow_create_keytab_host_add = \
                        allow_create_keytab_host or []
                    allow_create_keytab_host_del = []
                    allow_create_keytab_hostgroup_add = \
                        allow_create_keytab_hostgroup or []
                    allow_create_keytab_hostgroup_del = []
                    allow_retrieve_keytab_user_add = \
                        allow_retrieve_keytab_user or []
                    allow_retrieve_keytab_user_del = []
                    allow_retrieve_keytab_group_add = \
                        allow_retrieve_keytab_group or []
                    allow_retrieve_keytab_group_del = []
                    allow_retrieve_keytab_host_add = \
                        allow_retrieve_keytab_host or []
                    allow_retrieve_keytab_host_del = []
                    allow_retrieve_keytab_hostgroup_add = \
                        allow_retrieve_keytab_hostgroup or []
                    allow_retrieve_keytab_hostgroup_del = []
                    dnsrecord_a_add = dnsrecord_args.get("arecord") or []
                    dnsrecord_a_del = []
                    dnsrecord_aaaa_add = dnsrecord_args.get("aaaarecord") or []
                    dnsrecord_aaaa_del = []

                # Remove canonical principal from principal_del
                canonical_principal = "host/" + name + "@" + server_realm
                if canonical_principal in principal_del and \
                   action == "host" and (principal is not None or
                                         canonical_principal not in principal):
                    principal_del.remove(canonical_principal)

                # Remove canonical managedby managedby_host_del for
                # action host if managedby_host is set and the canonical
                # managedby host is not in the managedby_host list.
                canonical_managedby_host = name
                if canonical_managedby_host in managedby_host_del and \
                   action == "host" and (managedby_host is None or
                                         canonical_managedby_host not in
                                         managedby_host):
                    managedby_host_del.remove(canonical_managedby_host)

                # Certificates need to be added and removed one by one,
                # because if entry already exists, the processing of
                # the remaining enries is stopped. The same applies to
                # the removal of non-existing entries.

                # Add certificates
                for _certificate in certificate_add:
                    commands.append([name, "host_add_cert",
                                     {
                                         "usercertificate":
                                         _certificate,
                                     }])
                # Remove certificates
                for _certificate in certificate_del:
                    commands.append([name, "host_remove_cert",
                                     {
                                         "usercertificate":
                                         _certificate,
                                     }])

                # Managedby_Hosts need to be added and removed one by one,
                # because if entry already exists, the processing of
                # the remaining enries is stopped. The same applies to
                # the removal of non-existing entries.

                # Add managedby_hosts
                for _managedby_host in managedby_host_add:
                    commands.append([name, "host_add_managedby",
                                     {
                                         "host":
                                         _managedby_host,
                                     }])
                # Remove managedby_hosts
                for _managedby_host in managedby_host_del:
                    commands.append([name, "host_remove_managedby",
                                     {
                                         "host":
                                         _managedby_host,
                                     }])

                # Principals need to be added and removed one by one,
                # because if entry already exists, the processing of
                # the remaining enries is stopped. The same applies to
                # the removal of non-existing entries.

                # Add principals
                for _principal in principal_add:
                    commands.append([name, "host_add_principal",
                                     {
                                         "krbprincipalname":
                                         _principal,
                                     }])
                # Remove principals
                for _principal in principal_del:
                    commands.append([name, "host_remove_principal",
                                     {
                                         "krbprincipalname":
                                         _principal,
                                     }])

                # Allow create keytab
                if len(allow_create_keytab_user_add) > 0 or \
                   len(allow_create_keytab_group_add) > 0 or \
                   len(allow_create_keytab_host_add) > 0 or \
                   len(allow_create_keytab_hostgroup_add) > 0:
                    commands.append(
                        [name, "host_allow_create_keytab",
                         {
                             "user": allow_create_keytab_user_add,
                             "group": allow_create_keytab_group_add,
                             "host": allow_create_keytab_host_add,
                             "hostgroup": allow_create_keytab_hostgroup_add,
                         }])

                # Disallow create keytab
                if len(allow_create_keytab_user_del) > 0 or \
                   len(allow_create_keytab_group_del) > 0 or \
                   len(allow_create_keytab_host_del) > 0 or \
                   len(allow_create_keytab_hostgroup_del) > 0:
                    commands.append(
                        [name, "host_disallow_create_keytab",
                         {
                             "user": allow_create_keytab_user_del,
                             "group": allow_create_keytab_group_del,
                             "host": allow_create_keytab_host_del,
                             "hostgroup": allow_create_keytab_hostgroup_del,
                         }])

                # Allow retrieve keytab
                if len(allow_retrieve_keytab_user_add) > 0 or \
                   len(allow_retrieve_keytab_group_add) > 0 or \
                   len(allow_retrieve_keytab_host_add) > 0 or \
                   len(allow_retrieve_keytab_hostgroup_add) > 0:
                    commands.append(
                        [name, "host_allow_retrieve_keytab",
                         {
                             "user": allow_retrieve_keytab_user_add,
                             "group": allow_retrieve_keytab_group_add,
                             "host": allow_retrieve_keytab_host_add,
                             "hostgroup": allow_retrieve_keytab_hostgroup_add,
                         }])

                # Disallow retrieve keytab
                if len(allow_retrieve_keytab_user_del) > 0 or \
                   len(allow_retrieve_keytab_group_del) > 0 or \
                   len(allow_retrieve_keytab_host_del) > 0 or \
                   len(allow_retrieve_keytab_hostgroup_del) > 0:
                    commands.append(
                        [name, "host_disallow_retrieve_keytab",
                         {
                             "user": allow_retrieve_keytab_user_del,
                             "group": allow_retrieve_keytab_group_del,
                             "host": allow_retrieve_keytab_host_del,
                             "hostgroup": allow_retrieve_keytab_hostgroup_del,
                         }])

                if len(dnsrecord_a_add) > 0 or len(dnsrecord_aaaa_add) > 0:
                    domain_name = name[name.find(".") + 1:]
                    host_name = name[:name.find(".")]

                    _args = {"idnsname": host_name}
                    if len(dnsrecord_a_add) > 0:
                        _args["arecord"] = dnsrecord_a_add
                        if reverse is not None:
                            _args["a_extra_create_reverse"] = reverse
                    if len(dnsrecord_aaaa_add) > 0:
                        _args["aaaarecord"] = dnsrecord_aaaa_add
                        if reverse is not None:
                            _args["aaaa_extra_create_reverse"] = reverse

                    commands.append([domain_name,
                                     "dnsrecord_add", _args])

                if len(dnsrecord_a_del) > 0 or len(dnsrecord_aaaa_del) > 0:
                    domain_name = name[name.find(".") + 1:]
                    host_name = name[:name.find(".")]

                    # There seems to be an issue with dnsrecord_del (not
                    # for dnsrecord_add) if aaaarecord is an empty list.
                    # Therefore this is done differently here:
                    _args = {"idnsname": host_name}
                    if len(dnsrecord_a_del) > 0:
                        _args["arecord"] = dnsrecord_a_del
                    if len(dnsrecord_aaaa_del) > 0:
                        _args["aaaarecord"] = dnsrecord_aaaa_del

                    commands.append([domain_name,
                                     "dnsrecord_del", _args])

            elif state == "absent":
                if action == "host":

                    if res_find is not None:
                        args = {}
                        if update_dns is not None:
                            args["updatedns"] = update_dns
                        commands.append([name, "host_del", args])
                else:

                    # Certificates need to be added and removed one by one,
                    # because if entry already exists, the processing of
                    # the remaining enries is stopped. The same applies to
                    # the removal of non-existing entries.

                    # Remove certificates
                    if certificate is not None:
                        for _certificate in certificate:
                            commands.append([name, "host_remove_cert",
                                             {
                                                 "usercertificate":
                                                 _certificate,
                                             }])

                    # Managedby_Hosts need to be added and removed one by one,
                    # because if entry already exists, the processing of
                    # the remaining enries is stopped. The same applies to
                    # the removal of non-existing entries.

                    # Remove managedby_hosts
                    if managedby_host is not None:
                        for _managedby_host in managedby_host:
                            commands.append([name, "host_remove_managedby",
                                             {
                                                 "host":
                                                 _managedby_host,
                                             }])

                    # Principals need to be added and removed one by one,
                    # because if entry already exists, the processing of
                    # the remaining enries is stopped. The same applies to
                    # the removal of non-existing entries.

                    # Remove principals
                    if principal is not None:
                        for _principal in principal:
                            commands.append([name, "host_remove_principal",
                                             {
                                                 "krbprincipalname":
                                                 _principal,
                                             }])

                    # Disallow create keytab
                    if allow_create_keytab_user is not None or \
                       allow_create_keytab_group is not None or \
                       allow_create_keytab_host is not None or \
                       allow_create_keytab_hostgroup is not None:
                        commands.append(
                            [name, "host_disallow_create_keytab",
                             {
                                 "user": allow_create_keytab_user,
                                 "group": allow_create_keytab_group,
                                 "host": allow_create_keytab_host,
                                 "hostgroup": allow_create_keytab_hostgroup,
                             }])

                    # Disallow retrieve keytab
                    if allow_retrieve_keytab_user is not None or \
                       allow_retrieve_keytab_group is not None or \
                       allow_retrieve_keytab_host is not None or \
                       allow_retrieve_keytab_hostgroup is not None:
                        commands.append(
                            [name, "host_disallow_retrieve_keytab",
                             {
                                 "user": allow_retrieve_keytab_user,
                                 "group": allow_retrieve_keytab_group,
                                 "host": allow_retrieve_keytab_host,
                                 "hostgroup": allow_retrieve_keytab_hostgroup,
                             }])

                    dnsrecord_args = gen_dnsrecord_args(ansible_module,
                                                        ip_address, reverse)

                    # Remove arecord and aaaarecord from dnsrecord_args
                    # if the record does not exits in res_find_dnsrecord
                    # to prevent "DNS resource record not found" error
                    if "arecord" in dnsrecord_args \
                       and dnsrecord_args["arecord"] is not None \
                       and len(dnsrecord_args["arecord"]) > 0 \
                       and (res_find_dnsrecord is None
                            or "arecord" not in res_find_dnsrecord):
                        del dnsrecord_args["arecord"]
                    if "aaaarecord" in dnsrecord_args \
                       and dnsrecord_args["aaaarecord"] is not None \
                       and len(dnsrecord_args["aaaarecord"]) > 0 \
                       and (res_find_dnsrecord is None
                            or "aaaarecord" not in res_find_dnsrecord):
                        del dnsrecord_args["aaaarecord"]

                    if "arecord" in dnsrecord_args or \
                       "aaaarecord" in dnsrecord_args:
                        domain_name = name[name.find(".") + 1:]
                        host_name = name[:name.find(".")]
                        dnsrecord_args["idnsname"] = host_name

                        commands.append([domain_name, "dnsrecord_del",
                                         dnsrecord_args])

            elif state == "disabled":
                if res_find is not None:
                    commands.append([name, "host_disable", {}])
                else:
                    raise ValueError("No host '%s'" % name)

            else:
                ansible_module.fail_json(msg="Unkown state '%s'" % state)

        del host_set

        # Execute commands

        changed = ansible_module.execute_ipa_commands(
            commands, result_handler, exception_handler,
            exit_args=exit_args, single_host=hosts is None)

    # Done

    ansible_module.exit_json(changed=changed, host=exit_args)


if __name__ == "__main__":
    main()

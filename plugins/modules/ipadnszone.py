#!/usr/bin/python
# -*- coding: utf-8 -*-

# Authors:
#   Sergio Oliveira Campos <seocam@redhat.com>
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

DOCUMENTATION = """
---
module: ipadnszone
short description: Manage FreeIPA dnszone
description: Manage FreeIPA dnszone
options:
  ipaadmin_principal:
    description: The admin principal
    default: admin
  ipaadmin_password:
    description: The admin password
    required: false
  name:
    description: The zone name string.
    required: true
    type: list
    alises: ["zone_name"]
  name_from_ip:
    description: |
      Derive zone name from reverse of IP (PTR).
      Can only be used with `state: present`.
    required: false
    type: str
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
    choices: ["present", "absent", "enabled", "disabled"]
  name_server:
    description: Authoritative nameserver domain name
    required: false
    type: str
  admin_email:
    description: Administrator e-mail address
    required: false
    type: str
  update_policy:
    description: BIND update policy
    required: false
    type: str
  dynamic_update:
    description: Allow dynamic updates
    required: false
    type: bool
    alises: ["dynamicupdate"]
  dnssec:
    description: Allow inline DNSSEC signing of records in the zone
    required: false
    type: bool
  allow_transfer:
    description: List of IP addresses or networks which are allowed to transfer the zone
    required: false
    type: bool
  allow_query:
    description: List of IP addresses or networks which are allowed to issue queries
    required: false
    type: bool
  serial:
    description: SOA record serial number
    required: false
    type: int
  refresh:
    description: SOA record refresh time
    required: false
    type: int
  retry:
    description: SOA record retry time
    required: false
    type: int
  expire:
    description: SOA record expire time
    required: false
    type: int
  minimum:
    description: How long should negative responses be cached
    required: false
    type: int
  ttl:
    description: Time to live for records at zone apex
    required: false
    type: int
  default_ttl:
    description: Time to live for records without explicit TTL definition
    required: false
    type: int
  nsec3param_rec:
    description: |
      NSEC3PARAM record for zone in format: hash_algorithm flags iterations
       salt.
    required: false
    type: str
  skip_overlap_check:
    description: |
      Force DNS zone creation even if it will overlap with an existing zone
    required: false
    type: bool
  skip_nameserver_check:
    description: Force DNS zone creation even if nameserver is not resolvable
    required: false
    type: bool
"""  # noqa: E501

EXAMPLES = """
---
# Ensure the zone is present (very minimal)
- ipadnszone:
    name: test.example.com

# Ensure the zone is present (all available arguments)
- ipadnszone:
    name: test.example.com
    ipaadmin_password: SomeADMINpassword
    allow_sync_ptr: true
    dynamic_update: true
    dnssec: true
    allow_transfer:
      - 1.1.1.1
      - 2.2.2.2
    allow_query:
      - 1.1.1.1
      - 2.2.2.2
    forwarders:
      - ip_address: 8.8.8.8
      - ip_address: 8.8.4.4
        port: 52
    serial: 1234
    refresh: 3600
    retry: 900
    expire: 1209600
    minimum: 3600
    ttl: 60
    default_ttl: 90
    name_server: ipaserver.test.local.
    admin_email: admin.admin@example.com
    nsec3param_rec: "1 7 100 0123456789abcdef"
    skip_overlap_check: true
    skip_nameserver_check: true
    state: present

# Ensure zone is present and disabled
- ipadnszone:
    name: test.example.com
    state: disabled

# Ensure zone is present and enabled
- ipadnszone:
    name: test.example.com
    state: enabled
"""

RETURN = """
dnszone:
  description: DNS Zone dict with zone name infered from `name_from_ip`.
  returned:
    If `state` is `present`, `name_from_ip` is used, and a zone was created.
  options:
    name:
      description: The name of the zone created, inferred from `name_from_ip`.
      returned: always
"""

from ipapython.dnsutil import DNSName  # noqa: E402
from ansible.module_utils.ansible_freeipa_module import (
    FreeIPABaseModule,
    is_ipv4_addr,
    is_ipv6_addr,
    is_valid_port,
)  # noqa: E402
import netaddr
import six


if six.PY3:
    unicode = str


class DNSZoneModule(FreeIPABaseModule):

    ipa_param_mapping = {
        # Direct Mapping
        "idnsforwardpolicy": "forward_policy",
        "idnssoaserial": "serial",
        "idnssoarefresh": "refresh",
        "idnssoaretry": "retry",
        "idnssoaexpire": "expire",
        "idnssoaminimum": "minimum",
        "dnsttl": "ttl",
        "dnsdefaultttl": "default_ttl",
        "idnsallowsyncptr": "allow_sync_ptr",
        "idnsallowdynupdate": "dynamic_update",
        "idnssecinlinesigning": "dnssec",
        "idnsupdatepolicy": "update_policy",
        # Mapping by method
        "idnsforwarders": "get_ipa_idnsforwarders",
        "idnsallowtransfer": "get_ipa_idnsallowtransfer",
        "idnsallowquery": "get_ipa_idnsallowquery",
        "idnssoamname": "get_ipa_idnssoamname",
        "idnssoarname": "get_ipa_idnssoarname",
        "skip_nameserver_check": "get_ipa_skip_nameserver_check",
        "skip_overlap_check": "get_ipa_skip_overlap_check",
        "nsec3paramrecord": "get_ipa_nsec3paramrecord",
    }

    def validate_ips(self, ips, error_msg):
        invalid_ips = [
            ip for ip in ips if not is_ipv4_addr(ip) or is_ipv6_addr(ip)
        ]
        if any(invalid_ips):
            self.fail_json(msg=error_msg % invalid_ips)

    def is_valid_nsec3param_rec(self, nsec3param_rec):
        try:
            part1, part2, part3, part4 = nsec3param_rec.split(" ")
        except ValueError:
            return False

        if not all([part1.isdigit(), part2.isdigit(), part3.isdigit()]):
            return False

        if not 0 <= int(part1) <= 255:
            return False

        if not 0 <= int(part2) <= 255:
            return False

        if not 0 <= int(part3) <= 65535:
            return False

        try:
            int(part4, 16)
        except ValueError:
            is_hex = False
        else:
            is_hex = True

        even_digits = len(part4) % 2 == 0
        is_dash = part4 == "-"

        # If not hex with even digits or dash then
        #   part4 is invalid
        if not ((is_hex and even_digits) or is_dash):
            return False

        return True

    def get_ipa_nsec3paramrecord(self, **kwargs):
        nsec3param_rec = self.ipa_params.nsec3param_rec
        if nsec3param_rec is not None:
            error_msg = (
                "Invalid nsec3param_rec: %s. "
                "Expected format: <0-255> <0-255> <0-65535> "
                "even-length_hexadecimal_digits_or_hyphen"
            ) % nsec3param_rec
            if not self.is_valid_nsec3param_rec(nsec3param_rec):
                self.fail_json(msg=error_msg)
            return nsec3param_rec

    def get_ipa_idnsforwarders(self, **kwargs):
        if self.ipa_params.forwarders is not None:
            forwarders = []
            for forwarder in self.ipa_params.forwarders:
                ip_address = forwarder.get("ip_address")
                if not (is_ipv4_addr(ip_address) or is_ipv6_addr(ip_address)):
                    self.fail_json(
                        msg="Invalid IP for DNS forwarder: %s" % ip_address
                    )

                port = forwarder.get("port", None)
                if port and not is_valid_port(port):
                    self.fail_json(
                        msg="Invalid port number for DNS forwarder: %s %s"
                        % (ip_address, port)
                    )
                formatted_forwarder = ip_address
                port = forwarder.get("port")
                if port:
                    formatted_forwarder += " port %d" % port
                forwarders.append(formatted_forwarder)

            return forwarders

    def get_ipa_idnsallowtransfer(self, **kwargs):
        if self.ipa_params.allow_transfer is not None:
            error_msg = "Invalid ip_address for DNS allow_transfer: %s"
            self.validate_ips(self.ipa_params.allow_transfer, error_msg)

            return (";".join(self.ipa_params.allow_transfer) or "none") + ";"

    def get_ipa_idnsallowquery(self, **kwargs):
        if self.ipa_params.allow_query is not None:
            error_msg = "Invalid ip_address for DNS allow_query: %s"
            self.validate_ips(self.ipa_params.allow_query, error_msg)

            return (";".join(self.ipa_params.allow_query) or "any") + ";"

    @staticmethod
    def _replace_at_symbol_in_rname(rname):
        """
        See RFC 1035 for more information.

        Section 8. MAIL SUPPORT
        https://tools.ietf.org/html/rfc1035#section-8
        """
        if "@" not in rname:
            return rname

        name, domain = rname.split("@")
        name = name.replace(".", r"\.")

        return ".".join((name, domain))

    def get_ipa_idnssoarname(self, **kwargs):
        if self.ipa_params.admin_email is not None:
            return DNSName(
                self._replace_at_symbol_in_rname(self.ipa_params.admin_email)
            )

    def get_ipa_idnssoamname(self, **kwargs):
        if self.ipa_params.name_server is not None:
            return DNSName(self.ipa_params.name_server)

    def get_ipa_skip_overlap_check(self, **kwargs):
        zone = kwargs.get('zone')
        if not zone and self.ipa_params.skip_overlap_check is not None:
            return self.ipa_params.skip_overlap_check

    def get_ipa_skip_nameserver_check(self, **kwargs):
        zone = kwargs.get('zone')
        if not zone and self.ipa_params.skip_nameserver_check is not None:
            return self.ipa_params.skip_nameserver_check

    def __reverse_zone_name(self, ipaddress):
        """
        Infer reverse zone name from an ip address.

        This function uses the same heuristics as FreeIPA to infer the zone
        name from ip.
        """
        try:
            ip = netaddr.IPAddress(str(ipaddress))
        except (netaddr.AddrFormatError, ValueError):
            net = netaddr.IPNetwork(ipaddress)
            items = net.ip.reverse_dns.split('.')
            prefixlen = net.prefixlen
            ip_version = net.version
        else:
            items = ip.reverse_dns.split('.')
            prefixlen = 24 if ip.version == 4 else 64
            ip_version = ip.version
        if ip_version == 4:
            return u'.'.join(items[4 - prefixlen // 8:])
        elif ip_version == 6:
            return u'.'.join(items[32 - prefixlen // 4:])
        else:
            self.fail_json(msg="Invalid IP version for reverse zone.")

    def get_zone(self, zone_name):
        get_zone_args = {"idnsname": zone_name, "all": True}
        response = self.api_command("dnszone_find", args=get_zone_args)

        zone = None
        is_zone_active = False

        if response["count"] == 1:
            zone = response["result"][0]
            is_zone_active = zone.get("idnszoneactive") == ["TRUE"]

        return zone, is_zone_active

    def get_zone_names(self):
        zone_names = self.__get_zone_names_from_params()
        if len(zone_names) > 1 and self.ipa_params.state != "absent":
            self.fail_json(
                msg=("Please provide a single name. Multiple values for 'name'"
                     "can only be supplied for state 'absent'.")
            )

        return zone_names

    def __get_zone_names_from_params(self):
        if not self.ipa_params.name:
            return [self.__reverse_zone_name(self.ipa_params.name_from_ip)]
        return self.ipa_params.name

    def check_ipa_params(self):
        if not self.ipa_params.name and not self.ipa_params.name_from_ip:
            self.fail_json(
                msg="Either `name` or `name_from_ip` must be provided."
            )
        if self.ipa_params.state != "present" and self.ipa_params.name_from_ip:
            self.fail_json(
                msg=(
                    "Cannot use argument `name_from_ip` with state `%s`."
                    % self.ipa_params.state
                )
            )

    def define_ipa_commands(self):
        for zone_name in self.get_zone_names():
            # Look for existing zone in IPA
            zone, is_zone_active = self.get_zone(zone_name)
            args = self.get_ipa_command_args(zone=zone)
            just_added = False

            if self.ipa_params.state in ["present", "enabled", "disabled"]:
                if not zone:
                    # Since the zone doesn't exist we just create it
                    #   with given args
                    self.add_ipa_command("dnszone_add", zone_name, args)
                    is_zone_active = True
                    just_added = True

                else:
                    # Zone already exist so we need to verify if given args
                    #   matches the current config. If not we updated it.
                    if self.require_ipa_attrs_change(args, zone):
                        self.add_ipa_command("dnszone_mod", zone_name, args)

                if self.ipa_params.state == "enabled" and not is_zone_active:
                    self.add_ipa_command("dnszone_enable", zone_name)

                if self.ipa_params.state == "disabled" and is_zone_active:
                    self.add_ipa_command("dnszone_disable", zone_name)

            if self.ipa_params.state == "absent":
                if zone:
                    self.add_ipa_command("dnszone_del", zone_name)

            # Due to a bug in FreeIPA dnszone-add won't set
            #   SOA Serial. The good news is that dnszone-mod does the job.
            # See: https://pagure.io/freeipa/issue/8227
            # Because of that, if the zone was just added with a given serial
            #   we run mod just after to workaround the bug
            if just_added and self.ipa_params.serial is not None:
                args = {
                    "idnssoaserial": self.ipa_params.serial,
                }
                self.add_ipa_command("dnszone_mod", zone_name, args)

    def process_command_result(self, name, command, args, result):
        super(DNSZoneModule, self).process_command_result(
            name, command, args, result
        )
        if command == "dnszone_add" and self.ipa_params.name_from_ip:
            dnszone_exit_args = self.exit_args.setdefault('dnszone', {})
            dnszone_exit_args['name'] = name


def get_argument_spec():
    forwarder_spec = dict(
        ip_address=dict(type=str, required=True),
        port=dict(type=int, required=False, default=None),
    )

    return dict(
        state=dict(
            type="str",
            default="present",
            choices=["present", "absent", "enabled", "disabled"],
        ),
        ipaadmin_principal=dict(type="str", default="admin"),
        ipaadmin_password=dict(type="str", required=False, no_log=True),
        name=dict(
            type="list", default=None, required=False, aliases=["zone_name"]
        ),
        name_from_ip=dict(type="str", default=None, required=False),
        forwarders=dict(
            type="list",
            default=None,
            required=False,
            options=dict(**forwarder_spec),
        ),
        forward_policy=dict(
            type="str",
            required=False,
            default=None,
            choices=["only", "first", "none"],
        ),
        name_server=dict(type="str", required=False, default=None),
        admin_email=dict(type="str", required=False, default=None),
        allow_sync_ptr=dict(type="bool", required=False, default=None),
        update_policy=dict(type="str", required=False, default=None),
        dynamic_update=dict(
            type="bool",
            required=False,
            default=None,
            aliases=["dynamicupdate"],
        ),
        dnssec=dict(type="bool", required=False, default=None),
        allow_transfer=dict(type="list", required=False, default=None),
        allow_query=dict(type="list", required=False, default=None),
        serial=dict(type="int", required=False, default=None),
        refresh=dict(type="int", required=False, default=None),
        retry=dict(type="int", required=False, default=None),
        expire=dict(type="int", required=False, default=None),
        minimum=dict(type="int", required=False, default=None),
        ttl=dict(type="int", required=False, default=None),
        default_ttl=dict(type="int", required=False, default=None),
        nsec3param_rec=dict(type="str", required=False, default=None),
        skip_nameserver_check=dict(type="bool", required=False, default=None),
        skip_overlap_check=dict(type="bool", required=False, default=None),
    )


def main():
    DNSZoneModule(
        argument_spec=get_argument_spec(),
        mutually_exclusive=[["name", "name_from_ip"]],
        required_one_of=[["name", "name_from_ip"]],
    ).ipa_run()


if __name__ == "__main__":
    main()

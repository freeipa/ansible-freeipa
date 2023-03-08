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


from pytest_sourceorder import ordered

from utils import AnsibleFreeIPATestCase, kinit_admin, kdestroy

BASE_PATH = "pytests/dnszone/playbooks/"


@ordered
class TestDNSZone(AnsibleFreeIPATestCase):
    def test_dnszone_add_without_forwarder(self):
        """TC-01: Add dns zone without forwarder."""
        zone01 = "01testzone.test"
        self.check_notexists([zone01], "dnszone-find")
        self.run_playbook(BASE_PATH + "dnszone_add_without_forwarder.yml")
        self.check_details([zone01], "dnszone-find")

    def test_dnszone_add_multiple_ipv4_ipv6_forwarders(self):
        """TC-04: Update multiple ipv4 and ipv6 forwarders."""
        zone04 = "04testzone.test"
        self.check_notexists([zone04], "dnszone-find")

        # add dns zone with multiple forwarders
        self.run_playbook(
            (BASE_PATH + "dnszone_add_multiple_ipv4_ipv6_forwarders.yml")
        )

        exp_forwarders = [
            "192.11.22.33",
            "192.11.22.34 port 23",
            "2001:db8:cafe:1::1",
            "2001:db8:cafe:1::4 port 34",
        ]
        exp_forwarders = ", ".join(exp_forwarders)
        self.check_details([exp_forwarders], "dnszone-find", [zone04])

    def test_dnszone_with_forward_policy_only(self):
        """TC-26: Add DNS zone with forward_policy only."""
        zone26 = "26testzone.test"
        self.check_notexists([zone26], "dnszone-find")
        # add dns zone
        self.run_playbook(BASE_PATH + "dnszone_with_forward_policy_only.yml")
        self.check_details(["Forward policy: only"], "dnszone-find", [zone26])

    def test_dnszone_disable(self):
        """TC-30: Disable DNS Zone."""
        zone26 = "26testzone.test"
        self.check_details(
            ["Active zone: (TRUE|True)"], "dnszone-find", [zone26]
        )
        # Disable dns zone
        self.run_playbook(BASE_PATH + "dnszone_disable.yml")
        self.check_details(
            ["Active zone: (FALSE|False)"], "dnszone-find", [zone26]
        )

    def test_dnszone_enable(self):
        """TC-31: Enable DNS Zone."""
        zone26 = "26testzone.test"
        self.check_details(
            ["Active zone: (FALSE|False)"], "dnszone-find", [zone26]
        )
        # Enable dns zone
        self.run_playbook(BASE_PATH + "dnszone_enable.yml")
        self.check_details(
            ["Active zone: (TRUE|True)"], "dnszone-find", [zone26]
        )

    def test_dnszone_name_from_ip(self):
        """TC-35: Add dns zone with reverse zone IP. Bug#1845056."""
        zone = "8.192.in-addr.arpa."
        expected_msg = "Zone name: {0}".format(zone)
        self.check_notexists([expected_msg], "dnszone-find", [zone])

        self.mark_xfail_using_ansible_freeipa_version(
            version="ansible-freeipa-0.1.12-5.el8.noarch",
            reason="Fix is not available for BZ-1845056",
        )

        self.run_playbook(BASE_PATH + "dnszone_name_from_ip.yml")
        self.check_details([expected_msg], "dnszone-find", [zone])

    def test_dnszone_del_multiple(self):
        """TC-33: Delete multiple DNS zones Bug#1845058."""
        zone = ["delzone1.com", "delzone2.com", "delzone3.com"]
        for add_zone in zone:
            kinit_admin(self.master)
            self.master.run("ipa dnszone-add " + add_zone)
            self.check_details([add_zone], "dnszone-show", [add_zone])
            kdestroy(self.master)

        self.mark_xfail_using_ansible_freeipa_version(
            version="ansible-freeipa-0.1.12-5.el8.noarch",
            reason="Fix is not available for BZ-1845058",
        )

        self.run_playbook(BASE_PATH + "dnszone_del_multiple.yml")
        # verify multiple dnszones are removed
        for add_zone in zone:
            error = "ipa: ERROR: {0}.: DNS zone not found".format(add_zone)
            self.check_notexists([error], "dnszone-show", [add_zone])

    def test_dnszone_invalid_ip(self):
        """TC-07: Update with invalid IPs in allow_transfer. Bug#1845051."""
        invalid_zone_name = "invalidzone.test"
        invalid_zone_ip = "in.va.li.d"
        expected_error = "Invalid IP for DNS forwarder"

        self.mark_xfail_using_ansible_freeipa_version(
            version="ansible-freeipa-0.1.12-5.el8.noarch",
            reason="Fix is not available for BZ-1845058",
        )

        self.run_playbook_with_exp_msg(
            BASE_PATH + "dnszone_invalid_ip.yml", expected_error,
        )
        self.check_notexists(
            [invalid_zone_ip], "dnszone-show", [invalid_zone_name],
        )

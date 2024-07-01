# -*- coding: utf-8 -*-

# Authors:
#   Thomas Woerner <twoerner@redhat.com>
#
# Copyright (C) 2024 Red Hat
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
name: freeipa
version_added: "1.13.0"
short_description: Compiles a dynamic inventory from IPA domain
description: |
  Compiles a dynamic inventory from IPA domain, filters servers by role(s).
options:
  plugin:
    description: Marks this as an instance of the "freeipa" plugin.
    required: True
    choices: ["freeipa"]
  ipaadmin_principal:
    description: The admin principal.
    default: admin
    type: str
  ipaadmin_password:
    description: The admin password.
    required: true
    type: str
  server:
    description: FQDN of server to start the scan.
    type: str
    required: true
  verify:
    description: |
      The server TLS certificate file for verification (/etc/ipa/ca.crt).
      Turned off if not set.
    type: str
    required: false
  role:
    description: |
      The role(s) of the server. If several roles are given, only servers
      that have all the roles are returned.
    type: list
    elements: str
    choices: ["IPA master", "CA server", "KRA server", "DNS server",
              "AD trust controller", "AD trust agent"]
    required: false
  inventory_group:
    description: |
      The inventory group to create. The default group name is "ipaservers".
    type: str
    default: ipaservers
author:
  - Thomas Woerner (@t-woerner)
"""

EXAMPLES = """
# inventory.config file in YAML format
plugin: freeipa
server: ipaserver-01.ipa.local
ipaadmin_password: SomeADMINpassword

# inventory.config file in YAML format with server TLS certificate verification
plugin: freeipa
server: ipaserver-01.ipa.local
ipaadmin_password: SomeADMINpassword
verify: ca.crt
"""

import os
try:
    import requests
except ImportError:
    requests = None
try:
    import urllib3
except ImportError:
    urllib3 = None

from ansible import constants
from ansible.errors import AnsibleParserError
from ansible.module_utils.common.text.converters import to_native
from ansible.plugins.inventory import BaseInventoryPlugin
from ansible.module_utils.six.moves.urllib.parse import quote


class InventoryModule(BaseInventoryPlugin):

    NAME = 'freeipa'

    def verify_file(self, path):
        # pylint: disable=super-with-arguments
        if super(InventoryModule, self).verify_file(path):
            _name, ext = os.path.splitext(path)
            if ext in constants.YAML_FILENAME_EXTENSIONS:
                return True
        return False

    def parse(self, inventory, loader, path, cache=False):
        # pylint: disable=super-with-arguments
        super(InventoryModule, self).parse(inventory, loader, path,
                                           cache=cache)
        self._read_config_data(path)  # This also loads the cache

        self.get_option("plugin")

        if requests is None:
            raise AnsibleParserError("The required Python library "
                                     "'requests' could not be imported.")

        ipaadmin_principal = self.get_option("ipaadmin_principal")
        ipaadmin_password = self.get_option("ipaadmin_password")
        server = self.get_option("server")
        verify = self.get_option("verify")
        role = self.get_option("role")
        inventory_group = self.get_option("inventory_group")

        if verify is not None:
            if not os.path.exists(verify):
                raise AnsibleParserError("ERROR: Could not load %s" % verify)
        else:
            verify = False
            # Disable certificate verification warning without certificate
            # as long as urllib3 could have been loaded.
            if urllib3 is not None:
                urllib3.disable_warnings(
                    urllib3.exceptions.InsecureRequestWarning)

        self.inventory.add_group(inventory_group)

        ipa_url = "https://%s/ipa" % server

        s = requests.Session()
        s.headers.update({"referer": ipa_url})
        s.headers.update({"Content-Type":
                          "application/x-www-form-urlencoded"})
        s.headers.update({"Accept": "text/plain"})

        data = 'user=%s&password=%s' % (quote(ipaadmin_principal, safe=''),
                                        quote(ipaadmin_password, safe=''))
        response = s.post("%s/session/login_password" % ipa_url,
                          data=data, verify=verify)

        # Now use json API
        s.headers.update({"Content-Type": "application/json"})

        kw_args = {}
        if role is not None:
            kw_args["servrole"] = role
        json_data = {
            "method" : "server_find",
            "params": [[], kw_args],
            "id": 0
        }
        response = s.post("%s/session/json" % ipa_url, json=json_data,
                          verify=verify)
        json_res = response.json()

        error = json_res.get("error")
        if error is not None:
            raise AnsibleParserError("ERROR: %s" % to_native(error))

        if "result" in json_res and "result" in json_res["result"]:
            res = json_res["result"].get("result")
            if isinstance(res, list):
                for server in res:
                    self.inventory.add_host(server["cn"][0],
                                            group=inventory_group)

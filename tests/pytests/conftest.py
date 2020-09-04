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

import os
import yaml


def get_inventory(inventory_path):
    with open(inventory_path) as inventory_yaml:
        return yaml.safe_load(inventory_yaml)


def set_env_if_not_set(envvar, value):
    if not os.getenv(envvar):
        os.environ[envvar] = value


def pytest_configure(config):
    test_dir = os.getenv("TWD")
    if not test_dir:
        return

    config_dir = os.path.join(test_dir, "config")
    if os.path.exists(config_dir):
        inventory_path = os.path.join(config_dir, "test.inventory.yaml")
        inventory = get_inventory(inventory_path)
        print("Configuring execution using {}".format(inventory_path))
        ipaservers = inventory["all"]["children"]["ipaserver"]["hosts"]
        ipaserver = list(ipaservers.values())[0]
        private_key = os.path.join(config_dir, "id_rsa")

        set_env_if_not_set("ANSIBLE_PRIVATE_KEY_FILE", private_key)
        set_env_if_not_set("IPA_SERVER_HOST", ipaserver["ansible_host"])
        set_env_if_not_set("ANSIBLE_REMOTE_USER", ipaserver["ansible_user"])

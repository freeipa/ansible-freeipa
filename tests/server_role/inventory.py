#!/usr/bin/env python
"""Dynamic inventory to test ipaserver role."""

import os
import sys
from collections import namedtuple

try:
    import yaml

    inventory_to_string = yaml.dump
except ImportError:
    import json

    inventory_to_string = json.dumps

Config = namedtuple(
    "Config",
    """
    engine
    container
    hostname
    ipa_domain
    ipa_realm
    setup_kra
    setup_dns
    dns_no_forwarders
    dns_auto_reverse
    setup_adtrust
    ipa_netbios_name
""",
)


def to_boolean(value):
    return value.lower() == "true"


def get_inventory_data(config):
    """Generate inventory based on given configuration."""
    return {
        "all": {
            "children": {
                "ipaserver": {
                    "hosts": {
                        "ipa_server": {
                            "ansible_connection": config.engine,
                            "ansible_host": config.container,
                        },
                    },
                    "vars": {
                        # KRA
                        "ipaserver_setup_kra": config.setup_kra,
                        # DNS
                        "ipaserver_setup_dns": config.setup_dns,
                        "ipaserver_no_forwarders": config.dns_no_forwarders,
                        "ipaserver_auto_reverse": config.dns_auto_reverse,
                        # AD Trust
                        "ipaserver_setup_adtrust": config.setup_adtrust,
                        "ipaserver_netbios_name": config.ipa_netbios_name,
                        # adjtimex fails on container, so do not set ntp
                        "ipaclient_no_ntp": True,
                        # server configuration
                        "ipaserver_hostname": config.hostname,
                    },
                },
            },
            "vars": {
                # server/realm
                "ipaserver_domain": config.ipa_domain,
                "ipaserver_realm": config.ipa_realm,
                # passwords
                "ipaadmin_password": "SomeADMINpassword",
                "ipadm_password": "SomeDMpassword",
            },
        },
    }


def gen_default_inventory():
    default_hostname = "ipaserver.test.local"
    ipa_hostname = os.environ.get("IPA_HOSTNAME", default_hostname).split(".")

    setup_dns = to_boolean(os.environ.get("SETUP_DNS", "False"))

    config = Config(
        engine=(
            "containers.podman.podman"
            if "--podman" in sys.argv
            else "community.docker.docker"
        ),
        container=os.environ.get("IPA_CONTAINER", "ipaserver_test_container"),
        hostname=".".join(ipa_hostname),
        ipa_domain=os.environ.get("IPA_DOMAIN", ".".join(ipa_hostname[1:])),
        ipa_realm=os.environ.get(
            "IPA_REALM", ".".join(ipa_hostname[1:]).upper()
        ),
        setup_kra=to_boolean(os.environ.get("SETUP_KRA", "False")),
        setup_dns=setup_dns,
        dns_no_forwarders=os.environ.get("DNS_NO_FORWARDERS", setup_dns),
        dns_auto_reverse=os.environ.get("DNS_AUTO_REVERSE", setup_dns),
        setup_adtrust=to_boolean(os.environ.get("SETUP_ADTRUST", "False")),
        ipa_netbios_name=os.environ.get("IPA_NETBIOS_NAME", "IPA"),
    )
    print(inventory_to_string(get_inventory_data(config)))


if "--matrix" in sys.argv:  # pylint: disable=no-else-raise
    raise NotImplementedError("Test matrix not implemented yet.")
else:
    gen_default_inventory()

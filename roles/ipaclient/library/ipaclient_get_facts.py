#!/usr/bin/python
# -*- coding: utf-8 -*-

import os
import re
import six
try:
    from six.moves.configparser import RawConfigParser
except ImportError:
    from ConfigParser import RawConfigParser

from ansible.module_utils.basic import AnsibleModule

# pylint: disable=unused-import
try:
    from ipalib import api  # noqa: F401
except ImportError:
    HAS_IPALIB = False
else:
    HAS_IPALIB = True
    from ipaplatform.paths import paths
    try:
        # FreeIPA >= 4.5
        from ipalib.install import sysrestore
    except ImportError:
        # FreeIPA 4.4 and older
        from ipapython import sysrestore

try:
    import ipaserver  # noqa: F401
except ImportError:
    HAS_IPASERVER = False
else:
    HAS_IPASERVER = True

SERVER_SYSRESTORE_STATE = "/var/lib/ipa/sysrestore/sysrestore.state"
NAMED_CONF = "/etc/named.conf"
VAR_LIB_PKI_TOMCAT = "/var/lib/pki/pki-tomcat"


def is_ntpd_configured():
    # ntpd is configured when sysrestore.state contains the line
    # [ntpd]
    ntpd_conf_section = re.compile(r'^\s*\[ntpd\]\s*$')

    try:
        with open(SERVER_SYSRESTORE_STATE) as f:
            for line in f.readlines():
                if ntpd_conf_section.match(line):
                    return True
        return False
    except IOError:
        return False


def is_dns_configured():
    # dns is configured when /etc/named.conf contains the line
    # dyndb "ipa" "/usr/lib64/bind/ldap.so" {
    bind_conf_section = re.compile(r'^\s*dyndb\s+"ipa"\s+"[^"]+"\s+{$')

    try:
        with open(NAMED_CONF) as f:
            for line in f.readlines():
                if bind_conf_section.match(line):
                    return True
        return False
    except IOError:
        return False


def is_dogtag_configured(subsystem):
    # ca / kra is configured when the directory
    # /var/lib/pki/pki-tomcat/[ca|kra] # exists
    available_subsystems = {'ca', 'kra'}
    assert subsystem in available_subsystems

    return os.path.isdir(os.path.join(VAR_LIB_PKI_TOMCAT, subsystem))


def is_ca_configured():
    return is_dogtag_configured('ca')


def is_kra_configured():
    return is_dogtag_configured('kra')


def is_client_configured():
    # IPA Client is configured when /etc/ipa/default.conf exists
    # and /var/lib/ipa-client/sysrestore/sysrestore.state exists

    fstore = sysrestore.FileStore(paths.IPA_CLIENT_SYSRESTORE)
    return (os.path.isfile(paths.IPA_DEFAULT_CONF) and fstore.has_files())


def is_server_configured():
    # IPA server is configured when /etc/ipa/default.conf exists
    # and /var/lib/ipa/sysrestore/sysrestore.state exists
    return (os.path.isfile(paths.IPA_DEFAULT_CONF) and
            os.path.isfile(SERVER_SYSRESTORE_STATE))


def get_ipa_conf():
    # Extract basedn, realm and domain from /etc/ipa/default.conf
    parser = RawConfigParser()
    parser.read(paths.IPA_DEFAULT_CONF)
    basedn = parser.get('global', 'basedn')
    realm = parser.get('global', 'realm')
    domain = parser.get('global', 'domain')
    return dict(
        basedn=basedn,
        realm=realm,
        domain=domain
        )


def get_ipa_version():
    try:
        from ipapython import version
    except ImportError:
        return None
    else:
        version_info = []
        for part in version.VERSION.split('.'):
            # DEV versions look like:
            # 4.4.90.201610191151GITd852c00
            # 4.4.90.dev201701071308+git2e43db1
            # 4.6.90.pre2
            if part.startswith('dev') or part.startswith('pre') or \
               'GIT' in part:
                version_info.append(part)
            else:
                version_info.append(int(part))

        return dict(
            api_version=version.API_VERSION,
            num_version=version.NUM_VERSION,
            vendor_version=version.VENDOR_VERSION,
            version=version.VERSION,
            version_info=version_info
            )


def main():
    module = AnsibleModule(
        argument_spec=dict(),
        supports_check_mode=True
    )

    # The module does not change anything, meaning that
    # check mode is supported

    facts = dict(
        packages=dict(
            ipalib=HAS_IPALIB,
            ipaserver=HAS_IPASERVER,
        ),
        configured=dict(
            client=False,
            server=False,
            dns=False,
            ca=False,
            kra=False,
            ntpd=False
        )
    )

    if HAS_IPALIB:
        if is_client_configured():
            facts['configured']['client'] = True

            facts['version'] = get_ipa_version()
            for key, value in six.iteritems(get_ipa_conf()):
                facts[key] = value

    if HAS_IPASERVER:
        if is_server_configured():
            facts['configured']['server'] = True
            facts['configured']['dns'] = is_dns_configured()
            facts['configured']['ca'] = is_ca_configured()
            facts['configured']['kra'] = is_kra_configured()
            facts['configured']['ntpd'] = is_ntpd_configured()

    module.exit_json(
        changed=False,
        ansible_facts=dict(ipa=facts)
        )


if __name__ == '__main__':
    main()

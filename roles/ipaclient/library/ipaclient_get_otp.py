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
module: ipaclient_get_otp
short_description: Get OTP for host enrollment
description: Get OTP for host enrollment
options:
  ipaadmin_principal:
    description: The admin principal.
    default: admin
    type: str
  ipaadmin_password:
    description: |
      The admin password. Either ipaadmin_password or ipaadmin_keytab needs
      to be given.
    required: false
    type: str
  ipaadmin_keytab:
    description: |
      The admin keytab. Either ipaadmin_password or ipaadmin_keytab needs
      to be given.
    type: str
    required: false
  hostname:
    description: The FQDN hostname.
    type: str
    required: true
author:
  - Thomas Woerner (@t-woerner)
"""

EXAMPLES = """
"""

RETURN = """
host:
  description: Host dict with random password
  returned: always
  type: dict
  contains:
    randompassword:
      description: The generated random password
      type: str
"""

import os
import tempfile
import shutil
from contextlib import contextmanager
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_text
from ansible.module_utils import six

try:
    from ipalib import api
    from ipalib import errors as ipalib_errors  # noqa
    from ipalib.config import Env
    from ipaplatform.paths import paths
    from ipapython.ipautil import run
    from ipalib.constants import DEFAULT_CONFIG
    try:
        from ipalib.install.kinit import kinit_password, kinit_keytab
    except ImportError:
        from ipapython.ipautil import kinit_password, kinit_keytab
except ImportError as _err:
    MODULE_IMPORT_ERROR = str(_err)
else:
    MODULE_IMPORT_ERROR = None


if six.PY3:
    unicode = str


def temp_kinit(principal, password, keytab):
    """Kinit with password or keytab using a temporary ccache."""
    ccache_dir = tempfile.mkdtemp(prefix='krbcc')
    ccache_name = os.path.join(ccache_dir, 'ccache')

    try:
        if password:
            kinit_password(principal, password, ccache_name)
        else:
            kinit_keytab(principal, keytab, ccache_name)
    except RuntimeError as e:
        raise RuntimeError("Kerberos authentication failed: %s" % str(e))

    os.environ["KRB5CCNAME"] = ccache_name
    return ccache_dir, ccache_name


def temp_kdestroy(ccache_dir, ccache_name):
    """Destroy temporary ticket and remove temporary ccache."""
    if ccache_name is not None:
        run([paths.KDESTROY, '-c', ccache_name], raiseonerr=False)
        os.environ.pop('KRB5CCNAME', None)
    if ccache_dir is not None:
        shutil.rmtree(ccache_dir, ignore_errors=True)


@contextmanager
def ipa_connect(module, principal=None, password=None, keytab=None):
    """
    Create a context with a connection to IPA API.

    Parameters
    ----------
    module: AnsibleModule
        The AnsibleModule to use
    principal: string
        The optional principal name
    password: string
        The optional password. Either password or keytab needs to be given.
    keytab: string
        The optional keytab. Either password or keytab needs to be given.

    """
    if not password and not keytab:
        module.fail_json(msg="One of password and keytab is required.")
    if not principal:
        principal = "admin"

    ccache_dir = None
    ccache_name = None
    try:
        ccache_dir, ccache_name = temp_kinit(principal, password, keytab)
        # api_connect start
        env = Env()
        env._bootstrap()
        env._finalize_core(**dict(DEFAULT_CONFIG))

        api.bootstrap(context="server", debug=env.debug, log=None)
        api.finalize()

        if api.env.in_server:
            backend = api.Backend.ldap2
        else:
            backend = api.Backend.rpcclient

        if not backend.isconnected():
            backend.connect(ccache=ccache_name)
        # api_connect end
    except Exception as e:
        module.fail_json(msg=str(e))
    else:
        try:
            yield ccache_name
        except Exception as e:
            module.fail_json(msg=str(e))
        finally:
            temp_kdestroy(ccache_dir, ccache_name)


def ipa_command(command, name, args):
    """
    Execute an IPA API command with a required `name` argument.

    Parameters
    ----------
    command: string
        The IPA API command to execute.
    name: string
        The name parameter to pass to the command.
    args: dict
        The parameters to pass to the command.

    """
    return api.Command[command](name, **args)


def _afm_convert(value):
    if value is not None:
        if isinstance(value, list):
            return [_afm_convert(x) for x in value]
        if isinstance(value, dict):
            return {_afm_convert(k): _afm_convert(v)
                    for k, v in value.items()}
        if isinstance(value, str):
            return to_text(value)

    return value


def module_params_get(module, name):
    return _afm_convert(module.params.get(name))


def host_show(module, name):
    _args = {
        "all": True,
    }

    try:
        _result = ipa_command("host_show", name, _args)
    except ipalib_errors.NotFound as e:
        msg = str(e)
        if "host not found" in msg:
            return None
        module.fail_json(msg="host_show failed: %s" % msg)

    return _result["result"]


def main():
    module = AnsibleModule(
        argument_spec=dict(
            ipaadmin_principal=dict(type="str", default="admin"),
            ipaadmin_password=dict(type="str", required=False, no_log=True),
            ipaadmin_keytab=dict(type="str", required=False, no_log=False),
            hostname=dict(type="str", required=True),
        ),
        mutually_exclusive=[["ipaadmin_password", "ipaadmin_keytab"]],
        supports_check_mode=True,
    )

    if MODULE_IMPORT_ERROR is not None:
        module.fail_json(msg=MODULE_IMPORT_ERROR)

    # In check mode always return changed.
    if module.check_mode:
        module.exit_json(changed=True)

    ipaadmin_principal = module_params_get(module, "ipaadmin_principal")
    ipaadmin_password = module_params_get(module, "ipaadmin_password")
    ipaadmin_keytab = module_params_get(module, "ipaadmin_keytab")
    if ipaadmin_keytab:
        if not os.path.exists(ipaadmin_keytab):
            module.fail_json(msg="Unable to open ipaadmin_keytab '%s'" %
                             ipaadmin_keytab)

    hostname = module_params_get(module, "hostname")

    exit_args = {}

    # Connect to IPA API
    with ipa_connect(module, ipaadmin_principal, ipaadmin_password,
                     ipaadmin_keytab):
        res_show = host_show(module, hostname)

        args = {"random": True}
        if res_show is None:
            # Create new host, force is needed to create the host without
            # IP address.
            args["force"] = True
            result = ipa_command("host_add", hostname, args)
        else:
            # If host exists and has a keytab (is enrolled) then disable the
            # host to be able to create a new OTP.
            if res_show["has_keytab"]:
                ipa_command("host_disable", hostname, {})
            result = ipa_command("host_mod", hostname, args)

        exit_args["randompassword"] = result['result']['randompassword']

    module.exit_json(changed=True, host=exit_args)


if __name__ == "__main__":
    main()

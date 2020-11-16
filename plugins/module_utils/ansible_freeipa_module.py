#!/usr/bin/python
# -*- coding: utf-8 -*-

# Authors:
#   Sergio Oliveira Campos <seocam@redhat.com>
#   Thomas Woerner <twoerner@redhat.com>
#
# Copyright (C) 2019  Red Hat
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


import sys
import operator
import os
import uuid
import tempfile
import shutil
import gssapi
from datetime import datetime
from pprint import pformat

try:
    from packaging import version
except ImportError:
    # If `packaging` not found, split version string for creating version
    # object. Although it is not PEP 440 compliant, it will work for stable
    # FreeIPA releases.
    import re

    class version:
        @staticmethod
        def parse(version_str):
            """
            Split a version string A.B.C, into a tuple.

            This will not work for `rc`, `dev` or similar version string.
            """
            return tuple(re.split("[-_\.]", version_str))  # noqa: W605

from ipalib import api
from ipalib import errors as ipalib_errors  # noqa
from ipalib.config import Env
from ipalib.constants import DEFAULT_CONFIG, LDAP_GENERALIZED_TIME_FORMAT

try:
    from ipalib.install.kinit import kinit_password, kinit_keytab
except ImportError:
    from ipapython.ipautil import kinit_password, kinit_keytab
from ipapython.ipautil import run
from ipapython.dn import DN
from ipapython.version import VERSION
from ipaplatform.paths import paths
from ipalib.krb_utils import get_credentials_if_valid
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_text
from ansible.module_utils.common.text.converters import jsonify

try:
    from ipalib.x509 import Encoding
except ImportError:
    from cryptography.hazmat.primitives.serialization import Encoding

try:
    from ipalib.x509 import load_pem_x509_certificate
except ImportError:
    from ipalib.x509 import load_certificate
    load_pem_x509_certificate = None

import socket
import base64
import six

try:
    from collections.abc import Mapping  # noqa
except ImportError:
    from collections import Mapping  # noqa


if six.PY3:
    unicode = str


def valid_creds(module, principal):  # noqa
    """Get valid credentials matching the princial, try GSSAPI first."""
    if "KRB5CCNAME" in os.environ:
        ccache = os.environ["KRB5CCNAME"]
        module.debug('KRB5CCNAME set to %s' % ccache)

        try:
            cred = gssapi.Credentials(usage='initiate',
                                      store={'ccache': ccache})
        except gssapi.raw.misc.GSSError as e:
            module.fail_json(msg='Failed to find default ccache: %s' % e)
        else:
            module.debug("Using principal %s" % str(cred.name))
            return True

    elif "KRB5_CLIENT_KTNAME" in os.environ:
        keytab = os.environ.get('KRB5_CLIENT_KTNAME', None)
        module.debug('KRB5_CLIENT_KTNAME set to %s' % keytab)

        ccache_name = "MEMORY:%s" % str(uuid.uuid4())
        os.environ["KRB5CCNAME"] = ccache_name

        try:
            cred = kinit_keytab(principal, keytab, ccache_name)
        except gssapi.raw.misc.GSSError as e:
            module.fail_json(msg='Kerberos authentication failed : %s' % e)
        else:
            module.debug("Using principal %s" % str(cred.name))
            return True

    creds = get_credentials_if_valid()
    if creds and \
       creds.lifetime > 0 and \
       "%s@" % principal in creds.name.display_as(creds.name.name_type):
        return True
    return False


def temp_kinit(principal, password):
    """Kinit with password using a temporary ccache."""
    if not password:
        raise RuntimeError("The password is not set")
    if not principal:
        principal = "admin"

    ccache_dir = tempfile.mkdtemp(prefix='krbcc')
    ccache_name = os.path.join(ccache_dir, 'ccache')

    try:
        kinit_password(principal, password, ccache_name)
    except RuntimeError as e:
        raise RuntimeError("Kerberos authentication failed: {}".format(e))

    os.environ["KRB5CCNAME"] = ccache_name
    return ccache_dir, ccache_name


def temp_kdestroy(ccache_dir, ccache_name):
    """Destroy temporary ticket and remove temporary ccache."""
    if ccache_name is not None:
        run([paths.KDESTROY, '-c', ccache_name], raiseonerr=False)
        del os.environ['KRB5CCNAME']
    if ccache_dir is not None:
        shutil.rmtree(ccache_dir, ignore_errors=True)


def api_connect(context=None):
    """
    Initialize IPA API with the provided context.

    `context` can be any of:
        * `server` (default)
        * `ansible-freeipa`
        * `cli_installer`
    """
    env = Env()
    env._bootstrap()
    env._finalize_core(**dict(DEFAULT_CONFIG))

    # available contexts are 'server', 'ansible-freeipa' and 'cli_installer'
    if context is None:
        context = 'server'

    api.bootstrap(context=context, debug=env.debug, log=None)
    api.finalize()

    if api.env.in_server:
        backend = api.Backend.ldap2
    else:
        backend = api.Backend.rpcclient

    if not backend.isconnected():
        backend.connect(ccache=os.environ.get('KRB5CCNAME', None))


def api_command(module, command, name, args):
    """Call ipa.Command."""
    return api.Command[command](name, **args)


def api_command_no_name(module, command, args):
    """Call ipa.Command without a name."""
    return api.Command[command](**args)


def api_check_command(command):
    """Return if command exists in command list."""
    return command in api.Command


def api_check_param(command, name):
    """Check if param exists in command param list."""
    return name in api.Command[command].params


def api_check_ipa_version(oper, requested_version):
    """
    Compare the installed IPA version against a requested version.

    The valid operators are: <, <=, >, >=, ==, !=
    """
    oper_map = {
        "<": operator.lt,
        "<=": operator.le,
        ">": operator.gt,
        ">=": operator.ge,
        "==": operator.eq,
        "!=": operator.ne,
    }
    operation = oper_map.get(oper)
    if not(operation):
        raise NotImplementedError("Invalid operator: %s" % oper)
    return operation(version.parse(VERSION), version.parse(requested_version))


def execute_api_command(module, principal, password, command, name, args):
    """
    Execute an API command.

    Get KRB ticket if not already there, initialize api, connect,
    execute command and destroy ticket again if it has been created also.
    """
    ccache_dir = None
    ccache_name = None
    try:
        if not valid_creds(module, principal):
            ccache_dir, ccache_name = temp_kinit(principal, password)
        api_connect()

        return api_command(module, command, name, args)
    except Exception as e:
        module.fail_json(msg=str(e))

    finally:
        temp_kdestroy(ccache_dir, ccache_name)


def date_format(value):
    accepted_date_formats = [
        LDAP_GENERALIZED_TIME_FORMAT,  # generalized time
        '%Y-%m-%dT%H:%M:%SZ',  # ISO 8601, second precision
        '%Y-%m-%dT%H:%MZ',     # ISO 8601, minute precision
        '%Y-%m-%dZ',           # ISO 8601, date only
        '%Y-%m-%d %H:%M:%SZ',  # non-ISO 8601, second precision
        '%Y-%m-%d %H:%MZ',     # non-ISO 8601, minute precision
    ]

    for date_format in accepted_date_formats:
        try:
            return datetime.strptime(value, date_format)
        except ValueError:
            pass
    raise ValueError("Invalid date '%s'" % value)


def compare_args_ipa(module, args, ipa):  # noqa
    """Compare IPA obj attrs with the command args.

    This function compares IPA objects attributes with the args the
    module is intending to use to call a command. This is useful to know
    if call to IPA server will be needed or not.
    In other to compare we have to prepare the perform slight changes in
    data formats.

    Returns True if they are the same and False otherwise.
    """
    base_debug_msg = "Ansible arguments and IPA commands differed. "

    for key in args.keys():
        if key not in ipa:
            module.debug(
                base_debug_msg + "Command key not present in IPA: %s" % key
            )
            return False
        else:
            arg = args[key]
            ipa_arg = ipa[key]
            # If ipa_arg is a list and arg is not, replace arg
            # with list containing arg. Most args in a find result
            # are lists, but not all.
            if isinstance(ipa_arg, tuple):
                ipa_arg = list(ipa_arg)
            if isinstance(ipa_arg, list):
                if not isinstance(arg, list):
                    arg = [arg]
                if len(ipa_arg) != len(arg):
                    module.debug(
                        base_debug_msg
                        + "List length doesn't match for key %s: %d %d"
                        % (key, len(arg), len(ipa_arg),)
                    )
                    return False
                if isinstance(ipa_arg[0], str) and isinstance(arg[0], int):
                    arg = [to_text(_arg) for _arg in arg]
                if isinstance(ipa_arg[0], unicode) and isinstance(arg[0], int):
                    arg = [to_text(_arg) for _arg in arg]
            try:
                arg_set = set(arg)
                ipa_arg_set = set(ipa_arg)
            except TypeError:
                if arg != ipa_arg:
                    module.debug(
                        base_debug_msg
                        + "Different values: %s %s" % (arg, ipa_arg)
                    )
                    return False
            else:
                if arg_set != ipa_arg_set:
                    module.debug(
                        base_debug_msg
                        + "Different set content: %s %s"
                        % (arg_set, ipa_arg_set,)
                    )
                    return False
    return True


def _afm_convert(value):
    if value is not None:
        if isinstance(value, list):
            return [_afm_convert(x) for x in value]
        elif isinstance(value, dict):
            return {_afm_convert(k): _afm_convert(v) for k, v in value.items()}
        elif isinstance(value, str):
            return to_text(value)
        else:
            return value
    else:
        return value


def module_params_get(module, name):
    return _afm_convert(module.params.get(name))


def api_get_realm():
    return api.env.realm


def gen_add_del_lists(user_list, res_list):
    """Generate the lists for the addition and removal of members."""
    # The user list is None, therefore the parameter should not be touched
    if user_list is None:
        return [], []

    add_list = list(set(user_list or []) - set(res_list or []))
    del_list = list(set(res_list or []) - set(user_list or []))

    return add_list, del_list


def encode_certificate(cert):
    """
    Encode a certificate using base64.

    It also takes FreeIPA and Python versions into account.
    """
    if isinstance(cert, (str, unicode, bytes)):
        encoded = base64.b64encode(cert)
    else:
        encoded = base64.b64encode(cert.public_bytes(Encoding.DER))
    if not six.PY2:
        encoded = encoded.decode('ascii')
    return encoded


def load_cert_from_str(cert):
    cert = cert.strip()
    if not cert.startswith("-----BEGIN CERTIFICATE-----"):
        cert = "-----BEGIN CERTIFICATE-----\n" + cert
    if not cert.endswith("-----END CERTIFICATE-----"):
        cert += "\n-----END CERTIFICATE-----"

    if load_pem_x509_certificate is not None:
        cert = load_pem_x509_certificate(cert.encode('utf-8'))
    else:
        cert = load_certificate(cert.encode('utf-8'))
    return cert


def DN_x500_text(text):
    if hasattr(DN, "x500_text"):
        return DN(text).x500_text()
    else:
        # Emulate x500_text
        dn = DN(text)
        dn.rdns = reversed(dn.rdns)
        return str(dn)


def is_valid_port(port):
    if not isinstance(port, int):
        return False

    if 1 <= port <= 65535:
        return True

    return False


def is_ipv4_addr(ipaddr):
    """Test if given IP address is a valid IPv4 address."""
    try:
        socket.inet_pton(socket.AF_INET, ipaddr)
    except socket.error:
        return False
    return True


def is_ipv6_addr(ipaddr):
    """Test if given IP address is a valid IPv6 address."""
    try:
        socket.inet_pton(socket.AF_INET6, ipaddr)
    except socket.error:
        return False
    return True


def exit_raw_json(module, **kwargs):
    """
    Print the raw parameters in JSON format, without masking.

    Due to Ansible filtering out values in the output that match values
    in variables which has `no_log` set, if a module need to return user
    defined dato to the controller, it cannot rely on
    AnsibleModule.exit_json, as there is a chance that a partial match may
    occur, masking the data returned.

    This method is a replacement for AnsibleModule.exit_json. It has
    nearly the same implementation as exit_json, but does not filter
    data. Beware that this data will be logged by Ansible, and if it
    contains sensible data, it will be appear in the logs.
    """
    module.do_cleanup_files()
    print(jsonify(kwargs))
    sys.exit(0)


class AnsibleFreeIPAParams(Mapping):
    def __init__(self, ansible_module):
        self.mapping = ansible_module.params
        self.ansible_module = ansible_module

    def __getitem__(self, key):
        param = self.mapping[key]
        if param is not None:
            return _afm_convert(param)

    def __iter__(self):
        return iter(self.mapping)

    def __len__(self):
        return len(self.mapping)

    @property
    def names(self):
        return self.name

    def __getattr__(self, name):
        return self.get(name)


class FreeIPABaseModule(AnsibleModule):
    """
    Base class for FreeIPA Ansible modules.

    Provides methods useful methods to be used by our modules.

    This class should be overriten and instantiated for the module.
    A basic implementation of an Ansible FreeIPA module expects its
    class to:

    1. Define a class attribute ``ipa_param_mapping``
    2. Implement the method ``define_ipa_commands()``
    3. Implement the method ``check_ipa_params()`` (optional)

    After instantiating the class the method ``ipa_run()`` should be called.

    Example (ansible-freeipa/plugins/modules/ipasomemodule.py):

    class SomeIPAModule(FreeIPABaseModule):
        ipa_param_mapping = {
            "arg_to_be_passed_to_ipa_command": "module_param",
            "another_arg": "get_another_module_param",
        }

        def get_another_module_param(self):
            another_module_param = self.ipa_params.another_module_param
            # Validate or modify another_module_param
            # ...
            return another_module_param

        def check_ipa_params(self):
            # Validate your params here
            # Example:
            if not self.ipa_params.module_param in VALID_OPTIONS:
                self.fail_json(msg="Invalid value for argument module_param")

        def define_ipa_commands(self):
            args = self.get_ipa_command_args()

            self.add_ipa_command(
                "some_ipa_command",
                name="obj-name",
                args=args,
            )

    def main():
        ipa_module = SomeIPAModule(argument_spec=dict(
            module_param=dict(
                type="str",
                default=None,
                required=False,
            ),
            another_module_param=dict(
                type="str",
                default=None,
                required=False,
            ),
        ))
        ipa_module.ipa_run()

    if __name__ == "__main__":
        main()

    """

    ipa_param_mapping = None

    def __init__(self, *args, **kwargs):
        super(FreeIPABaseModule, self).__init__(*args, **kwargs)

        # Attributes to store kerberos credentials (if needed)
        self.ccache_dir = None
        self.ccache_name = None

        # Status of an execution. Will be changed to True
        #   if something is actually peformed.
        self.changed = False

        # Status of the connection with the IPA server.
        # We need to know if the connection was actually stablished
        #   before we start sending commands.
        self.ipa_connected = False

        # Commands to be executed
        self.ipa_commands = []

        # Module exit arguments.
        self.exit_args = {}

        # Wrapper around the AnsibleModule.params.
        # Return the actual params but performing transformations
        #   when needed.
        self.ipa_params = AnsibleFreeIPAParams(self)

    def get_ipa_command_args(self, **kwargs):
        """
        Return a dict to be passed to an IPA command.

        The keys of ``ipa_param_mapping`` are also the keys of the return dict.

        The values of ``ipa_param_mapping`` needs to be either:
            * A str with the name of a defined method; or
            * A key of ``AnsibleModule.param``.

        In case of a method the return of the method will be set as value
        for the return dict.

        In case of a AnsibleModule.param the value of the param will be
        set in the return dict. In addition to that boolean values will be
        automaticaly converted to uppercase strings (as required by FreeIPA
        server).

        """
        args = {}
        for ipa_param_name, param_name in self.ipa_param_mapping.items():

            # Check if param_name is actually a param
            if param_name in self.ipa_params:
                value = self.ipa_params.get(param_name)
                if isinstance(value, bool):
                    value = "TRUE" if value else "FALSE"

            # Since param wasn't a param check if it's a method name
            elif hasattr(self, param_name):
                method = getattr(self, param_name)
                if callable(method):
                    value = method(**kwargs)

            # We don't have a way to guess the value so fail.
            else:
                self.fail_json(
                    msg=(
                        "Couldn't get a value for '%s'. Option '%s' is not "
                        "a module argument neither a defined method."
                    )
                    % (ipa_param_name, param_name)
                )

            if value is not None:
                args[ipa_param_name] = value

        return args

    def check_ipa_params(self):
        """Validate ipa_params before command is called."""
        pass

    def define_ipa_commands(self):
        """Define commands that will be run in IPA server."""
        raise NotImplementedError

    def api_command(self, command, name=None, args=None):
        """Execute a single command in IPA server."""
        if args is None:
            args = {}

        if name is None:
            return api_command_no_name(self, command, args)

        return api_command(self, command, name, args)

    def __enter__(self):
        """
        Connect to IPA server.

        Check the there are working Kerberos credentials to connect to
        IPA server. If there are not we perform a temporary kinit
        that will be terminated when exiting the context.

        If the connection fails ``ipa_connected`` attribute will be set
        to False.
        """
        principal = self.ipa_params.ipaadmin_principal
        password = self.ipa_params.ipaadmin_password

        try:
            if not valid_creds(self, principal):
                self.ccache_dir, self.ccache_name = temp_kinit(
                    principal, password,
                )

            api_connect()

        except Exception as excpt:
            self.fail_json(msg=str(excpt))
        else:
            self.ipa_connected = True

        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """
        Terminate a connection with the IPA server.

        Deal with exceptions, destroy temporary kinit credentials and
        exit the module with proper arguments.

        """
        # TODO: shouldn't we also disconnect from api backend?
        temp_kdestroy(self.ccache_dir, self.ccache_name)

        if exc_type == SystemExit:
            raise

        if exc_val:
            self.fail_json(msg=str(exc_val))

        self.exit_json(changed=self.changed, **self.exit_args)

    def get_command_errors(self, command, result):
        """Look for erros into command results."""
        # Get all errors
        # All "already a member" and "not a member" failures in the
        # result are ignored. All others are reported.
        errors = []
        for item in result.get("failed", tuple()):
            failed_item = result["failed"][item]
            for member_type in failed_item:
                for member, failure in failed_item[member_type]:
                    if (
                        "already a member" in failure
                        or "not a member" in failure
                    ):
                        continue
                    errors.append(
                        "%s: %s %s: %s"
                        % (command, member_type, member, failure)
                    )

        if len(errors) > 0:
            self.fail_json(", ".join("errors"))

    def add_ipa_command(self, command, name=None, args=None):
        """Add a command to the list of commands to be executed."""
        self.ipa_commands.append((name, command, args or {}))

    def _run_ipa_commands(self):
        """Execute commands in self.ipa_commands."""
        result = None

        for name, command, args in self.ipa_commands:
            try:
                result = self.api_command(command, name, args)
            except Exception as excpt:
                self.fail_json(msg="%s: %s: %s" % (command, name, str(excpt)))
            else:
                self.process_command_result(name, command, args, result)
            self.get_command_errors(command, result)

    def process_command_result(self, name, command, args, result):
        """
        Process an API command result.

        This method can be overriden in subclasses, and change self.exit_values
        to return data in the result for the controller.
        """
        if "completed" in result:
            if result["completed"] > 0:
                self.changed = True
        else:
            self.changed = True

    def require_ipa_attrs_change(self, command_args, ipa_attrs):
        """
        Compare given args with current object attributes.

        Returns True in case current IPA object attributes differ from
        args passed to the module.
        """
        equal = compare_args_ipa(self, command_args, ipa_attrs)
        return not equal

    def pdebug(self, value):
        """Debug with pretty formatting."""
        self.debug(pformat(value))

    def ipa_run(self):
        """Execute module actions."""
        with self:
            if not self.ipa_connected:
                return

            self.check_ipa_params()
            self.define_ipa_commands()
            self._run_ipa_commands()

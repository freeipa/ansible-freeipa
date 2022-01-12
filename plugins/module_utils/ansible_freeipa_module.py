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


from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

__all__ = ["gssapi", "netaddr", "api", "ipalib_errors", "Env",
           "DEFAULT_CONFIG", "LDAP_GENERALIZED_TIME_FORMAT",
           "kinit_password", "kinit_keytab", "run", "DN", "VERSION",
           "paths", "get_credentials_if_valid", "Encoding",
           "load_pem_x509_certificate", "DNSName"]

import sys

# HACK: workaround for Ansible 2.9
# https://github.com/ansible/ansible/issues/68361
if 'ansible.executor' in sys.modules:
    for attr in __all__:
        setattr(sys.modules[__name__], attr, None)
else:
    import operator
    import os
    import uuid
    import tempfile
    import shutil
    import netaddr
    import gssapi
    from datetime import datetime
    from contextlib import contextmanager
    import inspect

    # ansible-freeipa requires locale to be C, IPA requires utf-8.
    os.environ["LANGUAGE"] = "C"

    try:
        from packaging import version
    except ImportError:
        # If `packaging` not found, split version string for creating version
        # object. Although it is not PEP 440 compliant, it will work for stable
        # FreeIPA releases.
        import re

        class version:  # pylint: disable=invalid-name, too-few-public-methods
            @staticmethod
            def parse(version_str):
                """
                Split a version string A.B.C, into a tuple.

                This will not work for `rc`, `dev` or similar version string.
                """
                return tuple(re.split("[-_.]", version_str))  # noqa: W605

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
    from ipapython.dnsutil import DNSName
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
    from ansible.module_utils import six

    try:
        from collections.abc import Mapping  # noqa
    except ImportError:
        from collections import Mapping  # pylint: disable=deprecated-class

    # Try to import is_ipa_configured or use a fallback implementation.
    try:
        from ipalib.facts import is_ipa_configured
    except ImportError:
        try:
            from ipaserver.install.installutils import is_ipa_configured
        except ImportError:
            from ipalib.install import sysrestore

            def is_ipa_configured():
                sstore = sysrestore.StateFile(paths.SYSRESTORE)

                if sstore.has_state('installation'):
                    return sstore.get_state('installation', 'complete')

                fstore = sysrestore.FileStore(paths.SYSRESTORE)

                IPA_MODULES = [  # pylint: disable=invalid-name
                    'httpd', 'kadmin', 'dirsrv', 'pki-tomcatd', 'install',
                    'krb5kdc', 'ntpd', 'named'
                ]

                for module in IPA_MODULES:
                    if sstore.has_state(module):
                        return True

                return fstore.has_files()

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

    def api_connect(context=None, **overrides):
        """
        Initialize IPA API with the provided configuration.

        Parameters
        ----------
        context:
            Set IPA API execution context. Valid values: "server", "client"

        overrides:
            Keyword argument dict containing arguments passed to
            api.bootstrap() to configure API connection.
            Valid overrides arguments include:
                ldap_cache: Control use of LDAP cache layer. (bool)

        """
        env = Env()
        env._bootstrap()
        env._finalize_core(**dict(DEFAULT_CONFIG))

        # Fail connection if an unexpected argument is passed in 'overrides'.
        _allowed = set(["ldap_cache"])
        _inv = set(overrides.keys()) - _allowed
        if _inv:
            raise ValueError("Cannot override parameters: %s" % ",".join(_inv))

        # If not set, context will be based on current API context.
        if context is None:
            context = "server" if is_ipa_configured() else "client"

        # Available contexts are 'server' and 'client'.
        if context not in ["server", "client"]:
            raise ValueError("Invalid execution context: %s" % (context))

        # IPA uses 'cli' for a 'client' context, but 'client'
        # provides a better user interface. Here we map the
        # value if needed.
        if context == "client":
            context = "cli"

        api.bootstrap(context=context, debug=env.debug, log=None, **overrides)
        api.finalize()

        if api.env.in_server:
            backend = api.Backend.ldap2
        else:
            backend = api.Backend.rpcclient

        if not backend.isconnected():
            backend.connect(ccache=os.environ.get('KRB5CCNAME', None))

    def api_command(_module, command, name, args):
        """Call ipa.Command."""
        return api.Command[command](name, **args)

    def api_command_no_name(_module, command, args):
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
        if not operation:
            raise NotImplementedError("Invalid operator: %s" % oper)
        return operation(version.parse(VERSION),
                         version.parse(requested_version))

    def date_format(value):
        accepted_date_formats = [
            LDAP_GENERALIZED_TIME_FORMAT,  # generalized time
            '%Y-%m-%dT%H:%M:%SZ',  # ISO 8601, second precision
            '%Y-%m-%dT%H:%MZ',     # ISO 8601, minute precision
            '%Y-%m-%dZ',           # ISO 8601, date only
            '%Y-%m-%d %H:%M:%SZ',  # non-ISO 8601, second precision
            '%Y-%m-%d %H:%MZ',     # non-ISO 8601, minute precision
        ]

        for _date_format in accepted_date_formats:
            try:
                return datetime.strptime(value, _date_format)
            except ValueError:
                pass
        raise ValueError("Invalid date '%s'" % value)

    def compare_args_ipa(module, args, ipa, ignore=None):  # noqa
        """Compare IPA obj attrs with the command args.

        This function compares IPA objects attributes with the args the
        module is intending to use to call a command. ignore can be a list
        of attributes, that should be ignored in the comparison.
        This is useful to know if a call to IPA server will be needed or not.
        In order to compare we have to perform slight changes in data formats.

        Returns True if they are the same and False otherwise.
        """
        base_debug_msg = "Ansible arguments and IPA commands differed. "

        # If both args and ipa are None, return there's no difference.
        # If only one is None, return there is a difference.
        # This tests avoid unecessary invalid access to attributes.
        if args is None or ipa is None:
            return args is None and ipa is None

        # Fail if args or ipa are not dicts.
        if not (isinstance(args, dict) and isinstance(ipa, dict)):
            raise TypeError("Expected 'dicts' to compare.")

        # Create filtered_args using ignore
        if ignore is None:
            ignore = []
        filtered_args = [key for key in args if key not in ignore]

        for key in filtered_args:
            if key not in ipa:  # pylint: disable=no-else-return
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
                    if isinstance(ipa_arg[0], unicode) \
                       and isinstance(arg[0], int):
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
            if isinstance(value, dict):
                return {_afm_convert(k): _afm_convert(v)
                        for k, v in value.items()}
            if isinstance(value, str):
                return to_text(value)

        return value

    def module_params_get(module, name):
        return _afm_convert(module.params.get(name))

    def module_params_get_lowercase(module, name):
        value = _afm_convert(module.params.get(name))
        if isinstance(value, list):
            value = [v.lower() for v in value]
        if isinstance(value, (str, unicode)):
            value = value.lower()
        return value

    def api_get_domain():
        return api.env.domain

    def ensure_fqdn(name, domain):
        if "." not in name:
            return "%s.%s" % (name, domain)
        return name

    def api_get_realm():
        return api.env.realm

    def api_get_basedn():
        return api.env.basedn

    def gen_add_del_lists(user_list, res_list):
        """
        Generate the lists for the addition and removal of members.

        This function should be used to apply a new user list as a set
        operation without action: members.

        For the addition of new and the removal of existing members with
        action: members gen_add_list and gen_intersection_list should
        be used.
        """
        # The user list is None, no need to do anything, return empty lists
        if user_list is None:
            return [], []

        add_list = list(set(user_list or []) - set(res_list or []))
        del_list = list(set(res_list or []) - set(user_list or []))

        return add_list, del_list

    def gen_add_list(user_list, res_list):
        """
        Generate add list for addition of new members.

        This function should be used to add new members with action: members
        and state: present.

        It is returning the difference of the user and res list if the user
        list is not None.
        """
        # The user list is None, no need to do anything, return empty list
        if user_list is None:
            return []

        return list(set(user_list or []) - set(res_list or []))

    def gen_intersection_list(user_list, res_list):
        """
        Generate the intersection list for removal of existing members.

        This function should be used to remove existing members with
        action: members and state: absent.

        It is returning the intersection of the user and res list if the
        user list is not None.
        """
        # The user list is None, no need to do anything, return empty list
        if user_list is None:
            return []

        return list(set(res_list or []).intersection(set(user_list or [])))

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

    def DN_x500_text(text):  # pylint: disable=invalid-name
        if hasattr(DN, "x500_text"):
            return DN(text).x500_text()
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

    def is_ip_address(ipaddr):
        """Test if given IP address is a valid IPv4 or IPv6 address."""
        try:
            netaddr.IPAddress(str(ipaddr))
        except (netaddr.AddrFormatError, ValueError):
            return False
        return True

    def is_ip_network_address(ipaddr):
        """Test if given IP address is a valid IPv4 or IPv6 address."""
        try:
            netaddr.IPNetwork(str(ipaddr))
        except (netaddr.AddrFormatError, ValueError):
            return False
        return True

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

    class IPAParamMapping(Mapping):
        """
        Provides IPA API mapping to playbook parameters or computed values.

        It can be used to define a mapping of playbook parameters
        or methods that provide computed values to IPA API arguments.

        Playbook parameters can be retrieved as properties,
        and the set of IPA arguments for a command can be
        retrived with ``get_ipa_command_args()``. The keys for
        ``param_mapping`` are also the keys of the argument set.

        The values of ``param_mapping`` can be either:
            * a str representing a key of ``AnsibleModule.params``.
            * a callable.

        In case of an ``AnsibleModule.param`` the value of the playbook
        param will be used for that argument. If it is a ``callable``,
        the value returned by the execution of it will be used.

        Example:
        -------
            def check_params(ipa_params):
                # Module parameters can be accessed as properties.
                if len(ipa_params.name) == 0:
                    ipa_params.ansible_module.fail_json(msg="No given name.")


            def define_ipa_commands(self):
                # Create the argument dict from the defined mapping.
                args = self.get_ipa_command_args()

                _commands = [("obj-name", "some_ipa_command", args)]
                return _commands


            def a_method_for_a_computed_param():
                return "Some computed value"


            def main():
                ansible_module = SomeIPAModule(argument_spec=dict(
                    name=dict(type="list", aliases=["cn"], required=True),
                    state=dict(type="str", default="present",
                               choices=["present", "absent"]),
                    module_param=(type="str", required=False),
                    )
                )

                # Define the playbook to IPA API mapping
                ipa_param_mapping = {
                    "arg_to_be_passed_to_ipa_command": "module_param",
                    "another_arg": a_method_for_a_computed_param,
                }
                ipa_params = IPAParamMapping(
                    ansible_module,
                    param_mapping=ipa_param_mapping
                )

                check_params(ipa_params)
                comands = define_ipa_commands(ipa_params)

                ansible_module.execute_ipa_commands(commands)

        """

        def __init__(self, ansible_module, param_mapping=None):
            self.mapping = ansible_module.params
            self.ansible_module = ansible_module
            self.param_mapping = param_mapping or {}

        def __getitem__(self, key):
            param = self.mapping[key]
            if param is None:
                return None
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

        def get_ipa_command_args(self, **kwargs):
            """Return a dict to be passed to an IPA command."""
            args = {}
            for ipa_param_name, param_name in self.param_mapping.items():

                # Check if param_name is actually a param
                if param_name in self.ansible_module.params:
                    value = self.ansible_module.params_get(param_name)
                    if isinstance(value, bool):
                        value = "TRUE" if value else "FALSE"

                # Since param wasn't a param check if it's a method name
                elif callable(param_name):
                    value = param_name(**kwargs)

                # We don't have a way to guess the value so fail.
                else:
                    self.ansible_module.fail_json(
                        msg=(
                            "Couldn't get a value for '%s'. Option '%s' is "
                            "not a module argument neither a defined method."
                        )
                        % (ipa_param_name, param_name)
                    )

                if value is not None:
                    args[ipa_param_name] = value

            return args

    class IPAAnsibleModule(AnsibleModule):
        """
        IPA Ansible Module.

        This class is an extended version of the Ansible Module that provides
        IPA specific methods to simplify module generation.

        Simple example:

        from ansible.module_utils.ansible_freeipa_module import \
            IPAAnsibleModule

        def main():
            ansible_module = IPAAnsibleModule(
                argument_spec=dict(
                      name=dict(type="str", aliases=["cn"], default=None),
                      state=dict(type="str", default="present",
                                 choices=["present", "absent"]),
                ),
            )

            # Get parameters
            name = ansible_module.params_get("name")
            state = ansible_module.params_get("state")

            # Connect to IPA API
            with ansible_module.ipa_connect():

                # Execute command
                if state == "present":
                    ansible_module.ipa_command("command_add", name, {})
                else:
                    ansible_module.ipa_command("command_del", name, {})

            # Done

            ansible_module.exit_json(changed=True)

        if __name__ == "__main__":
            main()

        """

        # IPAAnsibleModule argument specs used for all modules
        ipa_module_base_spec = dict(
            ipaadmin_principal=dict(type="str", default="admin"),
            ipaadmin_password=dict(type="str", required=False, no_log=True),
            ipaapi_context=dict(
                type="str", required=False, choices=["server", "client"],
            ),
            ipaapi_ldap_cache=dict(type="bool", default="True"),
        )

        def __init__(self, *args, **kwargs):
            # Extend argument_spec with ipa_module_base_spec
            if "argument_spec" in kwargs:
                _spec = kwargs["argument_spec"]
                _spec.update(self.ipa_module_base_spec)
                kwargs["argument_spec"] = _spec

            # pylint: disable=super-with-arguments
            super(IPAAnsibleModule, self).__init__(*args, **kwargs)

        @contextmanager
        def ipa_connect(self, context=None):
            """
            Create a context with a connection to IPA API.

            Parameters
            ----------
            context: string
                An optional parameter defining which context API
                commands will be executed.

            """
            # ipaadmin vars
            ipaadmin_principal = self.params_get("ipaadmin_principal")
            ipaadmin_password = self.params_get("ipaadmin_password")
            if context is None:
                context = self.params_get("ipaapi_context")

            # Get set of parameters to override in api.bootstrap().
            # Here, all 'ipaapi_*' params are allowed, and the control
            # of invalid parameters is delegated to api_connect.
            _excl_override = ["ipaapi_context"]
            overrides = {
                name[len("ipaapi_"):]: self.params_get(name)
                for name in self.params
                if name.startswith("ipaapi_") and name not in _excl_override
            }

            ccache_dir = None
            ccache_name = None
            try:
                if not valid_creds(self, ipaadmin_principal):
                    ccache_dir, ccache_name = temp_kinit(
                        ipaadmin_principal, ipaadmin_password)
                api_connect(context, **overrides)
            except Exception as e:
                self.fail_json(msg=str(e))
            else:
                try:
                    yield ccache_name
                except Exception as e:
                    self.fail_json(msg=str(e))
                finally:
                    temp_kdestroy(ccache_dir, ccache_name)

        def params_get(self, name):
            """
            Retrieve value set for module parameter.

            Parameters
            ----------
            name: string
                The name of the parameter to retrieve.

            """
            return module_params_get(self, name)

        def params_get_lowercase(self, name):
            """
            Retrieve value set for module parameter as lowercase, if not None.

            Parameters
            ----------
            name: string
                The name of the parameter to retrieve.

            """
            return module_params_get_lowercase(self, name)

        def params_fail_used_invalid(self, invalid_params, state, action=None):
            """
            Fail module execution if one of the invalid parameters is not None.

            Parameters
            ----------
            invalid_params:
                List of parameters that must value 'None'.
            state:
                State being tested.
            action:
                Action being tested (optional).

            """
            if action is None:
                msg = "Argument '{0}' can not be used with state '{1}'"
            else:
                msg = "Argument '{0}' can not be used with action "\
                      "'{2}' and state '{1}'"

            for param in invalid_params:
                if self.params.get(param) is not None:
                    self.fail_json(msg=msg.format(param, state, action))

        def ipa_command(self, command, name, args):
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
            return api_command(self, command, name, args)

        def ipa_command_no_name(self, command, args):
            """
            Execute an IPA API command requiring no `name` argument.

            Parameters
            ----------
            command: string
                The IPA API command to execute.
            args: dict
                The parameters to pass to the command.

            """
            return api_command_no_name(self, command, args)

        def ipa_get_domain(self):
            """Retrieve IPA API domain."""
            if not hasattr(self, "__ipa_api_domain"):
                setattr(self, "__ipa_api_domain", api_get_domain())
            return getattr(self, "__ipa_api_domain")

        @staticmethod
        def ipa_get_realm():
            """Retrieve IPA API realm."""
            return api_get_realm()

        @staticmethod
        def ipa_get_basedn():
            """Retrieve IPA API basedn."""
            return api_get_basedn()

        @staticmethod
        def ipa_command_exists(command):
            """
            Check if IPA command is supported.

            Parameters
            ----------
            command: string
                The IPA API command to verify.

            """
            return api_check_command(command)

        @staticmethod
        def ipa_command_param_exists(command, name):
            """
            Check if IPA command support a specific parameter.

            Parameters
            ----------
            command: string
                The IPA API command to test.
            name: string
                The parameter name to verify.

            """
            return api_check_param(command, name)

        @staticmethod
        def ipa_check_version(oper, requested_version):
            """
            Compare available IPA version.

            Parameters
            ----------
            oper: string
                The relational operator to use.
            requested_version: string
                The version to compare to.

            """
            return api_check_ipa_version(oper, requested_version)

        # pylint: disable=unused-argument
        @staticmethod
        def member_error_handler(module, result, command, name, args, errors):
            # Get all errors
            for failed_item in result.get("failed", []):
                failed = result["failed"][failed_item]
                for member_type in failed:
                    for member, failure in failed[member_type]:
                        errors.append("%s: %s %s: %s" % (
                            command, member_type, member, failure))

        def execute_ipa_commands(self, commands, result_handler=None,
                                 exception_handler=None,
                                 fail_on_member_errors=False,
                                 **handlers_user_args):
            """
            Execute IPA API commands from command list.

            Parameters
            ----------
            commands: list of string tuple
                The list of commands in the form (name, command and args)
                For commands that do not require a 'name', None needs be
                used.
            result_handler: function
                The user function to handle results of the single commands
            exception_handler: function
                The user function to handle exceptions of the single commands
                Returns True to continue to next command, else False
            fail_on_member_errors: bool
                Use default member error handler handler member_error_handler
            handlers_user_args: dict (user args mapping)
                The user args to pass to result_handler and exception_handler
                functions

            Example (ipauser module):

            def result_handler(module, result, command, name, args, exit_args,
                              one_name):
                if "random" in args and command in ["user_add", "user_mod"] \
                   and "randompassword" in result["result"]:
                    if one_name:
                        exit_args["randompassword"] = \
                            result["result"]["randompassword"]
                    else:
                        exit_args.setdefault(name, {})["randompassword"] = \
                            result["result"]["randompassword"]

            def exception_handler(module, ex, exit_args, one_name):
                if ex.exception == ipalib_errors.EmptyModlist:
                    result = {}
                return False

            exit_args = {}
            changed = module.execute_ipa_commands(commands, result_handler,
                                                  exception_handler,
                                                  exit_args=exit_args,
                                                  one_name=len(names)==1)

            ansible_module.exit_json(changed=changed, user=exit_args)

            """
            # Fail on given handlers_user_args without result or exception
            # handler
            if result_handler is None and exception_handler is None and \
               len(handlers_user_args) > 0:
                self.fail_json(msg="Args without result and exception hander: "
                               "%s" % repr(handlers_user_args))

            # Fail on given result_handler and fail_on_member_errors
            if result_handler is not None and fail_on_member_errors:
                self.fail_json(
                    msg="result_handler given and fail_on_member_errors set")

            # No commands, report no changes
            if commands is None:
                return False

            # In check_mode return if there are commands to do
            if self.check_mode:
                return len(commands) > 0

            # Error list for result_handler and error_handler
            _errors = []

            # Handle fail_on_member_errors, set result_handler to
            # member_error_handler
            # Add internal _errors for result_hendler if the module is not
            # adding it. This also activates the final fail_json if
            # errors are found.
            if fail_on_member_errors:
                result_handler = IPAAnsibleModule.member_error_handler
                handlers_user_args["errors"] = _errors
            elif result_handler is not None:
                if "errors" not in handlers_user_args:
                    # pylint: disable=deprecated-method
                    argspec = inspect.getargspec(result_handler)
                    if "errors" in argspec.args:
                        handlers_user_args["errors"] = _errors

            changed = False
            for name, command, args in commands:
                try:
                    if name is None:
                        result = self.ipa_command_no_name(command, args)
                    else:
                        result = self.ipa_command(command, name, args)

                    if "completed" in result:
                        if result["completed"] > 0:
                            changed = True
                    else:
                        changed = True

                    # If result_handler is not None, call it with user args
                    # defined in **handlers_user_args
                    if result_handler is not None:
                        result_handler(self, result, command, name, args,
                                       **handlers_user_args)

                except Exception as e:
                    if exception_handler is not None and \
                       exception_handler(self, e, **handlers_user_args):
                        continue
                    self.fail_json(msg="%s: %s: %s" % (command, name, str(e)))

            # Fail on errors from result_handler and exception_handler
            if len(_errors) > 0:
                self.fail_json(msg=", ".join(_errors))

            return changed

    class FreeIPABaseModule(IPAAnsibleModule):
        """
        Base class for FreeIPA Ansible modules.

        Provides methods useful methods to be used by our modules.

        This class should be overriten and instantiated for the module.
        A basic implementation of an Ansible FreeIPA module expects its
        class to:

        1. Define a class attribute ``ipa_param_mapping``
        2. Implement the method ``define_ipa_commands()``
        3. Implement the method ``check_ipa_params()`` (optional)

        After instantiating the class the method ``ipa_run()`` should be
        called.

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
                    self.fail_json(
                        msg="Invalid value for argument module_param")

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
            # pylint: disable=super-with-arguments
            super(FreeIPABaseModule, self).__init__(*args, **kwargs)

            self.deprecate(
                msg="FreeIPABaseModule is deprecated. Use IPAAnsibleModule.",
                version="1.5.0"
            )

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

        def get_ipa_command_args(self, **kwargs):
            """
            Return a dict to be passed to an IPA command.

            The keys of ``ipa_param_mapping`` are also the keys of the return
            dict.

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
            self.deprecate(
                msg=(
                    "FreeIPABaseModule is deprecated. Use IPAAnsibleModule. "
                    "Use 'AnsibleFreeIPAParams.get_ipa_command_args()', "
                    "Instantiate it using the class 'ipa_params_mapping'."
                ),
                version="1.5.0"
            )
            mapping = IPAParamMapping(self, self.ipa_param_mapping)
            return mapping.get_ipa_command_args(**kwargs)

        def check_ipa_params(self):
            """Validate ipa_params before command is called."""
            self.deprecate(
                msg=(
                    "FreeIPABaseModule is deprecated. Use IPAAnsibleModule. "
                ),
                version="1.5.0"
            )
            pass  # pylint: disable=unnecessary-pass

        def define_ipa_commands(self):
            """Define commands that will be run in IPA server."""
            raise NotImplementedError

        def add_ipa_command(self, command, name=None, args=None):
            """Add a command to the list of commands to be executed."""
            self.ipa_commands.append((name, command, args or {}))

        def _run_ipa_commands(self):
            """Execute commands in self.ipa_commands."""
            self.changed = self.execute_ipa_commands(
                self.ipa_commands,
                result_handler=self.process_results.__func__,
                exit_args=self.exit_args
            )

        def process_results(
            self, result, command, name, args, exit_args
        ):  # pylint: disable=unused-argument
            """
            Process an API command result.

            This method must be overriden in subclasses if 'exit_args'
            is to be modified.
            """
            self.deprecate(
                msg=(
                    "FreeIPABaseModule is deprecated. Use IPAAnsibleModule. "
                ),
                version="1.5.0"
            )
            self.process_command_result(name, command, args, result)

        def process_command_result(self, _name, _command, _args, result):
            """
            Process an API command result.

            This method can be overriden in subclasses, and
            change self.exit_values to return data in the
            result for the controller.
            """
            self.deprecate(
                msg=(
                    "FreeIPABaseModule is deprecated. Use IPAAnsibleModule. "
                    "To aid in porting to IPAAnsibleModule, change to "
                    "'FreeIPABaseModule.process_results'."
                ),
                version="1.5.0"
            )

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
            self.deprecate(
                msg=(
                    "FreeIPABaseModule is deprecated. Use IPAAnsibleModule. "
                    "FreeIPABaseModule require_ipa_attrs_change() is "
                    "deprecated. Use ansible_freeipa_module.compare_args()."
                ),
                version="1.5.0"
            )
            equal = compare_args_ipa(self, command_args, ipa_attrs)
            return not equal

        def ipa_run(self):
            """Execute module actions."""
            self.deprecate(
                msg=(
                    "FreeIPABaseModule is deprecated. Use IPAAnsibleModule."
                ),
                version="1.5.0"
            )
            ipaapi_context = self.params_get("ipaapi_context")
            with self.ipa_connect(context=ipaapi_context):
                self.check_ipa_params()
                self.define_ipa_commands()
                self._run_ipa_commands()
            self.exit_json(changed=self.changed, **self.exit_args)

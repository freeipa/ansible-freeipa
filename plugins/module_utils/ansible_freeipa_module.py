# -*- coding: utf-8 -*-

# Authors:
#   Sergio Oliveira Campos <seocam@redhat.com>
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

__all__ = ["gssapi", "netaddr", "api", "ipalib_errors", "Env",
           "DEFAULT_CONFIG", "LDAP_GENERALIZED_TIME_FORMAT",
           "kinit_password", "kinit_keytab", "run", "DN", "VERSION",
           "paths", "tasks", "get_credentials_if_valid", "Encoding",
           "DNSName", "getargspec", "certificate_loader",
           "write_certificate_list", "boolean", "template_str",
           "urlparse"]

import os
# ansible-freeipa requires locale to be C, IPA requires utf-8.
os.environ["LANGUAGE"] = "C"

import sys
import operator
import tempfile
import shutil
import socket
import base64
import ast
from datetime import datetime
from contextlib import contextmanager
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_text
from ansible.module_utils.common.text.converters import jsonify
from ansible.module_utils import six
from ansible.module_utils.common._collections_compat import Mapping
from ansible.module_utils.parsing.convert_bool import boolean

# Import getargspec from inspect or provide own getargspec for
# Python 2 compatibility with Python 3.11+.
try:
    from inspect import getargspec
except ImportError:
    from collections import namedtuple
    from inspect import getfullargspec

    # The code is copied from Python 3.10 inspect.py
    # Authors: Ka-Ping Yee <ping@lfw.org>
    #          Yury Selivanov <yselivanov@sprymix.com>
    ArgSpec = namedtuple('ArgSpec', 'args varargs keywords defaults')

    def getargspec(func):
        args, varargs, varkw, defaults, kwonlyargs, _kwonlydefaults, \
            ann = getfullargspec(func)
        if kwonlyargs or ann:
            raise ValueError(
                "Function has keyword-only parameters or annotations"
                ", use inspect.signature() API which can support them")
        return ArgSpec(args, varargs, varkw, defaults)


try:
    import uuid
    import netaddr
    import gssapi

    from ipalib import api
    from ipalib import errors as ipalib_errors  # noqa
    from ipalib.config import Env
    from ipalib.constants import DEFAULT_CONFIG, LDAP_GENERALIZED_TIME_FORMAT

    try:
        from ipalib.install.kinit import kinit_password, kinit_keytab
    except ImportError:
        from ipapython.ipautil import kinit_password, kinit_keytab
    from ipapython.ipautil import run
    from ipapython.ipautil import template_str
    from ipapython.dn import DN
    from ipapython.version import VERSION
    from ipaplatform.paths import paths
    from ipaplatform.tasks import tasks
    from ipalib.krb_utils import get_credentials_if_valid
    from ipapython.dnsutil import DNSName
    from ipapython import kerberos

    try:
        from ipalib.x509 import Encoding
    except ImportError:
        from cryptography.hazmat.primitives.serialization import Encoding

    try:
        from ipalib.x509 import load_pem_x509_certificate
        certificate_loader = load_pem_x509_certificate
    except ImportError:
        from ipalib.x509 import load_certificate
        certificate_loader = load_certificate
    from ipalib.x509 import write_certificate_list

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

    # Try to import dcerpc
    try:
        import ipaserver.dcerpc  # pylint: disable=no-member
        _dcerpc_bindings_installed = True  # pylint: disable=invalid-name
    except ImportError:
        _dcerpc_bindings_installed = False  # pylint: disable=invalid-name

    try:
        from urllib.parse import urlparse
    except ImportError:
        from ansible.module_utils.six.moves.urllib.parse import urlparse

except ImportError as _err:
    ANSIBLE_FREEIPA_MODULE_IMPORT_ERROR = str(_err)

    for attr in __all__:
        setattr(sys.modules[__name__], attr, None)

    uuid = None
    netaddr = None
    is_ipa_configured = None
    kerberos = None
    ipaserver = None  # pylint: disable=C0103
else:
    ANSIBLE_FREEIPA_MODULE_IMPORT_ERROR = None


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
    global _dcerpc_bindings_installed  # pylint: disable=C0103,W0603

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
        _dcerpc_bindings_installed = False

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
    return operation(tasks.parse_ipa_version(VERSION),
                     tasks.parse_ipa_version(requested_version))


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
    """Compare IPA object attributes against command arguments.

    This function compares 'ipa' attributes with the 'args' the module
    is intending to use as parameters to an IPA API command. A list of
    attribute names that should be ignored during comparison may be
    provided.

    The comparison will be performed on every attribute provided in
    'args'. If the attribute in 'args' or 'ipa' is not a scalar value
    (including strings) the comparison will be performed as if the
    attribute is a set of values, so duplicate values will count as a
    single one. If both values are scalar values, then a direct
    comparison is performed.

    If an attribute is not available in 'ipa', its value is considered
    to be a list with an empty string (['']), possibly forcing the
    conversion of the 'args' attribute to a list for comparison. This
    allows, for example, the usage of empty strings which should compare
    as equals to inexistent attributes (None), as is done in IPA API.

    This function is mostly useful to evaluate the need of a call to
    IPA server when provided arguments are equivalent to the existing
    values for a given IPA object.

    Parameters
    ----------
    module: AnsibleModule
        The AnsibleModule used to log debug messages.

    args: dict
        The set of attributes provided by the playbook task.

    ipa: dict
        The set of attributes from the IPA object retrieved.

    ignore: list
        An optional list of attribute names that should be ignored and
        not evaluated.

    Return
    ------
        True is returned if all attribute values in 'args' are
        equivalent to the corresponding attribute value in 'ipa'.
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
        arg = args[key]
        ipa_arg = ipa.get(key, [""])
        # If ipa_arg is a list and arg is not, replace arg
        # with list containing arg. Most args in a find result
        # are lists, but not all.
        if isinstance(ipa_arg, (list, tuple)):
            if not isinstance(arg, list):
                arg = [arg]
            if len(ipa_arg) != len(arg):
                module.debug(
                    base_debug_msg
                    + "List length doesn't match for key %s: %d %d"
                    % (key, len(arg), len(ipa_arg),)
                )
                return False
            # ensure list elements types are the same.
            if not (
                isinstance(ipa_arg[0], type(arg[0]))
                or isinstance(arg[0], type(ipa_arg[0]))
            ):
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


def module_params_get(module, name, allow_empty_list_item=False):
    value = _afm_convert(module.params.get(name))

    # Fail on empty strings in the list or if allow_empty_list_item is True
    # if there is another entry in the list together with the empty string.
    # Due to an issue in Ansible it is possible to use the empty string
    # "" for lists with choices, even if the empty list is not part of
    # the choices.
    # Ansible issue https://github.com/ansible/ansible/issues/77108
    if isinstance(value, list):
        for val in value:
            if isinstance(val, (str, unicode)) and not val:
                if not allow_empty_list_item:
                    module.fail_json(
                        msg="Parameter '%s' contains an empty string" %
                        name)
                elif len(value) > 1:
                    module.fail_json(
                        msg="Parameter '%s' may not contain another "
                        "entry together with an empty string" % name)

    return value


def module_params_get_lowercase(module, name, allow_empty_list_item=False):
    value = module_params_get(module, name, allow_empty_list_item)
    if isinstance(value, list):
        value = [v.lower() for v in value]
    if isinstance(value, (str, unicode)):
        value = value.lower()
    return value


def module_params_get_with_type_cast(
    module, name, datatype, allow_empty=False
):
    """
    Retrieve value set for module parameter as a specific data type.

    Parameters
    ----------
    module: AnsibleModule
        The module from where to get the parameter value from.
    name: string
        The name of the parameter to retrieve.
    datatype: type
        The type to convert the value to, if value is not empty.
    allow_empty: bool
        Allow an empty string for non list parameters or a list
        containing (only) an empty string item. This is used for
        resetting parameters to the default value.

    """
    value = module_params_get(module, name, allow_empty)
    if not allow_empty and value == "":
        module.fail_json(
            msg="Argument '%s' must not be an empty string" % (name,)
        )
    if value is not None and value != "":
        try:
            if datatype is bool:
                # We let Ansible handle bool values
                value = boolean(value)
            else:
                value = datatype(value)
        except ValueError:
            module.fail_json(
                msg="Invalid value '%s' for argument '%s'" % (value, name)
            )
        except TypeError as terr:
            # If Ansible fails to parse a boolean, it will raise TypeError
            module.fail_json(msg="Param '%s': %s" % (name, str(terr)))
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

    cert = certificate_loader(cert.encode('utf-8'))
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


def servicedelegation_normalize_principals(module, principal,
                                           check_exists=False):
    """
    Normalize servicedelegation principals.

    The principals can be service and with IPA 4.9.0+ also host principals.
    """

    def _normalize_principal_name(name, realm):
        # Normalize principal name
        # Copied from ipaserver/plugins/servicedelegation.py
        try:
            princ = kerberos.Principal(name, realm=realm)
        except ValueError as _err:
            raise ipalib_errors.ValidationError(
                name='principal',
                reason="Malformed principal: %s" % str(_err))

        if len(princ.components) == 1 and \
           not princ.components[0].endswith('$'):
            nprinc = 'host/' + unicode(princ)
        else:
            nprinc = unicode(princ)
        return nprinc

    def _check_exists(module, _type, name):
        # Check if item of type _type exists using the show command
        try:
            module.ipa_command("%s_show" % _type, name, {})
        except ipalib_errors.NotFound as e:
            msg = str(e)
            if "%s not found" % _type in msg:
                return False
            module.fail_json(msg="%s_show failed: %s" % (_type, msg))
        return True

    ipa_realm = module.ipa_get_realm()
    _principal = []
    for _princ in principal:
        princ = _princ
        realm = ipa_realm

        # Get principal and realm from _princ if there is a realm
        if '@' in _princ:
            princ, realm = _princ.rsplit('@', 1)

        # Lowercase principal
        princ = princ.lower()

        # Normalize principal
        try:
            nprinc = _normalize_principal_name(princ, realm)
        except ipalib_errors.ValidationError as err:
            module.fail_json(msg="%s: %s" % (_princ, str(err)))
        princ = unicode(nprinc)

        # Check that host principal exists
        if princ.startswith("host/"):
            if module.ipa_check_version("<", "4.9.0"):
                module.fail_json(
                    msg="The use of host principals is not supported "
                    "by your IPA version")

            # Get host FQDN (no leading 'host/' and no trailing realm)
            # (There is no removeprefix and removesuffix in Python2)
            _host = princ[5:]
            if _host.endswith("@%s" % realm):
                _host = _host[:-len(realm) - 1]

            # Seach for host
            if check_exists and not _check_exists(module, "host", _host):
                module.fail_json(msg="Host '%s' does not exist" % _host)

        # Check the service principal exists
        else:
            if check_exists and \
               not _check_exists(module, "service", princ):
                module.fail_json(msg="Service %s does not exist" % princ)

        _principal.append(princ)

    return _principal


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
    print(jsonify(kwargs))  # pylint: disable=W0012,ansible-bad-function
    sys.exit(0)  # pylint: disable=W0012,ansible-bad-function


def __get_domain_validator():
    if not _dcerpc_bindings_installed:
        raise ipalib_errors.NotFound(
            reason=(
                'Cannot perform SID validation without Samba 4 support '
                'installed. Make sure you have installed server-trust-ad '
                'sub-package of IPA on the server'
            )
        )

    # pylint: disable=no-member
    domain_validator = ipaserver.dcerpc.DomainValidator(api)
    # pylint: enable=no-member

    if not domain_validator.is_configured():
        raise ipalib_errors.NotFound(
            reason=(
                'Cross-realm trusts are not configured. Make sure you '
                'have run ipa-adtrust-install on the IPA server first'
            )
        )

    return domain_validator


def get_trusted_domain_sid_from_name(dom_name):
    """
    Given a trust domain name, returns the domain SID.

    Returns unicode string representation for a given trusted domain name
    or None if SID for the given trusted domain name could not be found.
    """
    domain_validator = __get_domain_validator()
    sid = domain_validator.get_sid_from_domain_name(dom_name)

    return unicode(sid) if sid is not None else None


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
                if (
                    self.ansible_module.ipa_check_version("<", "4.9.10")
                    and isinstance(value, bool)
                ):
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

    ipa_module_options_spec = dict(
        delete_continue=dict(
            type="bool", default=True, aliases=["continue"]
        )
    )

    def __init__(self, *args, **kwargs):
        # Extend argument_spec with ipa_module_base_spec
        if "argument_spec" in kwargs:
            _spec = kwargs["argument_spec"]
            _spec.update(self.ipa_module_base_spec)
            kwargs["argument_spec"] = _spec

        if "ipa_module_options" in kwargs:
            _update = {
                k: self.ipa_module_options_spec[k]
                for k in kwargs["ipa_module_options"]
            }
            _spec = kwargs.get("argument_spec", {})
            _spec.update(_update)
            kwargs["argument_spec"] = _spec
            del kwargs["ipa_module_options"]

        # pylint: disable=super-with-arguments
        super(IPAAnsibleModule, self).__init__(*args, **kwargs)

        if ANSIBLE_FREEIPA_MODULE_IMPORT_ERROR is not None:
            self.fail_json(msg=ANSIBLE_FREEIPA_MODULE_IMPORT_ERROR)

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

    def params_get(self, name, allow_empty_list_item=False):
        """
        Retrieve value set for module parameter.

        Parameters
        ----------
        name: string
            The name of the parameter to retrieve.
        allow_empty_list_item: bool
            The parameter allowes to have empty strings in a list

        """
        return module_params_get(self, name, allow_empty_list_item)

    def params_get_lowercase(self, name, allow_empty_list_item=False):
        """
        Retrieve value set for module parameter as lowercase, if not None.

        Parameters
        ----------
        name: string
            The name of the parameter to retrieve.
        allow_empty_list_item: bool
            The parameter allowes to have empty strings in a list

        """
        return module_params_get_lowercase(self, name, allow_empty_list_item)

    def params_get_with_type_cast(
        self, name, datatype, allow_empty=True
    ):
        """
        Retrieve value set for module parameter as a specific data type.

        Parameters
        ----------
        name: string
            The name of the parameter to retrieve.
        datatype: type
            The type to convert the value to, if not empty.
        datatype: type
            The type to convert the value to, if value is not empty.
        allow_empty: bool
            Allow an empty string for non list parameters or a list
            containing (only) an empty string item. This is used for
            resetting parameters to the default value.

        """
        return module_params_get_with_type_cast(
            self, name, datatype, allow_empty)

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
            setattr(self, "__ipa_api_domain", api_get_domain())  # noqa: B010
        return getattr(self, "__ipa_api_domain")  # noqa: B009

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

    def ipa_command_invalid_param_choices(self, command, name, value):
        """
        Return invalid parameter choices for IPA command.

        Parameters
        ----------
        command: string
            The IPA API command to test.
        name: string
            The parameter name to check.
        value: string
            The parameter value to verify.

        """
        if command not in api.Command:
            self.fail_json(msg="The command '%s' does not exist." % command)
        if name not in api.Command[command].params:
            self.fail_json(msg="The command '%s' does not have a parameter "
                           "named '%s'." % (command, name))
        if not hasattr(api.Command[command].params[name], "cli_metavar"):
            self.fail_json(msg="The parameter '%s' of the command '%s' does "
                           "not have choices." % (name, command))
        # For IPA 4.6 (RHEL-7):
        # - krbprincipalauthind in host_add does not have choices defined
        # - krbprincipalauthind in service_add does not have choices defined
        #
        # api.Command[command].params[name].cli_metavar returns "STR" and
        # ast.literal_eval failes with a ValueError "malformed string".
        #
        # There is no way to verify that the given values are valid or not in
        # this case. The check is done later on while applying the change
        # with host_add, host_mod, service_add and service_mod.
        try:
            _choices = ast.literal_eval(
                api.Command[command].params[name].cli_metavar)
        except ValueError:
            return None
        return (set(value or []) - set([""])) - set(_choices)

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
                argspec = getargspec(result_handler)
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

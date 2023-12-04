# -*- coding: utf-8 -*-

# Authors:
#   Thomas Woerner <twoerner@redhat.com>
#
# Copyright (C) 2023 Red Hat
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
module: ipaidp
short_description: Manage FreeIPA idp
description: Manage FreeIPA idp
extends_documentation_fragment:
  - ipamodule_base_docs
options:
  name:
    description: The list of idp name strings.
    required: true
    type: list
    elements: str
    aliases: ["cn"]
  auth_uri:
    description: OAuth 2.0 authorization endpoint
    required: false
    type: str
    aliases: ["ipaidpauthendpoint"]
  dev_auth_uri:
    description: Device authorization endpoint
    required: false
    type: str
    aliases: ["ipaidpdevauthendpoint"]
  token_uri:
    description: Token endpoint
    required: false
    type: str
    aliases: ["ipaidptokenendpoint"]
  userinfo_uri:
    description: User information endpoint
    required: false
    type: str
    aliases: ["ipaidpuserinfoendpoint"]
  keys_uri:
    description: JWKS endpoint
    required: false
    type: str
    aliases: ["ipaidpkeysendpoint"]
  issuer_url:
    description: The Identity Provider OIDC URL
    required: false
    type: str
    aliases: ["ipaidpissuerurl"]
  client_id:
    description: OAuth 2.0 client identifier
    required: false
    type: str
    aliases: ["ipaidpclientid"]
  secret:
    description: OAuth 2.0 client secret
    required: false
    type: str
    no_log: true
    aliases: ["ipaidpclientsecret"]
  scope:
    description: OAuth 2.0 scope. Multiple scopes separated by space
    required: false
    type: str
    aliases: ["ipaidpscope"]
  idp_user_id:
    description: Attribute for user identity in OAuth 2.0 userinfo
    required: false
    type: str
    aliases: ["ipaidpsub"]
  provider:
    description: |
      Pre-defined template string. This provides the provider defaults, which
      can be overridden with the other IdP options.
    required: false
    type: str
    choices: ["google","github","microsoft","okta","keycloak"]
    aliases: ["ipaidpprovider"]
  organization:
    description: Organization ID or Realm name for IdP provider templates
    required: false
    type: str
    aliases: ["ipaidporg"]
  base_url:
    description: Base URL for IdP provider templates
    required: false
    type: str
    aliases: ["ipaidpbaseurl"]
  rename:
    description: |
      New name the Identity Provider server object. Only with state: renamed.
    required: false
    type: str
    aliases: ["new_name"]
  delete_continue:
    description:
      Continuous mode. Don't stop on errors. Valid only if `state` is `absent`.
    required: false
    type: bool
    aliases: ["continue"]
  state:
    description: The state to ensure.
    choices: ["present", "absent", "renamed"]
    default: present
    type: str
author:
  - Thomas Woerner (@t-woerner)
"""

EXAMPLES = """
# Ensure keycloak idp my-keycloak-idp is present
- ipaidp:
    ipaadmin_password: SomeADMINpassword
    name: my-keycloak-idp
    provider: keycloak
    organization: main
    base_url: keycloak.idm.example.com:8443/auth
    client_id: my-client-id

# Ensure google idp my-google-idp is present
- ipaidp:
    ipaadmin_password: SomeADMINpassword
    name: my-google-idp
    auth_uri: https://accounts.google.com/o/oauth2/auth
    dev_auth_uri: https://oauth2.googleapis.com/device/code
    token_uri: https://oauth2.googleapis.com/token
    userinfo_uri: https://openidconnect.googleapis.com/v1/userinfo
    client_id: my-client-id
    scope: "openid email"
    idp_user_id: email

# Ensure google idp my-google-idp is present without using provider
- ipaidp:
    ipaadmin_password: SomeADMINpassword
    name: my-google-idp
    provider: google
    client_id: my-google-client-id

# Ensure keycloak idp my-keycloak-idp is absent
- ipaidp:
    ipaadmin_password: SomeADMINpassword
    name: my-keycloak-idp
    delete_continue: true
    state: absent

# Ensure idps my-keycloak-idp, my-github-idp and my-google-idp are absent
- ipaidp:
    ipaadmin_password: SomeADMINpassword
    name:
    - my-keycloak-idp
    - my-github-idp
    - my-google-idp
    delete_continue: true
    state: absent
"""

RETURN = """
"""


from ansible.module_utils.ansible_freeipa_module import \
    IPAAnsibleModule, compare_args_ipa, template_str, urlparse
from ansible.module_utils import six
from copy import deepcopy
import string
from itertools import chain

if six.PY3:
    unicode = str

# Copy from FreeIPA ipaserver/plugins/idp.py
idp_providers = {
    'google': {
        'ipaidpauthendpoint':
            'https://accounts.google.com/o/oauth2/auth',
        'ipaidpdevauthendpoint':
            'https://oauth2.googleapis.com/device/code',
        'ipaidptokenendpoint':
            'https://oauth2.googleapis.com/token',
        'ipaidpuserinfoendpoint':
            'https://openidconnect.googleapis.com/v1/userinfo',
        'ipaidpkeysendpoint':
            'https://www.googleapis.com/oauth2/v3/certs',
        'ipaidpscope': 'openid email',
        'ipaidpsub': 'email'},
    'github': {
        'ipaidpauthendpoint':
            'https://github.com/login/oauth/authorize',
        'ipaidpdevauthendpoint':
            'https://github.com/login/device/code',
        'ipaidptokenendpoint':
            'https://github.com/login/oauth/access_token',
        'ipaidpuserinfoendpoint':
            'https://api.github.com/user',
        'ipaidpscope': 'user',
        'ipaidpsub': 'login'},
    'microsoft': {
        'ipaidpauthendpoint':
            'https://login.microsoftonline.com/${ipaidporg}/oauth2/v2.0/'
            'authorize',
        'ipaidpdevauthendpoint':
            'https://login.microsoftonline.com/${ipaidporg}/oauth2/v2.0/'
            'devicecode',
        'ipaidptokenendpoint':
            'https://login.microsoftonline.com/${ipaidporg}/oauth2/v2.0/'
            'token',
        'ipaidpuserinfoendpoint':
            'https://graph.microsoft.com/oidc/userinfo',
        'ipaidpkeysendpoint':
            'https://login.microsoftonline.com/common/discovery/v2.0/keys',
        'ipaidpscope': 'openid email',
        'ipaidpsub': 'email',
    },
    'okta': {
        'ipaidpauthendpoint':
            'https://${ipaidpbaseurl}/oauth2/v1/authorize',
        'ipaidpdevauthendpoint':
            'https://${ipaidpbaseurl}/oauth2/v1/device/authorize',
        'ipaidptokenendpoint':
            'https://${ipaidpbaseurl}/oauth2/v1/token',
        'ipaidpuserinfoendpoint':
            'https://${ipaidpbaseurl}/oauth2/v1/userinfo',
        'ipaidpscope': 'openid email',
        'ipaidpsub': 'email'},
    'keycloak': {
        'ipaidpauthendpoint':
            'https://${ipaidpbaseurl}/realms/${ipaidporg}/protocol/'
            'openid-connect/auth',
        'ipaidpdevauthendpoint':
            'https://${ipaidpbaseurl}/realms/${ipaidporg}/protocol/'
            'openid-connect/auth/device',
        'ipaidptokenendpoint':
            'https://${ipaidpbaseurl}/realms/${ipaidporg}/protocol/'
            'openid-connect/token',
        'ipaidpuserinfoendpoint':
            'https://${ipaidpbaseurl}/realms/${ipaidporg}/protocol/'
            'openid-connect/userinfo',
        'ipaidpscope': 'openid email',
        'ipaidpsub': 'email'},
}


def find_idp(module, name):
    """Find if a idp with the given name already exist."""
    try:
        _result = module.ipa_command("idp_show", name, {"all": True})
    except Exception:  # pylint: disable=broad-except
        # An exception is raised if idp name is not found.
        return None

    res = _result["result"]

    # Decode binary string secret
    if "ipaidpclientsecret" in res and len(res["ipaidpclientsecret"]) > 0:
        res["ipaidpclientsecret"][0] = \
            res["ipaidpclientsecret"][0].decode("ascii")

    return res


def gen_args(auth_uri, dev_auth_uri, token_uri, userinfo_uri, keys_uri,
             issuer_url, client_id, secret, scope, idp_user_id, organization,
             base_url):
    _args = {}
    if auth_uri is not None:
        _args["ipaidpauthendpoint"] = auth_uri
    if dev_auth_uri is not None:
        _args["ipaidpdevauthendpoint"] = dev_auth_uri
    if token_uri is not None:
        _args["ipaidptokenendpoint"] = token_uri
    if userinfo_uri is not None:
        _args["ipaidpuserinfoendpoint"] = userinfo_uri
    if keys_uri is not None:
        _args["ipaidpkeysendpoint"] = keys_uri
    if issuer_url is not None:
        _args["ipaidpissuerurl"] = issuer_url
    if client_id is not None:
        _args["ipaidpclientid"] = client_id
    if secret is not None:
        _args["ipaidpclientsecret"] = secret
    if scope is not None:
        _args["ipaidpscope"] = scope
    if idp_user_id is not None:
        _args["ipaidpsub"] = idp_user_id
    if organization is not None:
        _args["ipaidporg"] = organization
    if base_url is not None:
        _args["ipaidpbaseurl"] = base_url
    return _args


# Copied and adapted from FreeIPA ipaserver/plugins/idp.py
def convert_provider_to_endpoints(module, _args, provider):
    """Convert provider option to auth-uri and token-uri,.."""
    if provider not in idp_providers:
        module.fail_json(msg="Provider '%s' is unknown" % provider)

    # For each string in the template check if a variable
    # is required, it is provided as an option
    points = deepcopy(idp_providers[provider])
    _r = string.Template.pattern
    for (_k, _v) in points.items():
        # build list of variables to be replaced
        subs = list(chain.from_iterable(
                    (filter(None, _s) for _s in _r.findall(_v))))
        if subs:
            for _s in subs:
                if _s not in _args:
                    module.fail_json(msg="Parameter '%s' is missing" % _s)
            points[_k] = template_str(_v, _args)
        elif _k in _args:
            points[_k] = _args[_k]

    _args.update(points)


def validate_uri(module, uri):
    try:
        parsed = urlparse(uri, 'https')
    except Exception:
        module.fail_json(msg="Invalid URI '%s': not an https scheme" % uri)

    if not parsed.netloc:
        module.fail_json(msg="Invalid URI '%s': missing netloc" % uri)


def main():
    ansible_module = IPAAnsibleModule(
        argument_spec=dict(
            # general
            name=dict(type="list", elements="str", required=True,
                      aliases=["cn"]),
            # present
            auth_uri=dict(required=False, type="str", default=None,
                          aliases=["ipaidpauthendpoint"]),
            dev_auth_uri=dict(required=False, type="str", default=None,
                              aliases=["ipaidpdevauthendpoint"]),
            token_uri=dict(required=False, type="str", default=None,
                           aliases=["ipaidptokenendpoint"]),
            userinfo_uri=dict(required=False, type="str", default=None,
                              aliases=["ipaidpuserinfoendpoint"]),
            keys_uri=dict(required=False, type="str", default=None,
                          aliases=["ipaidpkeysendpoint"]),
            issuer_url=dict(required=False, type="str", default=None,
                            aliases=["ipaidpissuerurl"]),
            client_id=dict(required=False, type="str", default=None,
                           aliases=["ipaidpclientid"]),
            secret=dict(required=False, type="str", default=None,
                        aliases=["ipaidpclientsecret"], no_log=True),
            scope=dict(required=False, type="str", default=None,
                       aliases=["ipaidpscope"]),
            idp_user_id=dict(required=False, type="str", default=None,
                             aliases=["ipaidpsub"]),
            provider=dict(required=False, type="str", default=None,
                          aliases=["ipaidpprovider"],
                          choices=["google", "github", "microsoft", "okta",
                                   "keycloak"]),
            organization=dict(required=False, type="str", default=None,
                              aliases=["ipaidporg"]),
            base_url=dict(required=False, type="str", default=None,
                          aliases=["ipaidpbaseurl"]),
            rename=dict(required=False, type="str", default=None,
                        aliases=["new_name"]),
            delete_continue=dict(required=False, type="bool", default=None,
                                 aliases=['continue']),
            # state
            state=dict(type="str", default="present",
                       choices=["present", "absent", "renamed"]),
        ),
        supports_check_mode=True,
        # mutually_exclusive=[],
        # required_one_of=[]
    )

    ansible_module._ansible_debug = True

    # Get parameters

    # general
    names = ansible_module.params_get("name")

    # present
    auth_uri = ansible_module.params_get("auth_uri")
    dev_auth_uri = ansible_module.params_get("dev_auth_uri")
    token_uri = ansible_module.params_get("token_uri")
    userinfo_uri = ansible_module.params_get("userinfo_uri")
    keys_uri = ansible_module.params_get("keys_uri")
    issuer_url = ansible_module.params_get("issuer_url")
    client_id = ansible_module.params_get("client_id")
    secret = ansible_module.params_get("secret")
    scope = ansible_module.params_get("scope")
    idp_user_id = ansible_module.params_get("idp_user_id")
    provider = ansible_module.params_get("provider")
    organization = ansible_module.params_get("organization")
    base_url = ansible_module.params_get("base_url")
    rename = ansible_module.params_get("rename")

    delete_continue = ansible_module.params_get("delete_continue")

    # state
    state = ansible_module.params_get("state")

    # Check parameters

    invalid = []

    if state == "present":
        if len(names) != 1:
            ansible_module.fail_json(
                msg="Only one idp can be added at a time.")
        if provider:
            if any([auth_uri, dev_auth_uri, token_uri, userinfo_uri,
                    keys_uri]):
                ansible_module.fail_json(
                    msg="Cannot specify both individual endpoints and IdP "
                    "provider")
            if provider not in idp_providers:
                ansible_module.fail_json(
                    msg="Provider '%s' is unknown" % provider)
        invalid = ["rename", "delete_continue"]
    else:
        # state renamed and absent
        invalid = ["auth_uri", "dev_auth_uri", "token_uri", "userinfo_uri",
                   "keys_uri", "issuer_url", "client_id", "secret", "scope",
                   "idp_user_id", "provider", "organization", "base_url"]

    if state == "renamed":
        if len(names) != 1:
            ansible_module.fail_json(
                msg="Only one permission can be renamed at a time.")
        invalid += ["delete_continue"]

    if state == "absent":
        if len(names) < 1:
            ansible_module.fail_json(msg="No name given.")
        invalid += ["rename"]

    ansible_module.params_fail_used_invalid(invalid, state)

    # Empty client_id test
    if client_id is not None and client_id == "":
        ansible_module.fail_json(msg="'client_id' is required")

    # Normalize base_url
    if base_url is not None and base_url.startswith('https://'):
        base_url = base_url[len('https://'):]

    # Validate uris
    for uri in [auth_uri, dev_auth_uri, token_uri, userinfo_uri, keys_uri]:
        if uri is not None and uri != "":
            validate_uri(ansible_module, uri)

    # Init

    changed = False
    exit_args = {}

    # Connect to IPA API
    with ansible_module.ipa_connect():

        if not ansible_module.ipa_command_exists("idp_add"):
            ansible_module.fail_json(
                msg="Managing idp is not supported by your IPA version")

        commands = []
        for name in names:
            # Make sure idp exists
            res_find = find_idp(ansible_module, name)

            # Create command
            if state == "present":

                # Generate args
                args = gen_args(auth_uri, dev_auth_uri, token_uri,
                                userinfo_uri, keys_uri, issuer_url, client_id,
                                secret, scope, idp_user_id, organization,
                                base_url)

                if provider is not None:
                    convert_provider_to_endpoints(ansible_module, args,
                                                  provider)

                # Found the idp
                if res_find is not None:
                    # The parameters ipaidpprovider, ipaidporg and
                    # ipaidpbaseurl are only available for idp-add to create
                    # then endpoints using provider, Therefore we have to
                    # remove them from args.
                    for arg in ["ipaidpprovider", "ipaidporg",
                                "ipaidpbaseurl"]:
                        if arg in args:
                            del args[arg]

                    # For all settings is args, check if there are
                    # different settings in the find result.
                    # If yes: modify
                    if not compare_args_ipa(ansible_module, args,
                                            res_find):
                        commands.append([name, "idp_mod", args])
                else:
                    if "ipaidpauthendpoint" not in args:
                        ansible_module.fail_json(
                            msg="Parameter '%s' is missing" % "auth_uri")
                    if "ipaidpdevauthendpoint" not in args:
                        ansible_module.fail_json(
                            msg="Parameter '%s' is missing" % "dev_auth_uri")
                    if "ipaidptokenendpoint" not in args:
                        ansible_module.fail_json(
                            msg="Parameter '%s' is missing" % "token_uri")
                    if "ipaidpuserinfoendpoint" not in args:
                        ansible_module.fail_json(
                            msg="Parameter '%s' is missing" % "userinfo_uri")

                    commands.append([name, "idp_add", args])

            elif state == "absent":
                if res_find is not None:
                    _args = {}
                    if delete_continue is not None:
                        _args = {"continue": delete_continue}
                    commands.append([name, "idp_del", _args])

            elif state == "renamed":
                if not rename:
                    ansible_module.fail_json(msg="No rename value given.")

                if res_find is None:
                    ansible_module.fail_json(
                        msg="No idp found to be renamed: '%s'" % (name))

                if name != rename:
                    commands.append(
                        [name, "idp_mod", {"rename": rename}])

            else:
                ansible_module.fail_json(msg="Unkown state '%s'" % state)

        # Execute commands

        changed = ansible_module.execute_ipa_commands(commands)

    # Done

    ansible_module.exit_json(changed=changed, **exit_args)


if __name__ == "__main__":
    main()

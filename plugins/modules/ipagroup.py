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
module: ipagroup
short_description: Manage FreeIPA groups
description: Manage FreeIPA groups
extends_documentation_fragment:
  - ipamodule_base_docs
options:
  name:
    description: The group name
    type: list
    elements: str
    required: false
    aliases: ["cn"]
  groups:
    description: The list of group dicts (internally gid).
    type: list
    elements: dict
    suboptions:
      name:
        description: The group (internally gid).
        type: str
        required: true
        aliases: ["cn"]
      description:
        description: The group description
        type: str
        required: false
      gid:
        description: The GID
        type: int
        required: false
        aliases: ["gidnumber"]
      nonposix:
        description: Create as a non-POSIX group
        required: false
        type: bool
      external:
        description: Allow adding external non-IPA members from trusted domains
        required: false
        type: bool
      posix:
        description:
          Create a non-POSIX group or change a non-POSIX to a posix group.
        required: false
        type: bool
      nomembers:
        description: Suppress processing of membership attributes
        required: false
        type: bool
      user:
        description: List of user names assigned to this group.
        required: false
        type: list
        elements: str
      group:
        description: List of group names assigned to this group.
        required: false
        type: list
        elements: str
      service:
        description:
        - List of service names assigned to this group.
        - Only usable with IPA versions 4.7 and up.
        required: false
        type: list
        elements: str
      membermanager_user:
        description:
        - List of member manager users assigned to this group.
        - Only usable with IPA versions 4.8.4 and up.
        required: false
        type: list
        elements: str
      membermanager_group:
        description:
        - List of member manager groups assigned to this group.
        - Only usable with IPA versions 4.8.4 and up.
        required: false
        type: list
        elements: str
      externalmember:
        description:
        - List of members of a trusted domain in DOM\\name or name@domain form.
          Requires "server" context.
        required: false
        type: list
        elements: str
        aliases: ["ipaexternalmember", "external_member"]
      idoverrideuser:
        description:
        - User ID overrides to add. Requires "server" context.
        required: false
        type: list
        elements: str
      rename:
        description: Rename the group object
        required: false
        type: str
        aliases: ["new_name"]
  description:
    description: The group description
    type: str
    required: false
  gid:
    description: The GID
    type: int
    required: false
    aliases: ["gidnumber"]
  nonposix:
    description: Create as a non-POSIX group
    required: false
    type: bool
  external:
    description: Allow adding external non-IPA members from trusted domains
    required: false
    type: bool
  posix:
    description:
      Create a non-POSIX group or change a non-POSIX to a posix group.
    required: false
    type: bool
  nomembers:
    description: Suppress processing of membership attributes
    required: false
    type: bool
  user:
    description: List of user names assigned to this group.
    required: false
    type: list
    elements: str
  group:
    description: List of group names assigned to this group.
    required: false
    type: list
    elements: str
  service:
    description:
    - List of service names assigned to this group.
    - Only usable with IPA versions 4.7 and up.
    required: false
    type: list
    elements: str
  membermanager_user:
    description:
    - List of member manager users assigned to this group.
    - Only usable with IPA versions 4.8.4 and up.
    required: false
    type: list
    elements: str
  membermanager_group:
    description:
    - List of member manager groups assigned to this group.
    - Only usable with IPA versions 4.8.4 and up.
    required: false
    type: list
    elements: str
  externalmember:
    description:
    - List of members of a trusted domain in DOM\\name or name@domain form.
      Requires "server" context.
    required: false
    type: list
    elements: str
    aliases: ["ipaexternalmember", "external_member"]
  idoverrideuser:
    description:
    - User ID overrides to add. Requires "server" context.
    required: false
    type: list
    elements: str
  query_param:
    description:
    - The fields to query with state=query.
    - Can be `ALL`, `BASE`, `PKEY_ONLY` or a list of specific field names.
    required: false
    type: list
    elements: str
    choices: ["ALL", "BASE", "PKEY_ONLY", "dn", "objectclass", "ipauniqueid",
      "ipantsecurityidentifier", "name", "description", "gid", "user",
      "group", "service", "externalmember", "idoverrideuser",
      "membermanager_user", "membermanager_group"]
  action:
    description: Work on group or member level
    type: str
    default: group
    choices: ["member", "group"]
  rename:
    description: Rename the group object
    required: false
    type: str
    aliases: ["new_name"]
  state:
    description: State to ensure
    type: str
    default: present
    choices: ["present", "absent", "renamed",
              "query"]
author:
  - Thomas Woerner (@t-woerner)
"""

EXAMPLES = """
# Create group ops with gid 1234
- ipagroup:
    ipaadmin_password: SomeADMINpassword
    name: ops
    gidnumber: 1234

# Create group sysops
- ipagroup:
    ipaadmin_password: SomeADMINpassword
    name: sysops

# Create group appops
- ipagroup:
    ipaadmin_password: SomeADMINpassword
    name: appops

# Create multiple groups ops, sysops
- ipagroup:
    ipaadmin_password: SomeADMINpassword
    groups:
    - name: ops
      gidnumber: 1234
    - name: sysops

# Add user member pinky to group sysops
- ipagroup:
    ipaadmin_password: SomeADMINpassword
    name: sysops
    action: member
    user:
    - pinky

# Add user member brain to group sysops
- ipagroup:
    ipaadmin_password: SomeADMINpassword
    name: sysops
    action: member
    user:
    - brain

# Add group members sysops and appops to group ops
- ipagroup:
    ipaadmin_password: SomeADMINpassword
    name: ops
    group:
    - sysops
    - appops

# Add user and group members to groups sysops and appops
- ipagroup:
    ipaadmin_password: SomeADMINpassword
    groups:
    - name: sysops
      user:
        - user1
    - name: appops
      group:
        - group2

# Rename a group
- ipagroup:
    ipaadmin_password: SomeADMINpassword
    name: oldname
    rename: newestname
    state: renamed

# Create a non-POSIX group
- ipagroup:
    ipaadmin_password: SomeADMINpassword
    name: nongroup
    nonposix: yes

# Turn a non-POSIX group into a POSIX group.
- ipagroup:
    ipaadmin_password: SomeADMINpassword
    name: nonposix
    posix: yes

# Create an external group and add members from a trust to it.
# Module will fail if running under 'client' context.
- ipagroup:
    ipaadmin_password: SomeADMINpassword
    name: extgroup
    external: yes
    externalmember:
    - WINIPA\\Web Users
    - WINIPA\\Developers

# Create multiple non-POSIX and external groups
- ipagroup:
    ipaadmin_password: SomeADMINpassword
    groups:
    - name: nongroup
      nonposix: true
    - name: extgroup
      external: true

# Remove groups sysops, appops, ops and nongroup
- ipagroup:
    ipaadmin_password: SomeADMINpassword
    name: sysops,appops,ops, nongroup
    state: absent

# Query base fields of a group
- ipagroup:
    ipaadmin_password: SomeADMINpassword
    name: ops
    state: query
  register: result

# Query specific fields of a group
- ipagroup:
    ipaadmin_password: SomeADMINpassword
    name: ops
    query_param:
    - description
    - gid
    - user
    state: query
  register: result

# Query all fields of a group
- ipagroup:
    ipaadmin_password: SomeADMINpassword
    name: ops
    query_param: ALL
    state: query
  register: result

# Query only the names of all groups
- ipagroup:
    ipaadmin_password: SomeADMINpassword
    query_param: PKEY_ONLY
    state: query
  register: result
"""

RETURN = """
"""

from ansible.module_utils._text import to_text
from ansible.module_utils.ansible_freeipa_module import \
    IPAAnsibleModule, compare_args_ipa, gen_add_del_lists, \
    gen_add_list, gen_intersection_list, gen_member_add_del_lists, \
    api_check_param, convert_to_sid, ipalib_errors
from ansible.module_utils import six
if six.PY3:
    unicode = str
# Ensuring (adding) several groups with mixed types external, nonposix
# and posix require to have a fix in IPA:
# FreeIPA issue: https://pagure.io/freeipa/issue/9349
# FreeIPA fix: https://github.com/freeipa/freeipa/pull/6741
try:
    from ipaserver.plugins import baseldap
except ImportError:
    FIX_6741_DEEPCOPY_OBJECTCLASSES = False
else:
    FIX_6741_DEEPCOPY_OBJECTCLASSES = \
        "deepcopy" in baseldap.LDAPObject.__json__.__code__.co_names


def group_show(module, name):
    _args = {"all": True}

    try:
        _result = module.ipa_command("group_show", name, _args).get("result")
    except ipalib_errors.NotFound:
        return None

    # The returned services are of type ipapython.kerberos.Principal,
    # also services are not case sensitive. Therefore services are
    # converted to lowercase strings to be able to do the comparison.
    if "member_service" in _result:
        _result["member_service"] = \
            [to_text(svc).lower() for svc in _result["member_service"]]
    # user_find is returning SIDs, but user_show is not. Therefore convert
    # external users to SIDs.
    if "ipaexternalmember" in _result:
        _result["ipaexternalmember"] = \
            convert_to_sid(_result["ipaexternalmember"])
    return _result


def query_convert_result(module, res):
    _res = {}
    for key in res:
        try:
            if key.startswith("member_") or key.startswith("membermanager_"):
                _res[key] = [to_text(svc) for svc in res[key]]
            elif isinstance(res[key], (list, tuple)):
                if len(res[key]) == 1:
                    _res[key] = to_text(res[key][0])
                else:
                    _res[key] = [to_text(item) for item in res[key]]
            elif key in ["gidnumber"]:
                _res[key] = int(res[key])
            else:
                _res[key] = to_text(res[key])
        except (TypeError, ValueError) as e:
            module.fail_json(
                msg="Failed to convert query result for '%s': %s"
                % (key, str(e)))
    return _res


def group_find(module, name):
    _args = {"all": True}

    try:
        if name:
            _args["cn"] = name
        _result = module.ipa_command_no_name(
            "group_find", _args).get("result")
        if _result and name:
            _result = _result[0]
    except ipalib_errors.NotFound:
        return None

    return _result


def check_parameters(module, state, action, group_params):
    invalid = ["description", "gid", "posix", "nonposix", "external",
               "nomembers"]
    if action == "group":
        if state == "present":
            invalid = []
        elif state == "absent":
            invalid.extend(["user", "group", "service", "externalmember"])
    if state == "renamed":
        if action == "member":
            module.fail_json(
                msg="Action member can not be used with state: renamed.")
        invalid.extend(["user", "group", "service", "externalmember"])
    else:
        invalid.append("rename")

    if state == "query":
        module.fail_json(
            msg="check_parameters can not be used with action query.")
    invalid.append("query_param")

    module.params_fail_used_invalid(invalid, state, action, group_params,
                                    PARAM_MAPPING)


def is_external_group(res_find):
    """Verify if the result group is an external group."""
    return res_find and 'ipaexternalgroup' in res_find['objectclass']


def is_posix_group(res_find):
    """Verify if the result group is an posix group."""
    return res_find and 'posixgroup' in res_find['objectclass']


def check_objectclass_args(module, res_find, posix, external):
    # Only a nonposix group can be changed to posix or external

    # A posix group can not be changed to nonposix or external
    if is_posix_group(res_find):
        if external is not None and external or posix is False:
            module.fail_json(
                msg="Cannot change `posix` group to `non-posix` or "
                "`external`.")
    # An external group can not be changed to nonposix or posix or nonexternal
    if is_external_group(res_find):
        if external is False or posix is not None:
            module.fail_json(
                msg="Cannot change `external` group to `posix` or "
                "`non-posix`.")


def convert_params(module, group_params):
    """Convert parameter values in group_params in-place."""
    nonposix = group_params.get("nonposix")
    external = group_params.get("external")
    posix = group_params.get("posix")

    if all((posix, nonposix)) or \
       all((posix, external)) or \
       all((nonposix, external)):
        module.fail_json(
            msg="parameters are mutually exclusive for group "
                "`{0}`: posix|nonposix|external".format(
                    group_params.get("name")))

    if external is False:
        module.fail_json(msg="group can not be non-external")

    if nonposix is not None:
        group_params["posix"] = not nonposix


PARAM_MAPPING = {
    # Read-only system fields
    "dn": {"return_only": True},
    "objectclass": {"return_only": True},
    "ipauniqueid": {"return_only": True},
    "ipantsecurityidentifier": {"return_only": True},

    # Query-only: name is the primary key
    "name": {"api_name": "cn", "gen_args": False},

    # Writable params (used in gen_args)
    "description": {},
    "gid": {"api_name": "gidnumber", "type": "int"},

    # Query-only: members handled via separate member commands
    "user": {"api_name": "member_user", "gen_args": False,
             "lowercase": True, "member": True},
    "group": {"api_name": "member_group", "gen_args": False,
              "lowercase": True, "member": True},
    "service": {"api_name": "member_service", "gen_args": False,
                "lowercase": True, "member": True},
    "externalmember": {"api_name": "ipaexternalmember", "gen_args": False},
    "idoverrideuser": {"api_name": "member_idoverrideuser",
                       "gen_args": False},
    "membermanager_user": {"gen_args": False, "lowercase": True,
                           "member": True},
    "membermanager_group": {"gen_args": False, "lowercase": True,
                            "member": True},

    # Writable params not queryable by name
    "rename": {"gen_args": False, "query": False},
    "nonposix": {"gen_args": False, "query": False},
    "external": {"gen_args": False, "query": False},
    "posix": {"gen_args": False, "query": False},
    "nomembers": {"query": False},

    # Module-level params (not per-item, checked via self.params)
    "query_param": {"module_param": True},
}


QUERY_FIELDS = {
    "prefix": "groups",
    "primary_key": "cn",
    "base": ["name", "description", "gid"]
}


def main():
    group_spec = dict(
        # present
        description=dict(type="str", default=None),
        gid=dict(type="int", aliases=["gidnumber"], default=None),
        nonposix=dict(required=False, type='bool', default=None),
        external=dict(required=False, type='bool', default=None),
        posix=dict(required=False, type='bool', default=None),
        nomembers=dict(required=False, type='bool', default=None),
        user=dict(required=False, type='list', elements="str",
                  default=None),
        group=dict(required=False, type='list', elements="str",
                   default=None),
        service=dict(required=False, type='list', elements="str",
                     default=None),
        idoverrideuser=dict(required=False, type='list', elements="str",
                            default=None),
        membermanager_user=dict(required=False, type='list',
                                elements="str", default=None),
        membermanager_group=dict(required=False, type='list',
                                 elements="str", default=None),
        externalmember=dict(required=False, type='list', elements="str",
                            default=None,
                            aliases=[
                                "ipaexternalmember",
                                "external_member"
                            ]),
        rename=dict(type="str", required=False, default=None,
                    aliases=["new_name"]),
    )

    query_param_settings = IPAAnsibleModule.build_query_param_settings(
        PARAM_MAPPING, QUERY_FIELDS
    )

    ansible_module = IPAAnsibleModule(
        argument_spec=dict(
            # general
            name=dict(type="list", elements="str", aliases=["cn"],
                      default=None, required=False),
            groups=dict(type="list",
                        default=None,
                        options=dict(
                            # Here name is a simple string
                            name=dict(type="str", required=True,
                                      aliases=["cn"]),
                            # Add group specific parameters
                            **group_spec
                        ),
                        elements='dict',
                        required=False),
            # query
            query_param=dict(type="list", elements="str", default=None,
                             choices=["ALL", "BASE", "PKEY_ONLY"]
                             + query_param_settings["ALL"],
                             required=False),
            # general
            action=dict(type="str", default="group",
                        choices=["member", "group"]),
            state=dict(type="str", default="present",
                       choices=["present", "absent", "renamed", "query"]),

            # Add group specific parameters for simple use case
            **group_spec
        ),
        # It does not make sense to set posix, nonposix or external at the
        # same time
        mutually_exclusive=[['posix', 'nonposix', 'external'],
                            ["name", "groups"]],
        supports_check_mode=True,
    )

    ansible_module._ansible_debug = True

    # Get parameters

    # general
    names = ansible_module.params_get("name")
    groups = ansible_module.params_get("groups")

    # query
    query_param = ansible_module.params_get("query_param")
    # state and action
    action = ansible_module.params_get("action")
    state = ansible_module.params_get("state")

    # Check parameters

    if state != "query":
        if (names is None or len(names) < 1) and \
           (groups is None or len(groups) < 1):
            ansible_module.fail_json(
                msg="At least one name or groups is required")
    else:
        if action == "member":
            ansible_module.fail_json(
                msg="Query is not possible with action=member")
        if groups is not None:
            ansible_module.fail_json(
                msg="groups can not be used with state=query, "
                "use name instead")

    if state in ["present", "renamed"]:
        if names is not None and len(names) != 1:
            what = "renamed" if state == "renamed" else "added"
            ansible_module.fail_json(
                msg="Only one group can be %s at a time using 'name'." % what)

    # Ensuring (adding) several groups with mixed types external, nonposix
    # and posix require to have a fix in IPA:
    #
    # FreeIPA issue: https://pagure.io/freeipa/issue/9349
    # FreeIPA fix: https://github.com/freeipa/freeipa/pull/6741
    #
    # The simple solution is to switch to client context for ensuring
    # several groups simply if the user was not explicitly asking for
    # the server context no matter if mixed types are used.
    context = ansible_module.params_get("ipaapi_context")
    if state == "present" and groups is not None and len(groups) > 1 \
       and not FIX_6741_DEEPCOPY_OBJECTCLASSES:
        if context is None:
            context = "client"
            ansible_module.debug(
                "Switching to client context due to an unfixed issue in "
                "your IPA version: https://pagure.io/freeipa/issue/9349")
        elif context == "server":
            ansible_module.fail_json(
                msg="Ensuring several groups with server context is not "
                "supported by your IPA version: "
                "https://pagure.io/freeipa/issue/9349")

    # Use groups if names is None
    if groups is not None:
        names = groups

    # Init

    changed = False
    exit_args = {}

    # Connect to IPA API
    with ansible_module.ipa_connect(context=context):

        if state == "query":
            exit_args = ansible_module.execute_query(
                names, query_param, group_find, query_param_settings,
                convert_result=lambda res: query_convert_result(
                    ansible_module, res)
            )

            ansible_module.exit_json(changed=False, group=exit_args)

        has_add_member_service = ansible_module.ipa_command_param_exists(
            "group_add_member", "service")
        has_add_membermanager = ansible_module.ipa_command_exists(
            "group_add_member_manager")
        has_idoverrideuser = api_check_param(
            "group_add_member", "idoverrideuser")

        commands = []
        group_set = set()

        for group_name in names:
            if isinstance(group_name, dict):
                name = group_name.get("name")
                if name in group_set:
                    ansible_module.fail_json(
                        msg="group '%s' is used more than once" % name)
                group_set.add(name)

                group_params = IPAAnsibleModule.extract_params_from_entry(
                    group_name, PARAM_MAPPING)

            elif (
                isinstance(
                    group_name, (str, unicode)  # pylint: disable=W0012,E0606
                )
            ):
                name = group_name
                group_params = IPAAnsibleModule.extract_params(
                    ansible_module, PARAM_MAPPING)
            else:
                ansible_module.fail_json(msg="Group '%s' is not valid" %
                                         repr(group_name))
                # Never reached, just added to make pylint happy
                name = None
                group_params = {}

            check_parameters(ansible_module, state, action, group_params)
            convert_params(ansible_module, group_params)

            rename = group_params.get("rename")
            posix = group_params.get("posix")
            external = group_params.get("external")

            # Check API capability for params used
            if group_params.get("service") is not None \
               and not has_add_member_service:
                ansible_module.fail_json(
                    msg="Managing a service as part of a group is not "
                    "supported by your IPA version")
            if (group_params.get("membermanager_user") is not None
                or group_params.get("membermanager_group") is not None) \
               and not has_add_membermanager:
                ansible_module.fail_json(
                    msg="Managing a membermanager user or group is not "
                    "supported by your IPA version")
            if group_params.get("idoverrideuser") is not None \
               and not has_idoverrideuser:
                ansible_module.fail_json(
                    msg="Managing a idoverrideuser as part of a group is not "
                    "supported by your IPA version")
            if (group_params.get("externalmember") is not None
                or group_params.get("idoverrideuser") is not None) \
               and context == "client":
                ansible_module.fail_json(
                    msg="Cannot use externalmember in client context.")

            # Make sure group exists
            res_find = group_show(ansible_module, name)

            # external members must be handled as SID
            externalmember = convert_to_sid(
                group_params.get("externalmember"))

            # idoverrides need to be compared through SID
            idoverrideuser = group_params.get("idoverrideuser")
            idoverrideuser_sid = convert_to_sid(idoverrideuser)
            res_idoverrideuser_sid = convert_to_sid(
                (res_find or {}).get("member_idoverrideuser", []))
            idoverride_set = dict(
                list(zip(idoverrideuser_sid or [], idoverrideuser or [])) +
                list(
                    zip(
                        res_idoverrideuser_sid or [],
                        (res_find or {}).get("member_idoverrideuser", [])
                    )
                )
            )

            externalmember_add, externalmember_del = [], []
            idoverrides_add, idoverrides_del = [], []

            # Create command
            if state == "present":
                # Can't change an existing posix group
                check_objectclass_args(ansible_module, res_find, posix,
                                       external)

                # Generate args
                args = IPAAnsibleModule.gen_args_from_mapping(
                    PARAM_MAPPING, group_params)

                if action == "group":
                    # Found the group
                    if res_find is not None:
                        # For all settings in args, check if there are
                        # different settings in the find result.
                        # If yes: modify
                        # Also if it is a modification from nonposix to posix
                        # or nonposix to external.
                        if not compare_args_ipa(
                            ansible_module, args, res_find
                        ) or (
                            not is_posix_group(res_find) and
                            not is_external_group(res_find) and
                            (posix or external)
                        ):
                            if posix:
                                args['posix'] = True
                            if external:
                                args['external'] = True
                            commands.append([name, "group_mod", args])
                    else:
                        if posix is not None and not posix:
                            args['nonposix'] = True
                        if external:
                            args['external'] = True
                        commands.append([name, "group_add", args])
                        # Set res_find dict for next step
                        res_find = {}

                    # if we just created/modified the group, update res_find
                    classes = list(res_find.setdefault("objectclass", []))
                    if external and not is_external_group(res_find):
                        classes.append("ipaexternalgroup")
                    if posix and not is_posix_group(res_find):
                        classes.append("posixgroup")
                    res_find["objectclass"] = classes

                elif action == "member":
                    if res_find is None:
                        ansible_module.fail_json(msg="No group '%s'" % name)

            elif state == "absent":
                if action == "group":
                    if res_find is not None:
                        commands.append([name, "group_del", {}])

                elif action == "member":
                    if res_find is None:
                        ansible_module.fail_json(msg="No group '%s'" % name)

            elif state == "renamed":
                if res_find is None:
                    ansible_module.fail_json(msg="No group '%s'" % name)
                elif rename != name:
                    commands.append([name, 'group_mod', {"rename": rename}])
            else:
                ansible_module.fail_json(msg="Unkown state '%s'" % state)

            # Compute member add/del lists for standard members
            if not has_add_member_service:
                group_params["service"] = None
            if not has_add_membermanager:
                group_params["membermanager_user"] = None
                group_params["membermanager_group"] = None
            member_lists = gen_member_add_del_lists(
                PARAM_MAPPING, group_params,
                res_find or {}, action, state)
            user_add, user_del = member_lists.get(
                "user", ([], []))
            group_add, group_del = member_lists.get(
                "group", ([], []))
            service_add, service_del = member_lists.get(
                "service", ([], []))
            membermanager_user_add, membermanager_user_del = member_lists.get(
                "membermanager_user", ([], []))
            (membermanager_group_add,
             membermanager_group_del) = member_lists.get(
                "membermanager_group", ([], []))

            # Compute externalmember add/del lists
            # (merges two res_find keys, can't use gen_member_add_del_lists)
            existing_external = (
                list(res_find.get("member_external", []))
                + list(res_find.get("ipaexternalmember", []))
            ) if res_find else []
            if state == "present" and action != "member":
                externalmember_add, externalmember_del = \
                    gen_add_del_lists(externalmember, existing_external)
            elif state == "present" and action == "member":
                externalmember_add = gen_add_list(
                    externalmember, existing_external)
                externalmember_del = []
            elif state == "absent" and action == "member":
                externalmember_add = []
                externalmember_del = gen_intersection_list(
                    externalmember, existing_external)
            else:
                externalmember_add = []
                externalmember_del = []

            # Compute idoverrideuser add/del lists
            # (SID-based comparison, can't use gen_member_add_del_lists)
            if state == "present" and action != "member":
                idoverrides_add, idoverrides_del = gen_add_del_lists(
                    idoverrideuser_sid, res_idoverrideuser_sid)
            elif state == "present" and action == "member":
                idoverrides_add = gen_add_list(
                    idoverrideuser_sid, res_idoverrideuser_sid)
                idoverrides_del = []
            elif state == "absent" and action == "member":
                idoverrides_add = []
                idoverrides_del = gen_intersection_list(
                    idoverrideuser_sid, res_idoverrideuser_sid)
            else:
                idoverrides_add = []
                idoverrides_del = []
            idoverrides_add = [
                idoverride_set[sid] for sid in set(idoverrides_add)
            ]
            idoverrides_del = [
                idoverride_set[sid] for sid in set(idoverrides_del)
            ]

            # manage members
            # setup member args for add/remove members.
            add_member_args = {
                "user": user_add,
                "group": group_add,
            }

            del_member_args = {
                "user": user_del,
                "group": group_del,
            }

            if has_idoverrideuser:
                add_member_args["idoverrideuser"] = idoverrides_add
                del_member_args["idoverrideuser"] = idoverrides_del

            if has_add_member_service:
                add_member_args["service"] = service_add
                del_member_args["service"] = service_del

            if is_external_group(res_find):
                if len(externalmember_add) > 0:
                    add_member_args["ipaexternalmember"] = \
                        externalmember_add
                if len(externalmember_del) > 0:
                    del_member_args["ipaexternalmember"] = \
                        externalmember_del
            elif externalmember:
                ansible_module.fail_json(
                    msg="Cannot add external members to a "
                        "non-external group."
                )

            # Add members
            add_members = any([user_add, group_add, idoverrides_add,
                               service_add, externalmember_add])
            if add_members:
                commands.append(
                    [name, "group_add_member", add_member_args]
                )
            # Remove members
            remove_members = any([user_del, group_del, idoverrides_del,
                                  service_del, externalmember_del])
            if remove_members:
                commands.append(
                    [name, "group_remove_member", del_member_args]
                )

            # manage membermanager members
            if has_add_membermanager:
                # Add membermanager users and groups
                if any([membermanager_user_add, membermanager_group_add]):
                    commands.append(
                        [name, "group_add_member_manager",
                         {
                             "user": membermanager_user_add,
                             "group": membermanager_group_add,
                         }]
                    )
                # Remove member manager
                if any([membermanager_user_del, membermanager_group_del]):
                    commands.append(
                        [name, "group_remove_member_manager",
                         {
                             "user": membermanager_user_del,
                             "group": membermanager_group_del,
                         }]
                    )

        # Execute commands
        changed = ansible_module.execute_ipa_commands(
            commands, batch=True, keeponly=[], fail_on_member_errors=True)

    # Done

    ansible_module.exit_json(changed=changed, **exit_args)


if __name__ == "__main__":
    main()

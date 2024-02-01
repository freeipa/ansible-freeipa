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
        required: false
        type: list
        elements: str
        aliases: ["ipaexternalmember", "external_member"]
      idoverrideuser:
        description:
        - User ID overrides to add
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
    required: false
    type: list
    elements: str
    aliases: ["ipaexternalmember", "external_member"]
  idoverrideuser:
    description:
    - User ID overrides to add
    required: false
    type: list
    elements: str
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
    choices: ["present", "absent", "renamed"]
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
"""

RETURN = """
"""

from ansible.module_utils._text import to_text
from ansible.module_utils.ansible_freeipa_module import \
    IPAAnsibleModule, compare_args_ipa, gen_add_del_lists, \
    gen_add_list, gen_intersection_list, api_check_param
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


def find_group(module, name):
    _args = {
        "all": True,
        "cn": name,
    }

    _result = module.ipa_command("group_find", name, _args)

    if len(_result["result"]) > 1:
        module.fail_json(
            msg="There is more than one group '%s'" % (name))
    elif len(_result["result"]) == 1:
        _res = _result["result"][0]
        # The returned services are of type ipapython.kerberos.Principal,
        # also services are not case sensitive. Therefore services are
        # converted to lowercase strings to be able to do the comparison.
        if "member_service" in _res:
            _res["member_service"] = \
                [to_text(svc).lower() for svc in _res["member_service"]]
        return _res

    return None


def gen_args(description, gid, nomembers):
    _args = {}
    if description is not None:
        _args["description"] = description
    if gid is not None:
        _args["gidnumber"] = gid
    if nomembers is not None:
        _args["nomembers"] = nomembers

    return _args


def gen_member_args(user, group, service, externalmember, idoverrideuser):
    _args = {}
    if user is not None:
        _args["member_user"] = user
    if group is not None:
        _args["member_group"] = group
    if service is not None:
        _args["member_service"] = service
    if externalmember is not None:
        _args["member_external"] = externalmember
    if idoverrideuser is not None:
        _args["member_idoverrideuser"] = idoverrideuser

    return _args


def check_parameters(module, state, action):
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
    module.params_fail_used_invalid(invalid, state, action)


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
            # general
            action=dict(type="str", default="group",
                        choices=["member", "group"]),
            state=dict(type="str", default="present",
                       choices=["present", "absent", "renamed"]),

            # Add group specific parameters for simple use case
            **group_spec
        ),
        # It does not make sense to set posix, nonposix or external at the
        # same time
        mutually_exclusive=[['posix', 'nonposix', 'external'],
                            ["name", "groups"]],
        required_one_of=[["name", "groups"]],
        supports_check_mode=True,
    )

    ansible_module._ansible_debug = True

    # Get parameters

    # general
    names = ansible_module.params_get("name")
    groups = ansible_module.params_get("groups")

    # present
    description = ansible_module.params_get("description")
    gid = ansible_module.params_get("gid")
    nonposix = ansible_module.params_get("nonposix")
    external = ansible_module.params_get("external")
    idoverrideuser = ansible_module.params_get("idoverrideuser")
    posix = ansible_module.params_get("posix")
    nomembers = ansible_module.params_get("nomembers")
    user = ansible_module.params_get_lowercase("user")
    group = ansible_module.params_get_lowercase("group")
    # Services are not case sensitive
    service = ansible_module.params_get_lowercase("service")
    membermanager_user = (
        ansible_module.params_get_lowercase("membermanager_user"))
    membermanager_group = (
        ansible_module.params_get_lowercase("membermanager_group"))
    externalmember = ansible_module.params_get("externalmember")
    # rename
    rename = ansible_module.params_get("rename")
    # state and action
    action = ansible_module.params_get("action")
    state = ansible_module.params_get("state")

    # Check parameters

    if (names is None or len(names) < 1) and \
       (groups is None or len(groups) < 1):
        ansible_module.fail_json(msg="At least one name or groups is required")

    if state in ["present", "renamed"]:
        if names is not None and len(names) != 1:
            what = "renamed" if state == "renamed" else "added"
            ansible_module.fail_json(
                msg="Only one group can be %s at a time using 'name'." % what)

    check_parameters(ansible_module, state, action)

    if external is False:
        ansible_module.fail_json(
            msg="group can not be non-external")

    # Ensuring (adding) several groups with mixed types external, nonposix
    # and posix require to have a fix in IPA:
    #
    # FreeIPA issue: https://pagure.io/freeipa/issue/9349
    # FreeIPA fix: https://github.com/freeipa/freeipa/pull/6741
    #
    # The simple solution is to switch to client context for ensuring
    # several groups simply if the user was not explicitly asking for
    # the server context no matter if mixed types are used.
    context = None
    if state == "present" and groups is not None and len(groups) > 1 \
       and not FIX_6741_DEEPCOPY_OBJECTCLASSES:
        _context = ansible_module.params_get("ipaapi_context")
        if _context is None:
            context = "client"
            ansible_module.debug(
                "Switching to client context due to an unfixed issue in "
                "your IPA version: https://pagure.io/freeipa/issue/9349")
        elif _context == "server":
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

    # If nonposix is used, set posix as not nonposix
    if nonposix is not None:
        posix = not nonposix

    # Connect to IPA API
    with ansible_module.ipa_connect(context=context):

        has_add_member_service = ansible_module.ipa_command_param_exists(
            "group_add_member", "service")
        if service is not None and not has_add_member_service:
            ansible_module.fail_json(
                msg="Managing a service as part of a group is not supported "
                "by your IPA version")

        has_add_membermanager = ansible_module.ipa_command_exists(
            "group_add_member_manager")
        if ((membermanager_user is not None or
             membermanager_group is not None) and not has_add_membermanager):
            ansible_module.fail_json(
                msg="Managing a membermanager user or group is not supported "
                "by your IPA version"
            )

        has_idoverrideuser = api_check_param(
            "group_add_member", "idoverrideuser")
        if idoverrideuser is not None and not has_idoverrideuser:
            ansible_module.fail_json(
                msg="Managing a idoverrideuser as part of a group is not "
                "supported by your IPA version")

        commands = []
        group_set = set()

        for group_name in names:
            if isinstance(group_name, dict):
                name = group_name.get("name")
                if name in group_set:
                    ansible_module.fail_json(
                        msg="group '%s' is used more than once" % name)
                group_set.add(name)
                # present
                description = group_name.get("description")
                gid = group_name.get("gid")
                nonposix = group_name.get("nonposix")
                external = group_name.get("external")
                idoverrideuser = group_name.get("idoverrideuser")
                posix = group_name.get("posix")
                # Check mutually exclusive condition for multiple groups
                # creation. It's not possible to check it with
                # `mutually_exclusive` argument in `IPAAnsibleModule` class
                # because it accepts only (list[str] or list[list[str]]). Here
                # we need to loop over all groups and fail on mutually
                # exclusive ones.
                if all((posix, nonposix)) or\
                   all((posix, external)) or\
                   all((nonposix, external)):
                    ansible_module.fail_json(
                        msg="parameters are mutually exclusive for group "
                            "`{0}`: posix|nonposix|external".format(name))
                # Duplicating the condition for multiple group creation
                if external is False:
                    ansible_module.fail_json(
                        msg="group can not be non-external")
                # If nonposix is used, set posix as not nonposix
                if nonposix is not None:
                    posix = not nonposix
                user = group_name.get("user")
                group = group_name.get("group")
                service = group_name.get("service")
                membermanager_user = group_name.get("membermanager_user")
                membermanager_group = group_name.get("membermanager_group")
                externalmember = group_name.get("externalmember")
                nomembers = group_name.get("nomembers")
                rename = group_name.get("rename")

                check_parameters(ansible_module, state, action)

            elif isinstance(group_name, (str, unicode)):
                name = group_name
            else:
                ansible_module.fail_json(msg="Group '%s' is not valid" %
                                         repr(group_name))

            # Make sure group exists
            res_find = find_group(ansible_module, name)

            user_add, user_del = [], []
            group_add, group_del = [], []
            service_add, service_del = [], []
            externalmember_add, externalmember_del = [], []
            idoverrides_add, idoverrides_del = [], []
            membermanager_user_add, membermanager_user_del = [], []
            membermanager_group_add, membermanager_group_del = [], []

            # Create command
            if state == "present":
                # Can't change an existing posix group
                check_objectclass_args(ansible_module, res_find, posix,
                                       external)

                # Generate args
                args = gen_args(description, gid, nomembers)

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
                    res_find.setdefault("objectclass", [])
                    if external and not is_external_group(res_find):
                        res_find["objectclass"].append("ipaexternalgroup")
                    if posix and not is_posix_group(res_find):
                        res_find["objectclass"].append("posixgroup")

                    member_args = gen_member_args(
                        user, group, service, externalmember, idoverrideuser
                    )
                    if not compare_args_ipa(ansible_module, member_args,
                                            res_find):
                        # Generate addition and removal lists
                        user_add, user_del = gen_add_del_lists(
                            user, res_find.get("member_user"))

                        group_add, group_del = gen_add_del_lists(
                            group, res_find.get("member_group"))

                        service_add, service_del = gen_add_del_lists(
                            service, res_find.get("member_service"))

                        (externalmember_add,
                         externalmember_del) = gen_add_del_lists(
                            externalmember, res_find.get("member_external"))

                        (idoverrides_add,
                         idoverrides_del) = gen_add_del_lists(
                            idoverrideuser,
                            res_find.get("member_idoverrideuser")
                        )

                    membermanager_user_add, membermanager_user_del = \
                        gen_add_del_lists(
                            membermanager_user,
                            res_find.get("membermanager_user")
                        )

                    membermanager_group_add, membermanager_group_del = \
                        gen_add_del_lists(
                            membermanager_group,
                            res_find.get("membermanager_group")
                        )

                elif action == "member":
                    if res_find is None:
                        ansible_module.fail_json(msg="No group '%s'" % name)

                    # Reduce add lists for member_user, member_group,
                    # member_service and member_external to new entries
                    # only that are not in res_find.
                    user_add = gen_add_list(
                        user, res_find.get("member_user"))
                    group_add = gen_add_list(
                        group, res_find.get("member_group"))
                    service_add = gen_add_list(
                        service, res_find.get("member_service"))
                    externalmember_add = gen_add_list(
                        externalmember, res_find.get("member_external"))
                    idoverrides_add = gen_add_list(
                        idoverrideuser, res_find.get("member_idoverrideuser"))

                    membermanager_user_add = gen_add_list(
                        membermanager_user,
                        res_find.get("membermanager_user")
                    )
                    membermanager_group_add = gen_add_list(
                        membermanager_group,
                        res_find.get("membermanager_group")
                    )

            elif state == "absent":
                if action == "group":
                    if res_find is not None:
                        commands.append([name, "group_del", {}])

                elif action == "member":
                    if res_find is None:
                        ansible_module.fail_json(msg="No group '%s'" % name)

                    if not is_external_group(res_find) and externalmember:
                        ansible_module.fail_json(
                            msg="Cannot add external members to a "
                                "non-external group."
                        )

                    user_del = gen_intersection_list(
                        user, res_find.get("member_user"))
                    group_del = gen_intersection_list(
                        group, res_find.get("member_group"))
                    service_del = gen_intersection_list(
                        service, res_find.get("member_service"))
                    externalmember_del = gen_intersection_list(
                        externalmember, res_find.get("member_external"))
                    idoverrides_del = gen_intersection_list(
                        idoverrideuser, res_find.get("member_idoverrideuser"))

                    membermanager_user_del = gen_intersection_list(
                        membermanager_user, res_find.get("membermanager_user"))
                    membermanager_group_del = gen_intersection_list(
                        membermanager_group,
                        res_find.get("membermanager_group")
                    )
            elif state == "renamed":
                if res_find is None:
                    ansible_module.fail_json(msg="No group '%s'" % name)
                elif rename != name:
                    commands.append([name, 'group_mod', {"rename": rename}])
            else:
                ansible_module.fail_json(msg="Unkown state '%s'" % state)

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
            elif externalmember or external:
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
            commands, fail_on_member_errors=True)

    # Done

    ansible_module.exit_json(changed=changed, **exit_args)


if __name__ == "__main__":
    main()

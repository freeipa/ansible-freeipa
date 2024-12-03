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
    compare_args_ipa, gen_add_del_lists, \
    gen_add_list, gen_intersection_list, \
    convert_param_value_to_lowercase, EntryFactory

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


def gen_member_args(entry):
    _args = {}
    if entry.user is not None:
        _args["member_user"] = entry.user
    if entry.group is not None:
        _args["member_group"] = entry.group
    if entry.service is not None:
        _args["member_service"] = entry.service
    if entry.externalmember is not None:
        _args["member_external"] = entry.externalmember
    if entry.idoverrideuser is not None:
        _args["member_idoverrideuser"] = entry.idoverrideuser

    return _args


def check_module_parameters(module, state):
    names = module.params_get("name")
    groups = module.params_get("groups")

    if (names is None or len(names) < 1) and \
       (groups is None or len(groups) < 1):
        module.fail_json(msg="At least one name or groups is required")

    if state in ["present", "renamed"]:
        if names is not None and len(names) != 1:
            what = "renamed" if state == "renamed" else "added"
            module.fail_json(
                msg="Only one group can be %s at a time using 'name'." % what)


def ensure_proper_context(module, state):
    # Ensuring (adding) several groups with mixed types external, nonposix
    # and posix require to have a fix in IPA:
    #
    # FreeIPA issue: https://pagure.io/freeipa/issue/9349
    # FreeIPA fix: https://github.com/freeipa/freeipa/pull/6741
    #
    # The simple solution is to switch to client context for ensuring
    # several groups simply if the user was not explicitly asking for
    # the server context no matter if mixed types are used.
    groups = module.params_get("groups")
    context = None
    if state == "present" and groups is not None and len(groups) > 1 \
       and not FIX_6741_DEEPCOPY_OBJECTCLASSES:
        _context = module.params_get("ipaapi_context")
        if _context is None:
            context = "client"
            module.debug(
                "Switching to client context due to an unfixed issue in "
                "your IPA version: https://pagure.io/freeipa/issue/9349")
        elif _context == "server":
            module.fail_json(
                msg="Ensuring several groups with server context is not "
                "supported by your IPA version: "
                "https://pagure.io/freeipa/issue/9349")
    return context


def get_invalid_parameters(module, state, action):
    """Retrieve a list of invalid parameters for the given state and action."""
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
    return invalid


def is_external_group(res_find):
    """Verify if the result group is an external group."""
    return res_find and 'ipaexternalgroup' in res_find['objectclass']


def is_posix_group(res_find):
    """Verify if the result group is an posix group."""
    return res_find and 'posixgroup' in res_find['objectclass']


def check_objectclass_args(module, res_find, entry):
    # Only a nonposix group can be changed to posix or external

    # A posix group can not be changed to nonposix or external
    if is_posix_group(res_find):
        if entry.external or entry.posix is False:
            module.fail_json(
                msg="Cannot change `posix` group to `non-posix` or "
                "`external`.")
    # An external group can not be changed to nonposix or posix or nonexternal
    if is_external_group(res_find):
        if entry.external is False:
            module.fail_json(
                msg="group can not be non-external")
        if entry.posix:
            module.fail_json(
                msg="Cannot change `external` group to `posix` or "
                "`non-posix`.")


def validate_entry(module, entry):
    # Check version support
    has_add_member_service = module.ipa_command_param_exists(
        "group_add_member", "service")
    has_add_member_manager = module.ipa_command_exists(
        "group_add_member_manager")
    has_idoverrideuser = module.ipa_command_param_exists(
        "group_add_member", "idoverrideuser")

    # check non-exclusive 'posix', 'nonposix' and 'external'.
    if len([
        entry[param] for param in ["posix", "nonposix", "external"]
        if entry[param] is not None
    ]) > 1:
        module.fail_json(
            msg="parameters are mutually exclusive for group "
                "`%s`" % entry.name)

    if entry.service is not None and not has_add_member_service:
        module.fail_json(
            msg="Managing a service as part of a group is not supported "
            "by your IPA version")

    if (
        (entry.membermanager_user is not None
            or entry.membermanager_group is not None)
        and not has_add_member_manager
    ):
        module.fail_json(
            msg="Managing a membermanager user or group is not supported "
            "by your IPA version"
        )

    if entry.idoverrideuser is not None and not has_idoverrideuser:
        module.fail_json(
            msg="Managing a idoverrideuser as part of a group is not "
            "supported by your IPA version")

    # Check mutually exclusive condition for multiple groups
    # creation. It's not possible to check it with
    # `mutually_exclusive` argument in `IPAAnsibleModule` class
    # because it accepts only (list[str] or list[list[str]]). Here
    # we need to loop over all groups and fail on mutually
    # exclusive ones.
    if all((entry.posix, entry.nonposix)) or\
       all((entry.posix, entry.external)) or\
       all((entry.nonposix, entry.external)):
        module.fail_json(
            msg="parameters are mutually exclusive for group "
                "`{0}`: posix|nonposix|external".format(entry.name))

    # If nonposix is used, set posix as not nonposix
    if entry.nonposix is not None:
        entry.posix = not entry.nonposix

    return entry


def main():
    module_params = {
        "name": {
            "type": "str",
            "required": True,
            "aliases": ["cn"],
        },
        "description": {
            "type": "str",
            "required": False,
            "default": None,
        },
        "gid": {
            "type": "int",
            "required": False,
            "default": None,
            "aliases": ["gidnumber"],
        },
        "nonposix": {
            "type": "bool",
            "required": False,
            "default": None,
        },
        "external": {
            "type": "bool",
            "required": False,
            "default": None,
        },
        "posix": {
            "type": "bool",
            "required": False,
            "default": None,
        },
        "user": {
            "type": "list",
            "elements": "str",
            "required": False,
            "default": None,
            "convert": [convert_param_value_to_lowercase],
        },
        "group": {
            "type": "list",
            "elements": "str",
            "required": False,
            "default": None,
            "convert": [convert_param_value_to_lowercase],
        },
        "service": {
            "type": "list",
            "elements": "str",
            "required": False,
            "default": None,
            "convert": [convert_param_value_to_lowercase],
        },
        "idoverrideuser": {
            "type": "list",
            "elements": "str",
            "required": False,
            "default": None,
        },
        "membermanager_user": {
            "type": "list",
            "elements": "str",
            "required": False,
            "default": None,
            "convert": [convert_param_value_to_lowercase],
        },
        "membermanager_group": {
            "type": "list",
            "elements": "str",
            "required": False,
            "default": None,
            "convert": [convert_param_value_to_lowercase],
        },
        "externalmember": {
            "type": "list",
            "elements": "str",
            "required": False,
            "default": None,
            "aliases": ["ipaexternalmember", "external_member"],
            "convert": [convert_param_value_to_lowercase],
        },
        "rename": {
            "type": "str",
            "required": False,
            "default": None,
            "aliases": ["new_name"]
        },
        "nomembers": {
            "type": "bool",
            "required": False,
            "default": None,
        },
    }

    entry_factory = EntryFactory(
        "group",
        module_params,
        valid_states=["present", "absent", "renamed"],
        validate_entry_function=validate_entry
    )

    ansible_module = entry_factory.ansible_module

    # Get state and action
    action = ansible_module.params_get("action")
    state = ansible_module.params_get("state")

    # Check parameters
    check_module_parameters(ansible_module, state)
    context = ensure_proper_context(ansible_module, state)
    invalid_params = get_invalid_parameters(ansible_module, state, action)

    # Init

    changed = False
    exit_args = {}

    # Connect to IPA API
    with ansible_module.ipa_connect(context=context):
        # Check version support
        has_add_member_service = ansible_module.ipa_command_param_exists(
            "group_add_member", "service")
        has_add_member_manager = ansible_module.ipa_command_exists(
            "group_add_member_manager")
        has_idoverrideuser = ansible_module.ipa_command_param_exists(
            "group_add_member", "idoverrideuser")

        commands = []
        group_set = set()

        for entry in entry_factory.get_entries(invalid_params):
            if entry.name in group_set:
                ansible_module.fail_json(
                    msg="group '%s' is used more than once" % entry.name)
            group_set.add(entry.name)

            # Make sure group exists
            res_find = find_group(ansible_module, entry.name)

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
                check_objectclass_args(ansible_module, res_find, entry)

                # Generate args
                args = gen_args(entry.description, entry.gid, entry.nomembers)

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
                            (entry.posix or entry.external)
                        ):
                            if entry.posix:
                                args['posix'] = True
                            if entry.external:
                                args['external'] = True
                            commands.append([entry.name, "group_mod", args])
                    else:
                        if entry.posix is False:
                            args['nonposix'] = True
                        if entry.external:
                            args['external'] = True
                        commands.append([entry.name, "group_add", args])
                        # Set res_find dict for next step
                        res_find = {}

                    # if we just created/modified the group, update res_find
                    res_find.setdefault("objectclass", [])
                    if entry.external and not is_external_group(res_find):
                        res_find["objectclass"].append("ipaexternalgroup")
                    if entry.posix and not is_posix_group(res_find):
                        res_find["objectclass"].append("posixgroup")

                    member_args = gen_member_args(entry)
                    if not compare_args_ipa(ansible_module, member_args,
                                            res_find):
                        # Generate addition and removal lists
                        user_add, user_del = gen_add_del_lists(
                            entry.user, res_find.get("member_user"))

                        group_add, group_del = gen_add_del_lists(
                            entry.group, res_find.get("member_group"))

                        service_add, service_del = gen_add_del_lists(
                            entry.service, res_find.get("member_service"))

                        (externalmember_add,
                         externalmember_del) = gen_add_del_lists(
                            entry.externalmember,
                            res_find.get("member_external")
                        )

                        (idoverrides_add,
                         idoverrides_del) = gen_add_del_lists(
                            entry.idoverrideuser,
                            res_find.get("member_idoverrideuser")
                        )

                    membermanager_user_add, membermanager_user_del = \
                        gen_add_del_lists(
                            entry.membermanager_user,
                            res_find.get("membermanager_user")
                        )

                    membermanager_group_add, membermanager_group_del = \
                        gen_add_del_lists(
                            entry.membermanager_group,
                            res_find.get("membermanager_group")
                        )

                elif action == "member":
                    if res_find is None:
                        ansible_module.fail_json(
                            msg="No group '%s'" % entry.name)

                    # Reduce add lists for member_user, member_group,
                    # member_service and member_external to new entries
                    # only that are not in res_find.
                    user_add = gen_add_list(
                        entry.user, res_find.get("member_user"))
                    group_add = gen_add_list(
                        entry.group, res_find.get("member_group"))
                    service_add = gen_add_list(
                        entry.service, res_find.get("member_service"))
                    externalmember_add = gen_add_list(
                        entry.externalmember, res_find.get("member_external"))
                    idoverrides_add = gen_add_list(
                        entry.idoverrideuser,
                        res_find.get("member_idoverrideuser")
                    )

                    membermanager_user_add = gen_add_list(
                        entry.membermanager_user,
                        res_find.get("membermanager_user")
                    )
                    membermanager_group_add = gen_add_list(
                        entry.membermanager_group,
                        res_find.get("membermanager_group")
                    )

            elif state == "absent":
                if action == "group":
                    if res_find is not None:
                        commands.append([entry.name, "group_del", {}])

                elif action == "member":
                    if res_find is None:
                        ansible_module.fail_json(
                            msg="No group '%s'" % entry.name)

                    if (
                        not is_external_group(res_find)
                        and entry.externalmember
                    ):
                        ansible_module.fail_json(
                            msg="Cannot add external members to a "
                                "non-external group."
                        )

                    user_del = gen_intersection_list(
                        entry.user, res_find.get("member_user"))
                    group_del = gen_intersection_list(
                        entry.group, res_find.get("member_group"))
                    service_del = gen_intersection_list(
                        entry.service, res_find.get("member_service"))
                    externalmember_del = gen_intersection_list(
                        entry.externalmember,
                        res_find.get("member_external")
                    )
                    idoverrides_del = gen_intersection_list(
                        entry.idoverrideuser,
                        res_find.get("member_idoverrideuser")
                    )

                    membermanager_user_del = gen_intersection_list(
                        entry.membermanager_user,
                        res_find.get("membermanager_user")
                    )
                    membermanager_group_del = gen_intersection_list(
                        entry.membermanager_group,
                        res_find.get("membermanager_group")
                    )
            elif state == "renamed":
                if res_find is None:
                    ansible_module.fail_json(msg="No group '%s'" % entry.name)
                elif entry.rename != entry.name:
                    commands.append(
                        [entry.name, 'group_mod', {"rename": entry.rename}]
                    )
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
            elif entry.externalmember or entry.external:
                ansible_module.fail_json(
                    msg="Cannot add external members to a "
                        "non-external group."
                )

            # Add members
            add_members = any([user_add, group_add, idoverrides_add,
                               service_add, externalmember_add])
            if add_members:
                commands.append(
                    [entry.name, "group_add_member", add_member_args]
                )
            # Remove members
            remove_members = any([user_del, group_del, idoverrides_del,
                                  service_del, externalmember_del])
            if remove_members:
                commands.append(
                    [entry.name, "group_remove_member", del_member_args]
                )

            # manage membermanager members
            if has_add_member_manager:
                # Add membermanager users and groups
                if any([membermanager_user_add, membermanager_group_add]):
                    commands.append(
                        [entry.name, "group_add_member_manager",
                         {
                             "user": membermanager_user_add,
                             "group": membermanager_group_add,
                         }]
                    )
                # Remove member manager
                if any([membermanager_user_del, membermanager_group_del]):
                    commands.append(
                        [entry.name, "group_remove_member_manager",
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

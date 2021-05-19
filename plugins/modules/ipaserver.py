#!/usr/bin/python
# -*- coding: utf-8 -*-

# Authors:
#   Thomas Woerner <twoerner@redhat.com>
#
# Copyright (C) 2021 Red Hat
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

ANSIBLE_METADATA = {
    "metadata_version": "1.0",
    "supported_by": "community",
    "status": ["preview"],
}

DOCUMENTATION = """
---
module: ipaserver
short description: Manage FreeIPA server
description: Manage FreeIPA server
options:
  ipaadmin_principal:
    description: The admin principal.
    default: admin
  ipaadmin_password:
    description: The admin password.
    required: false
  name:
    description: The list of server name strings.
    required: true
    aliases: ["cn"]
  location:
    description: |
      The server location string.
      "" for location reset.
      Only in state: present.
    required: false
    aliases: ["ipalocation_location"]
  service_weight:
    description: |
      Weight for server services
      Values 0 to 65535, -1 for weight reset.
      Only in state: present.
    required: false
    type: int
    aliases: ["ipaserviceweight"]
  hidden:
    description: |
      Set hidden state of a server.
      Only in state: present.
    required: false
    type: bool
  no_members:
    description: |
      Suppress processing of membership attributes
      Only in state: present.
    required: false
    type: bool
  delete_continue:
    description: |
      Continuous mode: Don't stop on errors.
      Only in state: absent.
    required: false
    type: bool
    aliases: ["continue"]
  ignore_last_of_role:
    description: |
      Skip a check whether the last CA master or DNS server is removed.
      Only in state: absent.
    required: false
    type: bool
  ignore_topology_disconnect:
    description: |
      Ignore topology connectivity problems after removal.
      Only in state: absent.
    required: false
    type: bool
  force:
    description: |
      Force server removal even if it does not exist.
      Will always result in changed.
      Only in state: absent.
    required: false
    type: bool
  state:
    description: The state to ensure.
    choices: ["present", "absent"]
    default: present
    required: true
"""

EXAMPLES = """
# Ensure server server.example.com is present
- ipaserver:
    ipaadmin_password: SomeADMINpassword
    name: server.example.com

# Ensure server server.example.com is absent
- ipaserver:
    ipaadmin_password: SomeADMINpassword
    name: server.example.com
    state: absent

# Ensure server server.example.com is present with location mylocation
- ipaserver:
    ipaadmin_password: SomeADMINpassword
    name: server.example.com
    location: mylocation

# Ensure server server.example.com is present without a location
- ipaserver:
    ipaadmin_password: SomeADMINpassword
    name: server.example.com
    location: ""

# Ensure server server.example.com is present with service weight 1
- ipaserver:
    ipaadmin_password: SomeADMINpassword
    name: server.example.com
    service_weight: 1

# Ensure server server.example.com is present without service weight
- ipaserver:
    ipaadmin_password: SomeADMINpassword
    name: server.example.com
    service_weight: -1

# Ensure server server.example.com is present and hidden
- ipaserver:
    ipaadmin_password: SomeADMINpassword
    name: server.example.com
    hidden: yes

# Ensure server server.example.com is present and not hidden
- ipaserver:
    ipaadmin_password: SomeADMINpassword
    name: server.example.com
    hidden: no

# Ensure server server.example.com is absent in continuous mode in error case
- ipaserver:
    ipaadmin_password: SomeADMINpassword
    name: server.example.com
    continue: yes
    state: absent

# Ensure server server.example.com is absent with last of role check skip
- ipaserver:
    ipaadmin_password: SomeADMINpassword
    name: server.example.com
    ignore_last_of_role: yes
    state: absent

# Ensure server server.example.com is absent with topology disconnect check
# skip
- ipaserver:
    ipaadmin_password: SomeADMINpassword
    name: server.example.com
    ignore_topology_disconnect: yes
    state: absent

# Ensure server server.example.com is absent in force mode
- ipaserver:
    ipaadmin_password: SomeADMINpassword
    name: server.example.com
    force: yes
    state: absent
"""

RETURN = """
"""


from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.ansible_freeipa_module import \
    temp_kinit, temp_kdestroy, valid_creds, api_connect, api_command, \
    api_command_no_name, compare_args_ipa, module_params_get, DNSName
import six

if six.PY3:
    unicode = str


def find_server(module, name):
    """Find if a server with the given name already exist."""
    try:
        _result = api_command(module, "server_show", name, {"all": True})
    except Exception:  # pylint: disable=broad-except
        # An exception is raised if server name is not found.
        return None
    else:
        return _result["result"]


def server_role_status(module, name):
    """Get server role of a hidden server with the given name."""
    try:
        _result = api_command_no_name(module, "server_role_find",
                                      {"server_server": name,
                                       "role_servrole": 'IPA master',
                                       "include_master": True,
                                       "raw": True,
                                       "all": True})
    except Exception:  # pylint: disable=broad-except
        # An exception is raised if server name is not found.
        return None
    else:
        return _result["result"][0]


def gen_args(location, service_weight, no_members, delete_continue,
             ignore_topology_disconnect, ignore_last_of_role, force):
    _args = {}
    if location is not None:
        if location != "":
            _args["ipalocation_location"] = DNSName(location)
        else:
            _args["ipalocation_location"] = None
    if service_weight is not None:
        _args["ipaserviceweight"] = service_weight
    if no_members is not None:
        _args["no_members"] = no_members
    if delete_continue is not None:
        _args["continue"] = delete_continue
    if ignore_topology_disconnect is not None:
        _args["ignore_topology_disconnect"] = ignore_topology_disconnect
    if ignore_last_of_role is not None:
        _args["ignore_last_of_role"] = ignore_last_of_role
    if force is not None:
        _args["force"] = force

    return _args


def main():
    ansible_module = AnsibleModule(
        argument_spec=dict(
            # general
            ipaadmin_principal=dict(type="str", default="admin"),
            ipaadmin_password=dict(type="str", required=False, no_log=True),

            name=dict(type="list", aliases=["cn"],
                      default=None, required=True),
            # present
            location=dict(required=False, type='str',
                          aliases=["ipalocation_location"], default=None),
            service_weight=dict(required=False, type='int',
                                aliases=["ipaserviceweight"], default=None),
            hidden=dict(required=False, type='bool', default=None),
            no_members=dict(required=False, type='bool', default=None),
            # absent
            delete_continue=dict(required=False, type='bool',
                                 aliases=["continue"], default=None),
            ignore_topology_disconnect=dict(required=False, type='bool',
                                            default=None),
            ignore_last_of_role=dict(required=False, type='bool',
                                     default=None),
            force=dict(required=False, type='bool',
                       default=None),
            # state
            state=dict(type="str", default="present",
                       choices=["present", "absent"]),
        ),
        supports_check_mode=True,
    )

    ansible_module._ansible_debug = True

    # Get parameters

    # general
    ipaadmin_principal = module_params_get(ansible_module,
                                           "ipaadmin_principal")
    ipaadmin_password = module_params_get(ansible_module, "ipaadmin_password")
    names = module_params_get(ansible_module, "name")

    # present
    location = module_params_get(ansible_module, "location")
    service_weight = module_params_get(ansible_module, "service_weight")
    # Service weight smaller than 0 leads to resetting service weight
    if service_weight is not None and \
       (service_weight < -1 or service_weight > 65535):
        ansible_module.fail_json(
            msg="service_weight %d is out of range [-1 .. 65535]" %
            service_weight)
    if service_weight == -1:
        service_weight = ""
    hidden = module_params_get(ansible_module, "hidden")
    no_members = module_params_get(ansible_module, "no_members")

    # absent
    delete_continue = module_params_get(ansible_module, "delete_continue")
    ignore_topology_disconnect = module_params_get(
        ansible_module, "ignore_topology_disconnect")
    ignore_last_of_role = module_params_get(ansible_module,
                                            "ignore_last_of_role")
    force = module_params_get(ansible_module, "force")

    # state
    state = module_params_get(ansible_module, "state")

    # Check parameters

    invalid = []

    if state == "present":
        if len(names) != 1:
            ansible_module.fail_json(
                msg="Only one server can be ensured at a time.")
        invalid = ["delete_continue", "ignore_topology_disconnect",
                   "ignore_last_of_role", "force"]

    if state == "absent":
        if len(names) < 1:
            ansible_module.fail_json(msg="No name given.")
        invalid = ["location", "service_weight", "hidden", "no_members"]

    for x in invalid:
        if vars()[x] is not None:
            ansible_module.fail_json(
                msg="Argument '%s' can not be used with state '%s'" %
                (x, state))

    # Init

    changed = False
    exit_args = {}
    ccache_dir = None
    ccache_name = None
    try:
        if not valid_creds(ansible_module, ipaadmin_principal):
            ccache_dir, ccache_name = temp_kinit(ipaadmin_principal,
                                                 ipaadmin_password)
        api_connect()

        commands = []
        for name in names:
            # Make sure server exists
            res_find = find_server(ansible_module, name)

            # Generate args
            args = gen_args(location, service_weight, no_members,
                            delete_continue, ignore_topology_disconnect,
                            ignore_last_of_role, force)

            # Create command
            if state == "present":
                # Server not found
                if res_find is None:
                    ansible_module.fail_json(
                        msg="Server '%s' not found" % name)

                # Remove location from args if "" (transformed to None)
                # and "ipalocation_location" not in res_find for idempotency
                if "ipalocation_location" in args and \
                   args["ipalocation_location"] is None and \
                   "ipalocation_location" not in res_find:
                    del args["ipalocation_location"]

                # Remove service weight from args if ""
                # and "ipaserviceweight" not in res_find for idempotency
                if "ipaserviceweight" in args and \
                   args["ipaserviceweight"] == "" and \
                   "ipaserviceweight" not in res_find:
                    del args["ipaserviceweight"]

                # For all settings is args, check if there are
                # different settings in the find result.
                # If yes: modify
                if not compare_args_ipa(ansible_module, args, res_find):
                    commands.append([name, "server_mod", args])

                # hidden handling
                if hidden is not None:
                    res_role_status = server_role_status(ansible_module,
                                                         name)

                    if "status" in res_role_status:
                        # Fail if status is configured, it should be done
                        # only in the installer
                        if res_role_status["status"] == "configured":
                            ansible_module.fail_json(
                                msg="'%s' in configured state, "
                                "unable to change state" % state)

                        if hidden and res_role_status["status"] == "enabled":
                            commands.append([name, "server_state",
                                             {"state": "hidden"}])
                        if not hidden and \
                           res_role_status["status"] == "hidden":
                            commands.append([name, "server_state",
                                             {"state": "enabled"}])

            elif state == "absent":
                if res_find is not None or force:
                    commands.append([name, "server_del", args])
            else:
                ansible_module.fail_json(msg="Unkown state '%s'" % state)

        # Execute commands

        for name, command, args in commands:
            try:
                result = api_command(ansible_module, command, name,
                                     args)
                if "completed" in result:
                    if result["completed"] > 0:
                        changed = True
                else:
                    changed = True
            except Exception as e:
                ansible_module.fail_json(msg="%s: %s: %s" % (command, name,
                                                             str(e)))

    except Exception as e:
        ansible_module.fail_json(msg=str(e))

    finally:
        temp_kdestroy(ccache_dir, ccache_name)

    # Done

    ansible_module.exit_json(changed=changed, **exit_args)


if __name__ == "__main__":
    main()

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
module: ipauser
short_description: Manage FreeIPA users
description: Manage FreeIPA users
extends_documentation_fragment:
  - ipamodule_base_docs
options:
  name:
    description: The list of users (internally uid).
    type: list
    elements: str
    required: false
    aliases: ["login"]
  users:
    description: The list of user dicts (internally uid).
    type: list
    elements: dict
    suboptions:
      name:
        description: The user (internally uid).
        type: str
        required: true
        aliases: ["login"]
      first:
        description: The first name. Required if user does not exist.
        type: str
        required: false
        aliases: ["givenname"]
      last:
        description: The last name. Required if user doesnot exst.
        type: str
        required: false
        aliases: ["sn"]
      fullname:
        description: The full name
        type: str
        required: false
        aliases: ["cn"]
      displayname:
        description: The display name
        type: str
        required: false
      initials:
        description: Initials
        type: str
        required: false
      homedir:
        description: The home directory
        type: str
        required: false
      gecos:
        description: The GECOS
        type: str
        required: false
      shell:
        description: The login shell
        type: str
        required: false
        aliases: ["loginshell"]
      email:
        description: List of email addresses
        type: list
        elements: str
        required: false
      principal:
        description: The kerberos principal
        type: list
        elements: str
        required: false
        aliases: ["principalname", "krbprincipalname"]
      principalexpiration:
        description: |
          The kerberos principal expiration date
          (possible formats: YYYYMMddHHmmssZ, YYYY-MM-ddTHH:mm:ssZ,
          YYYY-MM-ddTHH:mmZ, YYYY-MM-ddZ, YYYY-MM-dd HH:mm:ssZ,
          YYYY-MM-dd HH:mmZ) The trailing 'Z' can be skipped.
        type: str
        required: false
        aliases: ["krbprincipalexpiration"]
      passwordexpiration:
        description: |
          The kerberos password expiration date (FreeIPA-4.7+)
          (possible formats: YYYYMMddHHmmssZ, YYYY-MM-ddTHH:mm:ssZ,
          YYYY-MM-ddTHH:mmZ, YYYY-MM-ddZ, YYYY-MM-dd HH:mm:ssZ,
          YYYY-MM-dd HH:mmZ) The trailing 'Z' can be skipped.
          Only usable with IPA versions 4.7 and up.
        type: str
        required: false
        aliases: ["krbpasswordexpiration"]
      password:
        description: The user password
        type: str
        required: false
      random:
        description: Generate a random user password
        required: false
        type: bool
      uid:
        description: User ID Number (system will assign one if not provided)
        type: int
        required: false
        aliases: ["uidnumber"]
      gid:
        description: Group ID Number
        type: int
        required: false
        aliases: ["gidnumber"]
      street:
        description: Street address
        type: str
        required: false
      city:
        description: City
        type: str
        required: false
      userstate:
        description: State/Province
        type: str
        required: false
        aliases: ["st"]
      postalcode:
        description: Postalcode/ZIP
        type: str
        required: false
        aliases: ["zip"]
      phone:
        description: List of telephone numbers
        type: list
        elements: str
        required: false
        aliases: ["telephonenumber"]
      mobile:
        description: List of mobile telephone numbers
        type: list
        elements: str
        required: false
      pager:
        description: List of pager numbers
        type: list
        elements: str
        required: false
      fax:
        description: List of fax numbers
        type: list
        elements: str
        required: false
        aliases: ["facsimiletelephonenumber"]
      orgunit:
        description: Org. Unit
        type: str
        required: false
        aliases: ["ou"]
      title:
        description: The job title
        type: str
        required: false
      manager:
        description: List of managers
        type: list
        elements: str
        required: false
      carlicense:
        description: List of car licenses
        type: list
        elements: str
        required: false
      sshpubkey:
        description: List of SSH public keys
        required: false
        type: list
        elements: str
        aliases: ["ipasshpubkey"]
      userauthtype:
        description:
          List of supported user authentication types
          Use empty string to reset userauthtype to the initial value.
        type: list
        elements: str
        choices: ["password", "radius", "otp", "pkinit", "hardened", "idp",
                  "passkey", ""]
        required: false
        aliases: ["ipauserauthtype"]
      userclass:
        description:
        - User category
        - (semantics placed on this attribute are for local interpretation)
        type: list
        elements: str
        required: false
        aliases: ["class"]
      radius:
        description: RADIUS proxy configuration
        type: str
        required: false
        aliases: ["ipatokenradiusconfiglink"]
      radiususer:
        description: RADIUS proxy username
        type: str
        required: false
        aliases: ["radiususername", "ipatokenradiususername"]
      departmentnumber:
        description: Department Number
        type: list
        elements: str
        required: false
      employeenumber:
        description: Employee Number
        type: str
        required: false
      employeetype:
        description: Employee Type
        type: str
        required: false
      smb_logon_script:
        description: SMB logon script path
        type: str
        required: false
        aliases: ["ipantlogonscript"]
      smb_profile_path:
        description: SMB profile path
        type: str
        required: false
        aliases: ["ipantprofilepath"]
      smb_home_dir:
        description: SMB Home Directory
        type: str
        required: false
        aliases: ["ipanthomedirectory"]
      smb_home_drive:
        description: SMB Home Directory Drive
        type: str
        required: false
        choices: [
           'A:', 'B:', 'C:', 'D:', 'E:', 'F:', 'G:', 'H:', 'I:', 'J:',
           'K:', 'L:', 'M:', 'N:', 'O:', 'P:', 'Q:', 'R:', 'S:', 'T:',
           'U:', 'V:', 'W:', 'X:', 'Y:', 'Z:', ''
        ]
        aliases: ["ipanthomedirectorydrive"]
      preferredlanguage:
        description: Preferred Language
        type: str
        required: false
      idp:
        description: External IdP configuration
        type: str
        required: false
        aliases: ["ipaidpconfiglink"]
      idp_user_id:
        description: A string that identifies the user at external IdP
        type: str
        required: false
        aliases: ["ipaidpsub"]
      certificate:
        description: List of base-64 encoded user certificates
        type: list
        elements: str
        required: false
        aliases: ["usercertificate"]
      certmapdata:
        description:
        - List of certificate mappings
        - Only usable with IPA versions 4.5 and up.
        type: list
        elements: dict
        suboptions:
          certificate:
            description: Base-64 encoded user certificate
            type: str
            required: false
          issuer:
            description: Issuer of the certificate
            type: str
            required: false
          subject:
            description: Subject of the certificate
            type: str
            required: false
          data:
            description: Certmap data
            type: str
            required: false
        required: false
      noprivate:
        description: Don't create user private group
        required: false
        type: bool
      nomembers:
        description: Suppress processing of membership attributes
        required: false
        type: bool
      rename:
        description: Rename the user object
        required: false
        type: str
        aliases: ["new_name"]
    required: false
  first:
    description: The first name. Required if user does not exist.
    type: str
    required: false
    aliases: ["givenname"]
  last:
    description: The last name. Required if user doesnot exst.
    type: str
    required: false
    aliases: ["sn"]
  fullname:
    description: The full name
    type: str
    required: false
    aliases: ["cn"]
  displayname:
    description: The display name
    type: str
    required: false
  initials:
    description: Initials
    type: str
    required: false
  homedir:
    description: The home directory
    type: str
    required: false
  gecos:
    description: The GECOS
    type: str
    required: false
  shell:
    description: The login shell
    type: str
    required: false
    aliases: ["loginshell"]
  email:
    description: List of email addresses
    type: list
    elements: str
    required: false
  principal:
    description: The kerberos principal
    type: list
    elements: str
    required: false
    aliases: ["principalname", "krbprincipalname"]
  principalexpiration:
    description: |
      The kerberos principal expiration date
      (possible formats: YYYYMMddHHmmssZ, YYYY-MM-ddTHH:mm:ssZ,
      YYYY-MM-ddTHH:mmZ, YYYY-MM-ddZ, YYYY-MM-dd HH:mm:ssZ,
      YYYY-MM-dd HH:mmZ) The trailing 'Z' can be skipped.
    type: str
    required: false
    aliases: ["krbprincipalexpiration"]
  passwordexpiration:
    description: |
      The kerberos password expiration date (FreeIPA-4.7+)
      (possible formats: YYYYMMddHHmmssZ, YYYY-MM-ddTHH:mm:ssZ,
      YYYY-MM-ddTHH:mmZ, YYYY-MM-ddZ, YYYY-MM-dd HH:mm:ssZ,
      YYYY-MM-dd HH:mmZ) The trailing 'Z' can be skipped.
      Only usable with IPA versions 4.7 and up.
    type: str
    required: false
    aliases: ["krbpasswordexpiration"]
  password:
    description: The user password
    type: str
    required: false
  random:
    description: Generate a random user password
    required: false
    type: bool
  uid:
    description: User ID Number (system will assign one if not provided)
    type: int
    required: false
    aliases: ["uidnumber"]
  gid:
    description: Group ID Number
    type: int
    required: false
    aliases: ["gidnumber"]
  street:
    description: Street address
    type: str
    required: false
  city:
    description: City
    type: str
    required: false
  userstate:
    description: State/Province
    type: str
    required: false
    aliases: ["st"]
  postalcode:
    description: Postalcode/ZIP
    type: str
    required: false
    aliases: ["zip"]
  phone:
    description: List of telephone numbers
    type: list
    elements: str
    required: false
    aliases: ["telephonenumber"]
  mobile:
    description: List of mobile telephone numbers
    type: list
    elements: str
    required: false
  pager:
    description: List of pager numbers
    type: list
    elements: str
    required: false
  fax:
    description: List of fax numbers
    type: list
    elements: str
    required: false
    aliases: ["facsimiletelephonenumber"]
  orgunit:
    description: Org. Unit
    type: str
    required: false
    aliases: ["ou"]
  title:
    description: The job title
    type: str
    required: false
  manager:
    description: List of managers
    type: list
    elements: str
    required: false
  carlicense:
    description: List of car licenses
    type: list
    elements: str
    required: false
  sshpubkey:
    description: List of SSH public keys
    required: false
    type: list
    elements: str
    aliases: ["ipasshpubkey"]
  userauthtype:
    description:
      List of supported user authentication types
      Use empty string to reset userauthtype to the initial value.
    type: list
    elements: str
    choices: ["password", "radius", "otp", "pkinit", "hardened", "idp",
              "passkey", ""]
    required: false
    aliases: ["ipauserauthtype"]
  userclass:
    description:
    - User category
    - (semantics placed on this attribute are for local interpretation)
    type: list
    elements: str
    required: false
    aliases: ["class"]
  radius:
    description: RADIUS proxy configuration
    type: str
    required: false
    aliases: ["ipatokenradiusconfiglink"]
  radiususer:
    description: RADIUS proxy username
    type: str
    required: false
    aliases: ["radiususername", "ipatokenradiususername"]
  departmentnumber:
    description: Department Number
    type: list
    elements: str
    required: false
  employeenumber:
    description: Employee Number
    type: str
    required: false
  employeetype:
    description: Employee Type
    type: str
    required: false
  smb_logon_script:
    description: SMB logon script path
    type: str
    required: false
    aliases: ["ipantlogonscript"]
  smb_profile_path:
    description: SMB profile path
    type: str
    required: false
    aliases: ["ipantprofilepath"]
  smb_home_dir:
    description: SMB Home Directory
    type: str
    required: false
    aliases: ["ipanthomedirectory"]
  smb_home_drive:
    description: SMB Home Directory Drive
    type: str
    required: false
    choices: [
       'A:', 'B:', 'C:', 'D:', 'E:', 'F:', 'G:', 'H:', 'I:', 'J:',
       'K:', 'L:', 'M:', 'N:', 'O:', 'P:', 'Q:', 'R:', 'S:', 'T:',
       'U:', 'V:', 'W:', 'X:', 'Y:', 'Z:', ''
    ]
    aliases: ["ipanthomedirectorydrive"]
  preferredlanguage:
    description: Preferred Language
    type: str
    required: false
  idp:
    description: External IdP configuration
    type: str
    required: false
    aliases: ["ipaidpconfiglink"]
  idp_user_id:
    description: A string that identifies the user at external IdP
    type: str
    required: false
    aliases: ["ipaidpsub"]
  certificate:
    description: List of base-64 encoded user certificates
    type: list
    elements: str
    required: false
    aliases: ["usercertificate"]
  certmapdata:
    description:
    - List of certificate mappings
    - Only usable with IPA versions 4.5 and up.
    type: list
    elements: dict
    suboptions:
      certificate:
        description: Base-64 encoded user certificate
        type: str
        required: false
      issuer:
        description: Issuer of the certificate
        type: str
        required: false
      subject:
        description: Subject of the certificate
        type: str
        required: false
      data:
        description: Certmap data
        type: str
        required: false
    required: false
  noprivate:
    description: Don't create user private group
    required: false
    type: bool
  nomembers:
    description: Suppress processing of membership attributes
    required: false
    type: bool
  rename:
    description: Rename the user object
    required: false
    type: str
    aliases: ["new_name"]
  preserve:
    description: Delete a user, keeping the entry available for future use
    required: false
    type: bool
  update_password:
    description:
      Set password for a user in present state only on creation or always
    type: str
    choices: ["always", "on_create"]
    required: false
  query_param:
    description: The fields to query with state=query
    required: false
    type: list
    elements: str
    choices: ["ALL", "BASE", "PKEY_ONLY", "dn", "objectclass", "ipauniqueid",
      "ipantsecurityidentifier", "name", "first", "last", "fullname",
      "displayname", "initials", "homedir", "shell", "email",
      "principalexpiration", "passwordexpiration", "uid", "gid", "city",
      "userstate", "postalcode", "phone", "mobile", "pager", "fax",
      "orgunit", "title", "carlicense", "sshpubkey", "userauthtype",
      "userclass", "radius", "radiususer", "departmentnumber",
      "employeenumber", "employeetype", "preferredlanguage", "manager",
      "principal", "certificate", "certmapdata", "gecos", "password",
      "street", "idp", "idp_user_id", "smb_logon_script", "smb_profile_path",
      "smb_home_dir", "smb_home_drive", "krblastpwdchange",
      "krblastadminunlock", "krbextradata", "krbticketflags",
      "krbloginfailedcount", "krblastsuccessfulauth", "has_password",
      "has_keytab", "preserved", "memberof_group", "disabled"]
  action:
    description: Work on user or member level
    type: str
    default: "user"
    choices: ["member", "user"]
  state:
    description: State to ensure
    type: str
    default: present
    choices: ["present", "absent",
              "enabled", "disabled",
              "unlocked", "undeleted",
              "renamed", "query"]
author:
  - Thomas Woerner (@t-woerner)
"""

EXAMPLES = """
# Create user pinky
- ipauser:
    ipaadmin_password: SomeADMINpassword
    name: pinky
    first: pinky
    last: Acme
    uid: 10001
    gid: 100
    phone: "+555123457"
    email: pinky@acme.com
    passwordexpiration: "2023-01-19 23:59:59"
    password: "no-brain"
    update_password: on_create

# Create user brain
- ipauser:
    ipaadmin_password: SomeADMINpassword
    name: brain
    first: brain
    last: Acme

# Create multiple users pinky and brain
- ipauser:
    ipaadmin_password: SomeADMINpassword
    users:
    - name: pinky
      first: pinky
      last: Acme
    - name: brain
      first: brain
      last: Acme

# Delete user pinky, but preserved
- ipauser:
    ipaadmin_password: SomeADMINpassword
    name: pinky
    preserve: yes
    state: absent

# Undelete user pinky
- ipauser:
    ipaadmin_password: SomeADMINpassword
    name: pinky
    state: undeleted

# Disable user pinky
- ipauser:
    ipaadmin_password: SomeADMINpassword
    name: pinky,brain
    state: disabled

# Enable user pinky and brain
- ipauser:
    ipaadmin_password: SomeADMINpassword
    name: pinky,brain
    state: enabled

# Remove but preserve user pinky
- ipauser:
    ipaadmin_password: SomeADMINpassword
    users:
    - name: pinky
    preserve: yes
    state: absent

# Remove user pinky and brain
- ipauser:
    ipaadmin_password: SomeADMINpassword
    name: pinky,brain
    state: disabled

# Ensure a user has SMB attributes
- ipauser:
    ipaadmin_password: SomeADMINpassword
    name: smbuser
    first: SMB
    last: User
    smb_logon_script: N:\\logonscripts\\startup
    smb_profile_path: \\\\server\\profiles\\some_profile
    smb_home_dir: \\\\users\\home\\smbuser
    smb_home_drive: "U:"

# Rename an existing user
- ipauser:
    ipaadmin_password: SomeADMINpassword
    name: someuser
    rename: anotheruser
    state: renamed

# Query base fields of a user
- ipauser:
    ipaadmin_password: SomeADMINpassword
    name: pinky
    state: query
  register: result

# Query specific fields of a user
- ipauser:
    ipaadmin_password: SomeADMINpassword
    name: pinky
    query_param:
    - first
    - last
    - email
    state: query
  register: result

# Query all fields of a user
- ipauser:
    ipaadmin_password: SomeADMINpassword
    name: pinky
    query_param: ALL
    state: query
  register: result

# Query only the names of all users
- ipauser:
    ipaadmin_password: SomeADMINpassword
    query_param: PKEY_ONLY
    state: query
  register: result
"""

RETURN = """
user:
  description: User dict with random password
  returned: If random is yes and user did not exist or update_password is yes
  type: dict
  contains:
    randompassword:
      description: The generated random password
      type: str
      returned: |
        If only one user is handled by the module without using users parameter
    name:
      description: The user name of the user that got a new random password
      returned: |
        If several users are handled by the module with the users parameter
      type: dict
      contains:
        randompassword:
          description: The generated random password
          type: str
          returned: always
"""


from ansible.module_utils.ansible_freeipa_module import \
    IPAAnsibleModule, compare_args_ipa, gen_member_add_del_lists, \
    convert_date, \
    encode_certificate, load_cert_from_str, DN_x500_text, to_text, \
    ipalib_errors, convert_input_certificates, date_string
from ansible.module_utils import six
if six.PY3:
    unicode = str


def user_show(module, name):
    _args = {
        "all": True,
    }

    try:
        _result = module.ipa_command("user_show", name, _args).get("result")
    except ipalib_errors.NotFound:
        return None

    # Convert datetime to proper string representation
    for _expkey in ["krbpasswordexpiration", "krbprincipalexpiration"]:
        if _expkey in _result:
            _result[_expkey] = [date_string(x) for x in _result[_expkey]]
    # Transform each principal to a string
    _result["krbprincipalname"] = [
        to_text(x) for x in (_result.get("krbprincipalname") or [])
    ]
    _result["usercertificate"] = [
        encode_certificate(x) for x in (_result.get("usercertificate") or [])
    ]
    return _result


def query_convert_result(module, res):
    _res = {}
    for key in res:
        try:
            if key in ["manager", "krbprincipalname", "ipacertmapdata"]:
                _res[key] = [to_text(x) for x in (res.get(key) or [])]
            elif key == "usercertificate":
                _res[key] = [
                    encode_certificate(x) for x in (res.get(key) or [])
                ]
            elif isinstance(res[key], (list, tuple)):
                if len(res[key]) == 1:
                    # All single value parameters should not be lists
                    # This does not apply to manager, krbprincipalname,
                    # usercertificate and ipacertmapdata
                    _res[key] = to_text(res[key][0])
                else:
                    _res[key] = [to_text(x) for x in res[key]]
            elif key in ["uidnumber", "gidnumber"]:
                _res[key] = int(res[key])
            else:
                _res[key] = to_text(res[key])
        except (TypeError, ValueError) as e:
            module.fail_json(
                msg="Failed to convert query result for '%s': %s"
                % (key, str(e)))
    return _res


def user_find(module, name):
    _args = {"all": True}

    try:
        if name:
            _args["uid"] = name
        _result = module.ipa_command_no_name("user_find", _args).get("result")
        if _result:
            if name:
                _result = _result[0]

    except ipalib_errors.NotFound:
        return None

    return _result


def check_parameters(module, state, action, preserve, user_params):
    rename = user_params.get("rename")
    certmapdata = user_params.get("certmapdata")

    if state == "present" and action == "user":
        invalid = ["preserve"]
    else:
        invalid = [
            "first", "last", "fullname", "displayname", "initials", "homedir",
            "shell", "email", "principalexpiration", "passwordexpiration",
            "password", "random", "uid", "gid", "street", "city", "phone",
            "mobile", "pager", "fax", "orgunit", "title", "carlicense",
            "sshpubkey", "userauthtype", "userclass", "radius", "radiususer",
            "departmentnumber", "employeenumber", "employeetype",
            "preferredlanguage", "noprivate", "nomembers", "update_password",
            "gecos", "smb_logon_script", "smb_profile_path", "smb_home_dir",
            "smb_home_drive", "idp", "idp_user_id"
        ]

        if state == "present" and action == "member":
            invalid.append("preserve")
        else:
            if action == "user":
                invalid.extend(
                    ["principal", "manager", "certificate", "certmapdata"])

        if state == "query":
            module.fail_json(
                msg="check_parameters can not be used with action query.")
        if state == "query":
            invalid.append("users")

            if action == "member":
                module.fail_json(
                    msg="Query is not possible with action=member")
        else:
            invalid.append("query_param")

        if state != "absent" and preserve is not None:
            module.fail_json(
                msg="Preserve is only possible for state=absent")

    if state != "renamed":
        invalid.append("rename")
    else:
        invalid.extend([
            "preserve", "principal", "manager", "certificate", "certmapdata",
        ])
        if not rename:
            module.fail_json(
                msg="A value for attribute 'rename' must be provided.")
        if action == "member":
            module.fail_json(
                msg="Action member can not be used with state: renamed.")

    module.params_fail_used_invalid(invalid, state, action, user_params,
                                    PARAM_MAPPING)

    if certmapdata is not None:
        for x in certmapdata:
            _certificate = x.get("certificate")
            issuer = x.get("issuer")
            subject = x.get("subject")
            data = x.get("data")

            if data is not None:
                if _certificate is not None or issuer is not None or \
                   subject is not None:
                    module.fail_json(
                        msg="certmapdata: data can not be used with "
                        "certificate, issuer or subject")
                check_certmapdata(data)
            if _certificate is not None \
               and (issuer is not None or subject is not None):
                module.fail_json(
                    msg="certmapdata: certificate can not be used with "
                    "issuer or subject")
            if data is None and _certificate is None:
                if issuer is None:
                    module.fail_json(msg="certmapdata: issuer is missing")
                if subject is None:
                    module.fail_json(msg="certmapdata: subject is missing")

    # Check if userauthtype is invalid
    userauthtype = user_params.get("userauthtype")
    _invalid = module.ipa_command_invalid_param_choices(
        "user_add", "ipauserauthtype", userauthtype)
    if _invalid:
        module.fail_json(
            msg="The use of userauthtype '%s' is not supported "
            "by your IPA version" % "','".join(_invalid))


def convert_params(ansible_module, user_params, default_email_domain,
                   server_realm, state):
    """Convert parameter values in user_params in-place."""
    # Convert date fields
    for date_field in ("principalexpiration", "passwordexpiration"):
        val = user_params.get(date_field)
        if (
            val
            and isinstance(
                val, (str, unicode)  # pylint: disable=W0012,E0606
            )
        ):
            if val[-1] != "Z":
                val = val + "Z"
            user_params[date_field] = convert_date(val)

    # Extend email addresses without "@" with default domain
    email = user_params.get("email")
    if email is not None:
        user_params["email"] = [
            "%s@%s" % (_email, default_email_domain)
            if "@" not in _email else _email
            for _email in email
        ]

    # Add realm to principals missing "@"
    principal = user_params.get("principal")
    if principal is not None:
        user_params["principal"] = [
            x if "@" in x else x + "@" + server_realm
            for x in principal
        ]

    # Convert certmapdata dicts to X509 strings
    certmapdata = user_params.get("certmapdata")
    if certmapdata is not None:
        _result = []
        for x in certmapdata:
            certificate = x.get("certificate")
            issuer = x.get("issuer")
            subject = x.get("subject")
            data = x.get("data")

            if data is None:
                if issuer is None and subject is None:
                    cert = load_cert_from_str(certificate)
                    issuer = cert.issuer
                    subject = cert.subject

                _result.append("X509:<I>%s<S>%s" % (DN_x500_text(issuer),
                                                    DN_x500_text(subject)))
            else:
                _result.append(data)

        user_params["certmapdata"] = _result

    # Normalize base64 certificates
    certificate = user_params.get("certificate")
    user_params["certificate"] = convert_input_certificates(
        ansible_module, certificate, state)


def check_certmapdata(data):
    if not data.startswith("X509:"):
        return False

    i = data.find("<I>", 4)
    s = data.find("<S>", i)   # pylint: disable=invalid-name
    issuer = data[i + 3:s]
    subject = data[s + 3:]

    if i < 0 or s < 0 or "CN" not in issuer or "CN" not in subject:
        return False

    return True


def gen_certmapdata_args(certmapdata):
    return {"ipacertmapdata": to_text(certmapdata)}


# pylint: disable=unused-argument
def result_handler(module, result, command, name, args, exit_args,
                   errors, single_user):
    if "random" in args and command in ["user_add", "user_mod"] \
       and "randompassword" in result["result"]:
        if single_user:
            exit_args["randompassword"] = \
                result["result"]["randompassword"]
        else:
            exit_args.setdefault(name, {})["randompassword"] = \
                result["result"]["randompassword"]

    IPAAnsibleModule.member_error_handler(module, result, command, name, args,
                                          errors)


# password, randompassword and krbprincipalkey may not be in the returned
# information even in server context.
PARAM_MAPPING = {
    # Read-only system fields
    "dn": {"return_only": True},
    "objectclass": {"return_only": True},
    "ipauniqueid": {"return_only": True},
    "ipantsecurityidentifier": {"return_only": True},

    # Query-only: name is the primary key, handled separately
    "name": {"api_name": "uid", "gen_args": False},

    # Writable params
    "first": {"api_name": "givenname"},
    "last": {"api_name": "sn"},
    "fullname": {"api_name": "cn"},
    "displayname": {},
    "initials": {},
    "homedir": {"api_name": "homedirectory"},
    "shell": {"api_name": "loginshell"},
    "email": {"api_name": "mail", "nonempty_list": True},
    "principalexpiration": {"api_name": "krbprincipalexpiration"},
    "passwordexpiration": {"api_name": "krbpasswordexpiration"},
    "uid": {"api_name": "uidnumber", "type": "int", "convert_to": "text"},
    "gid": {"api_name": "gidnumber", "type": "int", "convert_to": "text"},
    "city": {"api_name": "l"},
    "userstate": {"api_name": "st"},
    "postalcode": {},
    "phone": {"api_name": "telephonenumber", "nonempty_list": True},
    "mobile": {"nonempty_list": True},
    "pager": {"nonempty_list": True},
    "fax": {"api_name": "facsimiletelephonenumber", "nonempty_list": True},
    "orgunit": {"api_name": "ou"},
    "title": {},
    "carlicense": {"nonempty_list": True},
    "sshpubkey": {"api_name": "ipasshpubkey", "nonempty_list": True,
                  "allow_empty_list_item": True},
    "userauthtype": {"api_name": "ipauserauthtype", "nonempty_list": True,
                     "allow_empty_list_item": True},
    "userclass": {},
    "radius": {"api_name": "ipatokenradiusconfiglink"},
    "radiususer": {"api_name": "ipatokenradiususername"},
    "departmentnumber": {},
    "employeenumber": {},
    "employeetype": {},
    "preferredlanguage": {},

    # Query-only: handled separately via member commands
    "manager": {"gen_args": False, "member": True},
    "principal": {"api_name": "krbprincipalname", "gen_args": False,
                  "member": True},
    "certificate": {"api_name": "usercertificate", "gen_args": False,
                    "member": True},
    "certmapdata": {"api_name": "ipacertmapdata", "gen_args": False,
                    "member": True},

    # Writable params not queryable by name
    "gecos": {},
    "password": {"api_name": "userpassword"},
    "random": {"query": False},
    "street": {},
    "rename": {"gen_args": False, "query": False},
    "noprivate": {"query": False},
    "nomembers": {"api_name": "no_members", "query": False},
    "idp": {"api_name": "ipaidpconfiglink"},
    "idp_user_id": {"api_name": "ipaidpsub"},
    "smb_logon_script": {"api_name": "ipantlogonscript"},
    "smb_profile_path": {"api_name": "ipantprofilepath"},
    "smb_home_dir": {"api_name": "ipanthomedirectory"},
    "smb_home_drive": {"api_name": "ipanthomedirectorydrive"},

    # Read-only status fields
    "krblastpwdchange": {"return_only": True},
    "krblastadminunlock": {"return_only": True},
    "krbextradata": {"return_only": True},
    "krbticketflags": {"return_only": True},
    "krbloginfailedcount": {"return_only": True},
    "krblastsuccessfulauth": {"return_only": True},
    "has_password": {"return_only": True},
    "has_keytab": {"return_only": True},
    "preserved": {"type": "bool", "return_only": True},
    "memberof_group": {"return_only": True},
    "disabled": {"api_name": "nsaccountlock", "type": "bool",
                 "gen_args": False},

    # Module-level params (not per-item, checked via self.params)
    "query_param": {"module_param": True},
    "users": {"module_param": True},
    "preserve": {"module_param": True},
    "update_password": {"module_param": True},
}

QUERY_FIELDS = {
    "prefix": "users",
    "primary_key": "uid",
    "base": [
        "name", "first", "last", "shell", "principal", "uid", "gid", "disabled"
    ]
}


def main():
    user_spec = dict(
        # present
        first=dict(type="str", aliases=["givenname"], default=None),
        last=dict(type="str", aliases=["sn"], default=None),
        fullname=dict(type="str", aliases=["cn"], default=None),
        displayname=dict(type="str", default=None),
        initials=dict(type="str", default=None),
        homedir=dict(type="str", default=None),
        gecos=dict(type="str", default=None),
        shell=dict(type="str", aliases=["loginshell"], default=None),
        email=dict(type="list", elements="str", default=None),
        principal=dict(type="list", elements="str",
                       aliases=["principalname", "krbprincipalname"],
                       default=None),
        principalexpiration=dict(type="str",
                                 aliases=["krbprincipalexpiration"],
                                 default=None),
        passwordexpiration=dict(type="str",
                                aliases=["krbpasswordexpiration"],
                                default=None, no_log=False),
        password=dict(type="str", default=None, no_log=True),
        random=dict(type='bool', default=None),
        uid=dict(type="int", aliases=["uidnumber"], default=None),
        gid=dict(type="int", aliases=["gidnumber"], default=None),
        street=dict(type="str", default=None),
        city=dict(type="str", default=None),
        userstate=dict(type="str", aliases=["st"], default=None),
        postalcode=dict(type="str", aliases=["zip"], default=None),
        phone=dict(type="list", elements="str", aliases=["telephonenumber"],
                   default=None),
        mobile=dict(type="list", elements="str", default=None),
        pager=dict(type="list", elements="str", default=None),
        fax=dict(type="list", elements="str",
                 aliases=["facsimiletelephonenumber"], default=None),
        orgunit=dict(type="str", aliases=["ou"], default=None),
        title=dict(type="str", default=None),
        manager=dict(type="list", elements="str", default=None),
        carlicense=dict(type="list", elements="str", default=None),
        sshpubkey=dict(type="list", elements="str", aliases=["ipasshpubkey"],
                       default=None),
        userauthtype=dict(type='list', elements="str",
                          aliases=["ipauserauthtype"], default=None,
                          choices=["password", "radius", "otp", "pkinit",
                                   "hardened", "idp", "passkey", ""]),
        userclass=dict(type="list", elements="str", aliases=["class"],
                       default=None),
        radius=dict(type="str", aliases=["ipatokenradiusconfiglink"],
                    default=None),
        radiususer=dict(type="str", aliases=["radiususername",
                                             "ipatokenradiususername"],
                        default=None),
        departmentnumber=dict(type="list", elements="str", default=None),
        employeenumber=dict(type="str", default=None),
        employeetype=dict(type="str", default=None),
        smb_logon_script=dict(type="str", default=None,
                              aliases=["ipantlogonscript"]),
        smb_profile_path=dict(type="str", default=None,
                              aliases=["ipantprofilepath"]),
        smb_home_dir=dict(type="str", default=None,
                          aliases=["ipanthomedirectory"]),
        smb_home_drive=dict(type="str", default=None,
                            choices=[
                                ("%c:" % chr(x))
                                for x in range(ord('A'), ord('Z') + 1)
                            ] + [""], aliases=["ipanthomedirectorydrive"]),
        preferredlanguage=dict(type="str", default=None),
        certificate=dict(type="list", elements="str",
                         aliases=["usercertificate"], default=None),
        certmapdata=dict(type="list", default=None,
                         options=dict(
                             # Here certificate is a simple string
                             certificate=dict(type="str", default=None),
                             issuer=dict(type="str", default=None),
                             subject=dict(type="str", default=None),
                             data=dict(type="str", default=None)
                         ),
                         elements='dict', required=False),
        noprivate=dict(type='bool', default=None),
        nomembers=dict(type='bool', default=None),
        idp=dict(type="str", default=None, aliases=['ipaidpconfiglink']),
        idp_user_id=dict(type="str", default=None,
                         aliases=['ipaidpsub']),
        rename=dict(type="str", required=False, default=None,
                    aliases=["new_name"]),
    )

    query_param_settings = IPAAnsibleModule.build_query_param_settings(
        PARAM_MAPPING, QUERY_FIELDS)

    ansible_module = IPAAnsibleModule(
        argument_spec=dict(
            # general
            name=dict(type="list", elements="str", aliases=["login"],
                      default=None, required=False),
            users=dict(type="list",
                       default=None,
                       options=dict(
                           # Here name is a simple string
                           name=dict(type="str", required=True,
                                     aliases=["login"]),
                           # Add user specific parameters
                           **user_spec
                       ),
                       elements='dict',
                       required=False),

            # deleted
            preserve=dict(required=False, type='bool', default=None),

            # mod
            update_password=dict(type='str', default=None, no_log=False,
                                 choices=['always', 'on_create']),

            # query
            query_param=dict(
                type="list", elements="str", default=None,
                choices=["ALL", "BASE", "PKEY_ONLY"]
                + query_param_settings["ALL"],
                required=False
            ),

            # general
            action=dict(type="str", default="user",
                        choices=["member", "user"]),
            state=dict(type="str", default="present",
                       choices=["present", "absent", "enabled", "disabled",
                                "unlocked", "undeleted", "renamed",
                                "query"]),

            # Add user specific parameters for simple use case
            **user_spec
        ),
        mutually_exclusive=[["name", "users"]],
        # Required one of [["name", "users"]] has been removed as there is
        # an extra test below and it is not working with state=query
        supports_check_mode=True,
    )

    ansible_module._ansible_debug = True

    # Get parameters

    # general
    names = ansible_module.params_get("name")
    users = ansible_module.params_get("users")

    preserve = ansible_module.params_get("preserve")
    update_password = ansible_module.params_get("update_password")

    # query
    query_param = ansible_module.params_get("query_param")
    # general
    action = ansible_module.params_get("action")
    state = ansible_module.params_get("state")

    # Check parameters

    if state != "query":
        if (names is None or len(names) < 1) and \
           (users is None or len(users) < 1):
            ansible_module.fail_json(msg="One of name and users is required")
    else:
        if action == "member":
            ansible_module.fail_json(
                msg="Query is not possible with action=member")
        if users is not None:
            ansible_module.fail_json(
                msg="users can not be used with state=query, "
                "use name instead")

    if state in ["present", "renamed"]:
        if names is not None and len(names) != 1:
            act = "renamed" if state == "renamed" else "added"
            ansible_module.fail_json(
                msg="Only one user can be %s at a time using name." % (act))

    # Use users if names is None
    if users is not None:
        names = users

    # Init

    changed = False
    exit_args = {}

    # Connect to IPA API
    with ansible_module.ipa_connect():

        if state == "query":
            exit_args = ansible_module.execute_query(
                names, query_param, user_find, query_param_settings,
                convert_result=lambda res: query_convert_result(
                    ansible_module, res)
            )

            ansible_module.exit_json(changed=False, user=exit_args)

        server_realm = ansible_module.ipa_get_realm()

        result = ansible_module.ipa_command_no_name("config_show", {})
        default_email_domain = result["result"]["ipadefaultemaildomain"][0]

        # commands

        commands = []
        user_set = set()

        for user in names:
            if isinstance(user, dict):
                name = user.get("name")
                if name in user_set:
                    ansible_module.fail_json(
                        msg="user '%s' is used more than once" % name)
                user_set.add(name)

                user_params = IPAAnsibleModule.extract_params_from_entry(
                    user, PARAM_MAPPING)

            elif (
                isinstance(
                    user, (str, unicode)  # pylint: disable=W0012,E0606
                )
            ):
                name = user
                user_params = IPAAnsibleModule.extract_params(
                    ansible_module, PARAM_MAPPING)
            else:
                ansible_module.fail_json(msg="User '%s' is not valid" %
                                         repr(user))
                # Never reached, just added to make pylint happy
                name = None
                user_params = {}

            # Unpack params used directly in business logic
            first = user_params.get("first")
            last = user_params.get("last")
            passwordexpiration = user_params.get("passwordexpiration")
            rename = user_params.get("rename")

            check_parameters(ansible_module, state, action, preserve,
                             user_params)
            convert_params(ansible_module, user_params,
                           default_email_domain, server_realm, state)

            # Check passwordexpiration availability
            if passwordexpiration is not None and \
               not ansible_module.ipa_command_param_exists(
                   "user_add", "krbpasswordexpiration"):
                ansible_module.fail_json(
                    msg="The use of passwordexpiration is not supported by "
                    "your IPA version")

            # Check certmapdata availability
            if user_params.get("certmapdata") is not None and \
               not ansible_module.ipa_command_exists("user_add_certmapdata"):
                ansible_module.fail_json(
                    msg="The use of certmapdata is not supported by "
                    "your IPA version")

            # Check if SMB attributes are available
            if (
                any([
                    user_params.get("smb_logon_script"),
                    user_params.get("smb_profile_path"),
                    user_params.get("smb_home_dir"),
                    user_params.get("smb_home_drive"),
                ])
                and not ansible_module.ipa_command_param_exists(
                    "user_mod", "ipanthomedirectory"
                )
            ):
                ansible_module.fail_json(
                    msg="The use of smb_logon_script, smb_profile_path, "
                    "smb_profile_path, and smb_home_drive is not supported "
                    "by your IPA version")

            # Check if IdP support is available
            require_idp = (
                user_params.get("idp") is not None
                or user_params.get("idp_user_id") is not None
                or user_params.get("userauthtype") == "idp"
            )
            has_idp_support = ansible_module.ipa_command_param_exists(
                "user_add", "ipaidpconfiglink"
            )
            if require_idp and not has_idp_support:
                ansible_module.fail_json(
                    msg="Your IPA version does not support External IdP.")

            # Make sure user exists
            res_find = user_show(ansible_module, name)

            # Create command
            if state == "present":
                # Generate args
                args = IPAAnsibleModule.gen_args_from_mapping(
                    PARAM_MAPPING, user_params)

                if action == "user":
                    # Found the user
                    if res_find is not None:
                        # Ignore password and random with
                        # update_password == on_create
                        if update_password == "on_create":
                            if "userpassword" in args:
                                del args["userpassword"]
                            if "random" in args:
                                del args["random"]
                        # if using "random:false" password should not be
                        # generated.
                        if not args.get("random", True):
                            del args["random"]
                        if "noprivate" in args:
                            del args["noprivate"]

                        # For all settings is args, check if there are
                        # different settings in the find result.
                        # If yes: modify
                        # The nomembers parameter is added to args for the
                        # api command. But no_members is never part of
                        # res_find from user-show, therefore this parameter
                        # needs to be ignored in compare_args_ipa.
                        if not compare_args_ipa(
                                ansible_module, args, res_find,
                                ignore=["no_members"]):
                            commands.append([name, "user_mod", args])

                    else:
                        # Make sure we have a first and last name
                        if first is None:
                            ansible_module.fail_json(
                                msg="First name is needed")
                        if last is None:
                            ansible_module.fail_json(
                                msg="Last name is needed")

                        smb_attrs = {
                            k: args[k]
                            for k in [
                                "ipanthomedirectory",
                                "ipanthomedirectorydrive",
                                "ipantlogonscript",
                                "ipantprofilepath",
                            ]
                            if k in args
                        }
                        for key in smb_attrs.keys():
                            del args[key]
                        commands.append([name, "user_add", args])
                        if smb_attrs:
                            commands.append([name, "user_mod", smb_attrs])
                elif action == "member":
                    if res_find is None:
                        ansible_module.fail_json(
                            msg="No user '%s'" % name)

            elif state == "absent":
                if action == "user":
                    if res_find is not None:
                        args = {}
                        if preserve is not None:
                            args["preserve"] = preserve
                        if (
                            not res_find.get("preserved", False)
                            or not args.get("preserve", False)
                        ):
                            commands.append([name, "user_del", args])
                elif action == "member":
                    if res_find is None:
                        ansible_module.fail_json(
                            msg="No user '%s'" % name)

            elif state == "undeleted":
                if res_find is not None:
                    if res_find.get("preserved", False):
                        commands.append([name, "user_undel", {}])
                else:
                    raise ValueError("No user '%s'" % name)

            elif state == "enabled":
                if res_find is not None:
                    if res_find["nsaccountlock"]:
                        commands.append([name, "user_enable", {}])
                else:
                    raise ValueError("No user '%s'" % name)

            elif state == "disabled":
                if res_find is not None:
                    if not res_find["nsaccountlock"]:
                        commands.append([name, "user_disable", {}])
                else:
                    raise ValueError("No user '%s'" % name)

            elif state == "unlocked":
                if res_find is not None:
                    commands.append([name, "user_unlock", {}])
                else:
                    raise ValueError("No user '%s'" % name)

            elif state == "renamed":
                if res_find is None:
                    ansible_module.fail_json(msg="No user '%s'" % name)
                else:
                    if rename != name:
                        commands.append([name, 'user_mod', {"rename": rename}])
            else:
                ansible_module.fail_json(msg="Unkown state '%s'" % state)

            # Handle members: principal, manager, certificate and
            # certmapdata
            member_lists = gen_member_add_del_lists(
                PARAM_MAPPING, user_params,
                res_find or {}, action, state)
            manager_add, manager_del = member_lists.get(
                "manager", ([], []))
            principal_add, principal_del = member_lists.get(
                "principal", ([], []))
            certificate_add, certificate_del = member_lists.get(
                "certificate", ([], []))
            certmapdata_add, certmapdata_del = member_lists.get(
                "certmapdata", ([], []))

            # Principals are not returned as utf8 for IPA using
            # python2 using user_show, therefore we need to
            # convert the principals that we should remove.
            principal_del = [to_text(x) for x in principal_del]

            # Remove canonical principal from principal_del. This only
            # applies to state=present, where principal_del is derived
            # from a full sync of the requested principal list; for
            # state=absent,action=member the canonical principal is a
            # removal the caller explicitly asked for.
            if state == "present":
                canonical_principal = name + "@" + server_realm
                if canonical_principal in principal_del:
                    principal_del.remove(canonical_principal)

            # Add managers
            if len(manager_add) > 0:
                commands.append([name, "user_add_manager",
                                 {
                                     "user": manager_add,
                                 }])
            # Remove managers
            if len(manager_del) > 0:
                commands.append([name, "user_remove_manager",
                                 {
                                     "user": manager_del,
                                 }])

            # Principals need to be added and removed one by one,
            # because if entry already exists, the processing of
            # the remaining enries is stopped. The same applies to
            # the removal of non-existing entries.

            # Add principals
            if len(principal_add) > 0:
                for _principal in principal_add:
                    commands.append([name, "user_add_principal",
                                     {
                                         "krbprincipalname":
                                         _principal,
                                     }])
            # Remove principals
            if len(principal_del) > 0:
                for _principal in principal_del:
                    commands.append([name, "user_remove_principal",
                                     {
                                         "krbprincipalname":
                                         _principal,
                                     }])

            # Certificates need to be added and removed one by one,
            # because if entry already exists, the processing of
            # the remaining enries is stopped. The same applies to
            # the removal of non-existing entries.

            # Add certificates
            if len(certificate_add) > 0:
                for _certificate in certificate_add:
                    commands.append([name, "user_add_cert",
                                     {
                                         "usercertificate":
                                         _certificate,
                                     }])
            # Remove certificates
            if len(certificate_del) > 0:
                for _certificate in certificate_del:
                    commands.append([name, "user_remove_cert",
                                     {
                                         "usercertificate":
                                         _certificate,
                                     }])

            # certmapdata need to be added and removed one by one,
            # because issuer and subject can only be done one by
            # one reliably (https://pagure.io/freeipa/issue/8097)

            # Add certmapdata
            if len(certmapdata_add) > 0:
                for _data in certmapdata_add:
                    commands.append([name, "user_add_certmapdata",
                                     gen_certmapdata_args(_data)])
            # Remove certmapdata
            if len(certmapdata_del) > 0:
                for _data in certmapdata_del:
                    commands.append([name, "user_remove_certmapdata",
                                     gen_certmapdata_args(_data)])

        del user_set

        # Execute commands

        changed = ansible_module.execute_ipa_commands(
            commands, result_handler, batch=True, keeponly=["randompassword"],
            exit_args=exit_args, single_user=users is None)

    # Done
    ansible_module.exit_json(changed=changed, user=exit_args)


if __name__ == "__main__":
    main()

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
        choices: ["password", "radius", "otp", "pkinit", "hardened", "idp", ""]
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
    choices: ["password", "radius", "otp", "pkinit", "hardened", "idp", ""]
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
              "renamed"]
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
    IPAAnsibleModule, compare_args_ipa, gen_add_del_lists, date_format, \
    encode_certificate, load_cert_from_str, DN_x500_text, to_text, \
    ipalib_errors
from ansible.module_utils import six
if six.PY3:
    unicode = str


def find_user(module, name):
    _args = {
        "all": True,
    }

    try:
        _result = module.ipa_command("user_show", name, _args).get("result")
    except ipalib_errors.NotFound:
        return None

    # Transform each principal to a string
    _result["krbprincipalname"] = [
        to_text(x) for x in (_result.get("krbprincipalname") or [])
    ]
    _result["usercertificate"] = [
        encode_certificate(x) for x in (_result.get("usercertificate") or [])
    ]
    return _result


def gen_args(first, last, fullname, displayname, initials, homedir, gecos,
             shell, email, principalexpiration, passwordexpiration, password,
             random, uid, gid, street, city, userstate, postalcode, phone,
             mobile, pager, fax, orgunit, title, carlicense, sshpubkey,
             userauthtype, userclass, radius, radiususer, departmentnumber,
             employeenumber, employeetype, preferredlanguage, smb_logon_script,
             smb_profile_path, smb_home_dir, smb_home_drive, idp, idp_user_id,
             noprivate, nomembers):
    # principal, manager, certificate and certmapdata are handled not in here
    _args = {}
    if first is not None:
        _args["givenname"] = first
    if last is not None:
        _args["sn"] = last
    if fullname is not None:
        _args["cn"] = fullname
    if displayname is not None:
        _args["displayname"] = displayname
    if initials is not None:
        _args["initials"] = initials
    if homedir is not None:
        _args["homedirectory"] = homedir
    if gecos is not None:
        _args["gecos"] = gecos
    if shell is not None:
        _args["loginshell"] = shell
    if email is not None and len(email) > 0:
        _args["mail"] = email
    if principalexpiration is not None:
        _args["krbprincipalexpiration"] = principalexpiration
    if passwordexpiration is not None:
        _args["krbpasswordexpiration"] = passwordexpiration
    if password is not None:
        _args["userpassword"] = password
    if random is not None:
        _args["random"] = random
    if uid is not None:
        _args["uidnumber"] = to_text(str(uid))
    if gid is not None:
        _args["gidnumber"] = to_text(str(gid))
    if street is not None:
        _args["street"] = street
    if city is not None:
        _args["l"] = city
    if userstate is not None:
        _args["st"] = userstate
    if postalcode is not None:
        _args["postalcode"] = postalcode
    if phone is not None and len(phone) > 0:
        _args["telephonenumber"] = phone
    if mobile is not None and len(mobile) > 0:
        _args["mobile"] = mobile
    if pager is not None and len(pager) > 0:
        _args["pager"] = pager
    if fax is not None and len(fax) > 0:
        _args["facsimiletelephonenumber"] = fax
    if orgunit is not None:
        _args["ou"] = orgunit
    if title is not None:
        _args["title"] = title
    if carlicense is not None and len(carlicense) > 0:
        _args["carlicense"] = carlicense
    if sshpubkey is not None and len(sshpubkey) > 0:
        _args["ipasshpubkey"] = sshpubkey
    if userauthtype is not None and len(userauthtype) > 0:
        _args["ipauserauthtype"] = userauthtype
    if userclass is not None:
        _args["userclass"] = userclass
    if radius is not None:
        _args["ipatokenradiusconfiglink"] = radius
    if radiususer is not None:
        _args["ipatokenradiususername"] = radiususer
    if departmentnumber is not None:
        _args["departmentnumber"] = departmentnumber
    if employeenumber is not None:
        _args["employeenumber"] = employeenumber
    if employeetype is not None:
        _args["employeetype"] = employeetype
    if preferredlanguage is not None:
        _args["preferredlanguage"] = preferredlanguage
    if idp is not None:
        _args["ipaidpconfiglink"] = idp
    if idp_user_id is not None:
        _args["ipaidpsub"] = idp_user_id
    if noprivate is not None:
        _args["noprivate"] = noprivate
    if nomembers is not None:
        _args["no_members"] = nomembers
    if smb_logon_script is not None:
        _args["ipantlogonscript"] = smb_logon_script
    if smb_profile_path is not None:
        _args["ipantprofilepath"] = smb_profile_path
    if smb_home_dir is not None:
        _args["ipanthomedirectory"] = smb_home_dir
    if smb_home_drive is not None:
        _args["ipanthomedirectorydrive"] = smb_home_drive
    return _args


def check_parameters(  # pylint: disable=unused-argument
        module, state, action, first, last, fullname, displayname, initials,
        homedir, gecos, shell, email, principal, principalexpiration,
        passwordexpiration, password, random, uid, gid, street, city, phone,
        mobile, pager, fax, orgunit, title, manager, carlicense, sshpubkey,
        userauthtype, userclass, radius, radiususer, departmentnumber,
        employeenumber, employeetype, preferredlanguage, certificate,
        certmapdata, noprivate, nomembers, preserve, update_password,
        smb_logon_script, smb_profile_path, smb_home_dir, smb_home_drive,
        idp, ipa_user_id, rename
):
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

    module.params_fail_used_invalid(invalid, state, action)

    if certmapdata is not None:
        for x in certmapdata:
            certificate = x.get("certificate")
            issuer = x.get("issuer")
            subject = x.get("subject")
            data = x.get("data")

            if data is not None:
                if certificate is not None or issuer is not None or \
                   subject is not None:
                    module.fail_json(
                        msg="certmapdata: data can not be used with "
                        "certificate, issuer or subject")
                check_certmapdata(data)
            if certificate is not None \
               and (issuer is not None or subject is not None):
                module.fail_json(
                    msg="certmapdata: certificate can not be used with "
                    "issuer or subject")
            if data is None and certificate is None:
                if issuer is None:
                    module.fail_json(msg="certmapdata: issuer is missing")
                if subject is None:
                    module.fail_json(msg="certmapdata: subject is missing")


def check_userauthtype(module, userauthtype):
    _invalid = module.ipa_command_invalid_param_choices(
        "user_add", "ipauserauthtype", userauthtype)
    if _invalid:
        module.fail_json(
            msg="The use of userauthtype '%s' is not supported "
            "by your IPA version" % "','".join(_invalid))


def extend_emails(email, default_email_domain):
    if email is not None:
        return ["%s@%s" % (_email, default_email_domain)
                if "@" not in _email else _email
                for _email in email]
    return email


def convert_certmapdata(certmapdata):
    if certmapdata is None:
        return None

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

    return _result


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
def result_handler(module, result, command, name, args, errors, exit_args,
                   single_user):

    if "random" in args and command in ["user_add", "user_mod"] \
       and "randompassword" in result["result"]:
        if single_user:
            exit_args["randompassword"] = \
                result["result"]["randompassword"]
        else:
            exit_args.setdefault(name, {})["randompassword"] = \
                result["result"]["randompassword"]

    # Get all errors
    # All "already a member" and "not a member" failures in the
    # result are ignored. All others are reported.
    if "failed" in result and len(result["failed"]) > 0:
        for item in result["failed"]:
            failed_item = result["failed"][item]
            for member_type in failed_item:
                for member, failure in failed_item[member_type]:
                    if "already a member" in failure \
                       or "not a member" in failure:
                        continue
                    errors.append("%s: %s %s: %s" % (
                        command, member_type, member, failure))


# pylint: disable=unused-argument
def exception_handler(module, ex, errors, exit_args, single_user):
    msg = str(ex)
    if "already contains" in msg \
       or "does not contain" in msg:
        return True
    #  The canonical principal name may not be removed
    if "equal to the canonical principal name must" in msg:
        return True
    return False


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
                                   "hardened", "idp", ""]),
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
                         aliases=['ipaidpconfiglink']),
        rename=dict(type="str", required=False, default=None,
                    aliases=["new_name"]),
    )

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

            # general
            action=dict(type="str", default="user",
                        choices=["member", "user"]),
            state=dict(type="str", default="present",
                       choices=["present", "absent", "enabled", "disabled",
                                "unlocked", "undeleted", "renamed"]),

            # Add user specific parameters for simple use case
            **user_spec
        ),
        mutually_exclusive=[["name", "users"]],
        required_one_of=[["name", "users"]],
        supports_check_mode=True,
    )

    ansible_module._ansible_debug = True

    # Get parameters

    # general
    names = ansible_module.params_get("name")
    users = ansible_module.params_get("users")

    # present
    first = ansible_module.params_get("first")
    last = ansible_module.params_get("last")
    fullname = ansible_module.params_get("fullname")
    displayname = ansible_module.params_get("displayname")
    initials = ansible_module.params_get("initials")
    homedir = ansible_module.params_get("homedir")
    gecos = ansible_module.params_get("gecos")
    shell = ansible_module.params_get("shell")
    email = ansible_module.params_get("email")
    principal = ansible_module.params_get("principal")
    principalexpiration = ansible_module.params_get(
        "principalexpiration")
    if principalexpiration is not None:
        if principalexpiration[:-1] != "Z":
            principalexpiration = principalexpiration + "Z"
        principalexpiration = date_format(principalexpiration)
    passwordexpiration = ansible_module.params_get("passwordexpiration")
    if passwordexpiration is not None:
        if passwordexpiration[:-1] != "Z":
            passwordexpiration = passwordexpiration + "Z"
        passwordexpiration = date_format(passwordexpiration)
    password = ansible_module.params_get("password")
    random = ansible_module.params_get("random")
    uid = ansible_module.params_get("uid")
    gid = ansible_module.params_get("gid")
    street = ansible_module.params_get("street")
    city = ansible_module.params_get("city")
    userstate = ansible_module.params_get("userstate")
    postalcode = ansible_module.params_get("postalcode")
    phone = ansible_module.params_get("phone")
    mobile = ansible_module.params_get("mobile")
    pager = ansible_module.params_get("pager")
    fax = ansible_module.params_get("fax")
    orgunit = ansible_module.params_get("orgunit")
    title = ansible_module.params_get("title")
    manager = ansible_module.params_get("manager")
    carlicense = ansible_module.params_get("carlicense")
    sshpubkey = ansible_module.params_get("sshpubkey",
                                          allow_empty_list_item=True)
    userauthtype = ansible_module.params_get("userauthtype",
                                             allow_empty_list_item=True)
    userclass = ansible_module.params_get("userclass")
    radius = ansible_module.params_get("radius")
    radiususer = ansible_module.params_get("radiususer")
    departmentnumber = ansible_module.params_get("departmentnumber")
    employeenumber = ansible_module.params_get("employeenumber")
    employeetype = ansible_module.params_get("employeetype")
    preferredlanguage = ansible_module.params_get("preferredlanguage")
    smb_logon_script = ansible_module.params_get("smb_logon_script")
    smb_profile_path = ansible_module.params_get("smb_profile_path")
    smb_home_dir = ansible_module.params_get("smb_home_dir")
    smb_home_drive = ansible_module.params_get("smb_home_drive")
    idp = ansible_module.params_get("idp")
    idp_user_id = ansible_module.params_get("idp_user_id")
    certificate = ansible_module.params_get("certificate")
    certmapdata = ansible_module.params_get("certmapdata")
    noprivate = ansible_module.params_get("noprivate")
    nomembers = ansible_module.params_get("nomembers")
    # deleted
    preserve = ansible_module.params_get("preserve")
    # mod
    update_password = ansible_module.params_get("update_password")
    # rename
    rename = ansible_module.params_get("rename")
    # general
    action = ansible_module.params_get("action")
    state = ansible_module.params_get("state")

    # Check parameters

    if (names is None or len(names) < 1) and \
       (users is None or len(users) < 1):
        ansible_module.fail_json(msg="One of name and users is required")

    if state in ["present", "renamed"]:
        if names is not None and len(names) != 1:
            act = "renamed" if state == "renamed" else "added"
            ansible_module.fail_json(
                msg="Only one user can be %s at a time using name." % (act))

    # Use users if names is None
    if users is not None:
        names = users
    else:
        check_parameters(
            ansible_module, state, action,
            first, last, fullname, displayname, initials, homedir, gecos,
            shell, email,
            principal, principalexpiration, passwordexpiration, password,
            random,
            uid, gid, street, city, phone, mobile, pager, fax, orgunit, title,
            manager, carlicense, sshpubkey, userauthtype, userclass, radius,
            radiususer, departmentnumber, employeenumber, employeetype,
            preferredlanguage, certificate, certmapdata, noprivate, nomembers,
            preserve, update_password, smb_logon_script, smb_profile_path,
            smb_home_dir, smb_home_drive, idp, idp_user_id, rename,
        )
        certmapdata = convert_certmapdata(certmapdata)

    # Init

    changed = False
    exit_args = {}

    # Connect to IPA API
    with ansible_module.ipa_connect():

        # Check version specific settings

        server_realm = ansible_module.ipa_get_realm()

        # Check API specific parameters

        check_userauthtype(ansible_module, userauthtype)

        # Default email domain

        result = ansible_module.ipa_command_no_name("config_show", {})
        default_email_domain = result["result"]["ipadefaultemaildomain"][0]

        # Extend email addresses

        email = extend_emails(email, default_email_domain)

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
                # present
                first = user.get("first")
                last = user.get("last")
                fullname = user.get("fullname")
                displayname = user.get("displayname")
                initials = user.get("initials")
                homedir = user.get("homedir")
                gecos = user.get("gecos")
                shell = user.get("shell")
                email = user.get("email")
                principal = user.get("principal")
                principalexpiration = user.get("principalexpiration")
                if principalexpiration is not None:
                    if principalexpiration[:-1] != "Z":
                        principalexpiration = principalexpiration + "Z"
                    principalexpiration = date_format(principalexpiration)
                passwordexpiration = user.get("passwordexpiration")
                if passwordexpiration is not None:
                    if passwordexpiration[:-1] != "Z":
                        passwordexpiration = passwordexpiration + "Z"
                    passwordexpiration = date_format(passwordexpiration)
                password = user.get("password")
                random = user.get("random")
                uid = user.get("uid")
                gid = user.get("gid")
                street = user.get("street")
                city = user.get("city")
                userstate = user.get("userstate")
                postalcode = user.get("postalcode")
                phone = user.get("phone")
                mobile = user.get("mobile")
                pager = user.get("pager")
                fax = user.get("fax")
                orgunit = user.get("orgunit")
                title = user.get("title")
                manager = user.get("manager")
                carlicense = user.get("carlicense")
                sshpubkey = user.get("sshpubkey")
                userauthtype = user.get("userauthtype")
                userclass = user.get("userclass")
                radius = user.get("radius")
                radiususer = user.get("radiususer")
                departmentnumber = user.get("departmentnumber")
                employeenumber = user.get("employeenumber")
                employeetype = user.get("employeetype")
                preferredlanguage = user.get("preferredlanguage")
                smb_logon_script = user.get("smb_logon_script")
                smb_profile_path = user.get("smb_profile_path")
                smb_home_dir = user.get("smb_home_dir")
                smb_home_drive = user.get("smb_home_drive")
                idp = user.get("idp")
                idp_user_id = user.get("idp_user_id")
                rename = user.get("rename")
                certificate = user.get("certificate")
                certmapdata = user.get("certmapdata")
                noprivate = user.get("noprivate")
                nomembers = user.get("nomembers")

                check_parameters(
                    ansible_module, state, action,
                    first, last, fullname, displayname, initials, homedir,
                    gecos, shell, email, principal, principalexpiration,
                    passwordexpiration, password, random, uid, gid, street,
                    city, phone, mobile, pager, fax, orgunit, title, manager,
                    carlicense, sshpubkey, userauthtype, userclass, radius,
                    radiususer, departmentnumber, employeenumber,
                    employeetype, preferredlanguage, certificate,
                    certmapdata, noprivate, nomembers, preserve,
                    update_password, smb_logon_script, smb_profile_path,
                    smb_home_dir, smb_home_drive, idp, idp_user_id, rename,
                )
                certmapdata = convert_certmapdata(certmapdata)

                # Check API specific parameters

                check_userauthtype(ansible_module, userauthtype)

                # Extend email addresses

                email = extend_emails(email, default_email_domain)

            elif isinstance(user, (str, unicode)):
                name = user
            else:
                ansible_module.fail_json(msg="User '%s' is not valid" %
                                         repr(user))

            # Fix principals: add realm if missing
            # We need the connected API for the realm, therefore it can not
            # be part of check_parameters as this is used also before the
            # connection to the API has been established.
            if principal is not None:
                principal = [x if "@" in x else x + "@" + server_realm
                             for x in principal]

            # Check passwordexpiration availability.
            # We need the connected API for this test, therefore it can not
            # be part of check_parameters as this is used also before the
            # connection to the API has been established.
            if passwordexpiration is not None and \
               not ansible_module.ipa_command_param_exists(
                   "user_add", "krbpasswordexpiration"):
                ansible_module.fail_json(
                    msg="The use of passwordexpiration is not supported by "
                    "your IPA version")

            # Check certmapdata availability.
            # We need the connected API for this test, therefore it can not
            # be part of check_parameters as this is used also before the
            # connection to the API has been established.
            if certmapdata is not None and \
               not ansible_module.ipa_command_exists("user_add_certmapdata"):
                ansible_module.fail_json(
                    msg="The use of certmapdata is not supported by "
                    "your IPA version")

            # Check if SMB attributes are available
            if (
                any([
                    smb_logon_script, smb_profile_path, smb_home_dir,
                    smb_home_drive
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
                idp is not None
                or idp_user_id is not None
                or userauthtype == "idp"
            )
            has_idp_support = ansible_module.ipa_command_param_exists(
                "user_add", "ipaidpconfiglink"
            )
            if require_idp and not has_idp_support:
                ansible_module.fail_json(
                    msg="Your IPA version does not support External IdP.")

            # Make sure user exists
            res_find = find_user(ansible_module, name)

            # Create command
            if state == "present":
                # Generate args
                args = gen_args(
                    first, last, fullname, displayname, initials, homedir,
                    gecos,
                    shell, email, principalexpiration, passwordexpiration,
                    password, random, uid, gid, street, city, userstate,
                    postalcode, phone, mobile, pager, fax, orgunit, title,
                    carlicense, sshpubkey, userauthtype, userclass, radius,
                    radiususer, departmentnumber, employeenumber, employeetype,
                    preferredlanguage, smb_logon_script, smb_profile_path,
                    smb_home_dir, smb_home_drive, idp, idp_user_id, noprivate,
                    nomembers,
                )

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
                    # Handle members: principal, manager, certificate and
                    # certmapdata
                    if res_find is not None:
                        # Generate addition and removal lists
                        manager_add, manager_del = gen_add_del_lists(
                            manager, res_find.get("manager"))

                        principal_add, principal_del = gen_add_del_lists(
                            principal, res_find.get("krbprincipalname"))
                        # Principals are not returned as utf8 for IPA using
                        # python2 using user_find, therefore we need to
                        # convert the principals that we should remove.
                        principal_del = [to_text(x) for x in principal_del]

                        certificate_add, certificate_del = gen_add_del_lists(
                            certificate, res_find.get("usercertificate"))

                        certmapdata_add, certmapdata_del = gen_add_del_lists(
                            certmapdata, res_find.get("ipacertmapdata"))

                    else:
                        # Use given managers and principals
                        manager_add = manager or []
                        manager_del = []
                        principal_add = principal or []
                        principal_del = []
                        certificate_add = certificate or []
                        certificate_del = []
                        certmapdata_add = certmapdata or []
                        certmapdata_del = []

                    # Remove canonical principal from principal_del
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

                elif action == "member":
                    if res_find is None:
                        ansible_module.fail_json(
                            msg="No user '%s'" % name)

                    # Ensure managers are present
                    if manager is not None and len(manager) > 0:
                        commands.append([name, "user_add_manager",
                                         {
                                             "user": manager,
                                         }])

                    # Principals need to be added and removed one by one,
                    # because if entry already exists, the processing of
                    # the remaining enries is stopped. The same applies to
                    # the removal of non-existing entries.

                    # Ensure principals are present
                    if principal is not None and len(principal) > 0:
                        for _principal in principal:
                            commands.append([name, "user_add_principal",
                                             {
                                                 "krbprincipalname":
                                                 _principal,
                                             }])

                    # Certificates need to be added and removed one by one,
                    # because if entry already exists, the processing of
                    # the remaining enries is stopped. The same applies to
                    # the removal of non-existing entries.

                    # Ensure certificates are present
                    if certificate is not None and len(certificate) > 0:
                        for _certificate in certificate:
                            commands.append([name, "user_add_cert",
                                             {
                                                 "usercertificate":
                                                 _certificate,
                                             }])

                    # certmapdata need to be added and removed one by one,
                    # because issuer and subject can only be done one by
                    # one reliably (https://pagure.io/freeipa/issue/8097)

                    # Ensure certmapdata are present
                    if certmapdata is not None and len(certmapdata) > 0:
                        for _data in certmapdata:
                            commands.append([name, "user_add_certmapdata",
                                             gen_certmapdata_args(_data)])

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

                    # Ensure managers are absent
                    if manager is not None and len(manager) > 0:
                        commands.append([name, "user_remove_manager",
                                         {
                                             "user": manager,
                                         }])

                    # Principals need to be added and removed one by one,
                    # because if entry already exists, the processing of
                    # the remaining enries is stopped. The same applies to
                    # the removal of non-existing entries.

                    # Ensure principals are absent
                    if principal is not None and len(principal) > 0:
                        commands.append([name, "user_remove_principal",
                                         {
                                             "krbprincipalname": principal,
                                         }])

                    # Certificates need to be added and removed one by one,
                    # because if entry already exists, the processing of
                    # the remaining enries is stopped. The same applies to
                    # the removal of non-existing entries.

                    # Ensure certificates are absent
                    if certificate is not None and len(certificate) > 0:
                        for _certificate in certificate:
                            commands.append([name, "user_remove_cert",
                                             {
                                                 "usercertificate":
                                                 _certificate,
                                             }])

                    # certmapdata need to be added and removed one by one,
                    # because issuer and subject can only be done one by
                    # one reliably (https://pagure.io/freeipa/issue/8097)

                    # Ensure certmapdata are absent
                    if certmapdata is not None and len(certmapdata) > 0:
                        # Using issuer and subject can only be done one by
                        # one reliably (https://pagure.io/freeipa/issue/8097)
                        for _data in certmapdata:
                            commands.append([name, "user_remove_certmapdata",
                                             gen_certmapdata_args(_data)])
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

        del user_set

        # Execute commands

        changed = ansible_module.execute_ipa_commands(
            commands, result_handler, exception_handler,
            exit_args=exit_args, single_user=users is None)

    # Done
    ansible_module.exit_json(changed=changed, user=exit_args)


if __name__ == "__main__":
    main()

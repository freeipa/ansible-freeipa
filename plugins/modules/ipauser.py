# -*- coding: utf-8 -*-

# Authors:
#   Thomas Woerner <twoerner@redhat.com>
#
# Copyright (C) 2019 Red Hat
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
    required: false
  users:
    description: The list of user dicts (internally uid).
    options:
      name:
        description: The user (internally uid).
        required: true
      first:
        description: The first name. Required if user does not exist.
        required: false
        aliases: ["givenname"]
      last:
        description: The last name. Required if user doesnot exst.
        required: false
        aliases: ["sn"]
      fullname:
        description: The full name
        required: false
        aliases: ["cn"]
      displayname:
        description: The display name
        required: false
      initials:
        description: Initials
        required: false
      homedir:
        description: The home directory
        required: false
      shell:
        description: The login shell
        required: false
        aliases: ["loginshell"]
      email:
        description: List of email addresses
        required: false
      principal:
        description: The kerberos principal
        required: false
        aliases: ["principalname", "krbprincipalname"]
      principalexpiration:
        description: |
          The kerberos principal expiration date
          (possible formats: YYYYMMddHHmmssZ, YYYY-MM-ddTHH:mm:ssZ,
          YYYY-MM-ddTHH:mmZ, YYYY-MM-ddZ, YYYY-MM-dd HH:mm:ssZ,
          YYYY-MM-dd HH:mmZ) The trailing 'Z' can be skipped.
        required: false
        aliases: ["krbprincipalexpiration"]
      passwordexpiration:
        description: |
          The kerberos password expiration date (FreeIPA-4.7+)
          (possible formats: YYYYMMddHHmmssZ, YYYY-MM-ddTHH:mm:ssZ,
          YYYY-MM-ddTHH:mmZ, YYYY-MM-ddZ, YYYY-MM-dd HH:mm:ssZ,
          YYYY-MM-dd HH:mmZ) The trailing 'Z' can be skipped.
          Only usable with IPA versions 4.7 and up.
        required: false
        aliases: ["krbpasswordexpiration"]
      password:
        description: The user password
        required: false
      random:
        description: Generate a random user password
        required: false
        type: bool
      uid:
        description: The UID
        required: false
        aliases: ["uidnumber"]
      gid:
        description: The GID
        required: false
        aliases: ["gidnumber"]
      city:
        description: City
        required: false
      userstate:
        description: State/Province
        required: false
        aliases: ["st"]
      postalcode:
        description: Postalcode/ZIP
        required: false
        aliases: ["zip"]
      phone:
        description: List of telephone numbers
        required: false
        aliases: ["telephonenumber"]
      mobile:
        description: List of mobile telephone numbers
        required: false
      pager:
        description: List of pager numbers
        required: false
      fax:
        description: List of fax numbers
        required: false
        aliases: ["facsimiletelephonenumber"]
      orgunit:
        description: Org. Unit
        required: false
      title:
        description: The job title
        required: false
      manager:
        description: List of managers
        required: false
      carlicense:
        description: List of car licenses
        required: false
      sshpubkey:
        description: List of SSH public keys
        required: false
        aliases: ["ipasshpubkey"]
      userauthtype:
        description:
          List of supported user authentication types
          Use empty string to reset userauthtype to the initial value.
        choices: ['password', 'radius', 'otp', '']
        required: false
        aliases: ["ipauserauthtype"]
      userclass:
        description:
        - User category
        - (semantics placed on this attribute are for local interpretation)
        required: false
      radius:
        description: RADIUS proxy configuration
        required: false
      radiususer:
        description: RADIUS proxy username
        required: false
      departmentnumber:
        description: Department Number
        required: false
      employeenumber:
        description: Employee Number
        required: false
      employeetype:
        description: Employee Type
        required: false
      preferredlanguage:
        description: Preferred Language
        required: false
      certificate:
        description: List of base-64 encoded user certificates
        required: false
      certmapdata:
        description:
        - List of certificate mappings
        - Only usable with IPA versions 4.5 and up.
        options:
          certificate:
            description: Base-64 encoded user certificate
            required: false
          issuer:
            description: Issuer of the certificate
            required: false
          subject:
            description: Subject of the certificate
            required: false
          data:
            description: Certmap data
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
    required: false
  first:
    description: The first name. Required if user does not exist.
    required: false
    aliases: ["givenname"]
  last:
    description: The last name. Required if user does not exist.
    required: false
    aliases: ["sn"]
  fullname:
    description: The full name
    required: false
    aliases: ["cn"]
  displayname:
    description: The display name
    required: false
  initials:
    description: Initials
    required: false
  homedir:
    description: The home directory
    required: false
  shell:
    description: The login shell
    required: false
    aliases: ["loginshell"]
  email:
    description: List of email addresses
    required: false
  principal:
    description: The kerberos principal
    required: false
    aliases: ["principalname", "krbprincipalname"]
  principalexpiration:
    description: |
      The kerberos principal expiration date
      (possible formats: YYYYMMddHHmmssZ, YYYY-MM-ddTHH:mm:ssZ,
      YYYY-MM-ddTHH:mmZ, YYYY-MM-ddZ, YYYY-MM-dd HH:mm:ssZ,
      YYYY-MM-dd HH:mmZ) The trailing 'Z' can be skipped.
    required: false
    aliases: ["krbprincipalexpiration"]
  passwordexpiration:
    description: |
      The kerberos password expiration date (FreeIPA-4.7+)
      (possible formats: YYYYMMddHHmmssZ, YYYY-MM-ddTHH:mm:ssZ,
      YYYY-MM-ddTHH:mmZ, YYYY-MM-ddZ, YYYY-MM-dd HH:mm:ssZ,
      YYYY-MM-dd HH:mmZ) The trailing 'Z' can be skipped.
      Only usable with IPA versions 4.7 and up.
    required: false
    aliases: ["krbpasswordexpiration"]
  password:
    description: The user password
    required: false
  random:
    description: Generate a random user password
    required: false
    type: bool
  uid:
    description: The UID
    required: false
    aliases: ["uidnumber"]
  gid:
    description: The GID
    required: false
    aliases: ["gidnumber"]
  city:
    description: City
    required: false
  userstate:
    description: State/Province
    required: false
    aliases: ["st"]
  postalcode:
    description: ZIP
    required: false
    aliases: ["zip"]
  phone:
    description: List of telephone numbers
    required: false
    aliases: ["telephonenumber"]
  mobile:
    description: List of mobile telephone numbers
    required: false
  pager:
    description: List of pager numbers
    required: false
  fax:
    description: List of fax numbers
    required: false
    aliases: ["facsimiletelephonenumber"]
  orgunit:
    description: Org. Unit
    required: false
  title:
    description: The job title
    required: false
  manager:
    description: List of managers
    required: false
  carlicense:
    description: List of car licenses
    required: false
  sshpubkey:
    description: List of SSH public keys
    required: false
    aliases: ["ipasshpubkey"]
  userauthtype:
    description:
      List of supported user authentication types
      Use empty string to reset userauthtype to the initial value.
    choices: ['password', 'radius', 'otp', '']
    required: false
    aliases: ["ipauserauthtype"]
  userclass:
    description:
    - User category
    - (semantics placed on this attribute are for local interpretation)
    required: false
  radius:
    description: RADIUS proxy configuration
    required: false
  radiususer:
    description: RADIUS proxy username
    required: false
  departmentnumber:
    description: Department Number
    required: false
  employeenumber:
    description: Employee Number
    required: false
  employeetype:
    description: Employee Type
    required: false
  preferredlanguage:
    description: Preferred Language
    required: false
  certificate:
    description: List of base-64 encoded user certificates
    required: false
  certmapdata:
    description:
    - List of certificate mappings
    - Only usable with IPA versions 4.5 and up.
    options:
      certificate:
        description: Base-64 encoded user certificate
        required: false
      issuer:
        description: Issuer of the certificate
        required: false
      subject:
        description: Subject of the certificate
        required: false
      data:
        description: Certmap data
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
  preserve:
    description: Delete a user, keeping the entry available for future use
    required: false
  update_password:
    description:
      Set password for a user in present state only on creation or always
    default: "always"
    choices: ["always", "on_create"]
    required: false
  action:
    description: Work on user or member level
    default: "user"
    choices: ["member", "user"]
  state:
    description: State to ensure
    default: present
    choices: ["present", "absent",
              "enabled", "disabled",
              "unlocked", "undeleted"]
author:
    - Thomas Woerner
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

# Remove user pinky and brain
- ipauser:
    ipaadmin_password: SomeADMINpassword
    name: pinky,brain
    state: disabled
"""

RETURN = """
user:
  description: User dict with random password
  returned: If random is yes and user did not exist or update_password is yes
  type: dict
  options:
    randompassword:
      description: The generated random password
      returned: If only one user is handled by the module
    name:
      description: The user name of the user that got a new random password
      returned: If several users are handled by the module
      type: dict
      options:
        randompassword:
          description: The generated random password
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


def gen_args(first, last, fullname, displayname, initials, homedir, shell,
             email, principalexpiration, passwordexpiration, password,
             random, uid, gid, city, userstate, postalcode, phone, mobile,
             pager, fax, orgunit, title, carlicense, sshpubkey, userauthtype,
             userclass, radius, radiususer, departmentnumber, employeenumber,
             employeetype, preferredlanguage, noprivate, nomembers):
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
    if noprivate is not None:
        _args["noprivate"] = noprivate
    if nomembers is not None:
        _args["no_members"] = nomembers
    return _args


def check_parameters(  # pylint: disable=unused-argument
        module, state, action, first, last, fullname, displayname, initials,
        homedir, shell, email, principal, principalexpiration,
        passwordexpiration, password, random, uid, gid, city, phone, mobile,
        pager, fax, orgunit, title, manager, carlicense, sshpubkey,
        userauthtype, userclass, radius, radiususer, departmentnumber,
        employeenumber, employeetype, preferredlanguage, certificate,
        certmapdata, noprivate, nomembers, preserve, update_password):
    invalid = []
    if state == "present":
        if action == "member":
            invalid = ["first", "last", "fullname", "displayname", "initials",
                       "homedir", "shell", "email", "principalexpiration",
                       "passwordexpiration", "password", "random", "uid",
                       "gid", "city", "phone", "mobile", "pager", "fax",
                       "orgunit", "title", "carlicense", "sshpubkey",
                       "userauthtype", "userclass", "radius", "radiususer",
                       "departmentnumber", "employeenumber", "employeetype",
                       "preferredlanguage", "noprivate", "nomembers",
                       "preserve", "update_password"]

    else:
        invalid = ["first", "last", "fullname", "displayname", "initials",
                   "homedir", "shell", "email", "principalexpiration",
                   "passwordexpiration", "password", "random", "uid",
                   "gid", "city", "phone", "mobile", "pager", "fax",
                   "orgunit", "title", "carlicense", "sshpubkey",
                   "userauthtype", "userclass", "radius", "radiususer",
                   "departmentnumber", "employeenumber", "employeetype",
                   "preferredlanguage", "noprivate", "nomembers",
                   "update_password"]
        if action == "user":
            invalid.extend(["principal", "manager",
                            "certificate", "certmapdata",
                            ])

        if state != "absent" and preserve is not None:
            module.fail_json(
                msg="Preserve is only possible for state=absent")

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
                   one_name):

    if "random" in args and command in ["user_add", "user_mod"] \
       and "randompassword" in result["result"]:
        if one_name:
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
def exception_handler(module, ex, errors, exit_args, one_name):
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
        shell=dict(type="str", aliases=["loginshell"], default=None),
        email=dict(type="list", default=None),
        principal=dict(type="list", aliases=["principalname",
                                             "krbprincipalname"],
                       default=None),
        principalexpiration=dict(type="str",
                                 aliases=["krbprincipalexpiration"],
                                 default=None),
        passwordexpiration=dict(type="str",
                                aliases=["krbpasswordexpiration"],
                                default=None),
        password=dict(type="str", default=None, no_log=True),
        random=dict(type='bool', default=None),
        uid=dict(type="int", aliases=["uidnumber"], default=None),
        gid=dict(type="int", aliases=["gidnumber"], default=None),
        city=dict(type="str", default=None),
        userstate=dict(type="str", aliases=["st"], default=None),
        postalcode=dict(type="str", aliases=["zip"], default=None),
        phone=dict(type="list", aliases=["telephonenumber"], default=None),
        mobile=dict(type="list", default=None),
        pager=dict(type="list", default=None),
        fax=dict(type="list", aliases=["facsimiletelephonenumber"],
                 default=None),
        orgunit=dict(type="str", aliases=["ou"], default=None),
        title=dict(type="str", default=None),
        manager=dict(type="list", default=None),
        carlicense=dict(type="list", default=None),
        sshpubkey=dict(type="list", aliases=["ipasshpubkey"],
                       default=None),
        userauthtype=dict(type='list', aliases=["ipauserauthtype"],
                          default=None,
                          choices=['password', 'radius', 'otp', '']),
        userclass=dict(type="list", aliases=["class"],
                       default=None),
        radius=dict(type="str", aliases=["ipatokenradiusconfiglink"],
                    default=None),
        radiususer=dict(type="str", aliases=["radiususername",
                                             "ipatokenradiususername"],
                        default=None),
        departmentnumber=dict(type="list", default=None),
        employeenumber=dict(type="str", default=None),
        employeetype=dict(type="str", default=None),
        preferredlanguage=dict(type="str", default=None),
        certificate=dict(type="list", aliases=["usercertificate"],
                         default=None),
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
    )

    ansible_module = IPAAnsibleModule(
        argument_spec=dict(
            # general
            name=dict(type="list", aliases=["login"], default=None,
                      required=False),
            users=dict(type="list",
                       aliases=["login"],
                       default=None,
                       options=dict(
                           # Here name is a simple string
                           name=dict(type="str", required=True),
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
                                "unlocked", "undeleted"]),

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
                                          allow_empty_string=True)
    userauthtype = ansible_module.params_get("userauthtype",
                                             allow_empty_string=True)
    userclass = ansible_module.params_get("userclass")
    radius = ansible_module.params_get("radius")
    radiususer = ansible_module.params_get("radiususer")
    departmentnumber = ansible_module.params_get("departmentnumber")
    employeenumber = ansible_module.params_get("employeenumber")
    employeetype = ansible_module.params_get("employeetype")
    preferredlanguage = ansible_module.params_get("preferredlanguage")
    certificate = ansible_module.params_get("certificate")
    certmapdata = ansible_module.params_get("certmapdata")
    noprivate = ansible_module.params_get("noprivate")
    nomembers = ansible_module.params_get("nomembers")
    # deleted
    preserve = ansible_module.params_get("preserve")
    # mod
    update_password = ansible_module.params_get("update_password")
    # general
    action = ansible_module.params_get("action")
    state = ansible_module.params_get("state")

    # Check parameters

    if (names is None or len(names) < 1) and \
       (users is None or len(users) < 1):
        ansible_module.fail_json(msg="One of name and users is required")

    if state == "present":
        if names is not None and len(names) != 1:
            ansible_module.fail_json(
                msg="Only one user can be added at a time using name.")

    check_parameters(
        ansible_module, state, action,
        first, last, fullname, displayname, initials, homedir, shell, email,
        principal, principalexpiration, passwordexpiration, password, random,
        uid, gid, city, phone, mobile, pager, fax, orgunit, title, manager,
        carlicense, sshpubkey, userauthtype, userclass, radius, radiususer,
        departmentnumber, employeenumber, employeetype, preferredlanguage,
        certificate, certmapdata, noprivate, nomembers, preserve,
        update_password)
    certmapdata = convert_certmapdata(certmapdata)

    # Use users if names is None
    if users is not None:
        names = users

    # Init

    changed = False
    exit_args = {}

    # Connect to IPA API
    with ansible_module.ipa_connect():

        # Check version specific settings

        server_realm = ansible_module.ipa_get_realm()

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
                certificate = user.get("certificate")
                certmapdata = user.get("certmapdata")
                noprivate = user.get("noprivate")
                nomembers = user.get("nomembers")

                check_parameters(
                    ansible_module, state, action,
                    first, last, fullname, displayname, initials, homedir,
                    shell, email, principal, principalexpiration,
                    passwordexpiration, password, random, uid, gid, city,
                    phone, mobile, pager, fax, orgunit, title, manager,
                    carlicense, sshpubkey, userauthtype, userclass, radius,
                    radiususer, departmentnumber, employeenumber,
                    employeetype, preferredlanguage, certificate,
                    certmapdata, noprivate, nomembers, preserve,
                    update_password)
                certmapdata = convert_certmapdata(certmapdata)

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

            # Make sure user exists
            res_find = find_user(ansible_module, name)

            # Create command
            if state == "present":
                # Generate args
                args = gen_args(
                    first, last, fullname, displayname, initials, homedir,
                    shell, email, principalexpiration, passwordexpiration,
                    password, random, uid, gid, city, userstate, postalcode,
                    phone, mobile, pager, fax, orgunit, title, carlicense,
                    sshpubkey, userauthtype, userclass, radius, radiususer,
                    departmentnumber, employeenumber, employeetype,
                    preferredlanguage, noprivate, nomembers)

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

                        commands.append([name, "user_add", args])

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

            else:
                ansible_module.fail_json(msg="Unkown state '%s'" % state)

        del user_set

        # Execute commands

        changed = ansible_module.execute_ipa_commands(
            commands, result_handler, exception_handler,
            exit_args=exit_args, one_name=len(names) == 1)

    # Done
    ansible_module.exit_json(changed=changed, user=exit_args)


if __name__ == "__main__":
    main()

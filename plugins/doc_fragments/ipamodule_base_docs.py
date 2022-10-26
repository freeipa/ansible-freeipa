# -*- coding: utf-8 -*-

# Authors:
#   Thomas Woerner <twoerner@redhat.com>
#
# Copyright (C) 2021  Red Hat
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


class ModuleDocFragment(object):  # pylint: disable=R0205,R0903
    DOCUMENTATION = r"""
options:
  ipaadmin_principal:
    description: The admin principal.
    default: admin
    type: str
  ipaadmin_password:
    description: The admin password.
    required: false
    type: str
  ipaapi_context:
    description: |
      The context in which the module will execute. Executing in a
      server context is preferred. If not provided context will be
      determined by the execution environment.
    choices: ["server", "client"]
    type: str
    required: false
  ipaapi_ldap_cache:
    description: Use LDAP cache for IPA connection.
    type: bool
    default: true
"""

    DELETE_CONTINUE = r"""
options:
  delete_continue:
    description: |
      Continuous mode. Don't stop on errors. Valid only if `state` is `absent`.
    aliases: ["continue"]
    type: bool
    default: True
"""

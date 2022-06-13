#!/bin/bash -eu

# Authors:
#   Thomas Woerner <twoerner@redhat.com>
#
# Copyright (C) 2022  Red Hat
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

nssdb=$1
module_name="OpenSC"
pkcs11_shared_lib="/usr/lib64/opensc-pkcs11.so"

if [ -z "${nssdb}" ]; then
    echo "Usage: $0 <nssdb>"
    exit 1
fi

if modutil -dbdir "${nssdb}" -list | grep -q "${module_name}" || p11-kit list-modules | grep -i "${module_name}" -q
then
    echo "${module_name} PKCS#11 module already configured"
else
    echo "" | modutil -dbdir "${nssdb}" -add "${module_name}" -libfile "${pkcs11_shared_lib}"
fi

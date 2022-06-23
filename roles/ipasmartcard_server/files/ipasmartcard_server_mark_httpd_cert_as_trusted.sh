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

directive=$1
nss_conf=$2
nickname=$3
alias_dir=$4

if [ -z "${directive}" ] || [ -z "${nss_conf}" ] || [ -z "${nickname}" ] || 
   [ -z "${alias_dir}" ]
then
    echo "Usage: $0 <directive> <nss conf> <nickname directive> <alias directory>"
    exit 1
fi

http_cert_nick=$(grep "${nickname}" "${nss_conf}" | cut -f 2 -d ' ')
certutil -M -n "$http_cert_nick" -d "${alias_dir}" -f "${alias_dir}/pwdfile.txt" -t "Pu,u,u"

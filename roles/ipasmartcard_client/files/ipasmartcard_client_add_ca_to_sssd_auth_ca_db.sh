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

cert_file=$1
db=$2

if [ -z "${cert_file}" ] || [ -z "${db}" ]; then
    echo "Usage: $0 <ca cert> <db file>"
    exit 1
fi

cat "${cert_file}" >> "${db}"

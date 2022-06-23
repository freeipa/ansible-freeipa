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
conf_file=$2

if [ -z "${directive}" ] || [ -z "${conf_file}" ]; then
    echo "Usage: $0 <directive> <config file>"
    exit 1
fi

if grep -q "${directive} " "${conf_file}"
then
    sed -i.ipabkp -r "s/^#*[[:space:]]*${directive}[[:space:]]+(on|off)$/${directive} on/" "${conf_file}"
else
    sed -i.ipabkp "/<\/VirtualHost>/i ${directive} on" "${conf_file}"
fi

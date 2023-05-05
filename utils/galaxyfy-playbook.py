#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Authors:
#   Thomas Woerner <twoerner@redhat.com>
#
# Copyright (C) 2019,2020 Red Hat
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

import sys
from galaxyfy import galaxyfy_playbook


def playbook(playbook_in, project_prefix, collection_prefix):
    changed = False
    with open(playbook_in) as in_f:
        lines = in_f.readlines()
        out_lines, changed = \
            galaxyfy_playbook(project_prefix, collection_prefix, lines)

    if changed:
        with open(playbook_in, "w") as out_f:
            for line in out_lines:
                out_f.write(line)


playbook(sys.argv[1], sys.argv[2], sys.argv[3])

#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Authors:
#   Thomas Woerner <twoerner@redhat.com>
#
# Copyright (C) 2020 Red Hat
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


def readme(readme_in, project_prefix, collection_prefix):
    out_lines = []

    with open(readme_in) as in_f:
        changed = False
        code = False
        code_lines = []
        for line in in_f:
            stripped = line.strip()
            if stripped.startswith("```"):
                if code:
                    _out_lines, _changed = \
                        galaxyfy_playbook(project_prefix, collection_prefix,
                                          code_lines)
                    out_lines.extend(_out_lines)
                    code_lines = []
                    if _changed:
                        changed = True
                    code = False
                else:
                    code = True
                    out_lines.append(line)
                    continue
            if code:
                code_lines.append(line)
            else:
                out_lines.append(line)

    if changed:
        with open(readme_in, "w") as out_f:
            for line in out_lines:
                out_f.write(line)


readme(sys.argv[1], sys.argv[2], sys.argv[3])

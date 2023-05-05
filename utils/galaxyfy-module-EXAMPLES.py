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


def module_EXAMPLES(module_in, project_prefix, collection_prefix):
    out_lines = []

    with open(module_in) as in_f:
        changed = False
        example = False
        example_lines = []
        for line in in_f:
            stripped = line.strip()
            if stripped in ['EXAMPLES = """', "EXAMPLES = '''"]:
                example = True
                out_lines.append(line)
                continue
            if example and stripped in ["'''", '"""']:
                _out_lines, _changed = \
                    galaxyfy_playbook(project_prefix, collection_prefix,
                                      example_lines)
                for _line in _out_lines:
                    out_lines.append(_line)
                example_lines = []
                if _changed:
                    changed = True
                example = False
                out_lines.append(line)
                continue
            if example:
                example_lines.append(line)
            else:
                out_lines.append(line)

    if changed:
        with open(module_in, "w") as out_f:
            for line in out_lines:
                out_f.write(line)


module_EXAMPLES(sys.argv[1], sys.argv[2], sys.argv[3])

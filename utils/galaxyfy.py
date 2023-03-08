#!/usr/bin/python
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

import re


def galaxyfy_playbook(project_prefix, collection_prefix, lines):
    po1 = re.compile('(%s.*:)$' % project_prefix)
    po2 = re.compile('(.*:) (%s.*)$' % project_prefix)
    out_lines = []

    pattern1 = r'%s.\1' % collection_prefix
    pattern2 = r'\1 %s.\2' % collection_prefix

    changed = False
    changeable = False
    include_role = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("- name:") or \
           stripped.startswith("- block:"):
            changeable = True
        elif stripped in ["set_fact:", "ansible.builtin.set_fact:", "vars:"]:
            changeable = False
            include_role = False
        elif stripped == "roles:":
            changeable = True
            include_role = False
        elif (stripped.startswith("include_role:") or
              stripped.startswith("ansible.builtin.include_role:")):
            include_role = True
        elif include_role and stripped.startswith("name:"):
            line = po2.sub(pattern2, line)
            changed = True
        elif changeable and stripped.startswith("- role:"):
            line = po2.sub(pattern2, line)
            changed = True
        elif (changeable and stripped.startswith(project_prefix)
              and not stripped.startswith(collection_prefix)  # noqa
              and stripped.endswith(":")):  # noqa
            line = po1.sub(pattern1, line)
            changed = True
            changeable = False  # Only change first line in task
        elif (stripped.startswith("- %s" % project_prefix)
              and stripped.endswith(":")):  # noqa
            line = po1.sub(pattern1, line)
            changed = True

        out_lines.append(line)

    return (out_lines, changed)

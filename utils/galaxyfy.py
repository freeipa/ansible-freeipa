#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Authors:
#   Thomas Woerner <twoerner@redhat.com>
#
# Copyright (C) 2019-2023 Red Hat
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
from facts import ROLES, ALL_MODULES


def get_indent(txt):
    return len(txt) - len(txt.lstrip())


def galaxyfy_playbook(project_prefix, collection_prefix, lines):
    po_module = re.compile('(%s.*):$' % project_prefix)
    po_module_arg = re.compile('(%s.*): (.*)$' % project_prefix)
    po_module_unnamed = re.compile('- (%s.*):$' % project_prefix)
    po_role = re.compile('(.*:) (%s.*)$' % project_prefix)

    pattern_module = r'%s.\1:' % collection_prefix
    pattern_module_arg = r'%s.\1: \2' % collection_prefix
    pattern_module_unnamed = r'- %s.\1:' % collection_prefix
    pattern_role = r'\1 %s.\2' % collection_prefix

    out_lines = []
    changed = False
    changeable = False
    include_role = False
    module_defaults = False
    module_defaults_indent = -1
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("- name:") or \
           stripped.startswith("- block:"):
            changeable = True
            module_defaults = False
            module_defaults_indent = -1
        elif stripped in ["set_fact:", "ansible.builtin.set_fact:", "vars:"]:
            changeable = False
            include_role = False
            module_defaults = False
            module_defaults_indent = -1
        elif stripped == "roles:":
            changeable = True
            include_role = False
            module_defaults = False
            module_defaults_indent = -1
        elif (stripped.startswith("include_role:") or
              stripped.startswith("ansible.builtin.include_role:")):
            include_role = True
            module_defaults = False
            module_defaults_indent = -1
        elif include_role and stripped.startswith("name:"):
            match = po_role.search(line)
            if match and match.group(2) in ROLES:
                line = po_role.sub(pattern_role, line)
                changed = True
        elif stripped == "module_defaults:":
            changeable = True
            include_role = False
            module_defaults = True
            module_defaults_indent = -1
        elif module_defaults:
            _indent = get_indent(line)
            if module_defaults_indent == -1:
                module_defaults_indent = _indent
            if _indent == module_defaults_indent:
                # only module, no YAML anchor or alias
                match = po_module.search(line)
                if match and match.group(1) in ALL_MODULES:
                    line = po_module.sub(pattern_module, line)
                    changed = True
                # module with YAML anchor or alias
                match = po_module_arg.search(line)
                if match and match.group(1) in ALL_MODULES:
                    line = po_module_arg.sub(pattern_module_arg, line)
                    changed = True
        elif changeable and stripped.startswith("- role:"):
            match = po_role.search(line)
            if match and match.group(2) in ROLES:
                line = po_role.sub(pattern_role, line)
                changed = True
        elif (changeable and stripped.startswith(project_prefix)
              and stripped.endswith(":")):  # noqa
            match = po_module.search(line)
            if match and match.group(1) in ALL_MODULES:
                line = po_module.sub(pattern_module, line)
                changed = True
                changeable = False  # Only change first line in task
        elif (stripped.startswith("- %s" % project_prefix)
              and stripped.endswith(":")):  # noqa
            match = po_module_unnamed.search(line)
            if match and match.group(1) in ALL_MODULES:
                line = po_module_unnamed.sub(pattern_module_unnamed, line)
                changed = True

        out_lines.append(line)

    return (out_lines, changed)

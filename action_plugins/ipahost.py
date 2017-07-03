# Authors:
#   Florence Blanc-Renaud <frenaud@redhat.com>
#
# Copyright (C) 2017  Red Hat
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

import os

from ansible.errors import AnsibleError
from ansible.module_utils._text import to_native
from ansible.plugins.action import ActionBase

class ActionModule(ActionBase):
    def run(self, tmp=None, task_vars=None):
        """
        handler for file transfer operations

        ipa* commands can either provide a password or a keytab file
        in order to authenticate on the managed node with Kerberos.
        When a keytab is provided, it needs to be copied from the control
        node to the managed node.
        This Action Module performs the copy when needed.
        """

        if task_vars is None:
            task_vars = dict()

        result = super(ActionModule, self).run(tmp, task_vars)
        keytab = self._task.args.get('keytab', None)
        password = self._task.args.get('password', None)

        if (keytab is None and password is None):
            result['failed'] = True
            result['msg'] = "keytab or password is required"
            return result

        # If password is supplied, just need to execute the module
        if password:
            result.update(self._execute_module(task_vars=task_vars))
            return result

        # Password not supplied, need to transfer the keytab file
        # Check if the source keytab exists
        try:
            keytab = self._find_needle('files', keytab)
        except AnsibleError as e:
            result['failed'] = True
            result['msg'] = to_native(e)
            return result

        # Create the remote tmp dir
        tmp = self._make_tmp_path()
        tmp_keytab = self._connection._shell.join_path(
            tmp, os.path.basename(keytab))
        self._transfer_file(keytab, tmp_keytab)
        self._fixup_perms2((tmp, tmp_keytab))

        new_module_args = self._task.args.copy()
        new_module_args.update(dict(keytab=tmp_keytab))

        # Execute module
        result.update(self._execute_module(module_args=new_module_args, task_vars=task_vars))
        self._remove_tmp_path(tmp)
        return result

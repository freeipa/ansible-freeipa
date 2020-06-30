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

try:
    import gssapi
except ImportError:
    gssapi = None
import os
import shutil
import subprocess
import tempfile
from jinja2 import Template

from ansible.errors import AnsibleError
from ansible.module_utils._text import to_native
from ansible.plugins.action import ActionBase


def run_cmd(args, stdin=None):
    """Execute an external command."""
    p_in = None
    p_out = subprocess.PIPE
    p_err = subprocess.PIPE

    if stdin:
        p_in = subprocess.PIPE

    p = subprocess.Popen(args, stdin=p_in, stdout=p_out, stderr=p_err,
                         close_fds=True)
    __temp, stderr = p.communicate(stdin)

    if p.returncode != 0:
        raise RuntimeError(stderr)


def kinit_password(principal, password, ccache_name, config):
    """
    Perform kinit using principal/password.

    It uses the specified config file to kinit and stores the TGT
    in ccache_name.
    """
    args = ["/usr/bin/kinit", principal, '-c', ccache_name]
    old_config = os.environ.get('KRB5_CONFIG')
    os.environ['KRB5_CONFIG'] = config

    try:
        return run_cmd(args, stdin=password.encode())
    finally:
        if old_config is not None:
            os.environ['KRB5_CONFIG'] = old_config
        else:
            os.environ.pop('KRB5_CONFIG', None)


def kinit_keytab(principal, keytab, ccache_name, config):
    """
    Perform kinit using principal/keytab.

    It uses the specified config file to kinit and stores the TGT
    in ccache_name.
    """
    if gssapi is None:
        raise ImportError("gssapi is not available")

    old_config = os.environ.get('KRB5_CONFIG')
    os.environ['KRB5_CONFIG'] = config
    try:
        name = gssapi.Name(principal, gssapi.NameType.kerberos_principal)
        store = {'ccache': ccache_name,
                 'client_keytab': keytab}
        cred = gssapi.Credentials(name=name, store=store, usage='initiate')
        return cred
    finally:
        if old_config is not None:
            os.environ['KRB5_CONFIG'] = old_config
        else:
            os.environ.pop('KRB5_CONFIG', None)


KRB5CONF_TEMPLATE = """
[logging]
 default = FILE:/var/log/krb5libs.log
 kdc = FILE:/var/log/krb5kdc.log
 admin_server = FILE:/var/log/kadmind.log

[libdefaults]
 default_realm = {{ ipa_realm }}
 dns_lookup_realm = false
 dns_lookup_kdc = true
 rdns = false
 ticket_lifetime = {{ ipa_lifetime }}
 forwardable = true
 udp_preference_limit = 0
 default_ccache_name = KEYRING:persistent:%{uid}

[realms]
 {{ ipa_realm }} = {
  kdc = {{ ipa_server }}:88
  master_kdc = {{ ipa_server }}:88
  admin_server = {{ ipa_server }}:749
  default_domain = {{ ipa_domain }}
}

[domain_realm]
 .{{ ipa_domain }} = {{ ipa_realm }}
 {{ ipa_domain }} = {{ ipa_realm }}
"""


class ActionModule(ActionBase):

    def run(self, tmp=None, task_vars=None):
        """
        Handle credential cache transfer.

        ipa* commands can either provide a password or a keytab file
        in order to authenticate on the managed node with Kerberos.
        The module is using these credentials to obtain a TGT locally on the
        control node:
        - need to create a krb5.conf Kerberos client configuration that is
        using IPA server
        - set the environment variable KRB5_CONFIG to point to this conf file
        - set the environment variable KRB5CCNAME to use a specific cache
        - perform kinit on the control node
        This command creates the credential cache file
        - copy the credential cache file on the managed node

        Then the IPA commands can use this credential cache file.
        """
        if task_vars is None:
            task_vars = dict()

        result = super(ActionModule, self).run(tmp, task_vars)
        principal = self._task.args.get('principal', None)
        keytab = self._task.args.get('keytab', None)
        password = self._task.args.get('password', None)
        lifetime = self._task.args.get('lifetime', '1h')

        if (not keytab and not password):
            result['failed'] = True
            result['msg'] = "keytab or password is required"
            return result

        if not principal:
            result['failed'] = True
            result['msg'] = "principal is required"
            return result

        data = self._execute_module(module_name='ipaclient_get_facts',
                                    module_args=dict(), task_vars=task_vars)

        try:
            domain = data['ansible_facts']['ipa']['domain']
            realm = data['ansible_facts']['ipa']['realm']
        except KeyError:
            result['failed'] = True
            result['msg'] = "The host is not an IPA server"
            return result

        items = principal.split('@')
        if len(items) < 2:
            principal = str('%s@%s' % (principal, realm))

        # Locally create a temp directory to store krb5.conf and ccache
        local_temp_dir = tempfile.mkdtemp()
        krb5conf_name = os.path.join(local_temp_dir, 'krb5.conf')
        ccache_name = os.path.join(local_temp_dir, 'ccache')

        # Create the krb5.conf from the template
        template = Template(KRB5CONF_TEMPLATE)
        content = template.render(dict(
            ipa_server=task_vars['ansible_host'],
            ipa_domain=domain,
            ipa_realm=realm,
            ipa_lifetime=lifetime))

        with open(krb5conf_name, 'w') as f:
            f.write(content)

        if password:
            try:
                # perform kinit -c ccache_name -l 1h principal
                kinit_password(principal, password, ccache_name,
                               krb5conf_name)
            except Exception as e:
                result['failed'] = True
                result['msg'] = 'kinit %s with password failed: %s' % \
                    (principal, to_native(e))
                return result

        else:
            # Password not supplied, need to use the keytab file
            # Check if the source keytab exists
            try:
                keytab = self._find_needle('files', keytab)
            except AnsibleError as e:
                result['failed'] = True
                result['msg'] = to_native(e)
                return result
            # perform kinit -kt keytab
            try:
                kinit_keytab(principal, keytab, ccache_name, krb5conf_name)
            except Exception as e:
                result['failed'] = True
                result['msg'] = 'kinit %s with keytab %s failed: %s' % \
                    (principal, keytab, str(e))
                return result

        try:
            # Create the remote tmp dir
            tmp = self._make_tmp_path()
            tmp_ccache = self._connection._shell.join_path(
                tmp, os.path.basename(ccache_name))

            # Copy the ccache to the remote tmp dir
            self._transfer_file(ccache_name, tmp_ccache)
            self._fixup_perms2((tmp, tmp_ccache))

            new_module_args = self._task.args.copy()
            new_module_args.pop('password', None)
            new_module_args.pop('keytab', None)
            new_module_args.pop('lifetime', None)
            new_module_args.update(ccache=tmp_ccache)

            # Execute module
            result.update(self._execute_module(module_args=new_module_args,
                                               task_vars=task_vars))
            return result
        finally:
            # delete the local temp directory
            shutil.rmtree(local_temp_dir, ignore_errors=True)

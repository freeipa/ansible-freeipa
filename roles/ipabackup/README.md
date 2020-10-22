ipabackup role
==============

Description
-----------

This role allows to backup an IPA server, to copy a backup from the server to the controller, to copy all backups from the server to the controller, to remove a backup from the server and to remove all backups form the server.


**Note**: The ansible playbooks and role require a configured ansible environment where the ansible nodes are reachable and are properly set up to have an IP address and a working package manager.


Features
--------
* Server backup
* Server backup to controller
* Copy backup from server to controller
* Copy all backups from server to controller
* Remove backup from the server
* Remove all backups from the server


Supported FreeIPA Versions
--------------------------

FreeIPA versions 4.5 and up are supported by the backup role.


Supported Distributions
-----------------------

* RHEL/CentOS 7.6+
* Fedora 26+
* Ubuntu


Requirements
------------

**Controller**
* Ansible version: 2.8+

**Node**
* Supported FreeIPA version (see above)
* Supported distribution (needed for package installation only, see above)


Usage
=====

Example inventory file with fixed domain and realm, setting up of the DNS server and using forwarders from /etc/resolv.conf:

```ini
[ipaserver]
ipaserver.example.com
```

Example playbook to create a backup on the IPA server locally:

```yaml
---
- name: Playbook to backup IPA server
  hosts: ipaserver
  become: true

  roles:
  - role: ipabackup
    state: present
```


Example playbook to create a backup of the IPA server that is transferred to the controller using the server name as prefix for the backup and removed on the server:

```yaml
---
- name: Playbook to backup IPA server to controller
  hosts: ipaserver
  become: true

  vars:
    ipabackup_to_controller: yes
    # ipabackup_keep_on_server: yes

  roles:
  - role: ipabackup
    state: present
```


Example playbook to create a backup of the IPA server that is transferred to the controller using the server name as prefix for the backup and kept on the server:

```yaml
---
- name: Playbook to backup IPA server to controller
  hosts: ipaserver
  become: true

  vars:
    ipabackup_to_controller: yes
    ipabackup_keep_on_server: yes

  roles:
  - role: ipabackup
    state: present
```


Copy backup `ipa-full-2020-10-01-10-00-00` from server to controller:

```yaml
---
- name: Playbook to copy backup from IPA server
  hosts: ipaserver
  become: true

  vars:
    ipabackup_name: ipa-full-2020-10-01-10-00-00

  roles:
  - role: ipabackup
    state: copied
```


Copy backups `ipa-full-2020-10-01-10-00-00` and `ipa-full-2020-10-02-10-00-00` from server to controller:

```yaml
---
- name: Playbook to copy backup from IPA server
  hosts: ipaserver
  become: true

  vars:
    ipabackup_name:
    - ipa-full-2020-10-01-10-00-00
    - ipa-full-2020-10-02-10-00-00

  roles:
  - role: ipabackup
    state: copied
```


Copy all backups from server to controller:

```yaml
---
- name: Playbook to copy all backups from IPA server
  hosts: ipaserver
  become: true

  vars:
    ipabackup_name: all

  roles:
  - role: ipabackup
    state: copied
```


Remove backup `ipa-full-2020-10-01-10-00-00` from server:

```yaml
---
- name: Playbook to remove backup from IPA server
  hosts: ipaserver
  become: true

  vars:
    ipabackup_name: ipa-full-2020-10-01-10-00-00

  roles:
  - role: ipabackup
    state: absent
```


Remove backups `ipa-full-2020-10-01-10-00-00` and `ipa-full-2020-10-02-10-00-00` from server:

```yaml
---
- name: Playbook to remove backup from IPA server
  hosts: ipaserver
  become: true

  vars:
    ipabackup_name:
    - ipa-full-2020-10-01-10-00-00
    - ipa-full-2020-10-02-10-00-00

  roles:
  - role: ipabackup
    state: absent
```


Remove all backups from server:

```yaml
---
- name: Playbook to remove all backups from IPA server
  hosts: ipaserver
  become: true

  vars:
    ipabackup_name: all

  roles:
  - role: ipabackup
    state: absent
```


Playbooks
=========

The example playbooks to do the backup, copy a backup and also to remove a backup are part of the repository in the playbooks folder.

```
backup-server.yml
backup-server-to-controller.yml
copy-backup-from-server.yml
remove-backup-from-server.yml
```

Please remember to link or copy the playbooks to the base directory of ansible-freeipa if you want to use the roles within the source archive.


Variables
=========

Base Variables
--------------

Variable | Description | Required
-------- | ----------- | --------
ipabackup_gpg | Encrypt the backup, bool (default: `no`) | no
ipabackup_gpg_keyring | Full path to the GPG keyring without the file extension, only for GPG 1 and IPA 4.6 str | no
ipabackup_data | Backup only the data, bool (default: `no`) | no
ipabackup_logs | Include log files in backup, bool (default: `no`) | no
ipabackup_online | Perform the LDAP backups online, for data only, bool (default: `no`) | no
ipabackup_disable_role_check | Perform the backup even if this host does not have all the roles used in the cluster. This is not recommended, bool (default: `no`) | no
ipabackup_log_file | Log to the given file on server, string | no
state | `present` to make a new backup, `absent` to remove a backup and `copied` to copy a backup from the server to the controller. string (default: `present`) | yes

Special Variables
-----------------

Variable | Description | Required
-------- | ----------- | --------
ipabackup_name | The IPA backup name(s). Only for removal of server local backup(s) with `state: absent` or to copy server local backup(s) to the controller with `state: copied`. If `all` is used all available backups are copied or removed. string list | no
ipabackup_keep_on_server | Keep local copy of backup on server with `ipabackup_to_controller`, bool (default: `no`) | no
ipabackup_to_controller | Copy backup to controller, prefixes backup with node name, remove backup on server if `ipabackup_keep_on_server` is not set, bool (default: `no`) | no
ipabackup_controller_path | Pre existing path on controller to store the backup in. If this is not set, the current working dir is used. string | no
ipabackup_controller_prefix | Set prefix to use for backup on controller, The default is the server FQDN, string | no


Authors
=======

Thomas Woerner

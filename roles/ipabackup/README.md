ipabackup role
==============

Description
-----------

This role allows to backup an IPA server, to copy a backup from the server to the controller, to copy all backups from the server to the controller, to remove a backup from the server, to remove all backups from the server, to restore an IPA server locally and from the controller and also to copy a backup from the controller to the server.


**Note**: The ansible playbooks and role require a configured ansible environment where the ansible nodes are reachable and are properly set up to have an IP address and a working package manager.


Features
--------
* Server backup
* Server backup to controller
* Copy backup from server to controller
* Copy all backups from server to controller
* Remove backup from the server
* Remove all backups from the server
* Server restore from server local backup.
* Server restore from controller.
* Copy a backup from the controller to the server.


Supported FreeIPA Versions
--------------------------

FreeIPA versions 4.5 and up are supported by the backup role.


Supported Distributions
-----------------------

* RHEL/CentOS 7.6+
* CentOS Stream 8+
* Fedora 26+
* Ubuntu 16.04 and 18.04


Requirements
------------

**Controller**
* Ansible version: 2.13+

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
    ipabackup_to_controller: yes

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
    ipabackup_to_controller: yes

  roles:
  - role: ipabackup
    state: copied
```


Copy all backups from server to controller that are following the backup naming scheme:

```yaml
---
- name: Playbook to copy all backups from IPA server
  hosts: ipaserver
  become: true

  vars:
    ipabackup_name: all
    ipabackup_to_controller: yes

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


Remove all backups from server that are following the backup naming scheme:

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


Example playbook to restore an IPA server locally:

```yaml
---
- name: Playbook to restore an IPA server
  hosts: ipaserver
  become: true

  vars:
    ipabackup_name: ipa-full-2020-10-22-11-11-44
    ipabackup_password: SomeDMpassword

  roles:
  - role: ipabackup
    state: restored
```


Example playbook to restore IPA server from controller:

```yaml
---
- name: Playbook to restore IPA server from controller
  hosts: ipaserver
  become: true

  vars:
    ipabackup_name: ipaserver.test.local_ipa-full-2020-10-22-11-11-44
    ipabackup_password: SomeDMpassword
    ipabackup_from_controller: yes

  roles:
  - role: ipabackup
    state: restored
```


Example playbook to copy a backup from controller to the IPA server:

```yaml
---
- name: Playbook to copy a backup from controller to the IPA server
  hosts: ipaserver
  become: true

  vars:
    ipabackup_name: ipaserver.test.local_ipa-full-2020-10-22-11-11-44
    ipabackup_from_controller: yes

  roles:
  - role: ipabackup
    state: copied
```


Playbooks
=========

The example playbooks to do the backup, copy a backup and also to remove a backup, also to do the restore, copy a backup to the server are part of the repository in the playbooks folder.

```
backup-server.yml
backup-server-to-controller.yml
copy-all-backups-from-server.yml
copy-backup-from-server.yml
remove-all-backups-from-server.yml
remove-backup-from-server.yml
restore-server.yml
restore-server-from-controller.yml
copy-backup-from-controller.yml
```

Please remember to link or copy the playbooks to the base directory of ansible-freeipa if you want to use the roles within the source archive.


Variables
=========

Base Variables
--------------

Variable | Description | Required
-------- | ----------- | --------
ipabackup_backend | The backend to restore within the instance or instances, str | no
ipabackup_data | Backup only the data with `state: present` and restore only the data with `state: restored`, bool (default: `no`) | no
ipabackup_disable_role_check | Perform the backup even if this host does not have all the roles used in the cluster. This is not recommended, bool (default: `no`) | no
ipabackup_gpg | Encrypt the backup, bool (default: `no`) | no
ipabackup_gpg_keyring | Full path to the GPG keyring without the file extension, only for GPG 1 and up to IPA 4.6 str | no
ipabackup_instance | The 389-ds instance to restore (defaults to all found), str | no
ipabackup_log_file | Log to the given file on server for `state: present` and `state: restored` only, string | no
ipabackup_logs | Include log files in backup, bool (default: `no`) | no
ipabackup_no_logs | Do not restore log files from the backup, bool (default: `no`) | no
ipabackup_online | Perform the LDAP backups online for data only with `state: present` and perform the LDAP restore online for data only with `state: restored`. If `ipabackup_data` is not set it will automatically be enabled.  bool (default: `no`) | no
ipabackup_password | The diretory manager password needed for restoring a backup with `state: restored`, str | no
state | `present` to make a new backup, `absent` to remove a backup and `copied` to copy a backup from the server to the controller or from the controller to the server, `restored` to restore a backup. string (default: `present`) | yes


Special Variables
-----------------

Variable | Description | Required
-------- | ----------- | --------
ipabackup_name | The IPA backup name(s). Only for removal of server local backup(s) with `state: absent`, to copy server local backup(s) to the controller with `state: copied` and `ipabackup_from_server` set, to copy a backup from the controller to the server with `state: copied` and `ipabackup_from_controller` set or to restore a backup with `state: restored` either locally on the server of from the controller with `ipabackup_from_controller` set. If `all` is used all available backups are copied or removed that are following the backup naming scheme. string list | no
ipabackup_keep_on_server | Keep local copy of backup on server with `state: present` and `ipabackup_to_controller`, bool (default: `no`) | no
ipabackup_to_controller | Copy backup to controller, prefixes backup with node name, remove backup on server if `ipabackup_keep_on_server` is not set, bool (default: `no`) | no
ipabackup_controller_path | Pre existing path on controller to store the backup in with `state: present`, path on the controller to copy the backup from with `state: copied` and `ipabackup_from_controller` set also for the restore with `state: restored` and `ipabackup_from_controller` set. If this is not set, the current working dir is used. string | no
ipabackup_name_prefix | Set prefix to use for backup directory on controller with `state: present` or `state: copied` and `ipabackup_to_controller` set, The default is the server FQDN, string | no
ipabackup_from_controller | Copy backup from controller to server, restore if `state: restored`, copy backup to server if `state: copied`, bool (default: `no`) | no
ipabackup_install_packages | Install needed packages to be able to apply the backup with `state: restored`, bool (default: `yes`) | no
ipabackup_firewalld_zone | The value defines the firewall zone that will be used with `state: restored`. This needs to be an existing runtime and permanent zone, bool (default: `no`) | no
ipabackup_setup_firewalld | The value defines if the needed services will automatically be opened in the firewall managed by firewalld with `state: restored`, bool (default: `yes`) | no


Authors
=======

Thomas Woerner

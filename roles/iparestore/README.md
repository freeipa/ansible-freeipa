iparestore role
==============

Description
-----------

This role allows to restore an IPA server locally and from the controller and also to copy a backup from the controller to the server.

**Note**: The ansible playbooks and role require a configured ansible environment where the ansible nodes are reachable and are properly set up to have an IP address and a working package manager.


Features
--------
* Server restore from local backup and from controller.
* Copy a backup from the controller to the server.


Supported FreeIPA Versions
--------------------------

FreeIPA versions 4.5 and up are supported by the restore role.


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

Example playbook to restore an IPA server locally:

```yaml
---
- name: Playbook to restore an IPA server
  hosts: ipaserver
  become: true

  vars:
    iparestore_name: ipa-full-2020-10-22-11-11-44
    iparestore_password: SomeDMpassword

  roles:
  - role: iparestore
    state: present
```


Example playbook to restore IPA server from controller:

```yaml
---
- name: Playbook to restore IPA server from controller
  hosts: ipaserver
  become: true

  vars:
    iparestore_name: ipaserver.test.local_ipa-full-2020-10-22-11-11-44
    iparestore_from_controller: yes
    iparestore_password: SomeDMpassword

  roles:
  - role: iparestore
    state: present
```


Example playbook to copy a backup from controller to the IPA server:

```yaml
---
- name: Playbook to copy a backup from controller to the IPA server
  hosts: ipaserver
  become: true

  vars:
    iparestore_name: ipaserver.test.local_ipa-full-2020-10-22-11-11-44

  roles:
  - role: iparestore
    state: copied
```


Playbooks
=========

The example playbooks to do the restore, copy a backup to the server are part of the repository in the playbooks folder.

```
restore-server.yml
restore-server-from-controller.yml
copy-backup-to-server.yml
```

Please remember to link or copy the playbooks to the base directory of ansible-freeipa if you want to use the roles within the source archive.


Variables
=========

Base Variables
--------------

Variable | Description | Required
-------- | ----------- | --------
iparestore_name | The backup to act on, str | yes
iparestore_password | The diretory manager password needed for restoring a backup with `state: present`, str | no
iparestore_data | Restore only the data, bool (default: `no`) | no
iparestore_online | Perform the LDAP restore online, for data only, bool (default: `no`) | no
iparestore_instance | The 389-ds instance to restore (defaults to all found), str | no
iparestore_backend | The backend to restore within the instance or instances, str | no
iparestore_no_logs | Do not restore log files from the backup, bool (default: `no`) | no
iparestore_log_file | Log to the given file on server, string | no
state | `present` to make a new restore, `copied` to copy a restore from the server to the controller. string (default: `present`) | yes

Special Variables
-----------------

Variable | Description | Required
-------- | ----------- | --------
iparestore_from_controller | Copy backup from controller to server, restore if `state: present`, copy backup to server if `state: copied`, bool (default: `no`) | no
iparestore_controller_path | Path on the controller to get the backup from. If this is not set, the current working dir is used. string | no
iparestore_install_packages | Install needed packages to be able to apply the backup, bool (default: `yes`) | no
iparestore_firewalld_zone | The value defines the firewall zone that will be used. This needs to be an existing runtime and permanent zone, bool (default: `no`) | no
iparestore_setup_firewalld | The value defines if the needed services will automatically be opened in the firewall managed by firewalld, bool (default: `yes`) | no


Authors
=======

Thomas Woerner

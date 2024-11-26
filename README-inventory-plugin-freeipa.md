Inventory plugin
================

Description
-----------


The inventory plugin compiles a dynamic inventory from IPA domain. The servers can be filtered by their role(s).

This plugin is using the Python requests binding, that is only available for Python 3.7 and up.


Features
--------
* Dynamic inventory


Supported FreeIPA Versions
--------------------------

FreeIPA versions 4.6.0 and up are supported by the inventory plugin.


Requirements
------------

**Controller**
* Ansible version: 2.14+

**Node**
* Supported FreeIPA version (see above)


Configuration
=============

The inventory plugin is automatically enabled from the Ansible collection or from the top directory of the git repo if the `plugins` folder is linked to `~/.ansible`.

If `ansible.cfg` was modified to point to the roles and modules with `roles_path`, `library` and `module_utils` tag, then it is needed to set `inventory_plugins` also:

```
inventory_plugins = /my/dir/ansible-freeipa/plugins/inventory
```

Usage
=====

Example inventory file "freeipa.yml":

```yml
---
plugin: freeipa
server: server.ipa.local
ipaadmin_password: SomeADMINpassword
```

Example inventory file "freeipa.yml" with server TLS certificate verification using local copy of `/etc/ipa/ca.crt` from the server:

```yml
---
plugin: freeipa
server: server.ipa.local
ipaadmin_password: SomeADMINpassword
verify: ca.crt
```


How to use the plugin
---------------------

With the `ansible-inventory` command it is possible to show the generated inventorey:

```bash
ansible-inventory -v -i freeipa.yml --graph
```

Example inventory file "freeipa.yml" for use with `playbooks/config/retrieve-config.yml`:

```yml
---
plugin: freeipa
server: server.ipa.local
ipaadmin_password: SomeADMINpassword
inventory_group: ipaserver
```

```bash
ansible-playbook -u root -i ipa.yml playbooks/config/retrieve-config.yml 
```

Variables
=========

Variable | Description | Required
-------- | ----------- | --------
`ipaadmin_principal` | The admin principal is a string and defaults to `admin` | no
`ipaadmin_password` | The admin password is a string and is required if there is no admin ticket available on the node | no
`server` | The FQDN of server to start the scan. (string) | yes
`verify` | The server TLS certificate file for verification (/etc/ipa/ca.crt). Turned off if not set. (string) | yes
`role` | The role(s) of the server. If several roles are given, only servers that have all the roles are returned. (list of strings) (choices: "IPA master", "CA server", "KRA server", "DNS server", "AD trust controller", "AD trust agent") | no
`inventory_group` | The inventory group to create. The default group name is "ipaservers". | no

Authors
=======

- Thomas Woerner

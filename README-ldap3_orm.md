Hostgroup inventory plugin
==========================

Description
-----------


Features
--------
* Creates inventory from ``ipaHostGroup`` entries.
* Uses [ldap3_orm configuration files](http://code.bsm-felder.de/doc/ldap3-orm/latest/classes/config.html).


Supported FreeIPA Versions
--------------------------

FreeIPA versions 4.4.0 and up are supported by the ``freeipa_ldap3_orm`` inventory plugin.


Requirements
------------

**Controller**
* Ansible version: 2.8+
* [ldap3-orm module](http://code.bsm-felder.de/doc/ldap3-orm) 2.6+
* [keyring module](https://keyring.readthedocs.io) (optional)

**Node**
* Supported FreeIPA version (see above)


Usage
=====

Ansible configuration file ``ansible.cfg``

```ini
[inventory]
enable_plugins = freeipa.ansible_freeipa.freeipa_ldap3_orm
```

Example inventory file (needs [keyring module](https://keyring.readthedocs.io))

```python
url = "ldaps://ldap.example.com"
base_dn = "cn=accounts,dc=example,dc=com"

connconfig = dict(
    user = "uid=guest,cn=users,cn=accounts,dc=example,dc=com",
    password = keyring,
)
```

By default freeipa does not allow to read out ``ipaHostGroup`` entries using
anonymous binds. Therefore it is necessary to provide some credentials in
the ``connconfig`` dictionary. Using keyring for safe password storage is
recommended but not mandatory here. A plain-text password may be provided
using ``password = "unencryptedSecret"``.

The inventory file can be specified in ansible calls using the ``-i <path>``
option, e.g.:

    $ ansible-inventory -i ./example --list

ldap3-orm configuration files can be specified using ``-i <path>``, allowing
reusing existing configuration files.

Hostgroups can be specified in playbooks as usual and will be fetched
dynamically from the corresponding freeipa server, e.g.

``ping.yml``
```yaml
---
- hosts: ipaservers
  tasks:
    - name: ping all freeipa instances in hostgroup ipaservers
      ping:
```

``$ ansible-playbook -i example ping.yml``

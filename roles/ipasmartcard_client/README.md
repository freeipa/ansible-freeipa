ipasmartcard_client role
========================

Description
-----------

This role allows to configure IPA clients for Smart Card authentication.

**Note**: The ansible-freeipa smartcard client role requires an enrolled IPA client.


Features
--------
* Client setup for Smart Card authentication


Supported FreeIPA Versions
--------------------------

FreeIPA versions 4.5 and up are supported by this role.


Supported Distributions
-----------------------

* RHEL/CentOS 7.6+
* CentOS Stream 8+
* Fedora 26+


Requirements
------------

**Controller**
* Ansible version: 2.13+

**Node**
* Supported FreeIPA version (see above)
* Supported distribution (needed for package installation only, see above)
* Enrolled IPA client


Limitations
-----------

Only the enablement of smartcards is supported by the role, there is no disablement.


Usage
=====

Example inventory file with IPA clients:

```ini
[ipaclients]
ipaclient1.example.com
ipaclient2.example.com

[ipaclients:vars]
ipaadmin_password=SomeADMINpassword
ipasmartcard_client_ca_certs=/etc/ipa/ca.crt
```

Example playbook to setup smartcard for the IPA clients using admin password and ipasmartcard_client_ca_certs from inventory file:

```yaml
---
- name: Playbook to setup smartcard for IPA clients
  hosts: ipaclients
  become: true

  roles:
  - role: ipasmartcard_client
    state: present
```

Playbooks
=========

The playbooks needed to setup smartcard for the IPA clients is part of the repository in the playbooks folder.

```
install-smartcard-clients.yml
```

Please remember to link or copy the playbooks to the base directory of ansible-freeipa if you want to use the roles within the source archive.


How to setup smartcard for clients
----------------------------------

```bash
ansible-playbook -v -i inventory/hosts install-smartcard-clients.yml
```
This will setup the clients for smartcard use.


Variables
=========

Variable | Description | Required
-------- | ----------- | --------
`ipaadmin_principal` | The kerberos principal used for admin. Will be set to `admin` if not set. (string) | no
`ipaadmin_password` | The password for the IPA admin user. As an alternative an admin user keytab can be used instead with `ipaadmin_keytab`. (string) | yes
`ipaadmin_keytab` | The admin keytab as an alternative to `ipaadmin_password`. (string) | no
`ipasmartcard_client_ca_certs` | The CA certificates for smartcard use. If `ipasmartcard_client_ca_certs` is not set, but `ipasmartcard_server_ca_certs`, then `ipasmartcard_server_ca_certs` will be used. | yes


Authors
=======

Thomas Woerner

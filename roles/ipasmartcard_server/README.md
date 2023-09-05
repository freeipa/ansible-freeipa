ipasmartcard_server role
========================

Description
-----------

This role allows to configure an IPA server (master or replica) for Smart Card authentication.

**Note**: The ansible-freeipa smartcard server role requires a configured IPA server with ipa-ca.DOMAIN resolvable by the DNS server.

With external DNS ipa-ca.DOMAIN needs to be set.


Features
--------
* Server setup for Smart Card authentication


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
* Deployed IPA server


Limitations
-----------

Only the enablement of smartcards is supported by the role, there is no disablement. The disablement of features in IPA in not supported.


Usage
=====

Example inventory file with ipa server and replicas:

```ini
[ipaserver]
ipaserver.example.com

[ipareplicas]
ipareplica1.example.com
ipareplica2.example.com

[ipacluster:children]
ipaserver
ipareplicas

[ipacluster:vars]
ipaadmin_password=SomeADMINpassword
ipasmartcard_server_ca_certs=/etc/ipa/ca.crt
```

Example playbook to setup smartcard for the IPA server using admin password and ipasmartcard_server_ca_certs from inventory file:

```yaml
---
- name: Playbook to setup smartcard for IPA server
  hosts: ipaserver
  become: true

  roles:
  - role: ipasmartcard_server
    state: present
```

Example playbook to setup smartcard for the IPA servers in ipareplicas group using admin password and ipasmartcard_server_ca_certs from inventory file:

```yaml
---
- name: Playbook to setup smartcard for IPA replicas
  hosts: ipareplicas
  become: true

  roles:
  - role: ipasmartcard_server
    state: present
```

Example playbook to setup smartcard for the IPA servers in ipaserver and ipareplicas group using admin password and ipasmartcard_server_ca_certs from inventory file:

```yaml
---
- name: Playbook to setup smartcard for IPA server and replicas
  hosts: ipaserver, ipareplicas
  become: true

  roles:
  - role: ipasmartcard_server
    state: present
```


Playbooks
=========

The playbooks needed to setup smartcard for the IPA server and the replicas are part of the repository in the playbooks folder.

```
install-smartcard-server.yml
install-smartcard-servers.yml
install-smartcard-replicas.yml
```

Please remember to link or copy the playbooks to the base directory of ansible-freeipa if you want to use the roles within the source archive.


How to setup smartcard for server
---------------------------------

```bash
ansible-playbook -v -i inventory/hosts install-smartcard-server.yml
```
This will setup the server for smartcard use.


How to setup smartcard for replicas
-----------------------------------

```bash
ansible-playbook -v -i inventory/hosts install-smartcard-replicas.yml
```
This will setup the replicas for smartcard use.


How to setup smartcard for server and replicas
----------------------------------------------

```bash
ansible-playbook -v -i inventory/hosts install-smartcard-servers.yml
```
This will setup the replicas for smartcard use.


Variables
=========

Variable | Description | Required
-------- | ----------- | --------
`ipaadmin_principal` | The kerberos principal used for admin. Will be set to `admin` if not set. (string) | no
`ipaadmin_password` | The password for the IPA admin user. As an alternative an admin user keytab can be used instead with `ipaadmin_keytab`. (string) | yes
`ipaadmin_keytab` | The admin keytab as an alternative to `ipaadmin_password`. (string) | no
`ipaserver_hostname` | Fully qualified name of the server. By default `ansible_facts['fqdn']` will be used. (string) | no
`ipaserver_domain` | The primary DNS domain of an existing IPA deployment. By default the domain will be used from ipa server-find result. (string)  | no
`ipasmartcard_server_ca_certs` | The CA certificates for smartcard use. (list of string) | yes


Authors
=======

Thomas Woerner

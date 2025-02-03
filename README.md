FreeIPA Ansible collection
==========================

This repository contains [Ansible](https://www.ansible.com/) roles and playbooks to install and uninstall [FreeIPA](https://www.freeipa.org/) `servers`, `replicas` and `clients`. Also modules for group, host, topology and user management.

**Note**: The Ansible playbooks and roles require a configured Ansible environment where the Ansible nodes are reachable and are properly set up to have an IP address and a working package manager.

Features
--------
* Server, replica and client deployment
* Cluster deployments: Server, replicas and clients in one playbook
* One-time-password (OTP) support for client installation
* Repair mode for clients
* Backup and restore, also to and from controller
* Smartcard setup for servers and clients
* Inventory plugin freeipa
* Modules for automembership rule management
* Modules for automount key management
* Modules for automount location management
* Modules for automount map management
* Modules for certificate management
* Modules for config management
* Modules for delegation management
* Modules for dns config management
* Modules for dns forwarder management
* Modules for dns record management
* Modules for dns zone management
* Modules for group management
* Modules for hbacrule management
* Modules for hbacsvc management
* Modules for hbacsvcgroup management
* Modules for host management
* Modules for hostgroup management
* Modules for idoverridegroup management
* Modules for idoverrideuser management
* Modules for idp management
* Modules for idrange management
* Modules for idview management
* Modules for location management
* Modules for netgroup management
* Modules for permission management
* Modules for privilege management
* Modules for pwpolicy management
* Modules for role management
* Modules for self service management
* Modules for server management
* Modules for service management
* Modules for service delegation rule management
* Modules for service delegation target management
* Modules for sudocmd management
* Modules for sudocmdgroup management
* Modules for sudorule management
* Modules for topology management
* Modules for trust management
* Modules for user management
* Modules for vault management

Supported FreeIPA Versions
--------------------------

FreeIPA versions 4.6 and up are supported by all roles.

The client role supports versions 4.4 and up, the server role is working with versions 4.5 and up, the replica role is currently only working with versions 4.6 and up.

Supported Distributions
-----------------------

* RHEL/CentOS 7.4+
* Fedora 40+
* Ubuntu
* Debian 10+ (ipaclient only, no server or replica!)

Requirements
------------

**Controller**
* Ansible version: 2.14+

**Node**
* Supported FreeIPA version (see above)
* Supported distribution (needed for package installation only, see above)

Limitations
-----------

**External signed CA**

External signed CA is now supported. But the currently needed two step process is an issue for the processing in a simple playbook.

Work is planned to have a new method to handle CSR for external signed CAs in a separate step before starting the server installation.


Usage
=====

How to use ansible-freeipa
--------------------------

**GIT repo**

The simplest method for now is to clone this repository on the controller from github directly and to start the deployment from the ansible-freeipa directory:

```bash
git clone https://github.com/freeipa/ansible-freeipa.git
cd ansible-freeipa
```
You can use the roles directly within the top directory of the git repo, but to be able to use the management modules in the plugins subdirectory, you have to either adapt `ansible.cfg` or create links for the roles, modules or directories.

You can either adapt ansible.cfg:

```
roles_path        = /my/dir/ansible-freeipa/roles
library           = /my/dir/ansible-freeipa/plugins/modules
module_utils      = /my/dir/ansible-freeipa/plugins/module_utils
inventory_plugins = /my/dir/ansible-freeipa/plugins/inventory
```

Or you can link the directories:

```
ansible-freeipa/roles to ~/.ansible/
ansible-freeipa/plugins/modules to ~/.ansible/plugins/
ansible-freeipa/plugins/module_utils to ~/.ansible/plugins/
```

**RPM package**

There are RPM packages available for Fedora. These are installing the roles and modules into the global Ansible directories for `roles`, `plugins/modules` and `plugins/module_utils` in the `/usr/share/ansible` directory. Therefore is it possible to use the roles and modules without adapting the names like it is done in the example playbooks.

**Ansible Galaxy**

This command will get the whole collection from galaxy:

```bash
ansible-galaxy collection install freeipa.ansible_freeipa
```

Ansible galaxy does not support the use of dash ('-') in a name and is automatically replacing this with an underscore ('\_'). Therefore the name is `ansible_freeipa`. The ansible_freeipa collection will be placed in the directory `~/.ansible/collections/ansible_collections/freeipa/ansible_freeipa` where it will be automatically be found for this user.


Ansible inventory file
----------------------

The most important parts of the inventory file is the definition of the nodes, settings and the management modules. Please remember to use [Ansible Vault](https://docs.ansible.com/ansible/latest/user_guide/vault.html) for passwords. The examples here are not using vault for better readability.

**Master server**

The master server is defined within the ```[ipaserver]``` group:
```yaml
[ipaserver]
ipaserver.test.local
```
There are variables that need to be set like ```domain```, ```realm```, ```admin password``` and ```dm password```. These can be set in the ```[ipaserver:vars]``` section:
```yaml
[ipaserver:vars]
ipaadmin_password=ADMPassword1
ipadm_password=DMPassword1
ipaserver_domain=test.local
ipaserver_realm=TEST.LOCAL
```

The admin principal is ```admin``` by default. Please set ```ipaadmin_principal``` if you need to change it.

You can also add more setting here, like for example to enable the DNS server or to set auto-forwarders:
```yaml
[ipaserver:vars]
ipaserver_setup_dns=yes
ipaserver_auto_forwarders=yes
```

But also to skip package installation or firewalld configuration:
```yaml
[ipaserver:vars]
ipaserver_install_packages=no
ipaserver_setup_firewalld=no
```
The installation of packages and also the configuration of the firewall are by default enabled.
Note that it is not enough to mask systemd firewalld service to skip the firewalld configuration. You need to set the variable to `no`.

For more server settings, please have a look at the [server role documentation](roles/ipaserver/README.md).

**Replica**

The replicas are defined within the ```[ipareplicas]``` group:
```yaml
[ipareplicas]
ipareplica1.test.local
ipareplica2.test.local
```

If the master server is already deployed and there are DNS txt records to be able to auto-detect the server, then it is not needed to set ```domain``` or ```realm``` for the replica deployment. But it might be needed to set the master server of a replica because of the topology. If this is needed, it can be set either in the ```[ipareplicas:vars]``` section if it will apply to all the replicas in the ```[ipareplicas]``` group or it is possible to set this also per replica in the ```[ipareplicas]``` group:
```yaml
[ipareplicas]
ipareplica1.test.local
ipareplica2.test.local ipareplica_servers=ipareplica1.test.local
```
This will create a chain from ```ipaserver.test.local <- ipareplica1.test.local <- ipareplica2.test.local```.

If you need to set more than one server for a replica (for fallbacks etc.), simply use a comma separated list for ```ipareplica_servers```:
```yaml
[ipareplicas_tier1]
ipareplica1.test.local

[ipareplicas_tier2]
ipareplica2.test.local ipareplica_servers=ipareplica1.test.local,ipaserver.test.local
```
The first entry in ```ipareplica_servers``` will be used as the master.

In this case you need to have separate tasks in the playbook to first deploy replicas from tier1 and then replicas from tier2:
```yaml
---
- name: Playbook to configure IPA replicas (tier1)
  hosts: ipareplicas_tier1
  become: true

  roles:
  - role: ipareplica
    state: present

- name: Playbook to configure IPA replicas (tier2)
  hosts: ipareplicas_tier2
  become: true

  roles:
  - role: ipareplica
    state: present
```

You can add settings for replica deployment:
```yaml
[ipareplicas:vars]
ipaadmin_password=ADMPassword1
ipadm_password=DMPassword1
ipaserver_domain=test.local
ipaserver_realm=TEST.LOCAL
```

You can also add more setting here, like for example to setup DNS or to enable auto-forwarders:
```yaml
[ipareplica:vars]
ipaserver_setup_dns=yes
ipaserver_auto_forwarders=yes
```

If you need to skip package installation or firewalld configuration:

```yaml
[ipareplicas:vars]
ipareplica_install_packages=no
ipareplica_setup_firewalld=no
```

The installation of packages and also the configuration of the firewall are by default enabled.
Note that it is not enough to mask systemd firewalld service to skip the firewalld configuration. You need to set the variable to `no`.

For more replica settings, please have a look at the [replica role documentation](roles/ipareplica/README.md).


**Client**

Clients are defined within the [ipaclients] group:
```yaml
[ipaclients]
ipaclient1.test.local
ipaclient2.test.local
ipaclient3.test.local
ipaclient4.test.local
```

For simple setups or in defined client environments it might not be needed to set domain or realm for the replica deployment. But it might be needed to set the master server of a client because of the topology. If this is needed, it can be set either in the [ipaclients:vars} section if it will apply to all the clients in the [ipaclients] group or it is possible to set this also per client in the [ipaclients] group:
```yaml
[ipaclients]
ipaclient1.test.local ipaclient_servers=ipareplica1.test.local
ipaclient2.test.local ipaclient_servers=ipareplica1.test.local
ipaclient3.test.local ipaclient_servers=ipareplica2.test.local
ipaclient4.test.local ipaclient_servers=ipareplica2.test.local
```
If you need to set more than one server for a client (for fallbacks etc.), simply use a comma separated list for ```ipaclient_servers```.

You can add settings for client deployment:
```yaml
[ipaclients:vars]
ipaadmin_password=ADMPassword1
ipaserver_domain=test.local
ipaserver_realm=TEST.LOCAL
```

For enhanced security it is possible to use a auto-generated one-time-password (OTP). This will be generated on the (first) server.

To enable the generation of the one-time-password:
```yaml
[ipaclients:vars]
ipaclient_use_otp=yes
```

For more client settings, please have a look at the [client role documentation](roles/ipaclient/README.md).

**Cluster**

If you want to deploy more than a master server at once, then it will be good to define a new group like ```[ipacluster]``` that contains all the other groups ```[ipaserver]```, ```[ipareplicas]``` and ```[ipaclients]```. This way it is not needed to set ```domain```, ```realm```, ```admin password``` or ```dm password``` for the single groups:
```yaml
[ipacluster:children]
ipaserver
ipareplicas
ipaclients

[ipacluster:vars]
ipaadmin_password=ADMPassword1
ipadm_password=DMPassword1
ipaserver_domain=test.local
ipaserver_realm=TEST.LOCAL
```
All these settings will be available in the ```[ipaserver]```, ```[ipareplicas]``` and ```[ipaclient]``` groups.

**Topology**

With this playbook it is possible to add a list of topology segments using the `ipatopologysegment` module.

```yaml
---
- name: Add topology segments
  hosts: ipaserver
  become: true
  gather_facts: false

  vars:
    ipaadmin_password: password1
    ipatopology_segments:
    - {suffix: domain, left: replica1.test.local, right: replica2.test.local}
    - {suffix: domain, left: replica2.test.local, right: replica3.test.local}
    - {suffix: domain, left: replica3.test.local, right: replica4.test.local}
    - {suffix: domain+ca, left: replica4.test.local, right: replica1.test.local}

  tasks:
  - name: Add topology segment
    ipatopologysegment:
      password: "{{ ipaadmin_password }}"
      suffix: "{{ item.suffix }}"
      name: "{{ item.name | default(omit) }}"
      left: "{{ item.left }}"
      right: "{{ item.right }}"
      #state: present
      #state: absent
      #state: checked
      state: reinitialized
    loop: "{{ ipatopology_segments | default([]) }}"
```



Playbooks
=========

The playbooks needed to deploy or undeploy servers, replicas and clients are part of the repository and placed in the playbooks folder. There are also playbooks to deploy and undeploy clusters. With them it is only needed to add an inventory file:
```
playbooks\
        install-client.yml
        install-cluster.yml
        install-replica.yml
        install-server.yml
        uninstall-client.yml
        uninstall-cluster.yml
        uninstall-replica.yml
        uninstall-server.yml
```

How to deploy a master server
-----------------------------

```bash
ansible-playbook -v -i inventory/hosts install-server.yml
```
This will deploy the master server defined in the inventory file.

If Ansible Vault is used for passwords, then it is needed to adapt the playbooks in this way:
```yaml
---
- name: Playbook to configure IPA servers
  hosts: ipaserver
  become: true
  vars_files:
  - playbook_sensitive_data.yml

  roles:
  - role: ipaserver
    state: present
```

It is also needed to provide the vault password file on the ansible-playbook command line:
```bash
ansible-playbook -v -i inventory/hosts --vault-password-file .vaul_pass.txt install-server.yml
```

How to deploy a replica
-----------------------

```bash
ansible-playbook -v -i inventory/hosts install-replica.yml
```
This will deploy the replicas defined in the inventory file.

How to setup a client
---------------------

```bash
ansible-playbook -v -i inventory/hosts install-client.yml
```
This will deploy the clients defined in the inventory file.

How to deploy a cluster
-----------------------

```bash
ansible-playbook -v -i inventory/hosts install-cluster.yml
```
This will deploy the server, replicas and clients defined in the inventory file.


Roles
=====

* [Server](roles/ipaserver/README.md)
* [Replica](roles/ipareplica/README.md)
* [Client](roles/ipaclient/README.md)
* [Backup](roles/ipabackup/README.md)
* [SmartCard server](roles/ipasmartcard_server/README.md)
* [SmartCard client](roles/ipasmartcard_client/README.md)

Modules in plugin/modules
=========================

* [ipaautomember](README-automember.md)
* [ipaautomountkey](README-automountkey.md)
* [ipaautomountlocation](README-automountlocation.md)
* [ipaautomountmap](README-automountmap.md)
* [ipacert](README-cert.md)
* [ipaconfig](README-config.md)
* [ipadelegation](README-delegation.md)
* [ipadnsconfig](README-dnsconfig.md)
* [ipadnsforwardzone](README-dnsforwardzone.md)
* [ipadnsrecord](README-dnsrecord.md)
* [ipadnszone](README-dnszone.md)
* [ipagroup](README-group.md)
* [ipahbacrule](README-hbacrule.md)
* [ipahbacsvc](README-hbacsvc.md)
* [ipahbacsvcgroup](README-hbacsvcgroup.md)
* [ipahost](README-host.md)
* [ipahostgroup](README-hostgroup.md)
* [idoverridegroup](README-idoverridegroup.md)
* [idoverrideuser](README-idoverrideuser.md)
* [idp](README-idp.md)
* [idrange](README-idrange.md)
* [idview](README-idview.md)
* [ipalocation](README-location.md)
* [ipanetgroup](README-netgroup.md)
* [ipapermission](README-permission.md)
* [ipaprivilege](README-privilege.md)
* [ipapwpolicy](README-pwpolicy.md)
* [iparole](README-role.md)
* [ipaselfservice](README-selfservice.md)
* [ipaserver](README-server.md)
* [ipaservice](README-service.md)
* [ipaservicedelegationrule](README-servicedelegationrule.md)
* [ipaservicedelegationtarget](README-servicedelegationtarget.md)
* [ipasudocmd](README-sudocmd.md)
* [ipasudocmdgroup](README-sudocmdgroup.md)
* [ipasudorule](README-sudorule.md)
* [ipatopologysegment](README-topology.md)
* [ipatopologysuffix](README-topology.md)
* [ipatrust](README-trust.md)
* [ipauser](README-user.md)
* [ipavault](README-vault.md)

If you want to write a new module please read [writing a new module](plugins/modules/README.md).

Inventory plugins in plugin/inventory
=====================================

* [freeipa](README-inventory-plugin-freeipa.md)

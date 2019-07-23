FreeIPA Ansible collection
==========================

This repository contains [Ansible](https://www.ansible.com/) roles and playbooks to install and uninstall [FreeIPA](https://www.freeipa.org/) `servers`, `replicas` and `clients`. Also modules for group, topology and user management.

**Note**: The ansible playbooks and roles require a configured ansible environment where the ansible nodes are reachable and are properly set up to have an IP address and a working package manager.

Features
--------
* Server, replica and client deployment
* Cluster deployments: Server, replicas and clients in one playbook
* One-time-password (OTP) support for client installation
* Repair mode for clients
* Modules for group management
* Modules for topology management
* Modules for user management

Supported FreeIPA Versions
--------------------------

FreeIPA versions 4.6 and up are supported by all roles. 

The client role supports versions 4.4 and up, the server role is working with versions 4.5 and up, the replica role is currently only working with versions 4.6 and up.

Supported Distributions
-----------------------

* RHEL/CentOS 7.4+
* Fedora 26+
* Ubuntu
* Debian 10+ (ipaclient only, no server or replica!)

Requirements
------------

**Controller**
* Ansible version: 2.8+ (ansible-freeipa is an Ansible Collection)
* /usr/bin/kinit is required on the controller if a one time password (OTP) is used
* python3-gssapi is required on the controller if a one time password (OTP) is used with keytab to install the client.

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

The simplest method for now is to clone this repository on the contoller from github directly and to start the deployment from the ansible-freeipa directory:

```bash
git clone https://github.com/freeipa/ansible-freeipa.git
cd ansible-freeipa
```
You can use the roles directly within the top directory of the git repo, but to be able to use the management modules in the plugins subdirectory, you have to either adapt `anisble.cfg` or create links for the modules or directories.

You can either adapt ansible.cfg:

```
library      = /my/dir/ansible-freeipa/plugins/modules
module_utils = /my/dir/ansible-freeipa/plugins/module_utils
```

Or you can link the directories:

```
ansible-freeipa/plugins/modules to ~/.ansible/plugins/
ansible-freeipa/plugins/module_utils to ~/.ansible/plugins/
```

**RPM package**

There are RPM packages available for Fedora 29+. These are installing the roles and modules into the global Ansible directories for `roles`, `plugins/modules` and `plugings/module_utils` in the `/usr/share/ansible` directory. Therefore is it possible to use the roles and modules without adapting the names like it is done in the example playbooks.

**Ansible galaxy**

This command will get the whole collection from galaxy:

```bash
mazer install freeipa.ansible_freeipa
```

Ansible galaxy does not support the use of dash ('-') in a name and is automatically replacing this with an underscore ('\_'). Therefore the name is `ansible_freeipa`. The ansible_freeipa collection will be placed in the directory `~/.ansible/collections/ansible_collections/freeipa/ansible_freeipa` where it will be automatically be found for this user.

The needed adaptions of collection prefixes for `modules` and `module_utils` will be done with ansible-freeipa release `0.1.6` for galaxy.


Ansible inventory file
----------------------

The most important parts of the inventory file is the definition of the nodes, settings and the management modules. Please remember to use [Ansible vault](https://docs.ansible.com/ansible/latest/user_guide/vault.html) for passwords. The examples here are not using vault for better readability.

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

The admin principle is ```admin``` by default. Please set ```ipaadmin_principal``` if you need to change it.

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

For enhanced security it is possible to use a auto-generated one-time-password (OTP). This will be generated on the controller using the (first) server. It is needed to have the Python gssapi bindings installed on the controller for this.
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

The playbooks needed to deploy or undeploy server, replicas and clients are part of the repository and placed in the playbooks folder. There are also playbooks to deploy and undeploy clusters. With them it is only needed to add an inventory file:
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

If Ansible vault is used for passwords, then it is needed to adapt the playbooks in this way:
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

It is also needed to provide the vault passowrd file on the ansible-playbook command line:
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

Modules in plugin/modules
=========================

* [ipagroup](README-group.md)
* [ipatopologysegment](README-topology.md)
* [ipatopologysuffix](README-topology.md)
* [ipauser](README-user.md)

ipareplica role
==============

Description
-----------

This role allows to configure a new IPA server that is a replica of the server. Once it has been created it is an exact copy of the original IPA server and is an equal  master.
Changes made to any master are automatically replicated to other masters.

This can be done in different ways using auto-discovery of the servers, domain and other settings or by specifying them.

**Note**: The ansible playbooks and role require a configured ansible environment where the ansible nodes are reachable and are properly set up to have an IP address and a working package manager.


Features
--------
* Replica deployment


Supported FreeIPA Versions
--------------------------

FreeIPA versions 4.6 and up are supported by the replica role.


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

Example inventory file with fixed principal using auto-discovery with DNS records:

```ini
[ipareplicas]
ipareplica1.example.com
ipareplica2.example.com

[ipareplicas:vars]
ipaadmin_principal=admin
```

Example playbook to setup the IPA client(s) using principal from inventory file and password from an [Ansible Vault](http://docs.ansible.com/ansible/latest/playbooks_vault.html) file:

```yaml
---
- name: Playbook to configure IPA replicas
  hosts: ipareplicas
  become: true
  vars_files:
  - playbook_sensitive_data.yml

  roles:
  - role: ipareplica
    state: present
```

Example playbook to unconfigure the IPA client(s) using principal and password from inventory file:

```yaml
---
- name: Playbook to unconfigure IPA replicas
  hosts: ipareplicas
  become: true

  roles:
  - role: ipareplica
    state: absent
```

Example inventory file with fixed server, principal, password and domain:

```ini
[ipaserver]
ipaserver.example.com

[ipareplicas]
ipareplica1.example.com
ipareplica2.example.com

[ipareplicas:vars]
ipareplica_domain=example.com
ipaadmin_principal=admin
ipaadmin_password=MySecretPassword123
ipadm_password=MySecretPassword456
```

Example playbook to setup the IPA client(s) using principal and password from inventory file:

```yaml
---
- name: Playbook to configure IPA replicas with username/password
  hosts: ipareplicas
  become: true

  roles:
  - role: ipareplica
    state: present
```

Example inventory file to remove a replica from the domain:

```ini
[ipareplicas]
ipareplica1.example.com

[ipareplicas:vars]
ipaadmin_password=MySecretPassword123
ipareplica_remove_from_domain=true
```

Example playbook to remove an IPA replica using admin passwords from the domain:

```yaml
---
- name: Playbook to remove IPA replica
  hosts: ipareplica
  become: true

  roles:
  - role: ipareplica
    state: absent
```

The inventory will enable the removal of the replica (also a replica) from the domain. Additional options are needed if the removal of the replica is resulting in a topology disconnect or if the replica is the last that has a role.

To continue with the removal with a topology disconnect it is needed to set these parameters:

```ini
ipareplica_ignore_topology_disconnect=true
ipareplica_remove_on_server=ipareplica2.example.com
```

To continue with the removal for a replica that is the last that has a role:

```ini
ipareplica_ignore_last_of_role=true
```

Be careful with enabling the `ipareplica_ignore_topology_disconnect` and especially `ipareplica_ignore_last_of_role`, the change can not be reverted easily.

The parameters `ipaserver_ignore_topology_disconnect`, `ipaserver_ignore_last_of_role`, `ipaserver_remove_on_server` and `ipaserver_remove_from_domain` can be used instead.


Playbooks
=========

The playbooks needed to deploy or undeploy a replica are part of the repository in the playbooks folder. There are also playbooks to deploy and undeploy clusters.
```
install-replica.yml
uninstall-replica.yml
```
Please remember to link or copy the playbooks to the base directory of ansible-freeipa if you want to use the roles within the source archive.


How to setup replicas
---------------------

```bash
ansible-playbook -v -i inventory/hosts install-replica.yml
```
This will deploy the replicas defined in the inventory file.


Variables
=========

Base Variables
--------------

Variable | Description | Required
-------- | ----------- | --------
`ipaservers` | This group with the IPA master full qualified hostnames. (list of strings) | mostly
`ipareplicas` | Group of IPA replica hostnames. (list of strings) | yes
`ipaadmin_password` | The password for the IPA admin user (string) | mostly
`ipareplica_ip_addresses` | The list of master server IP addresses. (list of strings) | no
`ipareplica_domain` | The primary DNS domain of an existing IPA deployment. (string) | no
`ipaserver_realm` | The Kerberos realm of an existing IPA deployment. (string) | no
`ipaserver_hostname` | Fully qualified name of the server. (string) | no
`ipaadmin_principal` | The authorized kerberos principal used to join the IPA realm. (string) | no
`ipareplica_no_host_dns` | Do not use DNS for hostname lookup during installation. (bool, default: false) | no
`ipareplica_skip_conncheck` | Skip connection check to remote master. (bool, default: false) | no
`ipareplica_pki_config_override` | Path to ini file with config overrides. This is only usable with recent FreeIPA versions. (string) | no
`ipareplica_mem_check` | Checking for minimum required memory for the deployment.  This is only usable with recent FreeIPA versions (4.8.10+) else ignored. (bool, default: yes) | no

Server Variables
----------------

Variable | Description | Required
-------- | ----------- | --------
`ipadm_password` | The password for the Directory Manager. (string) | mostly
`ipareplica_hidden_replica` | Install a hidden replica. (bool, default: false) | no
`ipareplica_setup_adtrust` | Configure AD trust capability. (bool, default: false) | no
`ipareplica_setup_ca` | Configure a dogtag CA. (bool, default: false) | no
`ipareplica_setup_kra` | Configure a dogtag KRA. (bool, default: false) | no
`ipareplica_setup_dns` | Configure bind with our zone. (bool, default: false) | no
`ipareplica_no_pkinit` | Disables pkinit setup steps. (bool, default: false) | no
`ipareplica_no_ui_redirect` | Do not automatically redirect to the Web UI. (bool, default: false) | no
`ipareplica_dirsrv_config_file` | The path to LDIF file that will be used to modify configuration of dse.ldif during installation of the directory server instance. (string)| no

SSL certificate Variables
-------------------------

Variable | Description | Required
-------- | ----------- | --------
`ipareplica_dirsrv_cert_files` | Files containing the Directory Server SSL certificate and private keys. (list of strings) | no
`ipareplica_http_cert_files` | Files containing the Apache Server SSL certificate and private key. (list of string) | no
`ipareplica_pkinit_cert_files` | Files containing the Kerberos KDC SSL certificate and private key. (list of string) | no
`ipareplica_dirsrv_pin` | The password to unlock the Directory Server private key. (string) | no
`ipareplica_http_pin` | The password to unlock the Apache Server private key. (string) | no
`ipareplica_pkinit_pin` | The password to unlock the Kerberos KDC private key. (string) | no
`ipareplica_dirsrv_cert_name` | Name of the Directory Server SSL certificate to install. (string) | no
`ipareplica_http_cert_name` | Name of the Apache Server SSL certificate to install. (string) | no
`ipareplica_pkinit_cert_name` | Name of the Kerberos KDC SSL certificate to install. (string) | no

Client Variables
----------------

Variable | Description | Required
-------- | ----------- | --------
`ipaclient_keytab` | Path to backed up keytab from previous enrollment. (string) | no
`ipaclient_mkhomedir` | Set to yes to configure PAM to create a users home directory if it does not exist. (string) | no
`ipaclient_force_join` | Force client enrollment even if already enrolled. (bool, default: false) | no
`ipaclient_ntp_servers` | The list defines the NTP servers to be used. (list of strings) | no
`ipaclient_ntp_pool` | The string value defines the ntp server pool to be used. (string) | no
`ipaclient_no_ntp` | The bool value defines if NTP will not be configured and enabled. (bool, default: false) | no
`ipaclient_ssh_trust_dns` | The bool value defines if OpenSSH client will be configured to trust DNS SSHFP records. (bool, default: false) | no
`ipaclient_no_ssh` | The bool value defines if OpenSSH client will be configured. (bool, default: false) | no
`ipaclient_no_sshd` | The bool value defines if OpenSSH server will be configured. (bool, default: false) | no
`ipaclient_no_sudo` | The bool value defines if SSSD will be configured as a data source for sudo. (bool, default: false) | no
`ipaclient_subid` | The bool value defines if SSSD will be configured as a data source for subid. (bool, default: false) | no
`ipaclient_no_dns_sshfp` | The bool value defines if DNS SSHFP records will not be created automatically. (bool, default: false) | no

Certificate system Variables
----------------------------

Variable | Description | Required
-------- | ----------- | --------
~~`ipareplica_skip_schema_check`~~ | ~~Skip check for updated CA DS schema on the remote master. (bool, default: false)~~ | ~~no~~

DNS Variables
-------------

Variable | Description | Required
-------- | ----------- | --------
`ipareplica_allow_zone_overlap` | Allow creation of (reverse) zone even if the zone is already resolvable. (bool, default: false) | no
`ipareplica_reverse_zones` | The reverse DNS zones to use. (list of strings) | no
`ipareplica_no_reverse` | Do not create reverse DNS zone. (bool, default: false) | no
`ipareplica_auto_reverse` | Try to resolve reverse records and reverse zones for server IP addresses. (bool, default: false) | no
`ipareplica_zonemgr` | The e-mail address of the DNS zone manager. (string, default: hostmaster@DOMAIN.) | no
`ipareplica_forwarders` | Add DNS forwarders to the DNS configuration. (list of strings) | no
`ipareplica_no_forwarders` | Do not add any DNS forwarders. Root DNS servers will be used instead. (bool, default: false) | no
`ipareplica_auto_forwarders` | Add DNS forwarders configured in /etc/resolv.conf to the list of forwarders used by IPA DNS. (bool, default: false) | no
`ipareplica_forward_policy` | DNS forwarding policy for global forwarders specified using other options. (choice: first,only) | no
`ipareplica_no_dnssec_validation` | Disable DNSSEC validation on this server. (bool, default: false) | no

AD trust Variables
------------------

Variable | Description | Required
-------- | ----------- | --------
~~`ipareplica_add_sids`~~ | ~~Add SIDs for existing users and groups as the final step. (bool, default: false)~~ | ~~no~~
~~`ipareplica_add_agents`~~ | ~~Add IPA masters to a list of hosts allowed to serve information about users from trusted forests. (bool, default: false)~~ | ~~no~~
`ipareplica_enable_compat`| Enables support for trusted domains users for old clients through Schema Compatibility plugin. (bool, default: false) | no
`ipareplica_netbios_name` | The NetBIOS name for the IPA domain. (string) | no
`ipareplica_rid_base` | First RID value of the local domain. (integer) | no
`ipareplica_secondary_rid_base` | Start value of the secondary RID range. (integer) | no

Cluster Specific Variables
--------------------------

Variable | Description | Required
-------- | ----------- | --------
`ipareplica_servers` | Manually override list of servers for example in a cluster environment on a per replica basis. The list of servers is normally taken from from groups.ipaserver in cluster environments. (list of strings) | no
`ipaserver_domain` | Used if set in a cluster environment to overload `ipareplica_domain` | no

Special Variables
-----------------

Variable | Description | Required
-------- | ----------- | --------
`ipareplica_install_packages` | The bool value defines if the needed packages are installed on the node. (bool, default: true) | no
`ipareplica_setup_firewalld` | The value defines if the needed services will automatically be openen in the firewall managed by firewalld. (bool, default: true) | no
`ipareplica_firewalld_zone` | The value defines the firewall zone that will be used. This needs to be an existing runtime and permanent zone. (string) | no

Undeploy Variables (`state`: absent)
------------------------------------

These settings should only be used if the result is really wanted. The change might not be revertable easily.

Variable | Description | Required
-------- | ----------- | --------
`ipareplica_ignore_topology_disconnect` \| `ipaserver_ignore_topology_disconnect` | If enabled this enforces the removal of the replica even if it results in a topology disconnect. Be careful with this setting. (bool) | false
`ipareplica_ignore_last_of_role` \| `ipaserver_ignore_last_of_role` | If enabled this enforces the removal of the replica even if the replica is the last with one that has a role. Be careful, this might not be revered easily. (bool) | false
`ipareplica_remove_from_domain` \| `ipaserver_remove_from_domain` | This enables the removal of the replica from the domain additionally to the undeployment. (bool) | false
`ipareplica_remove_on_server` \| `ipaserver_remove_on_server` | The value defines the replica in the domain that will to be used to remove the replica from the domain if `ipareplica_ignore_topology_disconnect` and `ipareplica_remove_from_domain` are enabled. Without the need to enable `ipareplica_ignore_topology_disconnect`, the value will be automatically detected using the replication agreements of the replica. (string) | false


Authors
=======

Thomas Woerner

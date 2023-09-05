ipaserver role
==============

Description
-----------

This role allows to configure and IPA server.

**Note**: The ansible playbooks and role require a configured ansible environment where the ansible nodes are reachable and are properly set up to have an IP address and a working package manager.


Features
--------
* Server deployment


Supported FreeIPA Versions
--------------------------

FreeIPA versions 4.5 and up are supported by the server role.


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


Limitations
-----------

**External signed CA**
External signed CA is now supported. But the currently needed two step process is an issue for the processing in a simple playbook.

Work is planned to have a new method to handle CSR for external signed CAs in a separate step before starting the server installation.


Usage
=====

Example inventory file with fixed domain and realm, setting up of the DNS server and using forwarders from /etc/resolv.conf:

```ini
[ipaserver]
ipaserver2.example.com

[ipaserver:vars]
ipaserver_domain=example.com
ipaserver_realm=EXAMPLE.COM
ipaserver_setup_dns=yes
ipaserver_auto_forwarders=yes
```

Example playbook to setup the IPA server using admin and dirman passwords from an [Ansible Vault](http://docs.ansible.com/ansible/latest/playbooks_vault.html) file:

```yaml
---
- name: Playbook to configure IPA server
  hosts: ipaserver
  become: true
  vars_files:
  - playbook_sensitive_data.yml

  roles:
  - role: ipaserver
    state: present
```

Example playbook to unconfigure the IPA server using principal and password from inventory file:

```yaml
---
- name: Playbook to unconfigure IPA server
  hosts: ipaserver
  become: true

  roles:
  - role: ipaserver
    state: absent
```

Example inventory file with fixed domain, realm, admin and dirman passwords:

```ini
[ipaserver]
ipaserver.example.com

[ipaserver:vars]
ipaserver_domain=example.com
ipaserver_realm=EXAMPLE.COM
ipaadmin_password=MySecretPassword123
ipadm_password=MySecretPassword234
```

Example playbook to setup the IPA server using admin and dirman passwords from inventory file:

```yaml
---
- name: Playbook to configure IPA server
  hosts: ipaserver
  become: true

  roles:
  - role: ipaserver
    state: present
```

Example playbook to setup the IPA primary with external signed CA using the previous inventory file:

Server installation step 1: Generate CSR, copy to controller as `<ipaserver hostname>-ipa.csr`

```yaml
---
- name: Playbook to configure IPA server step1
  hosts: ipaserver
  become: true
  vars:
    ipaserver_external_ca: yes

  roles:
  - role: ipaserver
    state: present

  post_tasks:
  - name: Copy CSR /root/ipa.csr from node to "{{ groups.ipaserver[0] + '-ipa.csr' }}"
    fetch:
      src: /root/ipa.csr
      dest: "{{ groups.ipaserver[0] + '-ipa.csr' }}"
      flat: yes
```

Sign with CA: This is up to you

Server installation step 2: Copy `<ipaserver hostname>-chain.crt` to the IPA server and continue with installation of the primary.

```yaml
---
- name: Playbook to configure IPA server step3
  hosts: ipaserver
  become: true
  vars:
    ipaserver_external_cert_files: "/root/chain.crt"

  pre_tasks:
  - name: Copy "{{ groups.ipaserver[0] + '-chain.crt' }}" to /root/chain.crt on node
    copy:
      src: "{{ groups.ipaserver[0] + '-chain.crt' }}"
      dest: "/root/chain.crt"
      force: yes

  roles:
  - role: ipaserver
    state: present
```

The files can also be copied automatically: Set `ipaserver_copy_csr_to_controller` to true in the server installation step 1 and set `ipaserver_external_cert_files_from_controller` to point to the `chain.crt` file in the server installation step 2.

Since version 4.10, FreeIPA supports creating certificates using random serial numbers. Random serial numbers is a global and permanent setting, that can only be activated while deploying the first server of the domain. Replicas will inherit this setting automatically. An example of an inventory file to deploy a server with random serial numbers enabled is:

```ini
[ipaserver]
ipaserver.example.com

[ipaserver:vars]
ipaserver_domain=example.com
ipaserver_realm=EXAMPLE.COM
ipaadmin_password=MySecretPassword123
ipadm_password=MySecretPassword234
ipaserver_random_serial_numbers=true
```

By setting the variable in the inventory file, the same ipaserver deployment playbook, shown before, can be used.


Example inventory file to remove a server from the domain:

```ini
[ipaserver]
ipaserver.example.com

[ipaserver:vars]
ipaadmin_password=MySecretPassword123
ipaserver_remove_from_domain=true
```

Example playbook to remove an IPA server using admin passwords from the domain:

```yaml
---
- name: Playbook to remove IPA server
  hosts: ipaserver
  become: true

  roles:
  - role: ipaserver
    state: absent
```

The inventory will enable the removal of the server (also a replica) from the domain. Additional options are needed if the removal of the server/replica is resulting in a topology disconnect or if the server/replica is the last that has a role.

To continue with the removal with a topology disconnect it is needed to set these parameters:

```ini
ipaserver_ignore_topology_disconnect=true
ipaserver_remove_on_server=ipaserver2.example.com
```

To continue with the removal for a server that is the last that has a role:

```ini
ipaserver_ignore_last_of_role=true
```

Be careful with enabling the `ipaserver_ignore_topology_disconnect` and especially `ipaserver_ignore_last_of_role`, the change can not be reverted easily.


Playbooks
=========

The playbooks needed to deploy or undeploy a server are part of the repository in the playbooks folder. There are also playbooks to deploy and undeploy clusters.
```
install-server.yml
uninstall-server.yml
```
Please remember to link or copy the playbooks to the base directory of ansible-freeipa if you want to use the roles within the source archive.


How to setup a server
---------------------

```bash
ansible-playbook -v -i inventory/hosts install-server.yml
```
This will deploy the server defined in the inventory file.


Variables
=========

Base Variables
--------------

Variable | Description | Required
-------- | ----------- | --------
`ipaserver` | This group with the single IPA server full qualified hostname. (list of strings) | yes
`ipadm_password` | The password for the  Directory Manager. (string) | no
`ipaadmin_password` | The password for the IPA admin user (string) | no
`ipaserver_ip_addresses` | The list of master server IP addresses. (list of strings) | no
`ipaserver_domain` | The primary DNS domain of an existing IPA deployment. (string) | no
`ipaserver_realm` | The Kerberos realm of an existing IPA deployment. (string) | no
`ipaserver_hostname` | Fully qualified name of the server. (string) | no
`ipaserver_no_host_dns` | Do not use DNS for hostname lookup during installation. (bool, default: false) | no
`ipaserver_mem_check` | Checking for minimum required memory for the deployment. This is only usable with recent FreeIPA versions (4.8.10+) else ignored. (bool, default: yes) | no

Server Variables
----------------

Variable | Description | Required
-------- | ----------- | --------
`ipaserver_setup_adtrust` | Configure AD Trust capability. (bool, default: false) | no
`ipaserver_setup_kra` | Install and configure a KRA on this server. (bool, default: false) | no
`ipaserver_setup_dns` | Configure an integrated DNS server, create DNS zone specified by domain. (bool, default: false) | no
`ipaserver_idstart` | The starting user and group id number. (integer, default: random) | no
`ipaserver_idmax` | The maximum user and group id number. (integer, default: idstart+199999) | no
`ipaserver_no_hbac_allow` | Do not install allow_all HBAC rule. (bool) | no
`ipaserver_no_ui_redirect` | Do not automatically redirect to the Web UI. (bool) | no
`ipaserver_dirsrv_config_file` | The path to LDIF file that will be used to modify configuration of dse.ldif during installation. (string) | no
`ipaserver_pki_config_override` | Path to ini file with config overrides. This is only usable with recent FreeIPA versions. (string) | no
`ipaserver_random_serial_numbers` | Enable use of random serial numbers for certificates. Requires FreeIPA version 4.10 or later. (boolean) | no

SSL certificate Variables
-------------------------

Variable | Description | Required
-------- | ----------- | --------
`ipaserver_dirsrv_cert_files` | Files containing the Directory Server SSL certificate and private keys. (list of strings) | no
`ipaserver_http_cert_files` | File containing the Apache Server SSL certificate and private key. (list of string) | no
`ipaserver_pkinit_cert_files` | File containing the Kerberos KDC SSL certificate and private key. (list of string) | no
`ipaserver_dirsrv_pin` | The password to unlock the Directory Server private key. (string) | no
`ipaserver_http_pin` | The password to unlock the Apache Server private key. (string) | no
`ipaserver_pkinit_pin` | The password to unlock the Kerberos KDC private key. (string) | no
`ipaserver_dirsrv_cert_name` | Name of the Directory Server SSL certificate to install. (string) | no
`ipaserver_http_cert_name` | Name of the Apache Server SSL certificate to install. (string) | no
`ipaserver_pkinit_cert_name` | Name of the Kerberos KDC SSL certificate to install. (string) | no
`ipaserver_no_pkinit` | Disable pkinit setup steps (boolean) | no

NOTE: If one of the `ipaserver_http_cert_files` or `ipaserver_pkinit_cert_files` is specified, then both are required, so declaring only one of them will raise an error. Additionally, one of `ipaserver_pkinit_cert_files` or `ipaserver_no_pkinit` must be provided as well.

Client Variables
----------------

Variable | Description | Required
-------- | ----------- | --------
`ipaclient_ntp_servers` | The list defines the NTP servers to be used. | no
`ipaclient_ntp_pool` | The string value defines the ntp server pool to be used. | no
`ipaclient_no_ntp` | The bool value defines if NTP will not be configured and enabled. `ipaclient_no_ntp` defaults to `no`. | no
`ipaclient_ssh_trust_dns` | The bool value defines if OpenSSH client will be configured to trust DNS SSHFP records.  `ipaclient_ssh_trust_dns` defaults to `no`. | no
`ipaclient_no_ssh` | The bool value defines if OpenSSH client will be configured. `ipaclient_no_ssh` defaults to `no`. | no
`ipaclient_no_sshd` | The bool value defines if OpenSSH server will be configured. `ipaclient_no_sshd` defaults to `no`. | no
`ipaclient_no_sudo` | The bool value defines if SSSD will be configured as a data source for sudo. `ipaclient_no_sudo` defaults to `no`. | no
`ipaclient_subid` | The bool value defines if SSSD will be configured as a data source for subid. `ipaclient_subid` defaults to `no`. | no
`ipaclient_no_dns_sshfp` | The bool value defines if DNS SSHFP records will not be created automatically. `ipaclient_no_dns_sshfp` defaults to `no`. | no

Certificate system Variables
----------------------------

Variable | Description | Required
-------- | ----------- | --------
`ipaserver_external_ca` | Generate a CSR for the IPA CA certificate to be signed by an external CA. (bool, default: false) | no
`ipaserver_external_ca_type` | Type of the external CA. (choice: generic, ms-cs) | no
`ipaserver_external_ca_profile` | Specify the certificate profile/template to use at the external CA. (string) | no
`ipaserver_external_cert_files` | Files containing the IPA CA certificates and the external CA certificate chains (list of string) | no
`ipaserver_subject_base` | The certificate subject base (default O=<realm-name>). RDNs are in LDAP order (most specific RDN first). (string) | no
`ipaserver_ca_subject` | The CA certificate subject DN (default CN=Certificate Authority,O=<realm-name>). RDNs are in LDAP order (most specific RDN first). (string) | no
`ipaserver_ca_signing_algorithm` | Signing algorithm of the IPA CA certificate. (choice: SHA1withRSA, SHA256withRSA, SHA512withRSA) | no

DNS Variables
-------------

Variable | Description | Required
-------- | ----------- | --------
`ipaserver_allow_zone_overlap` | Allow creation of (reverse) zone even if the zone is already resolvable. (bool, default: false) | no
`ipaserver_reverse_zones` | The reverse DNS zones to use. (list of strings) | no
`ipaserver_no_reverse` | Do not create reverse DNS zone. (bool, default: false) | no
`ipaserver_auto_reverse` | Try to resolve reverse records and reverse zones for server IP addresses. (bool, default: false) | no
`ipaserver_zonemgr` | The e-mail address of the DNS zone manager. (string, default: hostmaster@DOMAIN.) | no
`ipaserver_forwarders` | Add DNS forwarders to the DNS configuration. (list of strings) | no
`ipaserver_no_forwarders` | Do not add any DNS forwarders. Root DNS servers will be used instead. (bool, default: false) | no
`ipaserver_auto_forwarders` | Add DNS forwarders configured in /etc/resolv.conf to the list of forwarders used by IPA DNS. (bool, default: false) | no
`ipaserver_forward_policy` | DNS forwarding policy for global forwarders specified using other options. (choice: first, only) | no
`ipaserver_no_dnssec_validation` | Disable DNSSEC validation on this server. (bool, default: false) | no

AD trust Variables
------------------

Variable | Description | Required
-------- | ----------- | --------
`ipaserver_enable_compat`| Enables support for trusted domains users for old clients through Schema Compatibility plugin. (bool, default: false) | no
`ipaserver_netbios_name` | The NetBIOS name for the IPA domain. (string) | no
`ipaserver_rid_base` | First RID value of the local domain. (integer) | no
`ipaserver_secondary_rid_base` | Start value of the secondary RID range. (integer) | no

Special Variables
-----------------

Variable | Description | Required
-------- | ----------- | --------
`ipaserver_install_packages` | The bool value defines if the needed packages are installed on the node. (bool, default: true) | no
`ipaserver_setup_firewalld` | The value defines if the needed services will automatically be opened in the firewall managed by firewalld. (bool, default: true) | no
`ipaserver_firewalld_zone` | The value defines the firewall zone that will be used. This needs to be an existing runtime and permanent zone. (string) | no
`ipaserver_external_cert_files_from_controller` | Files containing the IPA CA certificates and the external CA certificate chains on the controller that will be copied to the ipaserver host to `/root` folder. (list of string) | no
`ipaserver_copy_csr_to_controller` | Copy the generated CSR from the ipaserver to the controller as `"{{ inventory_hostname }}-ipa.csr"`. (bool) | no

Undeploy Variables (`state`: absent)
------------------------------------

These settings should only be used if the result is really wanted. The change might not be revertable easily.

Variable | Description | Required
-------- | ----------- | --------
`ipaserver_ignore_topology_disconnect` | If enabled this enforces the removal of the server even if it results in a topology disconnect. Be careful with this setting. (bool) | false
`ipaserver_ignore_last_of_role` | If enabled this enforces the removal of the server even if the server is the last with one that has a role. Be careful, this might not be revered easily. (bool) | false
`ipaserver_remove_from_domain` | This enables the removal of the server from the domain additionally to the undeployment. (bool) | false
`ipaserver_remove_on_server` | The value defines the server/replica in the domain that will to be used to remove the server/replica from the domain if `ipaserver_ignore_topology_disconnect` and `ipaserver_remove_from_domain` are enabled. Without the need to enable `ipaserver_ignore_topology_disconnect`, the value will be automatically detected using the replication agreements of the server/replica. (string) | false


Authors
=======

Thomas Woerner

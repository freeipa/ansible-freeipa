ipaclient role
==============

This [Ansible](https://www.ansible.com/) role allows to join hosts as clients to an IPA domain. This can be done in different ways using auto-discovery of the servers, domain and other settings or by specifying them.

**Note**: The ansible playbooks and role require a configured ansible environment where the ansible nodes are reachable and are properly set up to have an IP address and a working package manager.


Features
--------
* Client deployment
* One-time-password (OTP) support
* Repair mode
* DNS resolver configuration support


Supported FreeIPA Versions
--------------------------

FreeIPA versions 4.5 and up are supported by the client role. There is also limited support for version 4.4.


Supported Distributions
-----------------------

* RHEL/CentOS 7.4+
* CentOS Stream 8+
* Fedora 26+
* Ubuntu
* Debian


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
[ipaclients]
ipaclient1.example.com
ipaclient2.example.com

[ipaclients:vars]
ipaadmin_principal=admin
```

Example playbook to setup the IPA client(s) using principal from inventory file and password from an [Ansible Vault](http://docs.ansible.com/ansible/latest/playbooks_vault.html) file:

```yaml
- name: Playbook to configure IPA clients with username/password
  hosts: ipaclients
  become: true
  vars_files:
  - playbook_sensitive_data.yml

  roles:
  - role: ipaclient
    state: present
```

Example playbook to unconfigure the IPA client(s) using principal and password from inventory file:

```yaml
- name: Playbook to unconfigure IPA clients
  hosts: ipaclients
  become: true

  roles:
  - role: ipaclient
    state: absent
```

Example inventory file with fixed servers, principal, password and domain:

```ini
[ipaclients]
ipaclient1.example.com
ipaclient2.example.com

[ipaservers]
ipaserver.example.com

[ipaclients:vars]
ipaclient_domain=example.com
ipaadmin_principal=admin
ipaadmin_password=MySecretPassword123
```

Example playbook to setup the IPA client(s) using principal and password from inventory file:

```yaml
- name: Playbook to configure IPA clients with username/password
  hosts: ipaclients
  become: true

  roles:
  - role: ipaclient
    state: present
```

Example inventory file with configuration of dns resolvers:

```ini
[ipaclients]
ipaclient1.example.com
ipaclient2.example.com

[ipaservers]
ipaserver.example.com

[ipaclients:vars]
ipaadmin_principal=admin
ipaadmin_password=MySecretPassword123
ipaclient_domain=example.com
ipaclient_configure_dns_resolver=yes
ipaclient_dns_servers=192.168.100.1
```

Example inventory file with cleanup of dns resolvers:

```ini
[ipaclients]
ipaclient1.example.com
ipaclient2.example.com

[ipaservers]
ipaserver.example.com

[ipaclients:vars]
ipaadmin_principal=admin
ipaadmin_password=MySecretPassword123
ipaclient_domain=example.com
ipaclient_cleanup_dns_resolver=yes
```

Playbooks
=========

The playbooks needed to deploy or undeploy a client are part of the repository in the playbooks folder. There are also playbooks to deploy and undeploy clusters.
```
install-client.yml
uninstall-client.yml
```
Please remember to link or copy the playbooks to the base directory of ansible-freeipa if you want to use the roles within the source archive.


How to setup a client
---------------------

```bash
ansible-playbook -v -i inventory/hosts install-client.yml
```
This will deploy the clients defined in the inventory file.


Variables
=========

Base Variables
--------------

Variable | Description | Required
-------- | ----------- | --------
`ipaclients` | This group is a list of the names of the IPA clients in FQDN form. All these clients will be installed or configured using the playbook. | yes
`ipaclient_domain` | This string value sets the DNS domain that will be used for client installation. Usually the DNS domain is a lower-cased name of the Kerberos realm. If the role is for example used in a cluster inventory and `ipaserver_domain` is set, then it will be used. | no
`ipaclient_realm` | This string value sets the Kerberos realm that will be used for client installation. Usually the Kerberos realm is an upper-cased name of the DNS domain. If the role is for example used in a cluster inventory and `ipaserver_realm` is set, then it will be used. If `ipaclient_realm` is not set, then it will be generated from `ipaclient_domain` if this is set. | no
`ipaclient_mkhomedir` | This bool value defines if PAM will be configured to create a users home directory if it does not exist. `ipaclient_mkhomedir` defaults to `no`. | no
 `ipaclient_force_join` | This bool value defines if an already enrolled host can join again. `ipaclient_force_join` defaults to `no`. | no
`ipaclient_kinit_attempts` | The int value defines the number of tries to repeat the request for a failed host Kerberos ticket. `ipaclient_kinit_attempts` defaults to 5.| no
`ipaclient_ntp_servers` | The list defines the NTP servers to be used. | no
`ipaclient_ntp_pool` | The string value defines the ntp server pool to be used. | no
`ipaclient_no_ntp` | The bool value defines if NTP will not be configured and enabled. `ipaclient_no_ntp` defaults to `no`. | no
`ipaclient_ssh_trust_dns` | The bool value defines if OpenSSH client will be configured to trust DNS SSHFP records.  `ipaclient_ssh_trust_dns` defaults to `no`. | no
`ipaclient_no_ssh` | The bool value defines if OpenSSH client will be configured. `ipaclient_no_ssh` defaults to `no`. | no
`ipaclient_no_sshd` | The bool value defines if OpenSSH server will be configured. `ipaclient_no_sshd` defaults to `no`. | no
`ipaclient_no_sudo` | The bool value defines if SSSD will be configured as a data source for sudo. `ipaclient_no_sudo` defaults to `no`. | no
`ipaclient_subid` | The bool value defines if SSSD will be configured as a data source for subid. `ipaclient_subid` defaults to `no`. | no
`ipaclient_no_dns_sshfp` | The bool value defines if DNS SSHFP records will not be created automatically. `ipaclient_no_dns_sshfp` defaults to `no`. | no
`ipaclient_force` | The bool value defines if settings will be forced even in the error case. `ipaclient_force` defaults to `no`. | no
`ipaclient_force_ntpd` | The bool value defines if ntpd usage will be forced. This is not supported anymore and leads to a warning. `ipaclient_force_ntpd` defaults to `no`. | no
`ipaclient_nisdomain` | This string value defines the NIS domain name. | no
`ipaclient_no_nisdomain` | The bool value defines if the NIS domain name will not be configured. `ipaclient_no_nisdomain` defaults to `no`. | no
`ipaclient_configure_firefox` | The bool value defines if Firefox will be configured to use IPA domain credentials. `ipaclient_configure_firefox` defaults to `no`. | no
`ipaclient_firefox_dir` | The string value defines the Firefox installation directory. For example: '/usr/lib/firefox'. | no
`ipaclient_all_ip_addresses` | The bool value defines if DNS A/AAAA records for each IP address on the client will be created. `ipaclient_all_ip_addresses` defaults to `no`. | no
`ipasssd_fixed_primary` | The bool value defines if SSSD will be configured to use a fixed server as the primary IPA server. `ipasssd_fixed_primary` defaults to `no`. | no
`ipasssd_permit` | The bool value defines if SSSD will be configured to permit all access. Otherwise the machine will be controlled by the Host-based Access Controls (HBAC) on the IPA server. `ipasssd_permit` defaults to `no`. | no
`ipasssd_enable_dns_updates` | The bool value tells SSSD to automatically update DNS with the IP address of this client. `ipasssd_enable_dns_updates` defaults to `no`. | no
`ipasssd_no_krb5_offline_passwords` | The bool value defines if SSSD will be configured not to store user password when the server is offline . `ipasssd_no_krb5_offline_passwords` defaults to `no`. | no
`ipasssd_preserve_sssd` | The bool value defines if the old SSSD configuration will be preserved if it is not possible to merge it with a new one. `ipasssd_preserve_sssd` defaults to `no`. | no
`ipaclient_request_cert` | The bool value defines if the certificate for the machine wil be requested. The certificate will be stored in /etc/ipa/nssdb under the nickname "Local IPA host". . `ipaclient_request_cert` defaults to `no`. The option is deprecated and will be removed in a future release. | no
`ipaclient_keytab` | The string value contains the path on the node of a backup host keytab from a previous enrollment. | no
`ipaclient_automount_location` | Automount location | no


Server Variables
----------------

Variable | Description | Required
-------- | ----------- | --------
`ipaservers` | This group is a list of the IPA server full qualified host names. In a topology with a chain of servers and replicas, it is important to use the right server or replica as the server for the client. If there is a need to overwrite the setting for a client in the `ipaclients` group, please use the list `ipaclient_servers` explained below. If no `ipaservers` group is defined than the installation preparation step will try to use DNS autodiscovery to identify the the IPA server using DNS txt records. | mostly
`ipaadmin_keytab` | The string variable enables the use of an admin keytab as an alternative authentication method. The variable needs to contain the local path to the keytab file. If `ipaadmin_keytab` is used, then `ipaadmin_password` does not need to be set. If `ipaadmin_keytab` is used with `ipaclient_use_otp: yes` then the keytab needs to be available on the controller, else on the client node. The use of full path names is recommended. | no
`ipaadmin_principal` | The string variable only needs to be set if the name of the Kerberos admin principal is not "admin". If `ipaadmin_principal` is not set it will be set internally to "admin". | no
`ipaadmin_password` | The string variable contains the Kerberos password of the Kerberos admin principal. If `ipaadmin_keytab` is used, then `ipaadmin_password` does not need to be set. | mostly


Topology Variables
------------------

These variables can be used to define or change how clients are arranged within a cluster for example.

Variable | Description | Required
-------- | ----------- | --------
`ipaclient_no_dns_lookup` | The bool value defines if the `ipaservers` group will be used as servers for the clients automatically. If enabled this deactivates DNS lookup in Kerberos in client installations. `ipaclient_no_dns_lookup` defaults to `no`. | no
`ipaclient_servers` | The optional list can be used to manually override list of servers on a per client basis. The list of servers is normally taken from from `ipaservers` group. | no


Special Variables
-----------------

Variable | Description | Required
-------- | ----------- | --------
`ipaclient_use_otp` | The bool value defines if a one-time password will be generated to join a new or existing host. `ipaclient_use_otp` defaults to `no`. The enforcement on an existing host is not done if there is a working krb5.keytab on the host. If the generation of an otp is enforced for an existing host entry, then the host gets disabled and the containing keytab gets removed. | no
`ipaclient_otp` | The string value sets an already generated one-time password for the host. The role will use it and not try to generate a new one. Do not enable `ipaclient_use_otp` additionally. | no
`ipaclient_allow_repair` | The bool value defines if an already joined or partly set-up client can be repaired. `ipaclient_allow_repair` defaults to `no`. Contrary to `ipaclient_force_join=yes` the host entry will not be changed on the server. | no
`ipaclient_install_packages` | The bool value defines if the needed packages are installed on the node. `ipaclient_install_packages` defaults to `yes`. | no
`ipaclient_on_master` | The bool value is only used in the server and replica installation process to install the client part. It should not be set otherwise. `ipaclient_on_master` defaults to `no`. | no
`ipaclient_configure_dns_resolver` | The bool value defines if the DNS resolver is configured. This is useful if the IPA server has internal DNS support. `ipaclient_dns_server` need to be set also. The installation of packages is happening before the DNS resolver is configured, therefore package installation needs to be possible without the configuration of the DNS resolver. The DNS nameservers are configured for `NetworkManager`, `systemd-resolved` (if installed and enabled) and `/etc/resolv.conf` if neither NetworkManager nor systemd-resolved is used. | no
`ipaclient_dns_servers` | The list of DNS server IP addresses. This is only useful with `ipaclient_configure_dns_resolver`. | no
`ipaclient_cleanup_dns_resolver` | The bool value defines if DNS resolvers that have been configured before with `ipaclient_configure_dns_resolver` will be cleaned up again. | no


Authors
=======

Florence Blanc-Renaud

Thomas Woerner

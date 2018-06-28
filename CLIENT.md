ipaclient role
==============

Description
-----------

This role allows to join hosts as clients to an IPA domain. This can be done in differnt ways using auto-discovery of the servers, domain and other settings or by specifying them.

Usage
-----

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

Variables
---------

### `ipaclients`

The mandatory `ipaclients` group is a list of the names of the IPA clients in FQDN form. All these clients will be installed or configured using the playbook.

### `ipaclient_domain`

The optional `ipaclient_domain` variable sets the DNS domain that will be used for client installation. Usually the DNS domain is a lower-cased name of the Kerberos realm.

If `ipaclient_domain` is not set, then it will be generated from the domain part of the first entry from the `ipaservers` FQDN group if the group is defined and contains at least one entry. If `ipaservers` is not defined, then the domain will be tried to gather using DNS autodiscovery. `ipaclient_domain` needs to be set if the primary DNS domain is different from domain part of the server FQDN.

### `ipaclient_realm`

The optional `ipaclient_realm` sets the Kerberos realm that will be used for client installation. Usually the Kerberos realm is an upper-cased name of the DNS domain.

If `ipaclient_realm` is not set, then it will be generated from `ipaclient_domain` if this is set. If both are not set, then this 


### `ipaclient_keytab`

The optional `ipaclient_keytab` contains the path of a backup host keytab from a previous enrollment.

### `ipaclient_force_join`

The `ipaclient_force_join` bool value defines if an already enrolled host can join again. `ipaclient_force_join` defaults to `no`.

### `ipaclient_use_otp`

The `ipaclient_use_otp` bool value defines if a one-time password will be generated to join a new or existing host. `ipaclient_use_otp` defaults to `no`.

The enforcement on an existing host is not done if there is a working krb5.keytab on the host. If the generation of an otp is enforced for an existing host entry, then the host gets diabled and the containing keytab gets removed.

### `ipaclient_allow_repair`

The `ipaclient_allow_repair` bool value defines if an already joined or partly set-up client can be repaired. `ipaclient_allow_repair` defaults to `no`.

Contrary to `ipaclient_force_join=yes` the host entry will not be changed on the server.

### `ipaclient_kinit_attempts`

The optional `ipaclient_kinit_attempts` defines the number of tries to repeat the request for a failed host Kerberos ticket. `ipaclient_kinit_attempts` defaults to 3.

### `ipaclient_no_ntp`

The `ipaclient_no_ntp` bool value defines if NTP will not be configured and enabled. `ipaclient_no_ntp` defaults to `no`.

### `ipaclient_mkhomedir`

The `ipaclient_mkhomedir` bool value defines if PAM will be configured to create a users home directory if it does not exist. `ipaclient_mkhomedir` defaults to `no`.

Server Variables
----------------

### `ipaservers`

The optional `ipaservers` group is a list of the IPA server full qualified host names. In a topology with a chain of servers and replicas, it is important to use the right server or replica as the server for the client. If there is a need to overwrite the setting for a client in the `ipaclients` group, please use the list `ipaclient_servers` explained below.

If no `ipaservers` group is defined than the installation preparation step will try to use DNS autodiscovery to identify the the IPA server using DNS txt records.

### `ipaadmin_keytab`

The `ipaadmin_keytab` variable enables the use of an admin keytab as an alternativce authentication method. The variable needs to contain the local path to the keytab file. If `ipaadmin_keytab` is used, then `ipaadmin_password` does not need to be set.

### `ipaadmin_principal`

The optional `ipaadmin_principal` variable only needs to be set if the name of the Kerberos admin principal is not "admin". If `ipaadmin_principal` is not set it will be set internally to "admin".

### `ipaadmin_password`

The `ipaadmin_password` variable contains the Kerberos password of the Kerberos admin principal. If `ipaadmin_keytab` is used, then `ipaadmin_password` does not need to be set.


Topology Variables
------------------

These variables can be used to define or change how clients are arranged within a cluster for example.

### `ipaclient_no_dns_lookup`

The `ipaclient_no_dns_lookup` bool value defines if the `ipaservers` group will be used as servers for the clients automatically. If enabled this deactivates DNS lookup in Kerberos in client installations. `ipaclient_no_dns_lookup` defauults to `no`.

### `ipaclient_servers`

The optional `ipaclient_servers` varaible can be used to manually override list of servers on a per client basis. The list of servers is normally taken from from `ipaservers` group.

Requirements
------------

freeipa-client v4.4 or later

Authors
-------

Florence Blanc-Renaud

Thomas Woerner

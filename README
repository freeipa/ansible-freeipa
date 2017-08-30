ansible-freeipa
===============

Description
-----------

This role allows to join hosts as clients to an IPA domain. This can be done in differnt ways using auto-discovery of the servers, domain and other settings or by specifying them.

Usage
-----

Example inventory file with fixed principal and using auto-discovery with DNS records:

    [ipaclients]
    ipaclient1.example.com
    ipaclient2.example.com

    [ipaclients:vars]
    ipaclient_principal=admin

Example playbook to setup the IPA client(s) using principal from inventory file and password from an [Ansible Vault](http://docs.ansible.com/ansible/latest/playbooks_vault.html) file:

    - name: Playbook to configure IPA clients with username/password
      hosts: ipaclients
      become: true
      vars_files:
      - playbook_sensitive_data.yml
    
      roles:
      - role: ipaclient
        state: present

Example playbook to unconfigure the IPA client(s) using principal and password from inventory file:

    - name: Playbook to unconfigure IPA clients
      hosts: ipaclients
      become: true
    
      roles:
      - role: ipaclient
        state: absent

Example inventory file with fixed servers, principal, password and domain:

    [ipaclients]
    ipaclient1.example.com
    ipaclient2.example.com
    
    [ipaservers]
    ipaserver.example.com
    
    [ipaclients:vars]
    ipaclient_domain=example.com
    ipaclient_principal=admin
    ipaclient_password=MySecretPassword123

Example playbook to setup the IPA client(s) using principal and password from inventory file:

    - name: Playbook to configure IPA clients with username/password
      hosts: ipaclients
      become: true
    
      roles:
      - role: ipaclient
        state: present

Variables
---------

**ipaservers** - Group of IPA server hostnames.
 (list of strings, optional)

**ipaclient_domain** - The primary DNS domain of an existing IPA deployment.
 (string, optional)

**ipaclient_realm** - The Kerberos realm of an existing IPA deployment.
 (string, optional)

**ipaclient_principal** - The authorized kerberos principal used to join the IPA realm.
 (string, optional)

**ipaclient_password** - The password for the kerberos principal.
 (string, optional)

**ipaclient_keytab** - The path to a backed-up host keytab from previous enrollment.
 (string, optional)

**ipaclient_force_join** - Set force_join to yes to join the host even if it is already enrolled.
 (bool, optional)

**ipaclient_kinit_attempts** - Repeat the request for host Kerberos ticket X times if it fails.
 (int, optional)

**ipaclient_ntp** - Set to no to not configure and enable NTP
 (bool, optional)

**ipaclient_mkhomedir** - Set to yes to configure PAM to create a users home directory if it does not exist.
 (string, optional)

Requirements
------------

freeipa-client v4.6

Authors
-------

Florence Blanc-Renaud
Thomas Woerner

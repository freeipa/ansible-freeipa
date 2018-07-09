ipareplica role
==============

Description
-----------

This role allows to configure a new IPA server that is a replica of the server. Once it has been created it is an exact copy of the original IPA server and is an equal  master.
Changes made to any master are automatically replicated to other masters.

This can be done in differnt ways using auto-discovery of the servers, domain and other settings or by specifying them.

Usage
-----

Example inventory file with fixed principal using auto-discovery with DNS records:

    [ipareplicas]
    ipareplica1.example.com
    ipareplica2.example.com
    
    [ipareplicas:vars]
    ipaadmin_principal=admin

Example playbook to setup the IPA client(s) using principal from inventory file and password from an [Ansible Vault](http://docs.ansible.com/ansible/latest/playbooks_vault.html) file:

    - name: Playbook to configure IPA replicas
      hosts: ipareplicas
      become: true
      vars_files:
      - playbook_sensitive_data.yml
    
      roles:
      - role: ipareplica
        state: present

Example playbook to unconfigure the IPA client(s) using principal and password from inventory file:

    - name: Playbook to unconfigure IPA replicas
      hosts: ipareplicas
      become: true
    
      roles:
      - role: ipareplica
        state: absent

Example inventory file with fixed server, principal, password and domain:

    [ipaserver]
    ipaserver.example.com
    
    [ipareplicas]
    ipareplica1.example.com
    ipareplica2.example.com
    
    [ipareplicas:vars]
    ipaclient_domain=example.com
    ipaadmin_principal=admin
    ipaadmin_password=MySecretPassword123
    ipadm_password=MySecretPassword456

Example playbook to setup the IPA client(s) using principal and password from inventory file:

    - name: Playbook to configure IPA replicas with username/password
      hosts: ipareplicas
      become: true
    
      roles:
      - role: ipareplica
        state: present

Variables
---------

**ipaserver** - Group with IPA server hostname.
 (list of strings, optional)

**ipaclients** - Group of IPA client hostnames.
 (list of strings)

**ipaadmin_keytab** - The path to the admin keytab used for alternative authentication.
 (string, optional)

**ipaadmin_principal** - The authorized kerberos principal used to join the IPA realm.
 (string, optional)

**ipaadmin_password** - The password for the kerberos principal.
 (string, optional)
 
**ipaclient_domain** - The primary DNS domain of an existing IPA deployment.
 (string, optional)

**ipaclient_realm** - The Kerberos realm of an existing IPA deployment.
 (string, optional)

**ipaclient_keytab** - The path to a backed-up host keytab from previous enrollment.
 (string, optional)

**ipaclient_force_join** - Set force_join to yes to join the host even if it is already enrolled.
 (bool, optional)

**ipaclient_use_otp** - Enforce the generation of a one time password to configure new and existing hosts. The enforcement on an existing host is not done if there is a working krb5.keytab on the host. If the generation of an otp is enforced for an existing host entry, then the host gets diabled and the containing keytab gets removed.
 (bool, optional)

**ipaclient_allow_repair** - Allow repair of already joined hosts. Contrary to ipaclient_force_join the host entry will not be changed on the server.
 (bool, optional)

**ipaclient_kinit_attempts** - Repeat the request for host Kerberos ticket X times if it fails.
 (int, optional)

**ipaclient_ntp** - Set to no to not configure and enable NTP
 (bool, optional)

**ipaclient_mkhomedir** - Set to yes to configure PAM to create a users home directory if it does not exist.
 (string, optional)

Cluster Specific Variables
--------------------------

**ipaclient_no_dns_lookup** - Set to 'yes' to use groups.ipaserver in cluster environments as servers for the clients. This deactivates DNS lookup in krb5.
 (bool, optional, default: 'no')

**ipareplica_servers** - Manually override list of servers for example in a cluster environment on a per client basis. The list of servers is normally taken from from groups.ipaserver in cluster environments.
 (list of strings, optional)

Requirements
------------

freeipa-server v4.5 or later

Authors
-------

Florence Blanc-Renaud

Thomas Woerner
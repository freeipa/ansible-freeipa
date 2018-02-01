ipaserver role
==============

Description
-----------

This role allows to configure and IPA server.

Usage
-----

Example inventory file with fixed domain and realm, setting up of the DNS server and using forwarders from /etc/resolv.conf:

    [ipaserver]
    ipaserver2.example.com
    
    [ipaserver:vars]
    ipaserver_domain=example.com
    ipaserver_realm=EXAMPLE.COM
    ipaserver_setup_dns=yes
    ipaserver_auto_forwarders=yes

Example playbook to setup the IPA server using admin and dirman passwords from an [Ansible Vault](http://docs.ansible.com/ansible/latest/playbooks_vault.html) file:

    - name: Playbook to configure IPA server
      hosts: ipaserver
      become: true
      vars_files:
      - playbook_sensitive_data.yml
    
      roles:
      - role: ipaserver
        state: present

Example playbook to unconfigure the IPA client(s) using principal and password from inventory file:

    - name: Playbook to unconfigure IPA server
      hosts: ipaserver
      become: true
    
      roles:
      - role: ipaserver
        state: absent

Example inventory file with fixed domain, realm, admin and dirman passwords:

    [ipaserver]
    ipaserver.example.com
    
    [ipaserver:vars]
    ipaserver_domain=example.com
    ipaserver_realm=EXAMPLE.COM
    ipaadmin_password=MySecretPassword123
    ipadm_password=MySecretPassword234

Example playbook to setup the IPA server using admin and dirman passwords from inventory file:

    - name: Playbook to configure IPA server
      hosts: ipaserver
      become: true
    
      roles:
      - role: ipaserver
        state: present

Variables
---------

**ipaserver** - Group with the IPA server hostname
 (list of strings)

**ipaadmin_password** - The password for the IPA admin user.
 (string, optional)
 
 **ipadm_password** - The password for the  Directory Manager.
 (string, optional)
 
**ipaserver_domain** - The primary DNS domain of an existing IPA deployment.
 (string)

**ipaserver_realm** - The Kerberos realm of an existing IPA deployment.
 (string)

**ipaserver_idstart** - The starting user and group id number (default random).
 (integer, optional)

**ipaserver_idmax** - The maximum user and group id number (default: idstart+199999).
 (integer, optional)

**ipaserver_no_hbac_allow** - Do not install allow_all HBAC rule.
 (bool, optional)

**ipaserver_no_ui_redirect** - Do not automatically redirect to the Web UI.
 (bool, optional)

**ipaserver_dirsrv_config_file** - The path to LDIF file that will be used to modify configuration of dse.ldif during installation.
 (string, optional)

**ipaserver_setup_kra** - Install and configure a KRA on this server.
 (bool, optional)

**ipaserver_setup_dns** - Configure an integrated DNS server, create DNS zone specified by domain
 (string, optional)

**ipaserver_forwarders** - Add DNS forwarders to the DNS configuration.
 (list of strings, optional)

**ipaserver_no_forwarders** - Do not add any DNS forwarders. Root DNS servers will be used instead.
 (bool, optional)

**ipaserver_auto_forwarders** - Add DNS forwarders configured in /etc/resolv.conf to the list of forwarders used by IPA DNS.
 (bool, optional)

**ipaserver_forward_policy** - DNS forwarding policy for global forwarders specified using other options. first|only
 (choice, optional)

**ipaserver_reverse_zones** - The reverse DNS zones to use.
 (list of strings, optional)

**ipaserver_no_reverse** - Do not create reverse DNS zone.
 (bool, optional)

**ipaserver_auto_reverse** - Try to resolve reverse records and reverse zones for server IP addresses.
 (bool, optional)

**ipaserver_zonemgr** - The e-mail address of the DNS zone manager. Defaults to hostmaster@DOMAIN.
 (string, optional)

**ipaserver_no_host_dns** - Do not use DNS for hostname lookup during installation.
 (bool, optional)
              
**ipaserver_no_dnssec_validation** - Disable DNSSEC validation on this server.
 (bool, optional)
 
**ipaserver_allow_zone_overlap** - Allow creation of (reverse) zone even if the zone is already resolvable.
 (bool, optional)

**ipaserver_setup_adtrust** - Configure AD Trust capability.
 (bool, optional)
 
**ipaserver_netbios_name** - The NetBIOS name for the IPA domain.
 (string, optional)

**ipaserver_rid_base** - First RID value of the local domain.
 (integer, optional)

**ipaserver_secondary_rid_base** - Start value of the secondary RID range.
 (integer, optional)

**ipaserver_enable_compat** - Enables support for trusted domains users for old clients through Schema Compatibility plugin. 
 (bool, optional)
 
**ipaclient_force_join** - Set force_join to yes to join the host even if it is already enrolled.
 (bool, optional)

**ipaclient_no_ntp** - Set to no to not configure and enable NTP
 (bool, optional)

**ipaclient_mkhomedir** - Set to yes to configure PAM to create a users home directory if it does not exist.
 (string, optional)

Requirements
------------

freeipa-server v4.5 or later

Authors
-------

Thomas Woerner

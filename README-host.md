Host module
===========

Description
-----------

The host module allows to ensure presence, absence and disablement of hosts.

The host module is as compatible as possible to the Ansible upstream `ipa_host` module, but additionally offers to disable hosts.


Features
--------
* Host management


Supported FreeIPA Versions
--------------------------

FreeIPA versions 4.4.0 and up are supported by the ipahost module.


Requirements
------------

**Controller**
* Ansible version: 2.13+

**Node**
* Supported FreeIPA version (see above)


Usage
=====

Example inventory file

```ini
[ipaserver]
ipaserver.test.local
```


Example playbook to ensure host presence:

```yaml
---
- name: Playbook to handle hosts
  hosts: ipaserver
  become: true

  tasks:
  # Ensure host is present
  - ipahost:
      ipaadmin_password: SomeADMINpassword
      name: host01.example.com
      description: Example host
      ip_address: 192.168.0.123
      locality: Lab
      ns_host_location: Lab
      ns_os_version: CentOS 7
      ns_hardware_platform: Lenovo T61
      mac_address:
      - "08:00:27:E3:B1:2D"
      - "52:54:00:BD:97:1E"
      state: present
```
Compared to `ipa host-add` command no IP address conflict check is done as the ipahost module supports to have several IPv4 and IPv6 addresses for a host.


Example playbook to ensure host presence with several IP addresses:

```yaml
---
- name: Playbook to handle hosts
  hosts: ipaserver
  become: true

  tasks:
  # Ensure host is present
  - ipahost:
      ipaadmin_password: SomeADMINpassword
      name: host01.example.com
      description: Example host
      ip_address:
      - 192.168.0.123
      - 192.168.0.124
      - fe80::20c:29ff:fe02:a1b3
      - fe80::20c:29ff:fe02:a1b4
      locality: Lab
      ns_host_location: Lab
      ns_os_version: CentOS 7
      ns_hardware_platform: Lenovo T61
      mac_address:
      - "08:00:27:E3:B1:2D"
      - "52:54:00:BD:97:1E"
      state: present
```


Example playbook to ensure IP addresses are present for a host:

```yaml
---
- name: Playbook to handle hosts
  hosts: ipaserver
  become: true

  tasks:
  # Ensure host is present
  - ipahost:
      ipaadmin_password: SomeADMINpassword
      name: host01.example.com
      ip_address:
      - 192.168.0.124
      - fe80::20c:29ff:fe02:a1b4
      action: member
      state: present
```


Example playbook to ensure IP addresses are absent for a host:

```yaml
---
- name: Playbook to handle hosts
  hosts: ipaserver
  become: true

  tasks:
  # Ensure host is present
  - ipahost:
      ipaadmin_password: SomeADMINpassword
      name: host01.example.com
      ip_address:
      - 192.168.0.124
      - fe80::20c:29ff:fe02:a1b4
      action: member
      state: absent
```


Example playbook to ensure host presence without DNS:

```yaml
---
- name: Playbook to handle hosts
  hosts: ipaserver
  become: true

  tasks:
  # Ensure host is present without DNS
  - ipahost:
      ipaadmin_password: SomeADMINpassword
      name: host02.example.com
      description: Example host
      force: yes
```


Example playbook to ensure host presence with a random password:

```yaml
---
- name: Ensure host with random password
  hosts: ipaserver
  become: true

  tasks:
  - name: Host host01.example.com present with random password
    ipahost:
      ipaadmin_password: SomeADMINpassword
      name: host01.example.com
      random: yes
      force: yes
      update_password: on_create
    register: ipahost

  - name: Print generated random password
    debug:
      var: ipahost.host.randompassword
```
Please remember that a new random password will be generated for an existing but not enrolled host if `update_password` is not limited to `on_create`. For an already enrolled host the task will fail with `update_password` default setting `always`.

Example playbook to ensure presence of several hosts with a random password:

```yaml
---
- name: Ensure hosts with random password
  hosts: ipaserver
  become: true

  tasks:
  - name: Hosts host01.example.com and host01.example.com present with random passwords
    ipahost:
      ipaadmin_password: SomeADMINpassword
      hosts:
      - name: host01.example.com
        random: yes
        force: yes
        update_password: on_create
      - name: host02.example.com
        random: yes
        force: yes
        update_password: on_create
    register: ipahost

  - name: Print generated random password for host01.example.com
    debug:
      var: ipahost.host["host01.example.com"].randompassword

  - name: Print generated random password for host02.example.com
    debug:
      var: ipahost.host["host02.example.com"].randompassword
```
Please remember that a new random password will be generated for an existing but not enrolled host if `update_password` is not limited to `on_create`. For an already enrolled host the task will fail with `update_password` default setting `always`.


Example playbook to ensure presence of host member principal:

```yaml
---
- name: Host present with principal
  hosts: ipaserver
  become: true

  tasks:
  - name: Host host01.example.com present with principals host/testhost01.example.com and host/myhost01.example.com
    ipahost:
      ipaadmin_password: SomeADMINpassword
      name: host01.example.com
      principal:
      - host/testhost01.example.com
      - host/myhost01.example.com
      action: member
```


Example playbook to ensure presence of host member certificate:

```yaml
- name: Host present with certificate
  hosts: ipaserver
  become: true

  tasks:
  - name: Host host01.example.com present with certificate
    ipahost:
      ipaadmin_password: SomeADMINpassword
      name: host01.example.com
      certificate:
      - MIIC/zCCAeegAwIBAg...
      action: member
```


Example playbook to ensure presence of member managedby_host for serveral hosts:

```yaml
---
- name: Host present with managedby_host
  hosts: ipaserver
  become: true

  tasks:
    ipahost:
      ipaadmin_password: SomeADMINpassword
      hosts:
      - name: host01.example.com
        managedby_host: server.example.com
      - name: host02.example.com
        managedby_host: server.example.com
      action: member
```


Example playbook to disable a host:

```yaml
---
- name: Playbook to handle hosts
  hosts: ipaserver
  become: true

  tasks:
  # Ensure host is disabled
  - ipahost:
      ipaadmin_password: SomeADMINpassword
      name: host01.example.com
      update_dns: yes
      state: disabled
```
`update_dns` controls if the DNS entries will be updated in this case. For `state` present it is controlling the update of the DNS SSHFP records, but not the the other DNS records.


Example playbook to ensure a host is absent:

```yaml
---
- name: Playbook to handle hosts
  hosts: ipaserver
  become: true

  tasks:
  # Ensure host is absent
  - ipahost:
      ipaadmin_password: password1
      name: host01.example.com
      state: absent
```


Variables
=========

Variable | Description | Required
-------- | ----------- | --------
`ipaadmin_principal` | The admin principal is a string and defaults to `admin` | no
`ipaadmin_password` | The admin password is a string and is required if there is no admin ticket available on the node | no
`ipaapi_context` | The context in which the module will execute. Executing in a server context is preferred. If not provided context will be determined by the execution environment. Valid values are `server` and `client`. | no
`ipaapi_ldap_cache` | Use LDAP cache for IPA connection. The bool setting defaults to yes. (bool) | no
`name` \| `fqdn` | The list of host name strings. `name` with *host variables* or `hosts` containing *host variables* need to be used. | no
**Host variables** | Only used with `name` variable in the first level. | no
`hosts` | The list of host dicts. Each `hosts` dict entry can contain **host variables**.<br>There is one required option in the `hosts` dict:| no
&nbsp; | `name` \| `fqdn` - The user name string of the entry. | yes
&nbsp; | **Host variables** | no
`update_password` |  Set password for a host in present state only on creation or always. It can be one of `always` or `on_create` and defaults to `always`. | no
`action` | Work on host or member level. It can be on of `member` or `host` and defaults to `host`. | no
`state` | The state to ensure. It can be one of `present`, `absent` or `disabled`, default: `present`. | yes


**Host Variables:**

Variable | Description | Required
-------- | ----------- | --------
`description` | The host description. | no
`locality` | Host locality (e.g. "Baltimore, MD"). | no
`location` \| `ns_host_location` | Host physical location hint (e.g. "Lab 2"). | no
`platform` \| `ns_hardware_platform` | Host hardware platform (e.g. "Lenovo T61"). | no
`os` \| `ns_os_version` | Host operating system and version (e.g. "Fedora 9"). | no
`password` \| `user_password` \| `userpassword` | Password used in bulk enrollment for absent or not enrolled hosts. | no
`random` \| `random_password` |  Initiate the generation of a random password to be used in bulk enrollment for absent or not enrolled hosts. | no
`certificate` \| `usercertificate` | List of base-64 encoded host certificates | no
`managedby` \| `principalname` \| `krbprincipalname` | List of hosts that can manage this host | no
`principal` \| `principalname` \| `krbprincipalname` | List of principal aliases for this host | no
`allow_create_keytab_user` \| `ipaallowedtoperform_write_keys_user` | Users allowed to create a keytab of this host. | no
`allow_create_keytab_group` \| `ipaallowedtoperform_write_keys_group` | Groups allowed to create a keytab of this host. | no
`allow_create_keytab_host` \| `ipaallowedtoperform_write_keys_host` | Hosts allowed to create a keytab of this host. | no
`allow_create_keytab_hostgroup` \| `ipaallowedtoperform_write_keys_hostgroup` | Host groups allowed to create a keytab of this host. | no
`allow_retrieve_keytab_user` \| `ipaallowedtoperform_read_keys_user` | Users allowed to retieve a keytab of this host. | no
`allow_retrieve_keytab_group` \| `ipaallowedtoperform_read_keys_group` | Groups allowed to retieve a keytab of this host. | no
`allow_retrieve_keytab_host` \| `ipaallowedtoperform_read_keys_host` | Hosts allowed to retieve a keytab of this host. | no
`allow_retrieve_keytab_hostgroup` \| `ipaallowedtoperform_read_keys_hostgroup` | Host groups allowed to retieve a keytab of this host. | no
`mac_address` \| `macaddress` | List of hardware MAC addresses. | no
`sshpubkey` \| `ipasshpubkey` | List of SSH public keys | no
`userclass` \| `class` | Host category (semantics placed on this attribute are for local interpretation) | no
`auth_ind` \| `krbprincipalauthind` | Defines an allow list for Authentication Indicators. Use 'otp' to allow OTP-based 2FA authentications. Use 'radius' to allow RADIUS-based 2FA authentications. Use empty string to reset auth_ind to the initial value. Other values may be used for custom configurations. An additional check ensures that only types can be used that are supported by the IPA version. Choices: ["radius", "otp", "pkinit", "hardened", "idp", ""] | no
`requires_pre_auth` \| `ipakrbrequirespreauth` | Pre-authentication is required for the service (bool) | no
`ok_as_delegate` \| `ipakrbokasdelegate` | Client credentials may be delegated to the service (bool) | no
`ok_to_auth_as_delegate` \| `ipakrboktoauthasdelegate` | The service is allowed to authenticate on behalf of a client (bool) | no
`force` | Force host name even if not in DNS. | no
`reverse` | Reverse DNS detection. | no
`ip_address` \| `ipaddress` | The host IP address list. It can contain IPv4 and IPv6 addresses. No conflict check for IP addresses is done. | no
`update_dns` | For existing hosts: DNS SSHFP records are updated with `state` present and all DNS entries for a host removed with `state` absent. | no


Return Values
=============

There are only return values if one or more random passwords have been generated.

Variable | Description | Returned When
-------- | ----------- | -------------
`host` | Host dict with random password. (dict) <br>Options: | If random is yes and host did not exist or update_password is yes
&nbsp; | `randompassword` - The generated random password | If only one host is handled by the module without using the `hosts` parameter.
&nbsp; | `name` - The host name of the host that got a new random password. (dict) <br> Options: <br> &nbsp; `randompassword` - The generated random password | If several hosts are handled by the module with the `hosts` parameter.


Authors
=======

Thomas Woerner

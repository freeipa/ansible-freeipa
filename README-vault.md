Vault module
===================

Description
-----------

The vault module allows to ensure presence and absence of vault and members of vaults.

The vault module is as compatible as possible to the Ansible upstream `ipa_vault` module, and additionally offers to make sure that vault members, groups and owners are present or absent in a vault, and allow the archival of data in vaults.


Features
--------
* Vault management


Supported FreeIPA Versions
--------------------------

FreeIPA versions 4.4.0 and up are supported by the ipavault module.


Requirements
------------

**Controller**
* Ansible version: 2.8+

**Node**
* Supported FreeIPA version (see above)
* KRA service must be enabled


Usage
=====

Example inventory file

```ini
[ipaserver]
ipaserver.test.local
```

Example playbook to make sure vault is present (by default, vault type is `symmetric`):

```yaml
---
- name: Playbook to handle vaults
  hosts: ipaserver
  become: true

  tasks:
  - ipavault:
      ipaadmin_password: SomeADMINpassword
      name: symvault
      password: SomeVAULTpassword
      description: A standard private vault.
```

Example playbook to make sure that a vault and its members are present:

```yaml
---
- name: Playbook to handle vaults
  hosts: ipaserver
  become: true

  tasks:
  - ipavault:
      ipaadmin_password: SomeADMINpassword
      name: symvault
      username: admin
      users: user01
```

`action` controls if the vault, data, member or owner will be handled. To add or remove members or vault data, set `action` to `member`.

Example playbook to make sure that a vault member is present in vault:

```yaml
---
- name: Playbook to handle vaults
  hosts: ipaserver
  become: true

  tasks:
  - ipavault:
      ipaadmin_password: SomeADMINpassword
      name: symvault
      username: admin
      users: user01
      action: member
```

Example playbook to make sure that a vault owner is absent in vault:

```yaml
---
- name: Playbook to handle vaults
  hosts: ipaserver
  become: true

  tasks:
  - ipavault:
      ipaadmin_password: SomeADMINpassword
      name: symvault
      username: admin
      owner: user01
      action: member
      state: absent
```

Example playbook to make sure vault data is present in a symmetric vault:

```yaml
---
- name: Playbook to handle vaults
  hosts: ipaserver
  become: true

  tasks:
  - ipavault:
      ipaadmin_password: SomeADMINpassword
      name: symvault
      username: admin
      password: SomeVAULTpassword
      data: >
        Data archived.
        More data archived.
      action: member
```

Example playbook to retrieve vault data from a symmetric vault:

```yaml
---
- name: Playbook to handle vaults
  hosts: ipaserver
  become: true

  tasks:
  - ipavault:
      ipaadmin_password: SomeADMINpassword
      name: symvault
      username: admin
      password: SomeVAULTpassword
      retrieve: true
      action: member
```

Example playbook to make sure vault data is absent in a symmetric vault:

```yaml
---
- name: Playbook to handle vaults
  hosts: ipaserver
  become: true

  tasks:
  - ipavault:
      ipaadmin_password: SomeADMINpassword
      name: symvault
      username: admin
      password: SomeVAULTpassword
      action: member
      state: absent
```

Example playbook to make sure vault is absent:

```yaml
---
- name: Playbook to handle vaults
  hosts: ipaserver
  become: true

  tasks:
  - ipavault:
      ipaadmin_password: SomeADMINpassword
      name: symvault
      username: admin
      state: absent
```

Variables
=========

ipavault
-------

Variable | Description | Required
-------- | ----------- | --------
`ipaadmin_principal` | The admin principal is a string and defaults to `admin` | no
`ipaadmin_password` | The admin password is a string and is required if there is no admin ticket available on the node | no
`name` \| `cn` | The list of vault name strings. | yes
`description` | The vault description string. | no
`nomembers` | Suppress processing of membership attributes. (bool) | no
`password ` \| `vault_password` \| `ipavaultpassword` | Vault password. | no
`public_key ` \| `vault_public_key` \| `ipavaultpublickey` | Base64 encoded vault public key. | no
`public_key_file` \| `vault_public_key_file` | Path to file with public key. | no
`private_key `\| `vault_private_key` | Base64 encoded vault private key. Used only to retrieve data. | no
`private_key_file` \| `vault_private_key_file` | Path to file with private key. | no
`salt` \| `vault_salt` \| `ipavaultsalt` | Vault salt. | no
`vault_type` \| `ipavaulttype` | Vault types are based on security level. It can be one of `standard`, `symmetric` or `asymmetric`, default: `symmetric` | no
`user` \| `username` | Any user can own one or more user vaults. | no
`service` | Any service can own one or more service vaults. | no
`shared` | Vault is shared. Default to false. (bool) | no
`users` | Users that are members of the vault. | no
`groups` | Groups that are member of the vault. | no
`services` | Services that are member of the vault. | no
`data` \|`vault_data` \| `ipavaultdata` | Data to be stored in the vault. | no
`in` \| `datafile_in` | Path to file with data to be stored in the vault. | no
`out` \| `datafile_out` | Path to file to store data retrieved from the vault. | no
`retrieve` | If set to True, retrieve data stored in the vault. (bool) | no
`action` | Work on vault or member level. It can be on of `member` or `vault` and defaults to `vault`. | no
`state` | The state to ensure. It can be one of `present` or `absent`, default: `present`. | no


Notes
=====

ipavault uses a client context to execute, and it might affect execution time.


Authors
=======

Rafael Jeffman

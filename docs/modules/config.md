Config module
===========

Description
-----------

The config module allows the setting of global config parameters within IPA. If no parameters are specified it returns the list of all current parameters.

The config module is as compatible as possible to the Ansible upstream `ipa_config` module, but adds many additional parameters


Features
--------
* IPA server configuration management


Supported FreeIPA Versions
--------------------------

FreeIPA versions 4.4.0 and up are supported by the ipaconfig module.

Some variables are only supported on newer versions of FreeIPA. Check `Variables` section for details.

Requirements
------------

**Controller**
* Ansible version: 2.8+

**Node**
* Supported FreeIPA version (see above)


Usage
=====

Example inventory file

```ini
[ipaserver]
ipaserver.test.local
```


Example playbook to read config options:

```yaml
---
- name: Playbook to handle global config options
  hosts: ipaserver
  become: true
  tasks:
    - name: return current values of the global configuration options
      ipaconfig:
        ipaadmin_password: password
      register: result
    - name: display default login shell
      debug:
        msg: '{{result.config.defaultlogin }}'

    - name: ensure defaultloginshell and maxusernamelength are set as required
      ipaconfig:
        ipaadmin_password: password
        defaultlogin: /bin/bash
        maxusername: 64
```

```yaml
---
- name: Playbook to ensure some config options are set
  hosts: ipaserver
  become: true
  tasks:
    - name: set defaultlogin and maxusername
      ipaconfig:
        ipaadmin_password: password
        defaultlogin: /bin/bash
        maxusername: 64
```


Variables
=========

ipauser
-------

**General Variables:**

Variable | Description | Required
-------- | ----------- | --------
`ipaadmin_principal` | The admin principal is a string and defaults to `admin` | no
`ipaadmin_password` | The admin password is a string and is required if there is no admin ticket available on the node | no
`maxusername` \| `ipamaxusernamelength` |  Set the maximum username length (1 to 255) | no
`maxhostname` \| `ipamaxhostnamelength` |  Set the maximum hostname length between 64-255. Only usable with IPA versions 4.8.0 and up. | no
`homedirectory` \| `ipahomesrootdir` |  Set the default location of home directories | no
`defaultshell` \| `ipadefaultloginshell` |  Set the default shell for new users | no
`defaultgroup` \| `ipadefaultprimarygroup` |  Set the default group for new users | no
`emaildomain`\| `ipadefaultemaildomain`  |  Set the default e-mail domain | false
`searchtimelimit` \| `ipasearchtimelimit` |  Set maximum amount of time (seconds) for a search -1 to 2147483647 (-1 or 0 is unlimited) | no
`searchrecordslimit` \| `ipasearchrecordslimit` |  Set maximum number of records to search -1 to 2147483647 (-1 or 0 is unlimited) | no
`usersearch` \| `ipausersearchfields` |  Set list of fields to search when searching for users | no
`groupsearch` \| `ipagroupsearchfields` |  Set list of fields to search in when searching for groups | no
`enable_migration` \| `ipamigrationenabled` |  Enable migration mode (choices: True, False ) | no
`groupobjectclasses` \| `ipagroupobjectclasses` |  Set default group objectclasses (list) | no
`userobjectclasses` \| `ipauserobjectclasses` |  Set default user objectclasses (list) | no
`pwdexpnotify` \| `ipapwdexpadvnotify` |  Set number of days's notice of impending password expiration (0 to 2147483647) | no
`configstring` \| `ipaconfigstring` |  Set extra hashes to generate in password plug-in (choices:`AllowNThash`, `KDC:Disable Last Success`, `KDC:Disable Lockout`, `KDC:Disable Default Preauth for SPNs`). Use `""` to clear this variable. | no
`selinuxusermaporder` \| `ipaselinuxusermaporder`| Set ordered list in increasing priority of SELinux users | no
`selinuxusermapdefault`\| `ipaselinuxusermapdefault` |  Set default SELinux user when no match is found in SELinux map rule | no
`pac_type` \| `ipakrbauthzdata` |  set default types of PAC supported for services (choices: `MS-PAC`, `PAD`, `nfs:NONE`). Use `""` to clear this variable. | no
`user_auth_type` \| `ipauserauthtype` |  set default types of supported user authentication (choices: `password`, `radius`, `otp`, `disabled`). Use `""` to clear this variable. | no
`domain_resolution_order` \| `ipadomainresolutionorder` | Set list of domains used for short name qualification | no
`ca_renewal_master_server` \| `ipacarenewalmasterserver`| Renewal master for IPA certificate authority. | no


Return Values
=============

Variable | Description | Returned When
-------- | ----------- | -------------
`config` | config dict <br />Fields: | No values to configure are specified
&nbsp; | `maxusername` | &nbsp;
&nbsp; | `maxhostname` | &nbsp;
&nbsp; | `homedirectory` | &nbsp;
&nbsp; | `defaultshell` | &nbsp;
&nbsp; | `defaultgroup` | &nbsp;
&nbsp; | `emaildomain` | &nbsp;
&nbsp; | `searchtimelimit` | &nbsp;
&nbsp; | `searchrecordslimit` | &nbsp;
&nbsp; | `usersearch` | &nbsp;
&nbsp; | `groupsearch` | &nbsp;
&nbsp; | `enable_migration` | &nbsp;
&nbsp; | `groupobjectclasses` | &nbsp;
&nbsp; | `userobjectclasses` | &nbsp;
&nbsp; | `pwdexpnotify` | &nbsp;
&nbsp; | `configstring` | &nbsp;
&nbsp; | `selinuxusermapdefault` | &nbsp;
&nbsp; | `selinuxusermaporder` | &nbsp;
&nbsp; | `pac_type` | &nbsp;
&nbsp; | `user_auth_type` | &nbsp;
&nbsp; | `domain_resolution_order` | &nbsp;
&nbsp; | `ca_renewal_master_server` | &nbsp;

All returned fields take the same form as their namesake input parameters

Authors
=======

Chris Procter

Idp module
============

Description
-----------

The idp module allows to ensure presence and absence of idps.

Features
--------

* Idp management


Supported FreeIPA Versions
--------------------------

FreeIPA versions 4.4.0 and up are supported by the ipaidp module.


Requirements
------------

**Controller**
* Ansible version: 2.13

**Node**
* Supported FreeIPA version (see above)


Usage
=====

Example inventory file

```ini
[ipaserver]
ipaserver.test.local
```


Example playbook to make sure keycloak idp my-keycloak-idp is present:

```yaml
---
- name: Playbook to manage IPA idp.
  hosts: ipaserver
  become: false

  tasks:
  - name: Ensure keycloak idp my-keycloak-idp is present
    ipaidp:
      ipaadmin_password: SomeADMINpassword
      name: my-keycloak-idp
      provider: keycloak
      organization: main
      base_url: keycloak.idm.example.com:8443/auth
      client_id: my-client-id
```


Example playbook to make sure keycloak idp my-keycloak-idp is absent:

```yaml
---
- name: Playbook to manage IPA idp.
  hosts: ipaserver
  become: false

  tasks:
  - name: Ensure keycloak idp my-keycloak-idp is absent
    ipaidp:
      ipaadmin_password: SomeADMINpassword
      name: my-keycloak-idp
      delete_continue: true
      state: absent
```


Example playbook to make sure github idp my-github-idp is present:

```yaml
---
- name: Playbook to manage IPA idp.
  hosts: ipaserver
  become: false

  tasks:
  - name: Ensure github idp my-github-idp is present
    ipaidp:
      ipaadmin_password: SomeADMINpassword
      name: my-github-idp
      provider: github
      client_id: my-github-client-id
```


Example playbook to make sure google idp my-google-idp is present using provider defaults without specifying provider:

```yaml
---
- name: Playbook to manage IPA idp.
  hosts: ipaserver
  become: false

  tasks:
  - name: Ensure google idp my-google-idp is present using provider defaults without specifying provider
    ipaidp:
      ipaadmin_password: SomeADMINpassword
      name: my-google-idp
      auth_uri: https://accounts.google.com/o/oauth2/auth
      dev_auth_uri: https://oauth2.googleapis.com/device/code
      token_uri: https://oauth2.googleapis.com/token
      keys_uri: https://www.googleapis.com/oauth2/v3/certs
      userinfo_uri: https://openidconnect.googleapis.com/v1/userinfo
      client_id: my-google-client-id
      scope: "openid email"
      idp_user_id: email
```


Example playbook to make sure google idp my-google-idp is present using provider:

```yaml
---
- name: Playbook to manage IPA idp.
  hosts: ipaserver
  become: false

  tasks:
  - name: Ensure google idp my-google-idp is present using provider
    ipaidp:
      ipaadmin_password: SomeADMINpassword
      name: my-google-idp
      provider: google
      client_id: my-google-client-id
```


Example playbook to make sure idps my-keycloak-idp, my-github-idp and my-google-idp are absent:

```yaml
---
- name: Playbook to manage IPA idp.
  hosts: ipaserver
  become: false

  tasks:
  - name: Ensure idps my-keycloak-idp, my-github-idp and my-google-idp are absent
    ipaidp:
      ipaadmin_password: SomeADMINpassword
      name:
      - my-keycloak-idp
      - my-github-idp
      - my-google-idp
      delete_continue: true
      state: absent
```


Variables
---------

Variable | Description | Required
-------- | ----------- | --------
`ipaadmin_principal` | The admin principal is a string and defaults to `admin` | no
`ipaadmin_password` | The admin password is a string and is required if there is no admin ticket available on the node | no
`ipaapi_context` | The context in which the module will execute. Executing in a server context is preferred. If not provided context will be determined by the execution environment. Valid values are `server` and `client`. | no
`ipaapi_ldap_cache` | Use LDAP cache for IPA connection. The bool setting defaults to true. (bool) | false
`name` \| `cn` | The list of idp name strings. | yes
auth_uri \| ipaidpauthendpoint | OAuth 2.0 authorization endpoint string. | no
dev_auth_uri \| ipaidpdevauthendpoint | Device authorization endpoint string. | no
token_uri \| ipaidptokenendpoint | Token endpoint string. | no
userinfo_uri \| ipaidpuserinfoendpoint | User information endpoint string. | no
keys_uri \| ipaidpkeysendpoint | JWKS endpoint string. | no
issuer_url \| ipaidpissuerurl | The Identity Provider OIDC URL string. | no
client_id \| ipaidpclientid | OAuth 2.0 client identifier string. | no
secret \| ipaidpclientsecret | OAuth 2.0 client secret string. | no
scope \| ipaidpscope | OAuth 2.0 scope string. Multiple scopes separated by space. | no
idp_user_id \| ipaidpsub | Attribute string for user identity in OAuth 2.0 userinfo. | no
provider \| ipaidpprovider | Pre-defined template string. This provides the provider defaults, which can be overridden with the other IdP options. Choices: ["google","github","microsoft","okta","keycloak"] | no
organization \| ipaidporg | Organization ID string or Realm name for IdP provider templates. | no
base_url \| ipaidpbaseurl | Base URL string for IdP provider templates. | no
rename \| new_name | New name for the Identity Provider server object. Only with `state: renamed`. | no
delete_continue \| continue | Continuous mode. Don't stop on errors. Valid only if `state` is `absent`. | no
`state` | The state to ensure. It can be one of `present`, `absent`, `renamed`, default: `present`. | no


Authors
=======

Thomas Woerner

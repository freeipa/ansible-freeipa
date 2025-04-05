ansible-freeipa testing scenarios
=================================

The ansible-freeipa testing scenarios are a collection of scripts and configuration files to aid on the creation of environments composed of single or multiple IPA deployments, each one with one or more hosts, and external hosts like name servers or Samba Active Directory Domain Controllers.

The environment created is based on rootless containers (what itself may impose some limits and restrictions on testing) that are part of a `pod`. A custom bridge network is used for the `pod`.


Dependencies
------------

* ipalab-config version 0.10.3 or later
* podman-compose
* podman

All dependencies can be installed in a Python virtual environment.


Scenarios
---------

The following test scenarios are currently available:

**ipa-ad-trust.yml**

A scenario with one server, one client and one node not part of the IPA deployment running Samba AD DC. This scenario can be used to run AD related tests.


Restrictions
------------

When creating new scenarios, these rules apply:

* All scenarios `lab_name` must be `ansible-freeipa-scenario`
* All playbooks to be executed when starting a scenario must named starting with `config_`
* There's no guarantee on the order the configuration playbooks will be executed
* Non-IPA nodes are deployed before the IPA clusters


Usage Example
-------------

In this example a scenario with a server, a client and an AD Domain Controller (Samba) is created:

```
$ infra/scenarios/start-scenario infra/scenarios/ipa-ad-trust.yml
```

After the scenario is used, it can be shutdown with:

```
$ infra/scenarios/stop-scenario
```

To choose the distribution used for the IPA cluster, use the `-d` option:

```
$ infra/scenarios/start-scenario -d c9s infra/scenarios/ipa-ad-trust.yml
```


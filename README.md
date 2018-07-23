FreeIPA Ansible roles
=====================

This repository contains [Ansible](https://www.ansible.com/) roles and playbooks to install and uninstall [FreeIPA](https://www.freeipa.org/) `servers`, `replicas` and `clients`.

**Note**: The ansible playbooks and roles require a configured ansible environment where the ansible nodes are reachable and are properly set up to have an IP address and a working package manager.

Supported FreeIPA versions
--------------------------

For now only FreeIPA versions 4.5 and up are supported. The client role should also be functional with FreeIPA 4.4.

Supported Distributions
-----------------------

* RHEL/CentOS 7.4+
* Fedora 26+
* Ubuntu

Roles
-----

* [Server](SERVER.md)
* [Replica](REPLICA.md)
* [Client](CLIENT.md)

Examples
--------

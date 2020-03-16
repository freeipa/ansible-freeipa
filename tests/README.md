# Ansible FreeIPA Test Playbooks

This directory contains a series of playbooks used to test the idempotency of roles and modules provided by ansible-freeipa.


## Requirements

The only requirement to run ansible-freeipa tests it's to have a server with freeipa installed.

To help with that we provide a Vagrantfile with the base configuration for the tests. In order to use
`vagrant` to run the tests you will need to install the plugins `vagrant-hostmanager` and `vagrant-libvirt`.

On Fedora those can be installed with the following command: `dnf install vagrant vagrant-hostmanager vagrant-libvirt`

While virtualbox provider should also work this test environment is only tested and mainteined for libvirt.

To use libvirt as provider you can use the variables:

```
VAGRANT_DEFAULT_PROVIDER="libvirt"
LIBVIRT_DEFAULT_URI="qemu:///system"
```



## Topology

The topology implemented by the vagrant file consists of:

* 1 - Controller (a vagrant box where ansible will be called from);
* 1 - IPA server


## Provisioning the VMs

Before running the tests you will need to spin the controller and server boxes with  `vagrant up`.

After you have the machines started you will be able to install your IPA cluster running: `./vagrant-install-ipa.sh`


## Running the tests

To run a test playbook run `./run-test-in-vagrant.sh <playbook>`. For example: `./run-test-in-vagrant.sh host/test_hosts.yml`


## Destroying the VMs

Just run `vagrant destroy`


## Troubleshooting


### Host stuck trying to get IP address in vagrant up

Sometimes vagrant up command gets stuck "Waiting for domain to get an IP address". If that happens you can stop the command pressing 'ctrl-c' 2 times.

After that you can destroy the vm using `vagrant destroy <vm-name>` and try to create it again.



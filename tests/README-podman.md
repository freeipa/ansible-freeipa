# Testing ansible-freeipa modules with podman

> This document describe the rationale, design and usage of `utils/ansible-freeipa-test.sh`.<br>
> For the impatient, if you have [podman] installed, run `utils/ansible-freeipa-test.sh -m config` from the project root directory.

## Introduction

`ansible-freeipa` relies on two types of tests to verify the behavior is consistent with the modules design. There are pytest tests and Ansible playbook tests. All modules must provide a series of tasks in one or more Ansible playbook to test module behavior and idempotence verification, to be considered for inclusion.

Each pull request triggers the execution of all registered tests, for all modules, given the environment is available, so it is possible to verify that the changes do not break existing behavior. The tests also run on different versions of FreeIPA, namely, the available versions for CentOS 7, CentOS 8, and the latest Fedora version.

The problem is that, when executed in parallel, it takes about an hour to execute all tests in the current CI environment (as of May 2020), and it is not practical to wait so long to test minor modifications.

An alternative to running tests in the CI is to have a FreeIPA server installation in a virtual machine (e.g. with libvirt), as use the development workstation as an Ansible controller to that server, to verify the module behavior. It works very well, as is a recommended setup for testing, as it allows for different Linux distributions, different FreeIPA versions, etc.

Although the recommended way of testing `ansible-freeipa` is with a virtual machine, it also has some drawbacks, as requiring a virtual machine to be set, and having the available resources to run the virtualization along with the development environment.

Using containers is a lightweight version of the setup with a virtual machine, and, although it shows some limitations, it is a fast and easier to configure way of testing `ansible-freeipa` modules.

> NOTE: Tests with podman have only been tested under Fedora, but we'd like to hear about the experience in other environments.

## Prerequisites

The current size of the testing container is 1.4GB. FreeIPA requires about 2GB of free RAM.

If you have [podman] installed and working on your environment, and the available hardware requirements, `ansible-freeipa-test.sh` should work. Please, [open an issue] if it doesn't (don't forget to detail your environment and issues).

You will also need Python available, and in your `PATH`, and network connection allowing you to download data from https://quay.io.

## Using `ansible-freeipa-test.sh`

`ansible-freeipa-test.sh` is used to run playbook tests for `ansible-freeipa`. The tests are executed using a podman container as the FreeIPA server, and the almost all software infrastructure is installed in a Python virtual environment, using `pip`. This way, the environment is somewhat isolated from the development machine.

There are two options to prepare your testing environment, it is suggested that you take the easier path, which is described here. The hardest path is to create the containers and virtual environment yourself, where you have more flexibility, but are on your own.

There are a few options for `ansible-freeipa-test.sh`, here is the output of its usage message (displayed when using `-h`):

```
usage: ansbile-freeipa-test.sh [-v...] [-h] [-p CONTAINER] [-e VENV]
			                   [-m MODULE] [TEST...]

Run ansible-freeipa tests in a podman container, using a virtual environment.

position arguments:
  TEST                A list of playbook tests to be executed.
                      Either a TEST or a MODULE must be provided.

optional arguments:
  -h                  display this help message and exit.
  -v                  verbose mode (You may use -vvv or -vvvvv for
                      increased information.)
  -p CONTAINER        use the container with name/id CONTAINER.
                      default: dev-test-master
  -C                  If container did not exist, do not stop and
                      remove created container at exit.
  -e VENV             use the virtual environment VENV
                      default: asible-freeipa-tests
  -m MODULE           Add all tests for the MODULE (e.g.: -m config).
  -x                  Stop on first test failure.
```

You can use it to run single specific tests, or all tests for a module (all `test_*` found, recursively, in `tests/<MODULE>`). By issuing `utils/ansible-freeipa-test.sh tests/group/test_group.yml`, the selected playook will be executed, but if you use `utils/ansible-freeipa-test.sh -m dnszone`, all tests in `tests/dnszone` will be executed (`test_dnszone.yml`, `test_dnszone_mod.yml` and `test_dnszone_name_from_ip.yml`).

When you provide a set of tests (or modules) for `ansible-freeipa-test.sh`, it will create a container within [podman], based on `ansible-freeipa` CI's Fedora image. It will also create a Python virtual environment, where all the required tools will be installed. Neither your system installation, nor your user configuration is modified to install the used tools.

After the selected tests are executed, the container is stopped and removed (unles `-C` is used), but the image is kept. This prevents downloading the same image again. Your local image will be updated by `ansible-freeipa-test.sh`, if, when executing it, it finds that the upstream CI images has been updated.

Regular `podman` commands can be used to manage the container and images.

## Issues

While testing `ansible-freeipa` modules with [podman] and [Ansible] provides a very good baseline to check for development status of the module, some issues are still present. This list is not exaustive, but contain some common behaviors you will encounter when using `ansible-freeipa-test.sh`.

### Ansible warning messages

Currently there are some Ansible warning messages that can be safely ignored and will be fixed in the future.

> ```
[WARNING]: Unhandled error in Python interpreter discovery for host dev-test-
master: Expecting value: line 1 column 1 (char 0)```

This message has only been seen when running the Ansible playbooks with podman. It looks like an Ansible limitation, and does not interfere with tests, as far the script has been tested.

>```[WARNING]: Platform linux on host dev-test-master is using the discovered
Python interpreter at /usr/bin/python, but future installation of another
Python interpreter could change this. See https://docs.ansible.com/ansible/2.9/
reference_appendices/interpreter_discovery.html for more information.```

This message is shown on every Ansible execution, and will be removed in a future release of `ansilbe-freeipa`.

### Container is (or is not) removed.

When a test container does not exist, the default behavior is for `ansible-freeipa-test.sh` to create a new container and remove it after executing tests. If a test fails, the container is not removed, and this is on purpose. You may inspect container status with `podman exec -it <container_name> bash`.

If you want the container to be available, even if tests pass, use the `-C` option.


[ansible]: https://ansible.com
[podman]: https://podman.io
[open an issue]: https://github.com/freeipa/ansible-freeipa/issues/new

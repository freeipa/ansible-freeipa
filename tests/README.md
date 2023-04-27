# Running the tests

## Before starting

In order to run ansible-freeipa tests you will need to install the dependencies listed in the file `requirements-tests.txt` in your local machine. We'll call this local machine `controller`.

You will also need to have a remote host with freeipa server installed and configured. We'll call this remote host `ipaserver`.

Some other requirements:

 * The `controller` must be able to connect to `ipaserver` through ssh using keys.
 * IPA admin password must be `SomeADMINpassword`.
 * Directory Server admin password must be `SomeDMpassword`.

To provide broader test coverage, `ipaserver` should be configured with DNS and KRA support, and playbook tests are written based on this configuration. Without such support, some tests are expected to fail. Use a different configuration to evaluate those scenarios. See also [ipaserver role](../roles/ipaserver/README.md).

## Running the tests

To run the tests run:

```
IPA_SERVER_HOST=<ipaserver_host_or_ip> pytest
```

If you need to run using a different user you can use `ANSIBLE_REMOTE_USER`
environment variable. For example:

```
ANSIBLE_REMOTE_USER=root IPA_SERVER_HOST=<ipaserver_host_or_ip> pytest
```

If you want to use ssh with password, you must set `IPA_SSH_PASSWORD`
environment variable. For example:

```
IPA_SSH_PASSWORD=<ipaserver_ssh_password> IPA_SERVER_HOST=<ipaserver_host_or_ip> pytest
```


To run a single test use the full path with the following format:

```
IPA_SERVER_HOST=<ipaserver_host_or_ip> pytest tests/test_playbook_runs.py::sudorule::test_sudorule
```

To select which tests to run based on search use the option `-k`. For example:

```
IPA_SERVER_HOST=<ipaserver_host_or_ip> pytest -k dnszone
```

To see the ansible output use the option `--capture=sys`. For example:

```
IPA_SERVER_HOST=<ipaserver_host_or_ip> pytest --capture=sys
```

To see why tests were skipped use `-rs`. For example:

```
IPA_SERVER_HOST=<ipaserver_host_or_ip> pytest -rs
```

For a complete list of options check `pytest --help`.

### Disabling and enabling playbook tests

Sometimes it is useful to enable or disable specific playbook tests. To only run a subset of modules or tests, use the variables IPA_ENABLED_MODULES and IPA ENABLED_TESTS, to define a comma-separated list of modules or tests to be enabled. Any test or module not in the list will not be executed. For example, to run only `sudorule` and `sudocmd` tests:

```
IPA_ENABLE_MODULES="sudorule,sudocmd" IPA_SERVER_HOST=<ipaserver_host_or_ip> pytest
```

If all but a few selected tests are to be executed, use the IPA_DISABLED_MODULES or IPA_DISABLED_TESTS. For example, to run all, but "test_service_certificate" test:

```
IPA_DISABLED_TESTS=test_service_certificate IPA_SERVER_HOST=<ipaserver_host_or_ip> pytest
```

If none of this variables are defined, all tests will be executed.

To configure the tests that will run for your pull request, add a TEMP commit, with the configuration defined in the file `tests/azure/templates/variables.yml`. Set the variables `ipa_enable_modules`, `ipa_enable_tests`, `ipa_disable_modules`, and `ipa_disable_tests`, in the same way as the equivalent environment variables.

### Types of tests

#### Playbook tests

The playbook tests will run our roles / modules using Ansible with various parameters. Most of these tests will be executed more than once, to verify idempotence. In  general those tests don't verify the state of the machine after the playbook is executed.

To select only these tests use the option `-m "playbook"`

#### Python tests (pytests)

The pytests are tests that will execute small playbooks and then will verify the test results immediately after, using python code for that.

To select only these tests on a test execution use the option `-m "not playbook"`.


## Running tests in a docker container

It's also possible to run the tests in a container.

### Creating a container to run the tests

Before setting up a container you will need to install molecule framework:

```
pip install molecule-plugins[docker]
```

Now you can start a test container using the following command:
```
molecule create -s c8s
```

Note: Currently the containers available for running the tests are:
 * fedora-latest
 * centos-7
 * c8s
 * c9s

### Running the tests inside the container

To run the tests you will use pytest (works the same as for VMs).

```
RUN_TESTS_IN_DOCKER=1 IPA_SERVER_HOST=c8s pytest
```

### Cleaning up after tests

After running the tests you should probably destroy the test container using:

```
molecule destroy -s c8s
```

See [Running the tests](#running-the-tests) section for more information on available options.


## Running local tests with upstream CI images

To run tests locally using the same images used by upstream CI use `utils/run-tests.sh`.

```
utils/run-tests.sh tests/config/test_config.yml
```

To run all tests for a single plugin, use the `-s` option with plugin directory name. This will search, recursively for playbooks named with the pattern `test_*.yml`. To run all playbook tests for `ipauser`:

```
utils/run-tests.sh -s user
```

When executed, `utils/run-tests.sh` will create a container (either using `docker` or `podman`) using one of the testing ansible-freeipa images (https://quay.io/repository/ansible-freeipa/upstream-tests?tab=tags), run the selected tests against the container, and remove the container after tests are executed. If a test fails the container is not removed, so the failure can be investigated.

It is possible to keep the container after the execution, even if tests succeed, using the `-C` option:

```
utils/run-tests.sh -s config -C
```

By default the tests are executed against the latest version of the Fedora image (`fedora-latest`). The testing image can be selected with the `-i` option. Use `-l` to list the available image names.

```
utils/run-tests.sh -i c9s tests/host/test_host.yml
```


## Upcoming/desired improvements:

* A script to pre-config the complete test environment using virsh.
* A test matrix to run tests against different distros in parallel (probably using tox).

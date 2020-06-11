# Running the tests

## Before starting

In order to run ansible-freeipa tests you will need to have `ansible` and `pytest` installed on your machine. We'll call this local machine `controller`.

You will also need to have a remote host with freeipa server installed and configured. We'll call this remote host `ipaserver`.

Some other requirements:

 * The `controller` must be able to connect to `ipaserver` through ssh using keys.
 * `ipaserver` must be configured with DNS support. See [ipaserver role](../roles/ipaserver/README.md).
 * IPA admin password must be `SomeADMINpassword`.
 * Directory Server admin password must be `SomeDMpassword`.


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

To select which tests to run use the option `-k`. For example:

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


## Upcoming/desired improvements:

* A script to pre-config the complete test environment using virsh.
* A test matrix to run tests against different distros in parallel (probably using tox).
* Allow to connect to `ipaserver` using ssh and password.


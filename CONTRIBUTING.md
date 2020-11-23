Contributing to ansible-freeipa
===============================

As part of the [FreeIPA] project, ansible-freeipa follows
[FreeIPA's Code of Conduct].


Reporting bugs or Features
--------------------------

ansible-freeipa uses [Github issues] for the upstream development, so all RFEs
and bug reports should be added there.

If you have questions about the usage of ansible-freeipa modules and roles,
you should also submit an issue, so that anyone that knows an answer can help.


Development
-----------

Contribute code by submitting a [pull request]. All pull requests should be
created against the `master` branch. If your PR fixes an open issue, please,
add this information to the commit message, like _"Fix issue #num"_.

Every PR will have to pass some automatic checks and be reviewed by another
developer(s). Once they are approved, they will be merged.

In your commits, use clear messages that include intent, summary of changes,
and expected result. Use a template commit message [for modules] and
[for roles].

Upon review, it is fine to `force push` the changes.

**Preparing the development environment**

There are some useful tools that will help you develop for ansible-freeipa,
and you should install, at least, the modules in `requirements.txt`. You
can install the modules with your distribution package manager, or use pip,
as in the example:

```
python3 -m pip install --user -r requirements-dev.txt
```

We recommend using [pre-commit] so that the basic checks that will be executed
for your PR are executed locally, on your commits. To setup the pre-commit
hooks, issue the command:

```
pre-commit install
```

**Developing new modules**

When developing new modules use the script `utils/new_module`. If the module
should have `action: member` support, use the flag `-m`.

This script will create the basic structure for the module, the required files
for tests, playbooks, documentation and source code, all at the appropriate
places.


**Other helpfull tools**

Under directory `utils`, you will find other useful tools, like
**lint-check.sh**, which will run the Python and YAML linters on your code,
and **ansible-doc-test** which will verify if the documentation added to the
roles and modules source code has the right format.


Testing
-------

When testing ansible-freeipa's roles and modules, we aim to check if they
do what they intend to do, report the results correctly, and if they are
idempotent (although, sometimes the operation performed is not, like when
renaming items). To achieve this, we use Ansible playbooks.

The Ansible playbooks test can be found under the [tests] directory. They
should test the behavior of the module or role, and, if possible, provide
test cases for all attributes.

There might be some limitation on the testing environment, as some attributes
or operations are only available in some circumstances, like specific FreeIPA
versions, or some more elaborate scenarios (for example, requiring a
configured trust to an AD domain). For these cases, there are some `facts`
available that will only enable the tests if the testing environment is
enabled.

The tests run automatically on every pull request, using Fedora, CentOS 7,
and CentOS 8 environments.

See the document [Running the tests] and also the section `Preparing the
development environment`, to prepare your environment.


Documentation
-------------

We do our best to provide a correct and complete documentation for the modules
and roles we provide, but we sometimes miss something that users find it
important to be documented.

If you think something could be made easier to understand, or found an error
or omission in the documentation, fixing it will help other users and make
the experience on using the project much better.

Also, the [playbooks] can be seen as part of the documentation, as they are
examples of commonly performed tasks.

---
[FreeIPA]: https://freeipa.org
[FreeIPA's Code of Conduct]: https://github.com/freeipa/freeipa/blob/master/CODE_OF_CONDUCT.md
[for modules]: https://github.com/freeipa/ansible-freeipa/pull/357
[for roles]: https://github.com/freeipa/ansible-freeipa/pull/430
[Github issues]: https://github.com/freeipa/ansible-freeipa/issues
[pull request]: https://github.com/freeipa/ansible-freeipa/pulls
[playbooks]: playbooks
[pre-commit]: https://pre-commit.com
[Running the tests]: tests/README.md
[tests]: tests/

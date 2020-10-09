# Writing a new Ansible FreeIPA module

## Minimum requirements
A ansible-freeipa module should have:

* Code:
  * A module file placed in `plugins/modules/ipa<module_name>.py`

* Documentation:
  * `<module_name>.md` file placed under `docs/modules` and linked from the main README.md
  * Example playbooks under `playbooks/<module_name>/` directory

* Tests:
  * Test cases (also playbooks) defined in `tests/<module_name>/test_<something>.yml`. If needed, this directory might contain multiple files.

## Code

The module file have to start with the python shebang line, GPL license header and definition of the constants `ANSIBLE_METADATA`, `DOCUMENTATION`, `EXAMPLES` and `RETURNS`. Those constants need to be defined before the code (even imports). See https://docs.ansible.com/ansible/latest/dev_guide/developing_modules_general.html#starting-a-new-module for more information.

The script `utils/new_module` will help to create the basic structure required for a new module, but it will not add the link for the module documentation to the main README.md file.

Remember that your module should follow the same behavior as the FreeIPA command line tools, and it might provide support for more than one command, for example when the module has to manage members.

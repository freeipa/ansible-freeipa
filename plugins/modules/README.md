# Writing a new Ansible FreeIPA module

A ansible-freeipa module should have:

* Code:
  * A module file placed in `plugins/modules/<ipa_module_name>.py`

* Documentation:
  * `README-<module_name>.md` file in the root directory and linked from the main README.md
  * Example playbooks in `playbooks/<module_name>/` directory

* Tests:
  * Test cases (also playbooks) defined in `tests/<module_name>/test_<something>.yml`. It's ok to have multiple files in this directory.

Use the script `utils/new_module` to create the stub files for a new module.

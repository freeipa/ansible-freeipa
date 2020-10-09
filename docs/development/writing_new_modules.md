# Writing a new Ansible FreeIPA module

## Minimum requirements
A ansible-freeipa module should have:

* Code:
  * A module file placed in `plugins/modules/<ipa_module_name>.py`

* Documentation:
  * `README-<module_name>.md` file in the root directory and linked from the main README.md
  * Example playbooks in `playbooks/<module_name>/` directory

* Tests:
  * Test cases (also playbooks) defined in `tests/<module_name>/test_<something>.yml`. It's ok to have multiple files in this directory.

## Code

The module file have to start with the python shebang line, license header and definition of the constants `ANSIBLE_METADATA`, `DOCUMENTATION`, `EXAMPLES` and `RETURNS`. Those constants need to be defined before the code (even imports). See https://docs.ansible.com/ansible/latest/dev_guide/developing_modules_general.html#starting-a-new-module for more information.


Although it's use is not yet required, ansible-freeipa provides `FreeIPABaseModule` as a helper class for the implementation of new modules. See the example bellow:

```python

from ansible.module_utils.ansible_freeipa_module import FreeIPABaseModule


class SomeIPAModule(FreeIPABaseModule):
    ipa_param_mapping = {
        "arg_to_be_passed_to_ipa_command": "module_param",
        "another_arg": "get_another_module_param",
    }

    def get_another_module_param(self):
        another_module_param = self.ipa_params.another_module_param

        # Validate or modify another_module_param ...

        return another_module_param

    def check_ipa_params(self):

        # Validate your params here ...

        # Example:
        if not self.ipa_params.module_param in VALID_OPTIONS:
            self.fail_json(msg="Invalid value for argument module_param")

    def define_ipa_commands(self):
        args = self.get_ipa_command_args()

        self.add_ipa_command("some_ipa_command", name="obj-name", args=args)


def main():
    ipa_module = SomeIPAModule(argument_spec=dict(
        module_param=dict(type="str", default=None, required=False),
        another_module_param=dict(type="str", default=None, required=False),
    ))
    ipa_module.ipa_run()


if __name__ == "__main__":
    main()
```

In the example above, the module will call the command `some_ipa_command`, using "obj-name" as name and, `arg_to_be_passed_to_ipa_command` and `another_arg` as arguments.

The values of the arguments will be determined by the class attribute `ipa_param_mapping`.

In the case of `arg_to_be_passed_to_ipa_command` the key (`module_param`) is defined in the module `argument_specs` so the value of the argument is actually used.

On the other hand, `another_arg` as mapped to something else: a callable method. In this case the method will be called and it's result used as value for `another_arg`.

**NOTE**: Keep mind that to take advantage of the parameters mapping defined in `ipa_param_mapping` you will have to call `args = self.get_ipa_command_args()` and use `args` in your command. There is no implicit call of this method.


## Disclaimer

The `FreeIPABaseModule` is new and might not be suitable to all cases and every module yet. In case you need to extend it's functionality for a new module please open an issue or PR and we'll be happy to discuss it.

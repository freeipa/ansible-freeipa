"""Filter tests based on plugin modifications."""

import sys
import os
from importlib.machinery import SourceFileLoader
import types
from unittest import mock
import yaml


PYTHON_IMPORT = __import__


def get_plugins_from_playbook(playbook):
    """Get all plugins called in the given playbook."""
    def get_tasks(task_block):
        """
        Get all plugins used on tasks.

        Recursively process "block", "include_tasks" and "import_tasks".
        """
        _result = set()
        for tasks in task_block:
            for task in tasks:
                original_task = task
                if task == "block":
                    _result.update(get_tasks(tasks["block"]))
                elif task in ["include_tasks", "import_tasks"
                              "ansible.builtin.include_tasks",
                              "ansible.builtin.import_tasks"]:
                    parent = os.path.dirname(playbook)
                    include_task = tasks[task]
                    if isinstance(include_task, dict):
                        include_file = os.path.join(
                            parent, include_task["file"]
                        )
                    else:
                        include_file = os.path.join(parent, include_task)
                    _result.update(get_plugins_from_playbook(include_file))
                elif task in ["include_role",
                              "ansible.builtin.include_role"]:
                    _result.add(f"_{tasks[original_task]['name']}")
                elif task.startswith("ipa"):
                    # assume we are only interested in 'ipa*' modules/roles
                    _result.add(task)
                elif task == "role":
                    # not really a "task", but we'll handle the same way.
                    _result.add(f"_{tasks[task]}")
        return _result

    def load_playbook(filename):
        """Load playbook file using Python's YAML parser."""
        if not (filename.endswith("yml") or filename.endswith("yaml")):
            return []
        # print("Processing:", playbook)
        try:
            with open(filename, "rt") as playbook_file:
                data = yaml.safe_load(playbook_file)
        except yaml.scanner.ScannerError:  # If not a YAML/JSON file.
            return []
        except yaml.parser.ParserError:  # If not a YAML/JSON file.
            return []
        return data if data else []

    data = load_playbook(playbook)
    task_blocks = [t.get("tasks", []) if "tasks" in t else [] for t in data]
    role_blocks = [t.get("roles", []) if "roles" in t else [] for t in data]
    # assume file is a list of tasks if no "tasks" entry found.
    if not task_blocks:
        task_blocks = [data]
    _result = set()
    for task_block in task_blocks:
        _result.update(get_tasks(task_block))
    # roles
    for role_block in role_blocks:
        _result.update(get_tasks(role_block))

    return _result


def import_mock(name, *args):
    """Intercept 'import' calls and store module name."""
    if not hasattr(import_mock, "call_list"):
        setattr(import_mock, "call_list", set())  # noqa: B010
    import_mock.call_list.add(name)  # pylint: disable=no-member
    try:
        # print("NAME:", name)
        return PYTHON_IMPORT(name, *args)
    except ModuleNotFoundError:
        # We're not really interested in loading the module
        # if it can't be imported, it is not something we really care.
        return mock.Mock()
    except Exception:  # pylint: disable=broad-except
        print(
            "An unexpected error occured. Do you have all requirements set?",
            file=sys.stderr
        )
        sys.exit(1)


def parse_playbooks(test_module):
    """Load all playbooks for 'test_module' directory."""
    if test_module.name[0] in [".", "_"] or test_module.name == "pytests":
        return []
    _files = set()
    for arg in os.scandir(test_module):
        if arg.is_dir():
            _files.update(parse_playbooks(arg))
        else:
            for playbook in get_plugins_from_playbook(arg.path):
                if playbook.startswith("_"):
                    source = f"roles/{playbook[1:]}"
                    if os.path.isdir(source):
                        _files.add(source)
                else:
                    source = f"plugins/modules/{playbook}.py"
                    if os.path.isfile(source):
                        _files.add(source)
                        # If a plugin imports a module from the repository,
                        # we'l find it by patching the builtin __import__
                        # function and importing the module from the source
                        # file. The modules imported as a result of the import
                        # will be added to the import_mock.call_list list.
                        with mock.patch(
                            "builtins.__import__", side_effect=import_mock
                        ):
                            # pylint: disable=no-value-for-parameter
                            try:
                                loader = SourceFileLoader(playbook, source)
                                loader.exec_module(
                                    types.ModuleType(loader.name)
                                )
                            except Exception:  # pylint: disable=broad-except
                                # If import fails, we'll assume there's no
                                # plugin to be loaded. This is of little risk
                                # it is rare that a plugin includes another.
                                pass
                        # pylint: disable=no-member
                        candidates = [
                            f.split(".")[1:]
                            for f in import_mock.call_list
                            if f.startswith("ansible.")
                        ]
                        # pylint: enable=no-member
                        files = [
                            "plugins/" + "/".join(f) + ".py"
                            for f in candidates
                        ]
                        _files.update([f for f in files if os.path.isfile(f)])
                    else:
                        source = f"roles/{playbook}"
                        if os.path.isdir(source):
                            _files.add(source)

    return _files


def map_test_module_sources(base):
    """Create a map of 'test-modules' to 'plugin-sources', from 'base'."""
    # Find root directory of playbook tests.
    script_dir = os.path.dirname(__file__)
    test_root = os.path.realpath(os.path.join(script_dir, f"../{base}"))
    # create modules:source_files map
    _result = {}
    for test_module in [d for d in os.scandir(test_root) if d.is_dir()]:
        _depends_on = parse_playbooks(test_module)
        if _depends_on:
            _result[test_module.name] = _depends_on
    return _result


def usage(err=0):
    print("filter_plugins.py [-h|--help] [-p|--pytest] PY_SRC...")
    print(
        """
Print a comma-separated list of modules that should be tested if
PY_SRC is modified.

Options:

    -h, --help      Print this message and exit.
    -p, --pytest    Evaluate pytest tests (playbooks only).
"""
    )
    sys.exit(err)


def main():
    """Program entry point."""
    if "-h" in sys.argv or "--help" in sys.argv:
        usage()
    _base = "tests"
    if "-p" in sys.argv or "--pytest" in sys.argv:
        _base = "tests/pytests"
    call_args = [x for x in sys.argv[1:] if x not in ["-p", "--pytest"]]
    _mapping = map_test_module_sources(_base)
    _test_suits = (
        [
            _module for _module, _files in _mapping.items()
            for _arg in call_args
            for _file in _files
            if _file.startswith(_arg)
        ] + [
            _role for _role in [x for x in _mapping if x.endswith("_role")]
            for _arg in call_args
            if _arg.startswith("roles/ipa" + _role[:-5])
        ]
    )
    if _test_suits:
        print(",".join(sorted(_test_suits)))


if __name__ == "__main__":
    main()

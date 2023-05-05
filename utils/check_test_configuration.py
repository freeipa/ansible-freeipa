#!/usr/bin/env python

"""Check which tests are scheduled to be executed."""

import sys
import re
import os
import yaml


RE_IS_TEST = re.compile(r"(.*/)?test_.*\.yml")
RE_IS_VARS = re.compile(r"(.*/)?variables(_.*)?\.yaml")
REPO_ROOT = os.path.join(os.path.dirname(__file__), "..")


def get_tests():
    """Retrieve a list of modules and its tests."""

    def get_module(root):
        if root != _test_dir:
            while True:
                module = os.path.basename(root)
                root = os.path.dirname(root)
                if root == _test_dir:
                    return module
        return "."

    _result = {}
    _test_dir = os.path.join(REPO_ROOT, "tests")
    for root, _dirs, files in os.walk(_test_dir):
        module = get_module(root)
        _result[module] = [
            os.path.splitext(test)[0]
            for test in files
            if RE_IS_TEST.search(test)
        ]

    return _result


def get_test_config(scenarios):
    template_path = os.path.join(REPO_ROOT, "tests/azure/templates")
    _result = {}
    for _root, _dirs, files in os.walk(template_path):
        for filename in [x for x in files if RE_IS_VARS.search(x)]:
            _templates, *scenario = os.path.basename(
                os.path.splitext(filename)[0]
            ).split("_", 1)
            scenario = scenario[0] if scenario else "All"
            _result[scenario] = {}
            # only process selected scenarios
            if scenario not in scenarios and len(scenarios) > 1:
                continue
            with open(os.path.join(template_path, filename), "rt") as inp:
                data = yaml.safe_load(inp)
            if not data["variables"].get("empty", False):
                variables = data["variables"]
                for key, value in variables.items():
                    variables[key] = [
                        x.strip() for x in value.split(",") if x.strip()
                    ]
                _result[scenario] = variables

    return _result


def print_configuration(scenario, disabled, enabled):
    """Print the test configuration for a scenario."""
    print(f"\nScenario: {scenario}")
    for test_cfg, title in [(disabled, "Disabled"), (enabled, "Enabled")]:
        print(f"    {title} tests:")
        if test_cfg:
            for module, tests in test_cfg.items():
                print(f"        {module}:")
                for test in tests:
                    print(f"            - {test}")
        else:
            print("        No custom configuration.")


def main():
    if any(item in sys.argv for item in ["-h", "--help"]):
        print("usage: check_test_config.py [-h|--help] [SCENARIO...]")
        return

    scenarios = ["All"] + sys.argv[1:]
    all_tests = get_tests()
    test_config = get_test_config(scenarios)

    print("Test configuration:")
    for scenario in sorted(test_config.keys()):
        if scenario not in scenarios and len(scenarios) > 1:
            continue
        # extract scenario configuration
        config = test_config[scenario]
        disabled = {}
        enabled = {}
        for res, state in [(disabled, "disabled"), (enabled, "enabled")]:
            items = [
                x.strip()
                for x in
                os.environ.get(f"ipa_{state}_modules".upper(), "").split(",")
                if x.strip()
            ] if scenario == "All" else []
            modules = config.get(f"ipa_{state}_modules", []) + items
            for module in modules:
                if module != "None":
                    res[module] = set(all_tests[module])
            items = [
                x.strip()
                for x in
                os.environ.get(f"ipa_{state}_tests".upper(), "").split(",")
                if x.strip()
            ] if scenario == "All" else []
            test_list = config.get(f"ipa_{state}_tests", []) + items
            for test in test_list:
                if test == "None":
                    continue
                for module, tests in all_tests.items():
                    if test in tests:
                        mod = res.setdefault(module, set())
                        mod.add(test)
                        tests.remove(test)
        print_configuration(scenario, disabled, enabled)


if __name__ == "__main__":
    main()

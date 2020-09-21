#!/bin/bash

INFO="\033[37;1m"
WARN="\033[33;1m"
RST="\033[0m"

pushd "`dirname $0`/.." >/dev/null 2>&1

echo -e "${INFO}Running 'flake8'...${RST}"
flake8 plugins utils roles *.py
echo -e "${INFO}Running 'pydocstyle'...${RST}"
pydocstyle plugins utils roles *.py
echo -e "${INFO}Running 'pylint'...${RST}"
pylint plugins *.py

ANSIBLE_LIBRARY="${ANSIBLE_LIBRARY:-plugins/modules}"
ANSIBLE_MODULE_UTILS="${ANSIBLE_MODULE_UTILS:-plugins/module_utils}"
ANSIBLE_DOC_FRAGMENT_PLUGINS="${ANSIBLE_DOC_FRAGMENT_PLUGINS:-plugins/doc_fragments}"
export ANSIBLE_LIBRARY ANSIBLE_MODULE_UTILS ANSIBLE_DOC_FRAGMENT_PLUGINS

echo -e "${WARN}Missing file warnings are expected and can be ignored.${RST}"
echo -e "${INFO}Running 'ansible-lint'...${RST}"
playbook_dirs=(
    "tests"
    "playbooks"
)
ansible-lint --force-color "${playbook_dirs[@]}"

echo -e "${INFO}Running 'ansible-doc-test'...${RST}"
python "`dirname $0`/ansible-doc-test" -v roles plugins

echo -e "${INFO}Running 'yamllint'...${RST}"
yaml_dirs=(
    "tests"
    "playbooks"
    "molecule"
    "roles"
)
yamllint -f colored "${yaml_dirs[@]}"

popd >/dev/null 2>&1

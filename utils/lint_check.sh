#!/bin/bash -eu

INFO="\033[37;1m"
WARN="\033[33;1m"
RST="\033[0m"

topdir=$(dirname "$0")

pushd "${topdir}/.." >/dev/null 2>&1  || exit 1

echo -e "${INFO}Running 'flake8'...${RST}"
flake8 plugins utils roles setup.py
echo -e "${INFO}Running 'pydocstyle'...${RST}"
pydocstyle plugins utils roles setup.py
echo -e "${INFO}Running 'pylint'...${RST}"
pylint plugins roles setup.py

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
ansible-lint --offline --profile production --exclude tests/integration/ --exclude tests/unit/ --parseable --force-color "${playbook_dirs[@]}"

echo -e "${INFO}Running 'ansible-doc-test'...${RST}"
python "${topdir}/ansible-doc-test" -v roles plugins

echo -e "${INFO}Running 'yamllint'...${RST}"
yaml_dirs=(
    "tests"
    "playbooks"
    "molecule"
    "roles"
)
yamllint -f colored "${yaml_dirs[@]}"

popd >/dev/null 2>&1 || exit 1

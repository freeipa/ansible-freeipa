#!/bin/bash

topdir="`dirname $(dirname $0)`"

flake8 .
pydocstyle .

ANSIBLE_LIBRARY=${ANSIBLE_LIBRARY:-"${topdir}/plugins/modules"}
ANSIBLE_MODULE_UTILS=${ANSIBLE_MODULE_UTILS:-"${topdir}/plugins/module_utils"}

export ANSIBLE_LIBRARY ANSIBLE_MODULE_UTILS

yaml_dirs=(
    "${topdir}/tests"
    "${topdir}/playbooks"
    "${topdir}/molecule"
)

for dir in "${yaml_dirs[@]}"
do
    find "${dir}" -type f -name "*.yml" | xargs ansible-lint --force-color
done


for dir in "${yaml_dirs[@]}"
do
    find "${dir}" -type f -name "*.yml" | xargs yamllint 
done

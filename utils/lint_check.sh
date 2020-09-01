#!/bin/bash

topdir=`dirname $(dirname $0)`

flake8 .
pydocstyle .

ANSIBLE_LIBRARY=${ANSIBLE_LIBRARY:-"${topdir}/plugins/modules"}
ANSIBLE_MODULE_UTILS=${ANSIBLE_MODULE_UTILS:-"${topdir}/plugins/module_utils"}

export ANSIBLE_LIBRARY ANSIBLE_MODULE_UTILS

yaml_dirs=(
    "${topdir}/tests/*.yml"
    "${topdir}/tests/*/*.yml"
    "${topdir}/tests/*/*/*.yml"
    "${topdir}/playbooks/*.yml"
    "${topdir}/playbooks/*/*.yml"
    "${topdir}/molecule/*/*.yml"
    "${topdir}/molecule/*/*/*.yml"
)

ansible-lint --force-color ${yaml_dirs[@]}

yamllint -f colored ${yaml_dirs[@]}

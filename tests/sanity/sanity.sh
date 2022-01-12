#!/bin/bash

VENV=/tmp/ansible-test-venv
ANSIBLE_COLLECTION=freeipa-ansible_freeipa

virtualenv "$VENV"
# shellcheck disable=SC1091
source "$VENV"/bin/activate

python -m pip install --upgrade pip
pip install galaxy_importer

rm -f "$ANSIBLE_COLLECTION"-*.tar.gz
rm -f importer_result.json

utils/build-galaxy-release.sh

export GALAXY_IMPORTER_CONFIG=tests/sanity/galaxy-importer.cfg

collection=$(ls -1 "$ANSIBLE_COLLECTION"-*.tar.gz)
echo "Running: python -m galaxy_importer.main $collection"

error=0
while read -r line;
do
    if [[ $line == ERROR* ]]; then
        ((error++))
        echo -e "\033[31;1m${line}\033[0m"
    else
        echo "$line"
    fi
done < <(python -m galaxy_importer.main "$collection")

rm -rf "$VENV"

exit "$error"

#!/bin/bash -eu

TOPDIR=$(readlink -f "$(dirname "$0")/../..")
pushd "${TOPDIR}" >/dev/null || exit 1

VENV=/tmp/ansible-test-venv
ANSIBLE_COLLECTION=freeipa-ansible_freeipa

use_docker=$(docker -v >/dev/null 2>&1 && echo "True" || echo "False")

python -m venv "$VENV"
# shellcheck disable=SC1091
source "$VENV"/bin/activate

python -m pip install --upgrade pip
pip install galaxy_importer

rm -f "$ANSIBLE_COLLECTION"-*.tar.gz
rm -f importer_result.json

utils/build-galaxy-release.sh

sed "s/LOCAL_IMAGE_DOCKER = True/LOCAL_IMAGE_DOCKER = ${use_docker}/" < tests/sanity/galaxy-importer.cfg > ${VENV}/galaxy-importer.cfg
export GALAXY_IMPORTER_CONFIG=${VENV}/galaxy-importer.cfg

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

popd >/dev/null || exit 1

exit "$error"

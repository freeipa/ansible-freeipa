#!/bin/bash

namespace="${1-freeipa}"
collection="${2-ansible_freeipa}"
collection_prefix="${namespace}.${collection}"

galaxy_version=$(git describe --tags | sed -e "s/^v//")
echo $galaxy_version | grep "-" -q || galaxy_version="${galaxy_version}"
sed -i -e "s/version: .*/version: \"$galaxy_version\"/" galaxy.yml
sed -i -e "s/namespace: .*/namespace: \"$namespace\"/" galaxy.yml
sed -i -e "s/name: .*/name: \"$collection\"/" galaxy.yml

find . -name "*~" -exec rm {} \;

sed -i -e "s/ansible.module_utils.ansible_freeipa_module/ansible_collections.${collection_prefix}.plugins.module_utils.ansible_freeipa_module/" plugins/modules/*.py

(cd plugins/module_utils && {
    ln -s ../../roles/*/module_utils/*.py .
})

(cd plugins/modules && {
    sed -i -e "s/ansible.module_utils.ansible_ipa_/ansible_collections.${collection_prefix}.plugins.module_utils.ansible_ipa_/" ../../roles/*/library/*.py
    ln -s ../../roles/*/library/*.py .
})

[ ! -x plugins/action_plugins ] && mkdir plugins/action_plugins
(cd plugins/action_plugins && {
    ln -s ../../roles/*/action_plugins/*.py .
})

find plugins/modules -name "*.py" -print0 |
    while IFS= read -d -r '' line; do
        python utils/galaxyfy-module-EXAMPLES.py "$x" \
               "ipa" "$collection_prefix"
    done

find roles/*/library -name "*.py" -print0 |
    while IFS= read -d -r '' line; do
        python utils/galaxyfy-module-EXAMPLES.py "$x" \
               "ipa" "$collection_prefix"
    done

for x in roles/*/tasks/*.yml; do
    python utils/galaxyfy-playbook.py "$x" "ipa" "$collection_prefix"
done

find playbooks -name "*.yml" -print0 |
    while IFS= read -d -r '' line; do
        python utils/galaxyfy-playbook.py "$x" "ipa" "$collection_prefix"
    done

find . -name "README*.md" -print0 |
    while IFS= read -d -r '' line; do
        python utils/galaxyfy-README.py "$x" "ipa" "$collection_prefix"
    done

find tests -name "*.yml" -print0 |
    while IFS= read -d -r '' line; do
        python utils/galaxyfy-playbook.py "$x" "ipa" "$collection_prefix"
    done

#git diff

ansible-galaxy collection build

rm plugins/module_utils/ansible_ipa_*
rm plugins/modules/ipaserver_*
rm plugins/modules/ipareplica_*
rm plugins/modules/ipaclient_*
rm plugins/action_plugins/ipaclient_*
git reset --hard

#!/bin/bash

namespace="${1-freeipa}"
collection="${2-ansible_freeipa}"
collection_prefix="${namespace}.${collection}"

galaxy_version=$(git describe --tags | sed -e "s/^v//")
sed -i -e "s/version: .*/version: \"$galaxy_version\"/" galaxy.yml
sed -i -e "s/namespace: .*/namespace: \"$namespace\"/" galaxy.yml
sed -i -e "s/name: .*/name: \"$collection\"/" galaxy.yml

find . -name "*~" -exec rm {} \;

sed -i -e "s/ansible.module_utils.ansible_freeipa_module/ansible_collections.${collection_prefix}.plugins.module_utils.ansible_freeipa_module/" plugins/modules/*.py

(cd plugins/module_utils && {
    ln -sf ../../roles/*/module_utils/*.py .
})

(cd plugins/modules && {
    sed -i -e "s/ansible.module_utils.ansible_ipa_/ansible_collections.${collection_prefix}.plugins.module_utils.ansible_ipa_/" ../../roles/*/library/*.py
    ln -sf ../../roles/*/library/*.py .
})

[ ! -x plugins/action ] && mkdir plugins/action
(cd plugins/action && {
    ln -sf ../../roles/*/action_plugins/*.py .
})

echo "Fixing doc fragments in plugins/modules..."
for file in plugins/modules/*.py; do
    sed -i -e "s/- ipamodule_base_docs/- ${collection_prefix}.ipamodule_base_docs/" "$file"
done
echo -e "\033[AFixing doc framents in plugins/modules... \033[32;1mDONE\033[0m"

echo "Fixing examples in plugins/modules..."
find plugins/modules -name "*.py" -print0 |
    while IFS= read -d '' -r line; do
        python utils/galaxyfy-module-EXAMPLES.py "$line" \
               "ipa" "$collection_prefix"
    done
echo -e "\033[AFixing examples in plugins/modules... \033[32;1mDONE\033[0m"

echo "Fixing examples in roles/*/library..."
find roles/*/library -name "*.py" -print0 |
    while IFS= read -d '' -r line; do
        python utils/galaxyfy-module-EXAMPLES.py "$line" \
               "ipa" "$collection_prefix"
    done
echo -e "\033[AFixing examples in roles/*/library... \033[32;1mDONE\033[0m"

echo "Fixing playbooks in roles/*/tasks..."
for line in roles/*/tasks/*.yml; do
    python utils/galaxyfy-playbook.py "$line" "ipa" "$collection_prefix"
done
echo -e "\033[AFixing playbooks in roles/*tasks... \033[32;1mDONE\033[0m"

echo "Fixing playbooks in playbooks..."
find playbooks -name "*.yml" -print0 |
    while IFS= read -d '' -r line; do
        python utils/galaxyfy-playbook.py "$line" "ipa" "$collection_prefix"
    done
echo -e "\033[AFixing playbooks in playbooks... \033[32;1mDONE\033[0m"

echo "Fixing README(s)..."
find . -name "README*.md" -print0 |
    while IFS= read -d '' -r line; do
        python utils/galaxyfy-README.py "$line" "ipa" "$collection_prefix"
    done
echo -e "\033[AFixing examples in plugins/modules... \033[32;1mDONE\033[0m"

echo "Fixing playbbooks in tests..."
find tests -name "*.yml" -print0 |
    while IFS= read -d '' -r line; do
        python utils/galaxyfy-playbook.py "$line" "ipa" "$collection_prefix"
    done
echo -e "\033[AFixing playbooks in tests... \033[32;1mDONE\033[0m"

#git diff

ansible-galaxy collection build

rm plugins/module_utils/ansible_ipa_*
rm plugins/modules/ipaserver_*
rm plugins/modules/ipareplica_*
rm plugins/modules/ipaclient_*
rm plugins/action/ipaclient_*
rm plugins/action/ipabackup_*
if [ -d plugins/action ]; then rm -Rf plugins/action; fi
git reset --hard

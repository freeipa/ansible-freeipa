#!/bin/bash

galaxy_version=$(git describe --tags | sed -e "s/^v//")
echo $galaxy_version | grep "-" -q || galaxy_version="${galaxy_version}-1"
sed -i -e "s/version: .*/version: \"$galaxy_version\"/" galaxy.yml

find . -name "*~" -exec rm {} \;

sed -i -e "s/ansible.module_utils.ansible_freeipa_module/ansible_collections.freeipa.ansible_freeipa.plugins.module_utils.ansible_freeipa_module/" plugins/modules/*.py

cd plugins/module_utils && {
    ln -s ../../roles/ipa*/module_utils/*.py .
    cd ../..
}

cd plugins/modules && {
    sed -i -e "s/ansible.module_utils.ansible_ipa_/ansible_collections.freeipa.ansible_freeipa.plugins.module_utils.ansible_ipa_/" ../../roles/ipa*/library/*.py
    ln -s ../../roles/ipa*/library/*.py .
    cd ../..
}

[ ! -x plugins/action_plugins ] && mkdir plugins/action_plugins
cd plugins/action_plugins && {
    ln -s ../../roles/ipa*/action_plugins/*.py .
    cd ../..
}

for x in roles/ipa*/tasks/*.yml; do
    python utils/galaxyify-playbook.py "$x"
done

for x in $(find playbooks -name "*.yml" -print); do
    python utils/galaxyify-playbook.py "$x"
done

#git diff

ansible-galaxy collection build

rm plugins/module_utils/ansible_ipa_*
rm plugins/modules/ipaserver_*
rm plugins/modules/ipareplica_*
rm plugins/modules/ipaclient_*
rm plugins/action_plugins/ipaclient_*
git reset --hard


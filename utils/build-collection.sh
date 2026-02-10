#!/bin/bash -eu
#
# Build Ansible Collection from ansible-freeipa repo
#

prog=$(basename "$0")
pwd=$(pwd)

usage() {
    cat <<EOF
Usage: $prog [options] rpm|aah|galaxy

Build Anible Collection for ansible-freeipa.

The namespace and name are defined according to the argument:

  rpm     freeipa.ansible_freeipa   - General use and RPMs
  galaxy  freeipa.ansible_freeipa   - Ansible Galaxy
  aah     redhat.rhel_idm           - Ansible AutomationHub

The generated file README-COLLECTION.md is set in galaxy.yml as the
documentation entry point for the collections generated with aah and galaxy
as Ansible AutomationHub and also Ansible Galaxy are not able to render the
documentation README files in the collection properly.

Options:
  -a          Add all files, not only files known to git repo
  -k          Keep build directory
  -i          Install the generated collection
  -o <A.B.C>  Build offline without using git, using version A.B.C
              Also enables -a
  -p <path>   Install the generated collection in the given path, the
              ansible_collections sub directory will be created and will
              contain the collection: ansible_collections/<namespace>/<name>
              Also enables -i
  -h          Print this help

EOF
}

all=0
keep=0
install=0
path=
offline=
version=
namespace="freeipa"
name="ansible_freeipa"
while getopts "ahkio:p:" arg; do
    case $arg in
        a)
            all=1
            ;;
        h)
            usage
            exit 0
            ;;
        k)
            keep=1
            ;;
        i)
            install=1
            ;;
        o)
            version=$OPTARG
            offline=1
            all=1
            ;;
        p)
            path=$OPTARG
            install=1
            ;;
        \?)
            echo
            usage
            exit 1
            ;;
    esac
done
shift $((OPTIND-1))

if [ $# != 1 ]; then
    usage
    exit 1
fi

collection="$1"
case "$collection" in
    rpm|galaxy)
        # namespace and name are already set
        ;;
    aah)
        namespace="redhat"
        name="rhel_idm"
        ;;
    *)
        echo "Unknown collection '$collection'"
        usage
        exit 1
        ;;
esac
collection_prefix="${namespace}.${name}"
collection_uname="${collection^^}"

[ -z "$version" ] && \
    version=$(git describe --tags 2>/dev/null | sed -e "s/^v//")

if [ -z "$version" ]; then
    echo "Version could not be detected"
    exit 1
fi

echo "Building collection: ${namespace}-${name}-${version} for ${collection_uname}"

BUILD=".collection-build"

if [ -e "$BUILD" ]; then
    echo "Removing existing $BUILD ..."
    rm -rf "$BUILD"
    echo -e "\033[ARemoving existing $BUILD ... \033[32;1mDONE\033[0m"
fi
mkdir "$BUILD"
echo "Copying files to build dir $BUILD ..."
if [ $all == 1 ]; then
    # Copy all files except collection build dir
    for file in .[A-z]* [A-z]*; do
        [[ "$file" == "${BUILD}" ]] && continue
        cp -a "$file" "${BUILD}/"
    done
else
    # git ls-tree is quoting, therefore ignore SC2046: Quote this to prevent
    # word splitting
    # shellcheck disable=SC2046
    tar -cf - $(git ls-tree HEAD --name-only -r) | (cd "$BUILD/" && tar -xf -)
fi
echo -e "\033[ACopying files to build dir $BUILD ... \033[32;1mDONE\033[0m"
cd "$BUILD" || exit 1

echo "Removing .copr, .git* and .pre* files from build dir $BUILD ..."
rm -rf .copr .git* .pre*
echo -e "\033[ARemoving files from build dir $BUILD ... \033[32;1mDONE\033[0m"

if [ "$collection" != "rpm" ]; then
    mv README.md README-COLLECTION.md
    cat > README.md <<EOF
FreeIPA Ansible collection
==========================

This repository contains Ansible roles and playbooks to install and uninstall FreeIPA servers, replicas and clients, also management modules.

Important
---------

For the documentation of this collection, please have a look at the documentation in the collection archive. Starting point: Base collection directory, file **\`README-COLLECTION.md\`**.

${collection_uname} is not providing proper user documentation nor is able to render the documentation that is part of the collection. Therefore original \`README.md\` had to be renamed to \`README-COLLECTION.md\` to ensure that ${collection_uname} is not trying to render it.

Please ignore any modules and plugins in the ${collection_uname} documentation section with the prefix \`ipaserver_\`, \`ipareplica_\`, \`ipaclient_\`, \`ipabackup_\` and \`ipasmartcard_\` and also \`module_utils\` and \`doc_fragments\`. These files are used internally only and are not supported to be used otherwise.

There is also the [generic ansible-freeipa ${version} upstream documentation](https://github.com/freeipa/ansible-freeipa/blob/v${version}/README.md) and also the [latest generic ansible-freeipa upstream documentation](https://github.com/freeipa/ansible-freeipa/blob/master/README.md), both without using the collection prefix \`${collection_prefix}\`.
EOF
    if [ "$collection" == "aah" ]; then
        cat >> README.md <<EOF

Support
-------

This collection is maintained by Red Hat RHEL team.

As Red Hat Ansible Certified Content, this collection is entitled to support through the Ansible Automation Platform (AAP) using the **Create issue** button on the top right corner.
EOF
    fi
    sed -i -e "s/readme: .*/readme: README.md/" galaxy.yml
    sed -i -e "s/documentation: .*/documentation: README.md/" galaxy.yml
fi
sed -i -e "s/version: .*/version: \"$version\"/" galaxy.yml
sed -i -e "s/namespace: .*/namespace: \"$namespace\"/" galaxy.yml
sed -i -e "s/name: .*/name: \"$name\"/" galaxy.yml
find . -name "*~" -exec rm {} \;
find . -name "__py*__" -exec rm -rf {} \;


if [ "$offline" != "1" ]; then
    echo "Creating CHANGELOG.rst..."
    "$(dirname "$0")/changelog" --galaxy > CHANGELOG.rst
    echo -e "\033[ACreating CHANGELOG.rst... \033[32;1mDONE\033[0m"
else
    echo "Empty changelog, offline generated." > CHANGELOG.rst
fi

sed -i -e "s/ansible.module_utils.ansible_freeipa_module/ansible_collections.${collection_prefix}.plugins.module_utils.ansible_freeipa_module/" plugins/modules/*.py

python utils/create_action_group.py "meta/runtime.yml" "$collection_prefix"

mv roles/*/module_utils/*.py plugins/module_utils/
rmdir roles/*/module_utils

sed -i -e "s/ansible.module_utils.ansible_ipa_/ansible_collections.${collection_prefix}.plugins.module_utils.ansible_ipa_/" roles/*/library/*.py
mv roles/*/library/*.py plugins/modules/
rmdir roles/*/library

# There are no action plugins anymore in the roles, therefore this section
# is commneted out.
#[ ! -x plugins/action ] && mkdir plugins/action
#mv roles/*/action_plugins/*.py plugins/action/
#rmdir roles/*/action_plugins

# Adapt inventory plugin and inventory plugin README
echo "Fixing inventory plugin and doc..."
sed -i -e "s/plugin: freeipa/plugin: ${collection_prefix}.freeipa/g" plugins/inventory/freeipa.py
sed -i -e "s/choices: \[\"freeipa\"\]/choices: \[\"${collection_prefix}.freeipa\"\]/g" plugins/inventory/freeipa.py
sed -i -e "s/plugin: freeipa/plugin: ${collection_prefix}.freeipa/g" README-inventory-plugin-freeipa.md
echo -e "\033[AFixing inventory plugin and doc... \033[32;1mDONE\033[0m"

for doc_fragment in plugins/doc_fragments/*.py; do
    fragment=$(basename -s .py "$doc_fragment")

    echo "Fixing doc fragments for ${fragment} in plugins/modules..."
    for file in plugins/modules/*.py; do
        sed -i -e "s/- ${fragment}/- ${collection_prefix}.${fragment}/" "$file"
    done
    echo -e "\033[AFixing doc framents for ${fragment} in plugins/modules... \033[32;1mDONE\033[0m"
done

echo "Fixing examples in plugins/modules..."
find plugins/modules -name "*.py" -print0 |
    while IFS= read -d '' -r line; do
        python utils/galaxyfy-module-EXAMPLES.py "$line" \
               "ipa" "$collection_prefix"
    done
echo -e "\033[AFixing examples in plugins/modules... \033[32;1mDONE\033[0m"

echo "Fixing playbooks in roles/*/tasks..."
for line in roles/*/tasks/*.yml; do
    python utils/galaxyfy-playbook.py "$line" "ipa" "$collection_prefix"
done
echo -e "\033[AFixing playbooks in roles/*/tasks... \033[32;1mDONE\033[0m"

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

echo "Fixing playbooks in tests..."
find tests -name "*.yml" -print0 |
    while IFS= read -d '' -r line; do
        python utils/galaxyfy-playbook.py "$line" "ipa" "$collection_prefix"
    done
echo -e "\033[AFixing playbooks in tests... \033[32;1mDONE\033[0m"

ansible-galaxy collection build --force --output-path="$pwd"

cd "$pwd" || exit 1

if [ $keep == 0 ]; then
    echo "Removing build dir $BUILD ..."
    rm -rf "$BUILD"
    echo -e "\033[ARemoving build dir $BUILD ... \033[32;1mDONE\033[0m"
else
    echo "Keeping build dir $BUILD"
fi

if [ $install == 1 ]; then
    echo "Installing collection ${namespace}-${name}-${version}.tar.gz ..."
    ansible-galaxy collection install ${path:+"-p$path"} "${namespace}-${name}-${version}.tar.gz" --force ${offline/1/--offline}
fi

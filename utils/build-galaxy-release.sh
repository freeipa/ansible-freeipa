#!/bin/bash -eu
#
# Build Ansible Collection from ansible-freeipa repo
#

prog=$(basename "$0")
pwd=$(pwd)

usage() {
    cat <<EOF
Usage: $prog [options] [<namespace> <name>]

Build Anible Collection for ansible-freeipa.

The namespace defaults to freeipa an name defaults to ansible_freeipa,
if namespace and name are not given. Namespace and name need to be set
together.

Options:
  -a          Add all files, no only files known to git repo
  -k          Keep build directory
  -i          Install the generated collection
  -o <A.B.C>  Build offline without using git, using version A.B.C
              Also enables -a
  -p <path>   Installation the generated collection in the path, the
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
galaxy_version=
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
            galaxy_version=$OPTARG
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

if [ $# != 0 ] && [ $# != 2 ]; then
    usage
    exit 1
fi
namespace="${1-freeipa}"
name="${2-ansible_freeipa}"
if [ -z "$namespace" ]; then
    echo "Namespace might not be empty"
    exit 1
fi
if [ -z "$name" ]; then
    echo "Name might not be empty"
    exit 1
fi
collection_prefix="${namespace}.${name}"

[ -z "$galaxy_version" ] && \
    galaxy_version=$(git describe --tags 2>/dev/null | sed -e "s/^v//")

if [ -z "$galaxy_version" ]; then
    echo "Version could not be detected"
    exit 1
fi

echo "Building collection: ${namespace}-${name}-${galaxy_version}"

GALAXY_BUILD=".galaxy-build"

if [ -e "$GALAXY_BUILD" ]; then
    echo "Removing existing $GALAXY_BUILD ..."
    rm -rf "$GALAXY_BUILD"
    echo -e "\033[ARemoving existing $GALAXY_BUILD ... \033[32;1mDONE\033[0m"
fi
mkdir "$GALAXY_BUILD"
echo "Copying files to build dir $GALAXY_BUILD ..."
if [ $all == 1 ]; then
    # Copy all files except galaxy build dir
    for file in .[A-z]* [A-z]*; do
        [[ "$file" == "${GALAXY_BUILD}" ]] && continue
        cp -a "$file" "${GALAXY_BUILD}/"
    done
else
    # git ls-tree is quoting, therefore ignore SC2046: Quote this to prevent
    # word splitting
    # shellcheck disable=SC2046
    tar -cf - $(git ls-tree HEAD --name-only -r) | (cd "$GALAXY_BUILD/" && tar -xf -)
fi
echo -e "\033[ACopying files to build dir $GALAXY_BUILD ... \033[32;1mDONE\033[0m"
cd "$GALAXY_BUILD" || exit 1

sed -i -e "s/version: .*/version: \"$galaxy_version\"/" galaxy.yml
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
    echo "Removing build dir $GALAXY_BUILD ..."
    rm -rf "$GALAXY_BUILD"
    echo -e "\033[ARemoving build dir $GALAXY_BUILD ... \033[32;1mDONE\033[0m"
else
    echo "Keeping build dir $GALAXY_BUILD"
fi

if [ $install == 1 ]; then
    echo "Installing collection ${namespace}-${name}-${galaxy_version}.tar.gz ..."
    ansible-galaxy collection install ${path:+"-p$path"} "${namespace}-${name}-${galaxy_version}.tar.gz" --force ${offline/1/--offline}
fi

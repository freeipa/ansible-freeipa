#!/bin/bash

trap interrupt_exception SIGINT

WHITE="\033[37;1m"
YELLOW="\033[33;1m"
RED="\033[31;1m"
CYAN="\033[36;1m"
GREEN="\033[32;1m"
MAGENTA="\033[35;1m"
RST="\033[0m"

die() {
    echo -e "${RED}ERROR: $*\n${RST}"
    exit 1
}

quiet() {
     "$@" >/dev/null 2>&1
}

warn() {
    echo -e "${YELLOW}Warning: $*${RST}"
}


interrupt_exception() {
    trap - SIGINT
    warn "User interrupted test execution."
    cleanup
    exit 1
}

stop_container() {
    echo "Stopping container..."
    quiet ${engine} stop "${scenario}"
    echo "Removing container..."
    quiet ${engine} rm "${scenario}"
}

cleanup() {
    if [ "${STOP_CONTAINER}" = "1" ]
    then
        stop_container
        rm "${inventory}"
    fi

    if [ ! -z "${STOP_VIRTUALENV}" ]
    then
        echo "Deactivating virtual environment"
        deactivate
    fi
}

in_python_virtualenv() {
    local script
    read -r -d "" script <<'EOS'
import sys;
base = getattr(sys, "base_prefix", None) or getattr(sys, "real_prefix", None) or sys.prefix
print('yes' if sys.prefix != base else 'no')
EOS
    test "`python -c "${script}"`" = "yes"
}

run_inline_playbook() {
    local playbook
    local err
    playbook=`mktemp /tmp/ansible-freeipa-test-playbook_ipa.XXXXXXXX`
    cat - >"${playbook}"
    ansible-playbook -i "${inventory}" "${playbook}"
    err=$?
    rm "${playbook}"
    return ${err}
}

brief_usage() {
    cat << EOF

usage: ansbile-freeipa-test.sh [-v...] [-h] [-e VENV] [-x] [-M MEMORY]
                               [-i IMAGE] [-p CONTAINER] [-C] [-f]
                               [-A|-a PRED]
                               [-m MODULE] [TEST...]
EOF
}

usage() {
    brief_usage
    cat << EOF

Run ansible-freeipa tests in a container, using a virtual environment.

position arguments:
  TEST                A list of playbook tests to be executed.
                      Either a TEST or a MODULE must be provided.

optional arguments:
  -h                  display this help message and exit.
  -v                  verbose mode (You may use -vvv or -vvvvv for
                      increased information.)
  -i IMAGE            select one of the available ansible-freeipa
                      public images. Default is 'fedora-latest'.
                      Selecting message will force container
                      (re)creation.
  -p CONTAINER        use the container with name/id CONTAINER.
                      default: dev-test-master
  -f                  force creation of container, even if it exists.
  -C                  do not stop or remove container at exit.
  -e VENV             use the virtual environment VENV
                      default: asible-freeipa-tests
  -m MODULE           add all tests for the MODULE (e.g.: -m config).
  -x                  stop on first test failure.
  -M MEMORY           define container memory soft limit, in Gb
                      (default: 2)
  -A                  Use latest ansible-core version. (Will force
                      virtual environment recriation.)
  -a PRED             Set predicate to select ansible verion. (Will
                      force virtual environment recriation.)
                      Default: ">=2.9,<2.10" (Ansible 2.9)
  -t                  Run tests on all images: CentOS 7, CentOS 8
                      and Fedora.

EOF
}

TOPDIR="`dirname $0`/.."

TEST_SET=()
STOP_CONTAINER=1
CONTINUE_ON_ERROR="no"
scenario="dev-test-master"
IMAGE_TAG="fedora-latest"
engine="podman"
MEMORY=2
unset ANSIBLE_COLLECTIONS
unset ANSIBLE_VERSION
unset verbose
unset STOP_VIRTUALENV
unset FORCE_CONTAINER
unset TEST_ON_ALL

while getopts "Aa:Ce:fhi:m:M:p:tvx" opt
do
    case "${opt}" in
        A)
            ANSIBLE_VERSION='-core'
            ANSIBLE_COLLECTIONS="containers.podman"
            ;;
        a)
            ANSIBLE_VERSION="${OPTARG}"
            unset ANSIBLE_COLLECTIONS
            ;;
        # c) engine="${OPTARG}" ;;
        C) STOP_CONTAINER=0 ;;
        e) TESTENV_DIR="${OPTARG}" ;;
        f) FORCE_CONTAINER="yes" ;;
        h) usage && exit 0;;
        i) IMAGE_TAG=${OPTARG} ; FORCE_CONTAINER="yes" ;;
        m) TEST_SET+=(`find ${TOPDIR}/tests/${OPTARG} -name 'test_*.yml'`) ;;
        M) MEMORY=${OPTARG} ;;
        p) scenario="${OPTARG}" ;;
        v) verbose=${verbose:--}${opt} ;;
        x) unset CONTINUE_ON_ERROR ;;
        t) TEST_ON_ALL="yes" ; FORCE_CONTAINER="yes" ;;
        *) brief_usage && exit 1 ;;
    esac
done

TEST_SET+=(${@:$OPTIND})

[ ${#TEST_SET[@]} -gt 0 ] || die "No test defined."

if [ "${TEST_ON_ALL}" == "yes" -a ${STOP_CONTAINER} -ne 1 ]
then
    die "Containers must be stopped when testing against all images."
fi

inventory=`mktemp /tmp/ansible-freeipa-test-inventory.XXXXXXXX`
cat << EOF > "${inventory}"
[ipaserver]
${scenario}  ansible_connection=${engine}

[ipaserver:vars]
ipaserver_domain = test.local
ipaserver_realm = TEST.LOCAL
EOF

echo -e "${WHITE}INFO:${RST} Inventory file: ${CYAN}${inventory}${MAGENTA}"
cat "${inventory}"
echo -e "${RST}"

# prepare virtual environment
test_env="${TESTENV_DIR:-.ansible-freeipa-tests}"
VENV=`in_python_virtualenv && echo Y || echo N`
if [ -z "${ANSIBLE_VERSION}" ]
then
    ANSIBLE_VERSION=">=2.9,<2.10"
else
    [ "${VENV}" == "Y" ] && deactivate
    VENV="N"
    rm -rf "$test_env"
    warn "Virtual environment will be (re)created."
fi

if [ "$VENV" == "N" ]
then
    echo -e "${WHITE}Preparing virtual environment: ${test_env}${RST}"
    if [ ! -d "${test_env}" ]
    then
        echo -e "Creating virtual environment: ${test_env}..."
        if ! python3 -m venv "${test_env}"
        then
            die "Cannot create virtual environment."
        fi
    fi
    if [ -f "${test_env}/bin/activate" ]
    then
        echo -e "Starting virtual environment: ${test_env}"
        . "${test_env}/bin/activate"
        STOP_VIRTUALENV="yes"
    else
        die "Cannot activate environment."
    fi
    echo -e "${WHITE}Installing required tools.${RST}"
    echo "Upgrading: pip setuptools wheel"
    pip install --quiet --upgrade pip setuptools wheel
    echo "Installing: testinfra ansible${ANSIBLE_VERSION}"
    pip install --quiet "testinfra" "ansible${ANSIBLE_VERSION}"
    echo "Installing ansible-freeipa test requirements..."
    pip install --quiet -r requirements-tests.txt
    echo -e "${CYAN}Ansible version: `ansible --version | sed -n "1p"`${RST}"
    if [ ! -z "${ANSIBLE_COLLECTIONS}" ]
    then
        warn "Installed collections will not be removed after execution."
        echo "Installing: Ansible Collection ${ANSIBLE_COLLECTIONS}"
        ansible-galaxy collection install ${ANSIBLE_COLLECTIONS}
    fi
fi

# configure Ansible paths to roles and modules.
ANSIBLE_ROLES_PATH="${TOPDIR}/roles"
ANSIBLE_LIBRARY="${TOPDIR}/plugins/modules:${TOPDIR}/molecule"
ANSIBLE_MODULE_UTILS="${TOPDIR}/plugins/module_utils"

declare -a image_results

# Check if container exits.
echo -e "${WHITE}Checking '${scenario}' container.${RST}"
container_id=`${engine} ps --all -q -f "name=${scenario}\$"`

if [ "${TEST_ON_ALL}" == "yes" ]
then
    images=("centos-7" "centos-8" "fedora-latest")
else
    images=(${IMAGE_TAG})
fi

for IMAGE_TAG in ${images[@]}
do
    # if force recreation of container, and it exsits, remove it
    if  [ ! -z "${FORCE_CONTAINER}" -a ! -z "${container_id}" ]
    then
        warn "Removing existing container..."
        quiet ${engine} stop "${container_id}"
        quiet ${engine} rm "${container_id}"
        # this will force creation of a new container, later.
        unset container_id
    fi
    # if container is not set, create it.
    if  [ -z "${container_id}" ]
    then
        hostname="ipaserver.test.local"

        # Retrieve image and start container.
        echo -e "Pulling FreeIPA image '${CYAN}${IMAGE_TAG}${RST}'..."
        img_id=`${engine} pull -q quay.io/ansible-freeipa/upstream-tests:${IMAGE_TAG}`
        echo -e "Creating '${CYAN}${scenario}${RST}' container..."
        CONFIG="--hostname ${hostname} --name ${scenario} --memory ${MEMORY}g --memory-swap -1"
        container_id=`${engine} create ${CONFIG} "${img_id}"`
    else
        STOP_CONTAINER=0
    fi

    quiet ${engine} start "${scenario}"
    # wait for FreeIPA services to be available
    run_inline_playbook <<EOF
---
- name: Wait for IPA services to be available
  hosts: ipaserver
  gather_facts: no
  tasks:
  - name: Wait for IPA to be started.
    systemd:
      name: ipa
      state: started
  - name: Wait for Kerberos KDC to be started.
    systemd:
      name: krb5kdc
      state: started
    register: result
    until: not result.failed
    retries: 30
    delay: 5
  - name: Check if TGT is available for admin.
    shell:
      cmd: echo SomeADMINpassword | kinit -c ansible_freeipa_cache admin
    register: result
    until: not result.failed
    retries: 30
    delay: 5
  - name: Cleanup TGT.
    shell:
      cmd: kdestroy -c ansible_freeipa_cache -A
...
EOF
    if [ $? -ne 0 ]
    then
        cleanup
        die "Failed to verify IPA or KDC services."
    fi

    # Check image software versions.
    run_inline_playbook <<EOF
---
- name: Software environment.
  hosts: ipaserver
  become: yes
  gather_facts: no
  tasks:
  - name: Retrieve versions.
    shell:
      cmd: |
        rpm -q freeipa-server freeipa-client ipa-server ipa-client 389-ds-base pki-ca krb5-server
        cat /etc/redhat-release
        uname -a
    register: result
  - name: Testing environment.
    debug:
      var: result.stdout_lines
EOF
    if [ $? -ne 0 ]
    then
        cleanup
        die "Failed to verify software installation."
    fi

    # run tests
    RESULT=0
    for test in "${TEST_SET[@]}"
    do
        echo -e "\n${WHITE}Running: ${CYAN}${test#utils/../}${RST}"
        ansible-playbook ${verbose} -i "${inventory}" "${test}" || RESULT=2
        [ -z "${CONTINUE_ON_ERROR}" -a $RESULT -ne 0 ] && die "Stopping on test failure."
    done

    image_results[${#image_results[@]}]="${IMAGE_TAG}|${RESULT}"

    quiet stop_container
done

cleanup

# Return test result if any test has failed.
RESULT=0
for result in ${image_results[@]}
do
    img="${WHITE}`echo ${result} | cut -d'|' -f1`${RST}"
    error=`echo ${result} | cut -d'|' -f2`
    if [ ${error} -ne 0 ]
    then
        RESULT=${error}
        echo -e "${RED}FAILED${RST}: $img: Some playbooks tests have failed."
    else
        echo -e "${GREEN}Success${RST}: $img: all playbook tests passed."
    fi

done

exit ${RESULT}

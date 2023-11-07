#!/bin/bash -eu

trap interrupt_exception SIGINT

RST="\033[0m"
RED="\033[31m"
# BRIGHTRED="\033[31;1m"
# GREEN="\033[32m"
BRIGHTGREEN="\033[32;1m"
# BROWN="\033[33m"
YELLOW="\033[33;1m"
# NAVY="\033[34m"
BLUE="\033[34;1m"
# MAGENTA="\033[35m"
# BRIGHTMAGENTA="\033[35;1m"
# DARKCYAN="\033[36m"
# CYAN="\033[36;1m"
# BLACK="\033[30m"
# DARKGRAY="\033[30;1m"
# GRAY="\033[37m"
WHITE="\033[37;1m"

TOPDIR="$(readlink -f "$(dirname "$0")/..")"

interrupt_exception() {
    trap - SIGINT
    log warn "User interrupted test execution."
    cleanup
    exit 1
}

usage() {
    local prog="${0##*/}"
    cat <<EOF
usage: ${prog} [-h] [-l] [-e] [-K] [-c CONTAINER] [-s TESTS_SUITE] [-x] [-A SEED.GRP] [-i IMAGE] [-m MEMORY] [-v...] [TEST...]
    ${prog} runs playbook(s) TEST using an ansible-freeipa testing image.

EOF
}

help() {
    usage
    echo -e "$(cat <<EOF
positional arguments:
  TEST                A list of playbook tests to be executed.
                      Either a TEST or a MODULE must be provided.

optional arguments:
  -h              display this message and exit
  -c CONTAINER    use container CONTAINER to run tests
  -K              keep container, even if tests succeed
  -l              list available images
  -e              force recreation of the virtual environment
  -i IMAGE        select image to run the tests (default: fedora-latest)
  -m              container memory, in GiB (default: 3)
  -s TEST_SUITE   run all playbooks for test suite, which is a directory
                  under ${WHITE}tests${RST}
  -A SEED.GROUP   Replicate Azure's test group and seed (seed is YYYYMMDD)
  -v              Increase Ansible verbosity (can be used multiple times)
  -x              Stop on first error.
EOF
)"
}

log() {
    local level="${1^^}" message="${*:2}"
    case "${level}" in
        ERROR) COLOR="${RED}" ;;
        WARN)  COLOR="${YELLOW}" ;;
        DEBUG) COLOR="${BLUE}" ;;
        INFO) COLOR="${WHITE}" ;;
        SUCCESS) COLOR="${BRIGHTGREEN}" ;;
        *) COLOR="${RST}" ;;
    esac
    echo -en "${COLOR}"
    [ "${level}" == "ERROR" ] && echo -en "${level}:"
    echo -e "${message}${RST}"
}

quiet() {
     "$@" >/dev/null 2>&1
}

in_python_virtualenv() {
    local script
    read -r -d "" script <<EOS
import sys;
base = getattr(sys, "base_prefix", ) or getattr(sys, "real_prefix", ) or sys.prefix
print('yes' if sys.prefix != base else 'no')
EOS
    test "$(python -c "${script}")" == "yes"
}

run_inline_playbook() {
    local playbook
    local err
    quiet mkdir -p "${test_env}/playbooks"
    playbook=$(mktemp "${test_env}/playbooks/ansible-freeipa-test-playbook_ipa.XXXXXXXX")
    cat - >"${playbook}"
    ansible-playbook -i "${inventory}" "${playbook}"
    err=$?
    rm "${playbook}"
    return ${err}
}

die() {
    usg="N"
    if [ "${1}" == "-u" ]
    then
       usg="Y"
       shift 1
    fi
    log error "${*}"
    STOP_CONTAINER="N"
    cleanup
    [ "${usg}" == "Y" ] && usage
    exit 1
}

make_inventory() {
    local scenario=$1 engine=${2:-podman}
    inventory="${test_env}/inventory"
    log info "Inventory file: ${inventory}"
    cat << EOF > "${inventory}"
[ipaserver]
${scenario} ansible_connection=${engine}
[ipaserver:vars]
ipaserver_domain = test.local
ipaserver_realm = TEST.LOCAL
EOF
}

stop_container() {
    local scenario=${1} engine=${2:-podman}
    echo "Stopping container..."
    quiet "${engine}" stop "${scenario}"
    echo "Removing container..."
    quiet "${engine}" rm "${scenario}"
}

cleanup() {
    if [ $# -gt 0 ]
    then
        if [ "${STOP_CONTAINER}" != "N" ]
        then
            stop_container "${1}" "${2}"
            rm "${inventory}"
        else
            log info "Keeping container: $(podman ps --format "{{.Names}} - {{.ID}}" --filter "name=${1}")"
        fi
    fi
    if [ "${STOP_VIRTUALENV}" == "Y" ]
    then
        echo "Deactivating virtual environment"
        deactivate
    fi
}

list_images() {
    local quay_api="https://quay.io/api/v1/repository/ansible-freeipa/upstream-tests/tag"
    echo -e "${WHITE}Available images:"
    curl --silent -L "${quay_api}" | jq '.tags[]|.name' | tr -d '"'| sort | uniq | sed "s/.*/    &/"
    echo -e "${RST}"
}

# Defaults

ANSIBLE_VERSION=${ANSIBLE_VERSION:-'ansible-core'}
verbose=""
FORCE_ENV="N"
CONTINUE_ON_ERROR=""
STOP_CONTAINER="Y"
STOP_VIRTUALENV="N"
declare -a ENABLED_MODULES
declare -a ENABLED_TESTS
ENABLED_MODULES=()
ENABLED_TESTS=()
test_env="${TESTENV_DIR:-${VIRTUAL_ENV:-/tmp/ansible-freeipa-tests}}"
engine="podman"
IMAGE_REPO="quay.io/ansible-freeipa/upstream-tests"
IMAGE_TAG="fedora-latest"
scenario=""
MEMORY=3
hostname="ipaserver.test.local"
SEED=""
GROUP=0
SPLITS=0
ANSIBLE_COLLECTIONS=${ANSIBLE_COLLECTIONS:-"containers.podman"}

EXTRA_OPTIONS=""

# Process command options

while getopts ":hA:c:ei:Klms:vx" option
do
    case "$option" in
        h) help && exit 0 ;;
        A)
            [ ${#ENABLED_MODULES[@]} -eq 0 ] || die -u "Can't use '-A' with '-s'"
            SEED="$(cut -d. -f1 <<< "${OPTARG}" | tr -d "-")"
            GROUP="$(cut -d. -f2 <<< "${OPTARG}")"
            if [ -z "${SEED}" ] || [ -z "${GROUP}" ]
            then
                die -u "Seed for '-A' must have the format YYYYMMDD.N"
            fi
            SPLITS=3
        ;;
        c) scenario="${OPTARG}" ;;
        e) FORCE_ENV="Y" ;;
        i) IMAGE_TAG="${OPTARG}" ;;
        K) STOP_CONTAINER="N" ;;
        l) list_images && exit 0 || exit 1;;
        m) MEMORY="${OPTARG}" ;;
        s)
           [ ${SPLITS} -ne 0 ] && die -u "Can't use '-A' with '-s'"
           if [ -d "${TOPDIR}/tests/${OPTARG}" ]
           then
               ENABLED_MODULES+=("${OPTARG}")
           else
               log error "Invalid suite: ${OPTARG}"
           fi
           ;;
        v) verbose=${verbose:--}${option} ;;
        x) EXTRA_OPTIONS="$EXTRA_OPTIONS --exitfirst" ;;
        *) die -u "Invalid option: ${OPTARG}" ;;
    esac
done

for test in "${@:${OPTIND}}"
do
    # shellcheck disable=SC2207
    if stat "$test" >/dev/null 2>&1
    then
        [ ${SPLITS} -ne 0 ] && die -u "Can't define tests and use '-A'"
        ENABLED_TESTS+=($(basename "${test}" .yml))
    else
        log error "Test not found: ${test}"
    fi
done

[ ${SPLITS} -eq 0 ] && [ ${#ENABLED_MODULES[@]} -eq 0 ] && [ ${#ENABLED_TESTS[@]} -eq 0 ] && die -u "No test defined."

# Prepare virtual environment
VENV=$(in_python_virtualenv && echo Y || echo N)

if [ "${FORCE_ENV}" == "Y" ]
then
    [ "${VENV}" == "Y" ] && deactivate
    VENV="N"
    rm -rf "$test_env"
    log info "Virtual environment will be (re)created."
fi

if [ "$VENV" == "N" ]
then
    log info "Preparing virtual environment: ${test_env}"
    if [ ! -d "${test_env}" ]
    then
        log info "Creating virtual environment: ${test_env}..."
        if ! python3 -m venv "${test_env}"
        then
            die "Cannot create virtual environment."
        fi
    fi
    if [ -f "${test_env}/bin/activate" ]
    then
        log info "Starting virtual environment: ${test_env}"
        # shellcheck disable=SC1091
        . "${test_env}/bin/activate" || die "Cannot activate environment."
        STOP_VIRTUALENV="Y"
    else
        die "Cannot activate environment."
    fi
    log info "Installing required tools."
    log none "Upgrading: pip setuptools wheel"
    pip install --quiet --upgrade pip setuptools wheel
    log info "Installing dependencies from 'requirements-tests.txt'"
    pip install --quiet -r "${TOPDIR}/requirements-tests.txt"
    log info "Installing Ansible: ${ANSIBLE_VERSION}"
    pip install --quiet "${ANSIBLE_VERSION}"
    log debug "Ansible version: $(ansible --version | sed -n "1p")${RST}"
else
   log info "Using current virtual environment."
fi

if [ -n "${ANSIBLE_COLLECTIONS}" ]
then
    log warn "Installed collections will not be removed after execution."
    log none "Installing: Ansible Collection ${ANSIBLE_COLLECTIONS}"
    # shellcheck disable=SC2086
    quiet ansible-galaxy collection install ${ANSIBLE_COLLECTIONS} || die "Failed to install Ansible collections."
fi

# Ansible configuration
export ANSIBLE_ROLES_PATH="${TOPDIR}/roles"
export ANSIBLE_LIBRARY="${TOPDIR}/plugins:${TOPDIR}/molecule"
export ANSIBLE_MODULE_UTILS="${TOPDIR}/plugins/module_utils"

# Prepare container
container_id=""
container_status=("-f" "status=created" "-f" "status=running")
[ -n "${scenario}" ] && container_id="$(${engine} ps --all -q -f "name=${scenario}" "${container_status[@]}")"
if [ -z "${container_id}" ]
then
    # Retrieve image and start container.
    log info "Pulling FreeIPA image '${IMAGE_REPO}:${IMAGE_TAG}'..."
    img_id=$(${engine} pull -q "${IMAGE_REPO}:${IMAGE_TAG}")
    log info "Creating container..."
    CONFIG="--hostname ${hostname} --memory ${MEMORY}g --memory-swap -1 --dns none --add-host ipaserver.test.local:127.0.0.1"
    [ -n "${scenario}" ] && CONFIG="${CONFIG} --name ${scenario}"
    # shellcheck disable=SC2086
    container_id=$(${engine} create ${CONFIG} "${img_id}" || die "Cannot create container")
    echo "CONTAINER: ${container_id}"
fi
scenario="${scenario:-$(${engine} ps -q --format "{{.Names}}" --filter "id=${container_id}" "${container_status[@]}")}"
log debug "Using container: ${scenario}"

# Start container
make_inventory "${scenario}"
log info "Starting container for ${scenario}..."
quiet ${engine} start "${scenario}"

# create /etc/resolve.conf
run_inline_playbook <<EOF || die "Failed to create /etc/resolv.conf"
---
- name: Create /etc/resolv.conf
  hosts: ipaserver
  gather_facts: no
  become: yes
  tasks:
  - name: Create /etc/resolv.conf
    ansible.builtin.copy:
      dest: /etc/resolv.conf
      mode: 0644
      content: |
        search test.local
        nameserver 127.0.0.1
...
EOF

# wait for FreeIPA services to be available
run_inline_playbook <<EOF || die "Failed to verify IPA or KDC services."
---
- name: Wait for IPA services to be available
  hosts: ipaserver
  gather_facts: no
  tasks:
  - name: Wait for IPA to be started.
    ansible.builtin.systemd:
      name: ipa
      state: started
  - name: Wait for Kerberos KDC to be started.
    ansible.builtin.systemd:
      name: krb5kdc
      state: started
    register: result
    until: not result.failed
    retries: 30
    delay: 5
  - name: Check if TGT is available for admin.
    ansible.builtin.shell:
      cmd: echo SomeADMINpassword | kinit -c ansible_freeipa_cache admin
    register: result
    until: not result.failed
    retries: 30
    delay: 5
  - name: Cleanup TGT.
    ansible.builtin.shell:
      cmd: kdestroy -c ansible_freeipa_cache -A
...
EOF

# check image software versions.
run_inline_playbook <<EOF || die "Failed to verify software installation."
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


# run tests
RESULT=0

export RUN_TESTS_IN_DOCKER=${engine}
export IPA_SERVER_HOST="${scenario}"
if [ ${SPLITS} -ne 0 ]
then
    EXTRA_OPTIONS="${EXTRA_OPTIONS} --splits=${SPLITS} --group=${GROUP} --randomly-seed=${SEED}"
    log info "Running tests for group ${GROUP} of ${SPLITS} with seed ${SEED}"
else
    # shellcheck disable=SC2086
    joined="$(printf "%s," "${ENABLED_MODULES[@]}")"
    # shelcheck disable=SC2178
    IPA_ENABLED_MODULES="${joined%,}"
    joined="$(printf "%s," "${ENABLED_TESTS[@]}")"
    # shelcheck disable=SC2178
    IPA_ENABLED_TESTS="${joined%,}"
    export IPA_ENABLED_MODULES IPA_ENABLED_TESTS
    [ -n "${IPA_ENABLED_MODULES}" ] && log info "Test suites: ${IPA_ENABLED_MODULES}"
    [ -n "${IPA_ENABLED_TESTS}" ] && log info "Individual tests: ${IPA_ENABLED_TESTS}"
fi

IPA_VERBOSITY="${verbose}"
[ -n "${IPA_VERBOSITY}" ] && export IPA_VERBOSITY

# shellcheck disable=SC2086
if ! pytest -m "playbook" --verbose --color=yes ${EXTRA_OPTIONS}
then
    RESULT=2
    log error "Container not stopped for verification: ${scenario}"
    log info "Container: $(podman ps -f "id=${container_id}" --format "{{.Names}} - {{.ID}}")"
fi
[ -z "${CONTINUE_ON_ERROR}" ] && [ $RESULT -ne 0 ] && die "Stopping on test failure."

# cleanup environment
cleanup "${scenario}" "${engine}"

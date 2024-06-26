#!/bin/bash -eu

SCRIPTDIR="$(readlink -f "$(dirname "$0")")"
TOPDIR="$(readlink -f "${SCRIPTDIR}/..")"

# shellcheck source=utils/shfun
. "${SCRIPTDIR}/shfun"
# shellcheck source=utils/shcontainer
. "${SCRIPTDIR}/shcontainer"
# shellcheck source=utils/shansible
. "${SCRIPTDIR}/shansible"

usage() {
    local prog="${0##*/}"
    cat <<EOF
usage: ${prog} [-h] [-l] [-e] [-K] [-A|-a ANSIBLE] [-p INTERPRETER] [-c CONTAINER] [-s TESTS_SUITE] [-x] [-S SEED.GRP] [-i IMAGE] [-m MEMORY] [-v...] [TEST...]
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
  -a ANSIBLE      Ansible version to use, e.g. "ansible-core==2.16.0"
                  (default: latest ansible-core for the python version)
  -A              Do not install Ansible, use host's provided one.
  -c CONTAINER    use container CONTAINER to run tests
  -K              keep container, even if tests succeed
  -l              list available images
  -e              force recreation of the virtual environment
  -i IMAGE        select image to run the tests (default: fedora-latest)
  -m MEMORY       container memory, in GiB (default: 3)
  -p INTERPRETER  Python interpreter to use on target container
  -s TEST_SUITE   run all playbooks for test suite, which is a directory
                  under ${WHITE}tests${RST}
  -S SEED.GROUP   Replicate Azure's test group and seed (seed is YYYYMMDD)
  -v              Increase Ansible verbosity (can be used multiple times)
  -x              Stop on first error.
EOF
)"
}


# Defaults
verbose=""
engine="${engine:-"podman"}"
CONTINUE_ON_ERROR=""
STOP_CONTAINER="Y"
STOP_VIRTUALENV="N"
declare -a ENABLED_MODULES
declare -a ENABLED_TESTS
read -r -a ENABLED_MODULES <<< "${IPA_ENABLED_MODULES:-""}"
read -r -a ENABLED_TESTS <<< "${IPA_ENABLED_MODULES:-""}"
IMAGE_TAG="fedora-latest"
scenario="freeipa-tests"
MEMORY=3
IPA_HOSTNAME="ipaserver.test.local"
SEED="$(date "+%Y%m%d")"
GROUP=1
SPLITS=0
ANSIBLE_COLLECTIONS=${ANSIBLE_COLLECTIONS:-"${engine_collection}"}
SKIP_ANSIBLE=""
ansible_interpreter="/usr/bin/python3"
EXTRA_OPTIONS=""
unset ANSIBLE_VERSION

# Process command options

while getopts ":ha:Ac:ei:Klm:p:s:S:vx" option
do
    case "$option" in
        h) help && exit 0 ;;
        A)
           [ -n "${ANSIBLE_VERSION:-""}" ] && die "Can't use -A with '-a'"
           SKIP_ANSIBLE="YES"
           ;;
        a) 
           [ "${SKIP_ANSIBLE:-"no"}" == "YES" ] && die "Can't use -A with '-a'"
           ANSIBLE_VERSION="${OPTARG}"
           ;;
        c) scenario="${OPTARG}" ;;
        e) FORCE_ENV="Y" ;;
        i) IMAGE_TAG="${OPTARG}" ;;
        K) STOP_CONTAINER="N" ;;
        l) "${SCRIPTDIR}"/setup_test_container.sh -l && exit 0 || exit 1 ;;
        m) MEMORY="${OPTARG}" ;;
        p) ansible_interpreter="${OPTARG}" ;;
        s)
           [ ${SPLITS} -ne 0 ] && die -u "Can't use '-S' with '-s'"
           if [ -d "${TOPDIR}/tests/${OPTARG}" ]
           then
               ENABLED_MODULES+=("${OPTARG}")
           else
               log error "Invalid suite: ${OPTARG}"
           fi
           ;;
        S)
           [ ${#ENABLED_MODULES[@]} -eq 0 ] || die -u "Can't use '-A' with '-s'"
           SEED="$(cut -d. -f1 <<< "${OPTARG}" | tr -d "-")"
           GROUP="$(cut -d. -f2 <<< "${OPTARG}")"
           if [ -z "${SEED}" ] || [ -z "${GROUP}" ]
           then
               die -u "Seed for '-A' must have the format YYYYMMDD.N"
           fi
           SPLITS=3
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

export STOP_CONTAINER FORCE_ENV STOP_VIRTUALENV ansible_interpreter

# Ensure $python is set
[ -z "${python}" ] && python="python3"

log info "Controller Python executable: ${python}"
${python} --version

# Prepare virtual environment
start_virtual_environment
log info "Installing dependencies from 'requirements-tests.txt'"
pip install --upgrade -r "${TOPDIR}/requirements-tests.txt"

[ -z "${SKIP_ANSIBLE}" ] && install_ansible "${ANSIBLE_VERSION:-"ansible-core"}"

# Ansible configuration
export ANSIBLE_ROLES_PATH="${TOPDIR}/roles"
export ANSIBLE_LIBRARY="${TOPDIR}/plugins"
export ANSIBLE_MODULE_UTILS="${TOPDIR}/plugins/module_utils"

# Start container
"${SCRIPTDIR}/setup_test_container.sh" -e "${engine}" -m "${MEMORY}" -p "${ansible_interpreter}" -i "${IMAGE_TAG}" -n "${IPA_HOSTNAME}" -a "${scenario}" || die "Failed to setup test container"


# run tests
RESULT=0

export RUN_TESTS_IN_DOCKER=${engine}
export IPA_SERVER_HOST="${scenario}"
# Ensure proper ansible_python_interpreter is used by pytest.
export IPA_PYTHON_PATH="${ansible_interpreter}"

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
if ! pytest -m "playbook" --verbose --color=yes --suppress-no-test-exit-code --junit-xml=TEST-results-group-${GROUP:-1}.xml ${EXTRA_OPTIONS}
then
    RESULT=2
    log error "Container not stopped for verification: ${scenario}"
    log info "Container: $(${engine} ps -f "name=${scenario}" --format "{{.Names}} - {{.ID}}")"
fi
[ -z "${CONTINUE_ON_ERROR}" ] && [ $RESULT -ne 0 ] && die "Stopping on test failure."

# cleanup environment
cleanup "${scenario}" "${engine}"

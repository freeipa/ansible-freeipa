#!/bin/bash -eu

SCRIPTDIR="$(readlink -f "$(dirname "$0")")"
TOPDIR="$(readlink -f "${SCRIPTDIR}/../..")"
UTILSDIR="${SCRIPTDIR}"

# shellcheck source=infra/image/shfun
. "${UTILSDIR}/shfun"
# shellcheck source=infra/image/shcontainer
. "${UTILSDIR}/shcontainer"

set -o errexit -o errtrace

trap interrupt_exception SIGINT

interrupt_exception() {
    trap - ERR SIGINT
    log warn "User interrupted test execution."
    # shellcheck disable=SC2119
    cleanup
    exit 1
}

trap cleanup ERR EXIT SIGABRT SIGTERM SIGQUIT

# shellcheck disable=SC2120
cleanup() {
    trap - ERR EXIT SIGABRT SIGTERM SIGQUIT
    log info "Cleaning up environment"
    if [ "${STOP_VIRTUALENV:-"N"}" == "Y" ]
    then
        echo "Deactivating virtual environment"
        run_if_exists deactivate
    fi
}

usage() {
    local prog="${0##*/}"
    cat <<EOF
usage: ${prog} [-h] [-L] [-e] [-A|-a ANSIBLE] [-s TESTS_SUITE] [-x] [-S SEED.GRP] [-l] [-i IMAGE] [-v...] [TEST...]
    ${prog} runs test playbooks using an ansible-freeipa testing images.

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
  -L              list available images
  -l              Try to use local image first, if not found download.
  -e              force recreation of the virtual environment
  -i IMAGE        select image to run the tests
                  (default: fedora-latest-server)
  -s TEST_SUITE   run all playbooks for test suite, which is a directory
                  under ${WHITE}tests${RST}
  -S SEED.GROUP   Replicate Azure's test group and seed (seed is YYYYMMDD)
  -v              Increase Ansible verbosity (can be used multiple times)
  -x              Stop on first error.
EOF
)"
}

install_ansible() {
    ANSIBLE_VERSION="${1:-${ANSIBLE_VERSION:-"ansible-core"}}"
    [ $# -gt 0 ] && shift
    log info "Installing Ansible: ${ANSIBLE_VERSION}"
    pip install --quiet "${ANSIBLE_VERSION}"
    log debug "Ansible version: $(ansible --version | sed -n "1p")${RST}"

    if [ -n "${ANSIBLE_COLLECTIONS}" ]
    then
        collections_path="/tmp/ansible-freeipa-tests-collections"
        for collection in ${ANSIBLE_COLLECTIONS}
        do
            if ! quiet ansible-galaxy collection verify --offline "${collection}"
            then
                log info "Installing: Ansible Collection ${collection}"
                # shellcheck disable=SC2086
                quiet ansible-galaxy collection install \
                    -p "${collections_path}" \
                    "${collection}" || die "Failed to install Ansible collection: ${collection}"
            fi
        done
        default_collections_path="$(ansible-config init | grep "collections_path=" | cut -d= -f2-)"
        export ANSIBLE_COLLECTIONS_PATH="${collections_path}:${ANSIBLE_COLLECTIONS_PATH:-${default_collections_path}}"
    fi
    export ANSIBLE_VERSION
}


# Defaults
verbose=""
CONTINUE_ON_ERROR=""
STOP_VIRTUALENV="N"
FORCE_ENV="N"
declare -a ENABLED_MODULES
declare -a ENABLED_TESTS
read -r -a ENABLED_MODULES <<< "${IPA_ENABLED_MODULES:-""}"
read -r -a ENABLED_TESTS <<< "${IPA_ENABLED_MODULES:-""}"
IMAGE_TAG="fedora-latest-server"
IPA_HOSTNAME="ipaserver.test.local"
SEED="$(date "+%Y%m%d")"
GROUP=1
SPLITS=0
ANSIBLE_COLLECTIONS=${ANSIBLE_COLLECTIONS:-"containers.podman"}
SKIP_ANSIBLE=""
EXTRA_OPTIONS=""
unset LOCAL_IMAGES
unset ANSIBLE_VERSION

# Process command options

while getopts ":ha:Aei:lLs:S:vx" option
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
        e) FORCE_ENV="Y" ;;
        i) IMAGE_TAG="${OPTARG}" ;;
        L) list_images && exit 0 || exit 1 ;;
        l) LOCAL_IMAGES="-l" ;;
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

export IPA_SERVER_HOST="ansible-freeipa-tests"
export STOP_VIRTUALENV

python="$(get_python_executable)"

log info "Python executable: ${python}"
${python} --version

# Prepare virtual environment
declare -a venv_opts=()
[ "${FORCE_ENV}" == "Y" ] && venv_opts+=("-f")
start_virtual_environment "${venv_opts[@]}"
log info "Installing dependencies from 'requirements-tests.txt'"
pip install --upgrade -r "${TOPDIR}/requirements-tests.txt"

[ -z "${SKIP_ANSIBLE}" ] && install_ansible "${ANSIBLE_VERSION:-"ansible-core"}"

# Ansible configuration
export ANSIBLE_ROLES_PATH="${TOPDIR}/roles"
export ANSIBLE_LIBRARY="${TOPDIR}/plugins"
export ANSIBLE_MODULE_UTILS="${TOPDIR}/plugins/module_utils"

# Start test container
"${TOPDIR}/infra/image/start.sh" ${LOCAL_IMAGES:-} "${IMAGE_TAG}" -n "${IPA_HOSTNAME}"

# run tests
RESULT=0

export RUN_TESTS_IN_DOCKER=podman

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
if ! pytest -m "playbook" \
        --verbose \
        --color=yes \
        --suppress-no-test-exit-code \
        --junit-xml=TEST-results-group-${GROUP:-1}.xml \
        ${EXTRA_OPTIONS}
then
    RESULT=2
fi

if [ -z "${CONTINUE_ON_ERROR}" ] && [ $RESULT -ne 0 ]
then
    die "Stopping on test failure."
fi

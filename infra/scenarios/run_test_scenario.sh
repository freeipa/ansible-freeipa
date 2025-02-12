#!/bin/bash -eu

BASEDIR="$(dirname "$(readlink -f "$0")")"
TOPDIR="$(dirname "$(dirname "${BASEDIR}")")"
TESTDIR="${TOPDIR}/tests"

INVENTORY="${TOPDIR}/ansible-freeipa-scenario/inventory.yml"

color_run() {
    cat - | sed -e "
        /FAILED/s/^/[31;1m/
        /^ok/s/^/[32m/
        /^changed/s/^/[33m/
        /^skipping/s/^/[36m/
        /^PLAY RECAP/s/^/[37;1m/
        /: ok=/s/^/[37;1m/
        s/$/[0m/
    "
}

usage() {
    cat <<EOF
usage: run_test_scenario [-k] [-a] [-s SCENARIO] [-m MODULE] [PLAYBOOK...]

Run playbooks against an ansible-freeipa scenario.

Options:

    -h             Display this help screen.
    -k             Destroy the scenario after running tests.
    -a             Run all available test playbooks.
    -s SCENARIO    Select scenario (default: ipa-ad-trust)
    -m MODULE      Run all tests for module.
                   May be used multiple times.
    -v             Increase Ansible verbosity.
                   May be used multiple times.

Notes:

* When no PLAYBOOK or '-a' is provided, check changes in repository to select test to run.
EOF
}

die() {
    [ $# -gt 0 ] && echo "FATAL: $*" >&2
    exit 1
}

split() {
    python3 -c "print('\n'.join(input().split(',')))" <&0
}

declare -a MODULES=()
SCENARIO="${TOPDIR}/infra/scenarios/ipa-ad-trust.yml"
VERBOSITY=0

while getopts ":haks:m:v" option
do
    case "${option}" in
        h) usage && exit 1 ;;
        a) RUN_ALL="Y" ; export SKIP_GIT_TEST="True" ;;
        k) SHUTDOWN="YES" ;;
        m) MODULES+=("${OPTARG}") ;;
        v) VERBOSITY=$(VERBOSITY + 1) ;;
        *) die "Invalid option: ${option}" ;;
    esac
done
shift $((OPTIND - 1))

# Check test selection options
[ -n "${RUN_ALL:-}" ] && [ $# -gt 0 ] && die "Cannot use '-a' and set playbooks."
[ -n "${RUN_ALL:-}" ] && [ -n "${MODULES:-}" ] && die "Cannot use '-a' and select modules."

# Use provided tests
[ -n "${MODULES:-}" ] && IPA_ENABLED_MODULES="$(echo "${MODULES[@]}" | tr " " ",")"
[ -n "${1:-}" ] && IPA_ENABLED_TESTS="$(echo "$@" | tr " " "\n" | xargs -n 1 basename -s .yml | tr "\n" ",")"

# Ensure a scenario is running
if [ -z "$(podman pod ls --filter name=ansible-freeipa-scenario --format "{{ .Name }}")" ]
then
    "${TOPDIR}/infra/scenarios/start-scenario" "${SCENARIO}" || die
else
    echo "WARNING: Running tests against existing scenario."
fi

declare -a PLAYBOOKS=()

[ -z "${1:-}" ] && \
    [ -z "${IPA_ENABLED_MODULES:-}" ] \
    && [ -z "${IPA_ENABLED_TESTS:-}" ] \
    && . infra/azure/scripts/set_test_modules

# Get list of disabled tests
declare -a IGNORE

# Get playbooks for all enabled modules
for module in $(split <<< "${IPA_DISABLED_MODULES[@]}")
do
    grep -qe "^None" <<< "${module}" && continue
    # shellcheck disable=SC2207
    IGNORE+=($(find "${TESTDIR}/${module}" -name "test_*.yml" ))
done

# Get playbooks for all enabled tests
for module in $(split <<< "${IPA_DISABLED_TESTS[@]}")
do
    grep -qe "^None" <<< "${module}" && continue
    IGNORE+=("$(find "${TESTDIR}" -name "${module}.yml" )")
done

echo "${IGNORE[@]}" | tr " " "\n" > /tmp/ignored_tests

# remove duplicates
read -r -a IGNORE <<< "$(echo "${IGNORE[@]}" | tr " " "\n" | sort | uniq | tr "\n" " ")"

if [ -n "${IPA_ENABLED_MODULES:-}" ] || [ -n "${IPA_ENABLED_TESTS:-}" ]
then
    # Get list of enabled modules
    for module in $(split <<< "${IPA_ENABLED_MODULES[@]}")
    do
        grep -qe "^None" <<< "${module}" && continue
        # shellcheck disable=SC2207
        PLAYBOOKS+=($(find "${TESTDIR}/${module}" -name "test_*.yml" ))
    done

    # Get playbooks for all enabled tests
    for module in $(split <<< "${IPA_ENABLED_TESTS[@]}")
    do
        grep -qe "^None" <<< "${module}" && continue
        PLAYBOOKS+=("$(find "${TESTDIR}" -name "${module}.yml" )")
    done
    # remove duplicates
    read -r -a PLAYBOOKS <<< "$(echo "${PLAYBOOKS[@]}" | tr " " "\n" | sort | uniq | tr "\n" " ")"

else
    echo "INFO: Running all tests."
    # shellcheck disable=SC2207
    PLAYBOOKS=($(find "${TESTDIR}" -name "test_*.yml" | tr "\n" " "))
fi

echo -en "\n----------------------------------\n"

count=0
read -r -a test_playbooks <<< "$(grep -Fxvf /tmp/ignored_tests <(echo "${PLAYBOOKS[@]}" | tr " " "\n") | tr "\n" " ")"
[ ${#test_playbooks[@]} -gt 0 ]  && for test in "${test_playbooks[@]}"
do
    count=$((count + 1))
    logfile="test_run_$(basename "${test}" ".yml").log"
    echo -n "[$count/${#test_playbooks[@]}] Test playbook $(basename "${test}"): " | tee "/tmp/${logfile}"
    error="NO"
    ANSIBLE_VERBOSITY="${VERBOSITY}" ansible-playbook -i "${INVENTORY}" "${test}" >> "/tmp/${logfile}" 2>&1 || error="YES"
    if [ "${error}" == "YES" ]
    then
        echo -e "\033[31;1mFAIL\033[0m"
        mv "/tmp/${logfile}" "/tmp/FAILED_${logfile}"
    else
        echo -e "\033[32;1mSUCCESS\033[0m"
    fi
done

report_error() {
    echo -e "\033[37;1m\n====================================="
    head -n 1  "$1"
    echo -e "=====================================\033[0m"
    tail -n 200 "$1" | color_run
    # tail -n 200 "$1" | sed -e "/FAILED/s/^/[31;1m/" -e "/^ok/s/^/[32m/" -e "/^changed/s/^/[33m/" -e "s/$/[0m/"
}

find /tmp -name "*FAILED_*" 2>/dev/null | while read -r filename ; do report_error "${filename}" ; done

if [ "${SHUTDOWN:-"NO"}" == "YES" ]
then
    echo "Shutting down environment"
    infra/scenarios/stop-scenario
fi

# Return error code
[ "${error:-"NO"}" == "YES" ]

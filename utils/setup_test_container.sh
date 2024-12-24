#!/bin/bash -eu

SCRIPTDIR="$(readlink -f "$(dirname "$0")")"

# shellcheck source=utils/shcontainer
. "${SCRIPTDIR}/shcontainer"
# shellcheck source=utils/shansible
. "${SCRIPTDIR}/shansible"

usage() {
    local prog="${0##*/}"
    cat <<EOF
usage: ${prog} [-h] [-l] [-a] [-e ENGINE] [-i IMAGE] [-m MEMORY] [-n HOSTNAME] NAME
    ${prog} starts a container to test ansible-freeipa.

EOF
}

help() {
    usage
    echo -e "$(cat <<EOF
Arguments:

  NAME            set the container name

Options:

  -h              display this message and exit
  -l              list available images
  -a              Test Ansible connection.
  -e ENGINE       set the container engine to use
                  (default: ${WHITE}podman${RST}, if available)
  -i IMAGE        select image to run the tests (default: fedora-latest)
  -m MEMORY       set container memory, in GiB (default: 3)
  -n HOSTNAME     set the hostname in the container
                  (default: ipaserver.test.local)
  -p INTERPRETER  Python interpreter to use on target container
EOF
)"
}

list_images() {
    local quay_api="https://quay.io/api/v1/repository/ansible-freeipa/upstream-tests/tag"
    echo -e "${WHITE}Available images:"
    curl --silent -L "${quay_api}" | jq '.tags[]|.name' | tr -d '"'| sort | uniq | sed "s/.*/    &/"
    echo -e "${RST}"
}

IMAGE_TAG="fedora-latest"
MEMORY="${MEMORY:-3}"
IPA_HOSTNAME="${IPA_HOSTNAME:-"ipaserver.test.local"}"
test_env="${test_env:-"/tmp"}"
ansible_interpreter="/usr/bin/python3"
engine="podman"
ansible_test=""

while getopts ":hae:i:lm:n:p:" option
do
    case "$option" in
        h) help && exit 0 ;;
        a) ansible_test="yes" ;;
        e) engine="${OPTARG}" ;;
        i) IMAGE_TAG="${OPTARG}" ;;
        l) list_images && exit 0 || exit 1;;
        m) MEMORY="${OPTARG}" ;;
        n) IPA_HOSTNAME="${OPTARG}" ;;
        p) ansible_interpreter="${OPTARG}" ;;
        *) die -u "Invalid option: ${OPTARG}" ;;
    esac
done

export IPA_HOSTNAME MEMORY IMAGE_TAG scenario

shift $((OPTIND - 1))
[ $# == 1 ] || die -u "You must provide the name for a single container." 
scenario="${1}"
shift

prepare_container "${scenario}" "${IMAGE_TAG}"
start_container "${scenario}"

log info "Wait till systemd-journald is running"
max=20
wait=2
count=0
while ! podman exec "${scenario}" ps -x | grep -q "systemd-journald"
do
    if [ $count -ge $max ]; then
        die "Timeout: systemd-journald is not starting up"
    fi
    count=$((count+1))
    log none "Waiting ${wait} seconds .."
    sleep ${wait}
done

# wait for FreeIPA services to be available (usually ~45 seconds)
log info "Wait for container to be initialized."
wait=15
while podman exec "${scenario}" systemctl list-jobs | grep -qvi "no jobs running"
do
    log none "Waiting ${wait}s... "
    sleep "${wait}"
    log none "Retrying".
done

# run tests

# ensure we can get a TGT for admin
log info "Testing kinit with admin."
# shellcheck disable=SC2016
"${engine}" exec "${scenario}" /bin/sh -c 'for i in $(seq 5); do echo "SomeADMINpassword" | kinit -c ansible_freeipa_cache admin && kdestroy -c ansible_freeipa_cache -A && break; echo "Failed to get TGT. Retrying in 10s..."; sleep 10; done' || die "Failed to grant admin TGT."

# shellcheck disable=SC2154
log info "Creating inventory."
make_inventory "${scenario}" "${engine}" "${ansible_interpreter:-"/usr/bin/python3"}"
if [ -z "${inventory:-''}" ]
then
    log error "Could not create inventory file."
else
    # shellcheck disable=SC2154
    log info "Inventory path: [${inventory}]"
    # shellcheck disable=SC2154
    log debug "$(cat "${inventory}")"
    if [ "${ansible_test}" == "yes" ]
    then
        log info "Testing Ansible connection."
        # shellcheck disable=SC2154
        run_if_exists ansible_ping "${inventory}"
        log info "Querying installed software"
        run_if_exists query_container_installed_software
    fi
fi


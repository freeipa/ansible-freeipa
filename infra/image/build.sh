#!/bin/bash -eu

BASEDIR="$(readlink -f "$(dirname "$0")")"
TOPDIR="$(readlink -f "${BASEDIR}/../..")"

# shellcheck disable=SC1091
. "${BASEDIR}/shcontainer"
# shellcheck disable=SC1091
. "${TOPDIR}/utils/shfun"

valid_distro() {
    find "${BASEDIR}/dockerfile" -type f -printf "%f\n" | tr "\n" " "
}

usage() {
    local prog="${0##*/}"
    cat << EOF
usage: ${prog} [-h] [-p] [-s] distro
    ${prog} build a container image to test ansible-freeipa.
EOF
}

help() {
    cat << EOF
positional arguments:

    distro    The base distro to build the test container.
              Availble distros: $(valid_distro)

optional arguments:

    -p  Give extended privileges to the container
    -s  Deploy IPA server

EOF
}

name="ansible-freeipa-image-builder"
hostname="ipaserver.test.local"
# Number of cpus is not available in usptream CI (Ubuntu 22.04).
# cpus="2"
memory="3g"
quayname="quay.io/ansible-freeipa/upstream-tests"
privileged=""
deploy_server="N"

while getopts ":hps" option
do
    case "${option}" in
        h) help && exit 0 ;;
        p) privileged="privileged" ;;
        s) deploy_server="Y" ;;
        *) die -u "Invalid option: ${option}" ;;
    esac
done

shift $((OPTIND - 1))
distro=${1:-}

[ -n "${distro}" ] || die "Distro needs to be given.\nUse one of: $(valid_distro)"

[ -f "${BASEDIR}/dockerfile/${distro}" ] \
  || die "${distro} is not a valid distro target.\nUse one of: $(valid_distro)"

container_check

if [ "${deploy_server}" == "Y" ]
then
    [ -n "$(command -v "ansible-playbook")" ] || die "ansible-playbook is required to install FreeIPA."

    deploy_playbook="${TOPDIR}/playbooks/install-server.yml"
    [ -f "${deploy_playbook}" ] || die "Can't find playbook '${deploy_playbook}'"

    inventory_file="${BASEDIR}/build-inventory"
    [ -f "${inventory_file}" ] || die "Can't find inventory '${inventory_file}'"
fi

container_state=$(container_get_state "${name}")

tag="${distro}-base"
server_tag="${distro}-server"

container_remove_image_if_exists "${tag}"
[ "${deploy_server}" == "Y" ] && \
    container_remove_image_if_exists "${server_tag}"

container_build "${tag}" "${BASEDIR}/dockerfile/${distro}" "${BASEDIR}"
container_create "${name}" "${tag}" "${hostname}" "${memory}" "${privileged}"
container_commit "${name}" "${quayname}:${tag}"

if [ "${deploy_server}" == "Y" ]
then
    deployed=false

    [ "${container_state}" != "running" ] && container_start "${name}"

    container_wait_for_journald "${name}"

    log info "= Deploying IPA ="
    if ansible-playbook -u root -i "${inventory_file}" "${deploy_playbook}"
    then
        deployed=true
    fi
    echo

    if $deployed; then
        log info "= Enabling services ="
        container_exec "${name}" systemctl enable fixnet
        container_exec "${name}" systemctl enable fixipaip
        echo
    fi
    
    container_stop "${name}"

    $deployed || die "Deployment failed"

    container_commit "${name}" "${quayname}:${server_tag}"
fi

log info "= DONE: Image created. ="

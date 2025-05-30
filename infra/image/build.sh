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
usage: ${prog} [-h] [-n HOSTNAME] [-s] distro
    ${prog} build a container image to test ansible-freeipa.
EOF
}

help() {
    cat << EOF
positional arguments:

    distro    The base distro to build the test container.
              Availble distros: $(valid_distro)

optional arguments:

    -n HOSTNAME   Container hostname
    -p            Give extended privileges to the container
    -s            Deploy IPA server
EOF
}

name="ansible-freeipa-image-builder"
hostname="ipaserver.test.local"
cpus="2"
memory="3g"
quayname="quay.io/ansible-freeipa/upstream-tests"
deploy_server="N"
deploy_capabilities="SYS_ADMIN,SYSLOG"
capabilities=""

while getopts ":hn:s" option
do
    case "${option}" in
        h) help && exit 0 ;;
        n) hostname="${OPTARG}" ;;
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
    capabilities="${deploy_capabilities}"

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
container_create "${name}" "${tag}" \
    "hostname=${hostname}" \
    "memory=${memory}" \
    "cpus=${cpus}" \
    "${capabilities:+capabilities=$capabilities}"
container_commit "${name}" "${quayname}:${tag}"

if [ "${deploy_server}" == "Y" ]
then
    deployed=false

    # Set path to ansible-freeipa roles
    [ -z "${ANSIBLE_ROLES_PATH:-""}" ] && export ANSIBLE_ROLES_PATH="${TOPDIR}/roles"

    # Install collection containers.podman if not available
    if [ -z "$(ansible-galaxy collection list containers.podman)" ]
    then
        tmpdir="$(mktemp -d)"
        export ANSIBLE_COLLECTIONS_PATH="${tmpdir}"
        ansible-galaxy collection install -p "${tmpdir}" containers.podman
    fi

    [ "${container_state}" != "running" ] && container_start "${name}"

    container_wait_for_journald "${name}"

    log info "= Deploying IPA ="
    if ansible-playbook -u root -i "${inventory_file}" "${deploy_playbook}"
    then
        deployed=true
    fi
    echo
    
    container_stop "${name}"

    $deployed || die "Deployment failed"

    container_commit "${name}" "${quayname}:${server_tag}"
fi

log info "= DONE: Image created. ="

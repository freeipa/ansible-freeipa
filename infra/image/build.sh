#!/bin/bash -eu

BASEDIR="$(readlink -f "$(dirname "$0")")"
TOPDIR="$(readlink -f "${BASEDIR}/../..")"

. "${TOPDIR}/utils/shfun"

valid_distro() {
    find "${BASEDIR}/dockerfile" -type f -printf "%f\n" | tr "\n" " "
}

usage() {
    local prog="${0##*/}"
    cat << EOF
usage: ${prog} [-h] [i] distro
    ${prog} build a container image to test ansible-freeipa.
EOF
}

help() {
    cat << EOF
positional arguments:

    distro    The base distro to build the test container.
              Availble distros: $(valid_distro)

optional arguments:

    -s  Deploy IPA server

EOF
}

name="ansible-freeipa-image-builder"
hostname="ipaserver.test.local"
# Number of cpus is not available in usptream CI (Ubuntu 22.04).
# cpus="2"
memory="4g"
quayname="quay.io/ansible-freeipa/upstream-tests"
deploy_server="N"

while getopts ":hs" option
do
    case "${option}" in
        h) help && exit 0 ;;
        s) deploy_server="Y" ;;
        *) die -u "Invalid option: ${option}" ;;
    esac
done

shift $((OPTIND - 1))
distro=${1:-}

[ -n "${distro}" ] || die "Distro needs to be given.\nUse one of: $(valid_distro)"

[ -f "${BASEDIR}/dockerfile/${distro}" ] \
  || die "${distro} is not a valid distro target.\nUse one of: $(valid_distro)"

if [ "${deploy_server}" == "Y" ]
then
    [ -n "$(command -v "ansible-playbook")" ] || die "ansible-playbook is required to install FreeIPA."

    deploy_playbook="${TOPDIR}/playbooks/install-server.yml"
    [ -f "${deploy_playbook}" ] || die "Can't find playbook '${deploy_playbook}'"

    inventory_file="${BASEDIR}/inventory"
    [ -f "${inventory_file}" ] || die "Can't find inventory '${inventory_file}'"
fi

container_state="$(podman ps -q --all --format "{{.State}}" --filter "name=${name}")"

tag="${distro}-base"
server_tag="${distro}-server"

# in older (as in Ubuntu 22.04) podman versions,
# 'podman image rm --force' fails if the image
# does not exist.
remove_image_if_exists()
{
    local tag_to_remove
    tag_to_remove="${1}"
    if podman image exists "${tag_to_remove}"
    then
        log info "= Cleanup ${tag_to_remove} ="
        podman image rm "${tag_to_remove}" --force
        echo
    fi
}

remove_image_if_exists "${tag}"
[ "${deploy_server}" == "Y" ] && remove_image_if_exists "${server_tag}"


log info "= Building ${tag} ="
podman build -t "${tag}" -f "${BASEDIR}/dockerfile/${distro}" \
       "${BASEDIR}"
echo

log info "= Creating ${name} ="
podman create --privileged --name "${name}" --hostname "${hostname}" \
    --network bridge:interface_name=eth0 --systemd true \
    --memory "${memory}" --memory-swap -1 --no-hosts \
    --replace "${tag}"
echo

log info "= Committing \"${quayname}:${tag}\" ="
podman commit "${name}" "${quayname}:${tag}"
echo

if [ "${deploy_server}" == "Y" ]
then
    log info "= Starting ${name} ="
    [ "${container_state}" == "running" ] || podman start "${name}"
    echo

    log info "= Deploying IPA ="
    ansible-playbook -i "${inventory_file}" "${deploy_playbook}"
    echo

    log info "= Enabling additional services ="
    podman exec "${name}" systemctl enable fixnet
    podman exec "${name}" systemctl enable fixipaip
    echo
    
    log info "= Stopping container ${name} ="
    podman stop "${name}"
    echo

    log info "= Committing \"${quayname}:${server_tag}\" ="
    podman commit "${name}" "${quayname}:${server_tag}"
    echo
fi

log info "= DONE: Image created. ="

# For tests:
# podman start "${name}"
# while [ -n "$(podman exec ansible-test systemctl list-jobs | grep -vi "no jobs running")" ]; do echo "waiting.."; sleep 5; done
# # Run tests
# podman stop "${name}"

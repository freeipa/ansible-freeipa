#!/bin/bash -eu

BASEDIR="$(readlink -f "$(dirname "$0")")"
TOPDIR="$(readlink -f "${BASEDIR}/../..")"

# shellcheck disable=SC1091
. "${BASEDIR}/shcontainer"
# shellcheck disable=SC1091
. "${TOPDIR}/utils/shfun"

usage() {
    local prog="${0##*/}"
    cat << EOF
usage: ${prog} [-h] [-l] [-n HOSTNAME ] image
    ${prog} start a prebuilt ansible-freeipa test container image.
EOF
}

help() {
    cat << EOF
positional arguments:

    image    The image to start, leave empty to get list of images

optional arguments:

    -h            Show this message
    -l            Try to use local image first, if not found download.
    -n HOSTNAME   Set container hostname

NOTE:
    - The hostname must be the same as the hostname of the container
      when FreeIPA was deployed. Use only if you built the image and
      defined its hostname.

EOF
}

list_images() {
    local quay_api="https://quay.io/api/v1/repository/ansible-freeipa/upstream-tests/tag"
    log info "Available images on quay:"
    curl --silent -L "${quay_api}" | jq '.tags[]|.name' | tr -d '"'| sort | uniq | sed "s/.*/    &/"
    echo
    log info "Local images (use -l):"
    local_image=$(container_image_list "${repo}:")
    echo "${local_image}" | sed -e "s/.*://" | sed "s/.*/    &/"
    echo
}

repo="quay.io/ansible-freeipa/upstream-tests"
name="ansible-freeipa-tests"
hostname="ipaserver.test.local"
try_local_first="N"

while getopts ":hln:" option
do
    case "${option}" in
        h) help && exit 0 ;;
        l) try_local_first="Y" ;;
        n) hostname="${OPTARG}" ;;
        *) die -u "Invalid option: ${option}" ;;
    esac
done

shift $((OPTIND - 1))
image=${1:-}

container_check

if [ -z "${image}" ]; then
    list_images
    exit 0
fi

local_image=
if [ "${try_local_first}" == "Y" ]; then
    log info "= Trying to use local image first ="
    local_image=$(container_image_list "${repo}:${image}")
    [ -n "${local_image}" ] && log info "Found ${local_image}"
    echo
fi
if [ -z "${local_image}" ]; then
    log info "= Downloading from quay ="
    local_image=$(container_pull "${repo}:${image}")
    echo
fi

[ -z "${local_image}" ] && die "Image '${image}' is not valid"

container_create "${name}" "${local_image}" "hostname=${hostname}"
container_start "${name}"
container_wait_for_journald "${name}"
container_wait_up "${name}"

log info "Container ${name} is ready to be used."

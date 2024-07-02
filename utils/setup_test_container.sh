#!/bin/bash -eu

SCRIPTDIR="$(readlink -f "$(dirname "$0")")"
TOPDIR="$(readlink -f "${SCRIPTDIR}/..")"

# shellcheck source=utils/shcontainer
. "${SCRIPTDIR}/shcontainer"
# shellcheck source=utils/shansible
. "${SCRIPTDIR}/shansible"

usage() {
    local prog="${0##*/}"
    cat <<EOF
usage: ${prog} [-h] [-l] [-e ENGINE] [-i IMAGE] [-m MEMORY] [-n HOSTNAME] NAME
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
HOSTNAME="${HOSTNAME:-"ipaserver.test.local"}"
test_env="${test_env:-"/tmp"}"
ansible_interpreter="/usr/bin/python3"

while getopts ":he:i:lm:n:p:" option
do
    case "$option" in
        h) help && exit 0 ;;
        e) engine="${OPTARG}" ;;
        i) IMAGE_TAG="${OPTARG}" ;;
        l) list_images && exit 0 || exit 1;;
        m) MEMORY="${OPTARG}" ;;
	n) HOSTNAME="${OPTARG}" ;;
	p) ansible_interpreter="${OPTARG}" ;;
        *) die -u "Invalid option: ${OPTARG}" ;;
    esac
done

export HOSTNAME MEMORY IMAGE_TAG scenario

shift $((OPTIND - 1))
[ $# == 1 ] || die -u "You must provide the name for a single container." 
scenario="${1}"
shift

make_inventory "${scenario}" "${engine:-podman}" "${ansible_interpreter:-"/usr/bin/python3"}"
# shellcheck disable=SC2154
log info "Inventory path: [${inventory}]"
# shellcheck disable=SC2154
log debug "$(cat "${inventory}")"
prepare_container "${scenario}" "${IMAGE_TAG}"
start_container "${IMAGE_TAG}"

ansible_ping "${inventory}"

# configure ipaserver dns resolver to point to itself
run_inline_playbook "${test_env}/playbooks" <<EOF || die "Failed to verify IPA or KDC services."
---
- name: Set DNS resolver to localhost
  hosts: ipaserver
  become: true
  gather_facts: false
  tasks:
    # /etc/resolv.conf on containers must be overwriten
    # Both copy and file modules try to move data over it
    # and it fails with EBUSY.
    - name: Configure /etc/resolv.conf
      ansible.builtin.shell: echo "nameserver 127.0.0.1" > /etc/resolv.conf
      become: true
EOF

# wait for FreeIPA services to be available
run_inline_playbook "${test_env}/playbooks" <<EOF || die "Failed to verify IPA or KDC services."
---
- name: Wait for IPA services to be available
  hosts: ipaserver
  become: true
  gather_facts: false
  tasks:
  - name: Wait for IPA to be started.
    block:
      - name: Start IPA service
        ansible.builtin.shell: ipactl restart
        register: result
        until: not result.failed
        retries: 5
        delay: 30
    rescue:
      - name: Report failure
        ansible.builtin.shell: ipactl status
        failed_when: true
  - name: Wait for Kerberos KDC to be started.
    ansible.builtin.systemd:
      name: krb5kdc
      state: started
    register: result
    until: not result.failed
    retries: 15
    delay: 10
  - name: Check if TGT is available for admin.
    ansible.builtin.shell:
      cmd: echo SomeADMINpassword | kinit -c ansible_freeipa_cache admin
    register: result
    until: not result.failed
    retries: 5
    delay: 10
  - name: Cleanup TGT.
    ansible.builtin.shell:
      cmd: kdestroy -c ansible_freeipa_cache -A
...
EOF


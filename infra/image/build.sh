#!/bin/bash -eu

BASEDIR="$(readlink -f "$(dirname "$0")")"
TOPDIR="$(readlink -f "${BASEDIR}/../..")"

scenario=${1:-}
name="ansible-test"
hostname="ipaserver.test.local"
cpus="2"
memory="4g"
quayname="quay.io/ansible-freeipa/upstream-tests"

if [ -z "${scenario}" ]; then
    echo "ERROR: Image needs to be given"
    exit 1
fi
if [ ! -f "${BASEDIR}/dockerfile/${scenario}" ]; then
    echo "ERROR: ${scenario} is not a valid image"
    exit 1
fi

echo "= Cleanup existing ${scenario} ="
podman image rm "${scenario}" --force
echo

echo "= Building ${scenario} ="
podman build -t "${scenario}" -f "${BASEDIR}/dockerfile/${scenario}" \
       "${BASEDIR}"
echo

echo "= Creating ${name} ="
podman create --privileged --name "${name}" --hostname "${hostname}" \
       --network bridge:interface_name=eth0 --systemd true \
       --cpus "${cpus}" --memory "${memory}" --memory-swap -1 --no-hosts \
       --replace "${scenario}"
echo

echo "= Starting ${name} ="
podman start "${name}"
echo

echo "= Installing IPA ="
ansible-playbook -i "${BASEDIR}/inventory" \
       "${TOPDIR}/playbooks/install-server.yml"
echo

echo "= Enabling additional services ="
podman exec "${name}" systemctl enable fixnet
podman exec "${name}" systemctl enable fixipaip
echo

echo "= Stopping ${name} ="
podman stop "${name}"
echo

echo "= Committing \"${quayname}:${scenario}\" ="
podman commit "${name}" "${quayname}:${scenario}"
echo

echo "= DONE ="

# For tests:
# podman start "${name}"
# while [ -n "$(podman exec ansible-test systemctl list-jobs | grep -vi "no jobs running")" ]; do echo "waiting.."; sleep 5; done
# # Run tests
# podman stop "${name}"

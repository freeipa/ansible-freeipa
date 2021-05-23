#!/bin/sh

trap interrupt_exception SIGINT

WHITE="\033[37;1m"
YELLOW="\033[33;1m"
RED="\033[31;1m"
CYAN="\033[36;1m"
GREEN="\033[32;1m"
MAGENTA="\033[35;1m"
RST="\033[0m"

die() {
	echo $*
	exit 1
}

quiet() {
	 "$@" >/dev/null 2>&1
}

interrupt_exception() {
	die -e "${YELLOW}WARNING: User interrupted test execution.${RST}"
	exit 1
}

in_python_virtualenv() {
	read -r -d "" script <<'EOS'
import sys;
base = getattr(sys, "base_prefix", None) or getattr(sys, "real_prefix", None) or sys.prefix
print('yes' if sys.prefix != base else 'no')
EOS
    test "`python -c "${script}"`" == "yes"
}

usage() {
	cat << EOF
usage: ansbile-freeipa-test.sh [-v...] [-h] [-p CONTAINER] [-e VENV]
                               [-m MODULE] [TEST...]

Run ansible-freeipa tests in a podman container, using a virtual environment.

position arguments:
  TEST                A list of playbook tests to be executed.
                      Either a TEST or a MODULE must be provided.

optional arguments:
  -h                  display this help message and exit.
  -v                  verbose mode (You may use -vvv or -vvvvv for
                      increased information.)
  -p CONTAINER        use the container with name/id CONTAINER.
                      default: dev-test-master
  -C                  If container did not exist, do not stop and
                      remove created container at exit.
  -e VENV             use the virtual environment VENV
                      default: asible-freeipa-tests
  -m MODULE           Add all tests for the MODULE (e.g.: -m config).
  -x                  Stop on first test failure.
EOF
}

TOPDIR="`dirname $0`/.."

TEST_SET=()
STOP_CONTAINER=1
CONTINUE_ON_ERROR="no"
scenario="dev-test-master"
unset verbose
unset STOP_VIRTUALENV

while getopts ":e:vhp:Cm:x" opt
do
	case "${opt}" in
		v) verbose=${verbose:--}${opt} ;;
		h) usage && exit 0;;
		p) scenario="${OPTARG}" ;;
		e) TESTENV_DIR="${OPTARG}" ;;
		C) STOP_CONTAINER=0 ;;
		m) TEST_SET+=(`find ${TOPDIR}/tests/${OPTARG} -name 'test_*'`) ;;
		x) unset CONTINUE_ON_ERROR ;;
		*) break ;;
	esac
done

TEST_SET+=(${@:$OPTIND})

[ ${#TEST_SET[@]} -gt 0 ] || die -e "${RED}ERROR: No test defined.${RST}"

inventory=`mktemp /tmp/ansible-freeipa-test-inventory.XXXXXXXX`
cat << EOF > "${inventory}"
[ipaserver]
${scenario}  ansible_connection=podman
EOF

echo -e "${MAGENTA}INFO: Inventory file: ${inventory}"
cat << EOF
[ipaserver]
${scenario}  ansible_connection=podman
EOF
echo -e "${RST}"

# prepare virtual environment
if ! in_python_virtualenv
then
	test_env="${TESTENV_DIR:-.ansible-freeipa-tests}"

	echo -e "${GREEN}Preparing virtual environment: ${test_env}${RST}"
	[ ! -d "${test_env}" ] || python3 -m venv "${test_env}"
	if [ -f "${test_env}/bin/activate" ]
	then
		echo -e "${CYAN}Starting virtual environment: ${test_env}${RST}"
		. "${test_env}/bin/activate"
		STOP_VIRTUALENV="yes"
	else
		die "Cannot activate environment."
	fi
	echo -e "${WHITE}Installing required tools.${RST}"
	echo -e "${WHITE}Upgrading:${RST} pip setuptools wheel"
	pip install --quiet --upgrade pip setuptools wheel
	echo -e "${WHITE}Installing:${RST} testinfra ansible(2.9)"
	pip install --quiet "testinfra" "ansible>=2.9,<2.10"
	echo -e "${WHITE}Installing ansible-freeipa test requirements...${RST}"
	pip install --quiet -r requirements-tests.txt

fi

# configure Ansible paths to roles and modules.
ANSIBLE_ROLES_PATH="${TOPDIR}/roles"
ANSIBLE_LIBRARY="${TOPDIR}/plugins/modules:${TOPDIR}/molecule"
ANSIBLE_MODULE_UTILS="${TOPDIR}/plugins/module_utils"

# Retrieve and start podman image

echo -e "${WHITE}Checking podman '${scenario}' container.${RST}"
if ! podman container exists "${scenario}"
then
	hostname="ipaserver.test.local"

	echo "Pulling FreeIPA master Fedora latest image..."
	img_id=`podman pull quay.io/ansible-freeipa/upstream-tests:fedora-latest`
	echo "Creating '${scenario}' container..."
	CONFIG="--hostname='${hostname}' --name='${scenario}'"
	container_id=`podman create ${CONFIG} "${img_id}"`
else
	STOP_CONTAINER=0
fi

podman start "${scenario}"

# run tests
RESULT=0
for test in "${TEST_SET[@]}"
do
	echo -e "\n${WHITE}Running:${RST} ${test#utils/../}"
    ansible-playbook ${verbose} -i "${inventory}" "${test}" || RESULT=2
	if [ -z "${CONTINUE_ON_ERROR}" -a $RESULT -ne 0 ]
	then
		die "Stopping on test failure."
	fi
done

# cleanup

if [ "${STOP_CONTAINER}" == "1" ]
then
	echo "Stopping container..."
	quiet podman stop "${scenario}"
	echo "Removing container..."
	quiet podman rm "${scenario}"
fi

rm "${inventory}"

if [ ! -z "${STOP_VIRTUALENV}" ]
then
	echo "Deactivating virtual environment"
	deactivate
fi

# Return 2 if any test has failed.
exit ${RESULT}

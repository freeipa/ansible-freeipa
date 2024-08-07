#!/bin/bash -eu

function valid_fqdn()
{
    local name="${1}"

    [[ "${name}" =~ [[:space:]] ]] && return 1
    [[ "${name}" =~ \. ]] || return 1
    [[ "${name}" =~ \.\. ]] && return 1
    for i in ${name//./ }; do
        [[ "${i}" =~ ^[a-z0-9_/]+$ ]] || return 1
    done
    [[ "${name}" == "localhost.localdomain" ]] && return 1
    return 0
}

function valid_ipv4()
{
    local ip="${1}"
    local rematch="^([0-9]{1,3}\.){3}[0-9]{1,3}$"

    [[ "${ip}" =~ ${rematch} ]] || return 1
    for i in ${ip//./ }; do
        [[ ${i} -le 255 ]] || return 1
    done

    return 0
}

HOSTNAME=$(hostname)
IP=$(hostname -I | cut -d " " -f 1)

if [ -z "${HOSTNAME}" ] || ! valid_fqdn "${HOSTNAME}" ; then
    echo "ERROR: Failed to retrieve hostname."
    exit 1
fi
if [ -z "${IP}" ] || ! valid_ipv4 "${IP}" ; then
    echo "ERROR: Got invalid IPv4 address: '${IP}'"
    exit 1
fi

echo "Fix NET:"
echo "  HOSTNAME: '${HOSTNAME}'"
echo "  IP: '${IP}'"
echo

if grep -qE "^[^(#\s*)][0-9\.]+\s$HOSTNAME(\s|$)" /etc/hosts
then
    sed -i.bak -e "s/.*${HOSTNAME}/${IP}\t${HOSTNAME}/" /etc/hosts
else
    echo -e "$IP\t${HOSTNAME} ${HOSTNAME%%.*}" >> /etc/hosts
fi

cp -a /etc/resolv.conf /etc/resolv.conf.fixnet
cat > /etc/resolv.conf <<EOF
search ${HOSTNAME#*.}
nameserver 127.0.0.1
EOF

echo "/etc/hosts:"
cat "/etc/hosts"
echo
echo "/etc/resolv.conf:"
cat "/etc/resolv.conf"

exit 0

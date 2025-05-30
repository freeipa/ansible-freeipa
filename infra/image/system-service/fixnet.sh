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

DOMAIN=${HOSTNAME#*.}

echo "Fix NET:"
echo "  HOSTNAME: '${HOSTNAME}'"
echo "  DOMAIN:   '${DOMAIN}'"
echo "  IP:       '${IP}'"
echo

# /etc/hosts

sed -i -E "/\s+${HOSTNAME}(\s|$)/d" /etc/hosts
echo -e "$IP\t${HOSTNAME} ${HOSTNAME%%.*}" >> /etc/hosts

echo "/etc/hosts:"
cat "/etc/hosts"

# /etc/resolv.conf

# If bind is not installed, exit
[ -f "/etc/named.conf" ] || exit 0
# If dyndb is not enabled for bind, exit
grep -q '^dyndb "ipa"' "/etc/named.conf" || exit 0

cp -a /etc/resolv.conf /etc/resolv.conf.fixnet
cat > /etc/resolv.conf <<EOF
search ${DOMAIN}
nameserver 127.0.0.1
EOF

echo
echo "/etc/resolv.conf:"
cat "/etc/resolv.conf"

exit 0

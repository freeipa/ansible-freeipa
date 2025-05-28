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
export KRB5CCNAME=ansible_freeipa_cache

if [ -z "${HOSTNAME}" ] || ! valid_fqdn "${HOSTNAME}" ; then
    echo "ERROR: Got invalid hostname: '${HOSTNAME}'"
    exit 1
fi
if [ -z "${IP}" ] || ! valid_ipv4 "${IP}" ; then
    echo "ERROR: Got invalid IPv4 address: '${IP}'"
    exit 1
fi
PTR=$(echo "${IP}" | awk -F"." '{print $4}')
if [ -z "${PTR}" ] || [ -n "${PTR//[0-9]}" ]; then
    echo "ERROR: Failed to get PTR from IPv4 address: '${PTR}'"
    exit 1
fi
FORWARDER=$(grep -s -m 1 ^nameserver /etc/resolv.conf.fixnet | cut -d" " -f 2)
if [ -z "${FORWARDER}" ] || [ "${FORWARDER}" == "127.0.0.1" ]; then
    FORWARDER="8.8.8.8"
fi

echo "Fix IPA:"
echo "  HOSTNAME:  '${HOSTNAME}'"
echo "  IP:        '${IP}'"
echo "  PTR:       '${PTR}'"
echo "  FORWARDER: '${FORWARDER}'"

ZONES=$(ipa -e in_server=true dnszone-find --name-from-ip="${HOSTNAME}." \
            --raw --pkey-only | grep "idnsname:" | awk -F": " '{print $2}')
for zone in ${ZONES}; do
    echo
    if [[ "${zone}" == *".in-addr.arpa."* ]]; then
        echo "Fixing reverse zone ${zone}:"
        OLD_PTR=$(ipa -e in_server=true dnsrecord-find "${zone}" \
                      --ptr-rec="${HOSTNAME}." --raw | grep "idnsname:" | \
                      awk -F": " '{print $2}')
        if [ -z "${OLD_PTR}" ] || [ -n "${OLD_PTR//[0-9]}" ]; then
            echo "ERROR: Failed to get old PTR from '${zone}': '${OLD_PTR}'"
        else
            ipa -e in_server=true dnsrecord-mod "${zone}" "${OLD_PTR}" \
                --ptr-rec="${HOSTNAME}." --rename="${PTR}" || true
        fi
    else
        echo "Fixing forward zone ${zone}:"
        ipa -e in_server=true dnsrecord-mod test.local "${HOSTNAME%%.*}" \
            --a-rec="$IP" || true
        ipa -e in_server=true dnsrecord-mod test.local ipa-ca \
            --a-rec="$IP" || true
    fi
done

ipa -e in_server=true dnsserver-mod "${HOSTNAME}" \
    --forwarder="${FORWARDER}" || true

exit 0

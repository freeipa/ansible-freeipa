#!/bin/bash -eu

HOSTNAME=$(hostname)
IP=$(hostname -I | cut -d " " -f 1)

if [ -z "${HOSTNAME}" ]; then
    echo "ERROR: Failed to retrieve hostname."
    exit 1
fi
if [ -z "${IP}" ]; then
    echo "ERROR: Failed to retrieve IP address."
    exit 1
fi

# shellcheck disable=SC2143
if [ -n "$(grep -P "[[:space:]]${HOSTNAME}" /etc/hosts)" ]; then
    sed -ie "s/.*${HOSTNAME}/${IP}\t${HOSTNAME}/" /etc/hosts
else
    echo -e "$IP\t${HOSTNAME}" >> /etc/hosts
fi

echo "nameserver 127.0.0.1" > /etc/resolv.conf

exit 0

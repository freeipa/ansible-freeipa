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

if ! echo "SomeADMINpassword" | kinit -c ansible_freeipa_cache admin
then
    echo "ERROR: Failed to obtain Kerberos ticket"
    exit 1
fi
KRB5CCNAME=ansible_freeipa_cache \
    ipa dnsrecord-mod test.local "${HOSTNAME%%.*}" --a-rec="$IP"
KRB5CCNAME=ansible_freeipa_cache \
    ipa dnsrecord-mod test.local ipa-ca --a-rec="$IP"
kdestroy -c ansible_freeipa_cache -A

exit 0

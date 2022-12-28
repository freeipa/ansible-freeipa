#!/bin/sh

INPUT=${1:--}

echo "---"
# shellcheck disable=SC2002
cat "${INPUT}" | \
    grep HostName -B1 | \
    sed -e "/^--/d" \
        -e "/^Host/N;s/\n/:/;s/Host \([a-zA-Z0-9.]*\)/\1/;s/ *HostName \(.*\)/ \1/" \
        -e "s/server.*:/server_ip:/" \
        -e "s/cli-.*:/client_ip:/" \
        -e "s/rep-.*:/replica_ip:/"

#!/bin/sh

echo "---"

while [ -n "${1}" ]
do
    echo "${1}_ip: $(vagrant ssh -c "hostname -I" "${1}")"
    shift
done

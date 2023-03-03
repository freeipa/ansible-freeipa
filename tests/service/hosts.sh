#!/bin/bash -eu

NUM=${1-1000}
FILE="hosts.json"

echo "{" > "$FILE"

echo "  \"host_list\": [" >> "$FILE"

for i in $(seq 1 "$NUM"); do
    {
        echo "    {"
        echo "      \"name\": \"www.example$i.com\""
    } >> "$FILE"
    if [ "$i" -lt "$NUM" ]; then
       echo "    }," >> "$FILE"
    else
       echo "    }" >> "$FILE"
    fi
done

echo "  ]" >> "$FILE"

echo "}" >> "$FILE"

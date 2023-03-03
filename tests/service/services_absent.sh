#!/bin/bash -eu

NUM=1000
FILE="services_absent.json"

echo "{" > "$FILE"

echo "  \"services\": [" >> "$FILE"

for i in $(seq 1 "$NUM"); do
    echo "    {" >> "$FILE"
    echo "      \"name\": \"HTTP/www.example$i.com\"," >> "$FILE"
    if [ "$i" -lt "$NUM" ]; then
       echo "    }," >> "$FILE"
    else
       echo "    }" >> "$FILE"
    fi
done

echo "  ]" >> "$FILE"

echo "}" >> "$FILE"

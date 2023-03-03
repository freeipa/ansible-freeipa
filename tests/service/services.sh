#!/bin/bash -eu

NUM=${1-1000}
FILE="services.json"

echo "{" > "$FILE"

echo "  \"service_list\": [" >> "$FILE"

for i in $(seq 1 "$NUM"); do
    {
        echo "    {"
        echo "      \"name\": \"HTTP/www.example$i.com\","
        echo "      \"principal\": \"host/test.example$i.com\""
    } >> "$FILE"
    if [ "$i" -lt "$NUM" ]; then
       echo "    }," >> "$FILE"
    else
       echo "    }" >> "$FILE"
    fi
done

echo "  ]" >> "$FILE"

echo "}" >> "$FILE"

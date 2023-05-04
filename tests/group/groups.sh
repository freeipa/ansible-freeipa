#!/bin/bash -eu

NUM=${1-1000}
FILE="groups.json"

echo "{" > "$FILE"

echo "  \"group_list\": [" >> "$FILE"

for i in $(seq 1 "$NUM"); do
    {
        echo "    {"
        echo "      \"name\": \"group$i\","
        echo "      \"description\": \"group description $i\""
    } >> "$FILE"
    if [ "$i" -lt "$NUM" ]; then
       echo "    }," >> "$FILE"
    else
       echo "    }" >> "$FILE"
    fi
done

echo "  ]" >> "$FILE"

echo "}" >> "$FILE"

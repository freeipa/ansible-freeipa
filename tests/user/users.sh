#!/bin/bash -eu

NUM=${1-1000}
FILE="users.json"
date=$(date --date='+2 years' "+%Y-%m-%d %H:%M:%S")

echo "{" > "$FILE"

echo "  \"users\": [" >> "$FILE"

for i in $(seq 1 "$NUM"); do
    {
        echo "    {"
        echo "      \"name\": \"user$i\","
        echo "      \"first\": \"First $i\","
        echo "      \"last\": \"Last $i\","
        echo "      \"password\": \"user${i}PW\","
        echo "      \"passwordexpiration\": \"$date\""
    } >> "$FILE"
    if [ "$i" -lt "$NUM" ]; then
       echo "    }," >> "$FILE"
    else
       echo "    }" >> "$FILE"
    fi
done

echo "  ]" >> "$FILE"

echo "}" >> "$FILE"

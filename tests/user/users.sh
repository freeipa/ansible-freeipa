#!/bin/bash

NUM=${1-1000}
FILE="users.json"
date=$(date --date='+2 years' "+%Y-%m-%d %H:%M:%S")

echo "{" > $FILE

echo "  \"users\": [" >> $FILE

for i in $(seq 1 $NUM); do
    echo "    {" >> $FILE
    echo "      \"name\": \"user$i\"," >> $FILE
    echo "      \"first\": \"First $i\"," >> $FILE
    echo "      \"last\": \"Last $i\"," >> $FILE
    echo "      \"password\": \"user${i}PW\"," >> $FILE
    echo "      \"passwordexpiration\": \"$date\"" >> $FILE
    if [ $i -lt $NUM ]; then
       echo "    }," >> $FILE
    else
       echo "    }" >> $FILE
    fi
done

echo "  ]" >> $FILE

echo "}" >> $FILE

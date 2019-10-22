#!/bin/bash

NUM=1000
FILE="users_absent.json"

echo "{" > $FILE

echo "  \"users\": [" >> $FILE

for i in $(seq 1 $NUM); do
    echo "    {" >> $FILE
    echo "      \"name\": \"user$i\"," >> $FILE
    if [ $i -lt $NUM ]; then
       echo "    }," >> $FILE
    else
       echo "    }" >> $FILE
    fi
done

echo "  ]" >> $FILE

echo "}" >> $FILE

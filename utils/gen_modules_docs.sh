#!/bin/bash -eu

for i in roles/ipa*/*/*.py; do
    python utils/gen_module_docs.py "$i"
done

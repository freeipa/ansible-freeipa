#!/bin/bash -eu

systemctl stop sssd
rm -rf /var/lib/sss/{db,mc}/*
systemctl start sssd

#!/bin/bash

vagrant rsync controller

vagrant ssh controller -c "cd /vagrant/tests/; ansible-playbook -i ../inventory/hosts.cluster --ssh-extra-args='-o StrictHostKeyChecking=no' $*"

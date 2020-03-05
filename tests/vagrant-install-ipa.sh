#!/bin/bash

vagrant rsync controller

vagrant ssh controller -c "cd /vagrant/tests/; ansible-playbook -i ../inventory/hosts.cluster ../playbooks/install-cluster.yml --ssh-extra-args='-o StrictHostKeyChecking=no'"

#!/bin/bash

# Backup the original file
#sudo cp /etc/hosts /etc/hosts.bak
chmod 777 /etc/hosts
# Add a new entry
echo "192.168.100.120 dockermachine" >> /etc/hosts
echo "192.168.100.121 master1" >> /etc/hosts
echo "192.168.100.122 worker1" >> /etc/hosts
echo "192.168.100.123 dockervm" >> /etc/hosts
echo "192.168.100.145 k8s-master" >> /etc/hosts
echo "192.168.100.100 rancher-pak" >> /etc/hosts
# Display the updated file
sudo cat /etc/hosts

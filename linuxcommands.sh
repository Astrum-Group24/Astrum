#!/bin/bash

#BMM 10/6/2020 6:10am this script portion is designed to remotley access a Linux machine and run the respective commands

#BMM 10/6/2020 6:10am In order for the script to connect back to Astrum.sh it must have a clause for if the OS value equals Linux and the ability to repeat the commands for each device that it determines is Linux.

#BMM 10/6/2020 6:40am SSHPASS MUST BE INSTALLED ON ASTRUM

#BMM 10/7/2020 7:30am Variables from Astrum.sh can be passed as password, username, and hostname

sshpass -p 'A5t7um' ssh -o stricthostkeychecking=no root@zeropi-01.hpbd.uc.edu '

echo '\''<usb>'\''
for i in $(usb-devices | awk -F":" '\''{print $2}'\'' | grep Manufacturer | grep -v =Linux); do usb-devices | grep -B 3 -A 4 $i;done 
echo '\''</usb>'\''

echo '\''<drivespace>'\''
df -hP | grep -v Filesystem | awk '\''0+$5 >= 75  {print ;}'\''
echo '\''</drivespace>'\''

echo '\''<selinux>'\''
sestatus 
echo '\''</selinux>'\''

echo '\''<firewalld>'\''
firewall-cmd --state 
echo '\''</firewalld>'\''

echo '\''<iptables>'\''
service iptables status
echo '\''</iptables>'\''

echo '\''<users>'\''
awk -F: '\''{ print $1}'\'' /etc/passwd 
echo '\''</users>'\''

' > device.txt

#BMM 10/13/2020 8:04am for an example with all outputs visit linuxoutput.txt

#!/bin/bash

#BMM 10/6/2020 6:10am this script portion is designed to remotley access a Linux machine and run the respective commands

#BMM 10/6/2020 6:10am In order for the script to connect back to Astrum.sh it must have a clause for if the OS value equals Linux and the ability to repeat the commands for each device that it determines is Linux.

#BMM 10/6/2020 6:40am SSHPASS MUST BE INSTALLED ON ASTRUM

#Variables from Astrum.sh can be passed as password, username, and hostname

#BMM 10/7/2020 7:30am These are the remote commands that will run on the Linux device. They will be outputted to a temp file for further parsing.

sshpass -p 'A5t7um' ssh root@zeropi-01.hpbd.uc.edu '

for i in $(usb-devices | awk -F":" '\''{print $2}'\'' | grep Manufacturer | grep -v =Linux); do usb-devices | grep -B 3 -A 4 $i;done 

df -hP | grep -v Filesystem | awk '\''0+$5 >= 75  {print ;}'\''

sestatus 

firewall-cmd --state 

awk -F: '\''{ print $1}'\'' /etc/passwd 

' > device.txt

#BMM 10/7/2020 3:23pm I need to continue with parsing. I need an output for testing and I can gather with a Raspberry Pi 3. 

#!/bin/bash

#BMM 10/6/2020 6:10am this script portion is designed to remotley access a Linux machine and run the respective commands

#BMM 10/6/2020 6:10am In order for the script to connect back to Astrum.sh it must have a clause for if the OS value equals Linux and the ability to repeat the commands for each device that it determines is Linux.

#BMM 10/6/2020 6:40am SSHPASS MUST BE INSTALLED ON ASTRUM

#Variables from Astrum.sh can be passed as password, username, and hostname

#BMM 10/7/2020 7:30am These are the remote commands that will run on the Linux device. They will be outputted to a temp file for further parsing.

sshpass -p 'A5t7um' ssh root@zeropi-01.hpbd.uc.edu '

for i in $(usb-devices | awk -F":" '\''{'print $2'}'\'' | grep Manufacturer | grep -v =Linux); do usb-devices | grep -B 3 -A 4 $i;done

df -h 

sestatus 

firewall-cmd --state 

awk -F: '\''{ print $1}'\'' /etc/passwd 

' > device.temp

#BMM 10/7/2020 8:47am I need to continue with parsing. If run against the zeropi's nothing will show for usb devcies because it is looking for the Manufactuer value of the usb device and only reporting on what is not a Linux device. This line is able to locate a webcam or mouse, for instance. Will test with personal raspberry pi.


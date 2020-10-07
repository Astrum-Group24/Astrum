#!/bin/bash

#BMM 10/6/2020 6:10am this script portion is designed to remotley access a Linux machine and run the respective commands

#BMM 10/6/2020 6:10am In order for the script to connect back to Astrum.sh it must have a clause for if the OS value equals Linux and the ability to repeat the commands for each device that it determines is Linux.

#BMM 10/6/2020 6:40am SSHPASS MUST BE INSTALLED ON ASTRUM

#Variables from Astrum.sh can be passed as password, username, and hostname

sshpass -p 'A5t7um' ssh root@zeropi-01.hpbd.uc.edu '

echo "It worked"

df -h
' 

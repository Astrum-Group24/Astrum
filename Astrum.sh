#!/bin/bash
#
#Astrum Created by Vincent Neiheisel, Brett Johnson, and Brenna Martz
#
#Created on 9/7/2020 at 6:33pm 
#
#This script will be used to scan a host and gather open ports, vulnerabilities, etc. 
#This will then be used to generate a report, generate a script to resolve issues, and meet compliance standards.

#VJN 9/7/2020 6:50pm - host will house the machine being scanned. This will either be a Hostname or an IP address. 
read -p 'Enter Hostname or IP: ' host

#VJN 9/7/2020 6:57pm - This will test to see if the IP is valid or not Reference: https://www.linuxjournal.com/content/validating-ip-address-bash-script
if [[ $host =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
    OIFS=$IFS
    IFS='.'
    ip=($host)
    IFS=$OIFS
    [[ ${ip[0]} -le 255 && ${ip[1]} -le 255 && ${ip[2]} -le 255 && ${ip[3]} -le 255 ]]
    stat=$?
fi

#VJN 9/7/2020 7:04pm - stat tells you if the IP is valid or not. 0 = valid, 1 = invalid
echo $stat
#VJN 9/7/2020 7:04pm - this is being used to debug. tells the host being scanned 
echo $host
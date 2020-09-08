#!/bin/bash
#
#Astrum Created by Vincent Neiheisel, Brett Johnson, and Brenna Martz
#
#Created on 9/7/2020 at 6:33pm 
#
#This script will be used to scan a host and gather open ports, vulnerabilities, etc. 
#This will then be used to generate a report, generate a script to resolve issues, and meet compliance standards.

#VJN 9/7/2020 6:50pm - host will house the machine being scanned. This will either be a Hostname or an IP address. 
read -p 'Enter Hostname or IP (A CIDR range is also accepted in x.x.x.x/x format): ' host

#VJN 9/7/2020 6:57pm - This will test to see if the IP is valid or not Reference: https://www.linuxjournal.com/content/validating-ip-address-bash-script
if [[ $host =~ [a-zA-Z] ]]; then
    stat=2
elif [[ $host =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
    OIFS=$IFS
    IFS='.'
    ip=($host)
    IFS=$OIFS
    [[ ${ip[0]} -le 255 && ${ip[1]} -le 255 && ${ip[2]} -le 255 && ${ip[3]} -le 255 ]]
    stat=$?
fi

#BMM 9/8/2020 7:00am - Based on the stat assigned above, the appropriate error message will be generated or the nmap scan will be run
if [[ $stat=1 ]]; then
    echo "Sorry, something is wrong with that IP. Please try again."
else
    nmap -n -sL -T4 $host
fi

echo "Complete" 

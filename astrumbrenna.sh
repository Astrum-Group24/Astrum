#!/bin/bash
#
#Astrum Created by Vincent Neiheisel, Brett Johnson, and Brenna Martz
#
#Created on 9/7/2020 at 6:33pm 
#
#This script will be used to scan a host and gather open ports, vulnerabilities, etc. 
#This will then be used to generate a report, generate a script to resolve issues, and meet compliance standards.

#VJN 9/7/2020 6:50pm - host will house the machine being scanned. This will either be a Hostname or an IP address. 
read -p 'Enter Hostname or IP (a CIDR range in x.x.x.x/x format is accepted): ' host

#VJN 9/9/2020 11:42am - This will test to see if the IP and or cidr is valid or if it is a hostname is valid or not Reference: https://www.linuxjournal.com/content/validating-ip-address-bash-script
if [[ $host =~ [a-zA-Z] ]]; then
    #VJN 9/9/2020 11:42am - This section specifies that $host is a hostname and not an IP 
    stat=4
elif [[ $host =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
    #VJN 9/9/2020 11:42am - This section verifies just IPs
    OIFS=$IFS
    IFS='.'
    ip=($host)
    IFS=$OIFS
    
    #VJN 9/9/2020 11:42am - This section verifies that the IP sections are 255 or less
    [[ ${ip[0]} -le 255 && ${ip[1]} -le 255 && ${ip[2]} -le 255 && ${ip[3]} -le 255 ]]
    stat=$?
elif [[ $host =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\/[0-9]{1,2}$ ]]; then
    #VJN 9/9/2020 11:42am - This section verifies IPs and Cidrs
    #VJN 9/9/2020 11:42am - Seperates IP from Cidr
    ipaddress=$(echo $host | awk -F'/' '{ print $1 }')
    
    echo "ipaddress:     $ipaddress" #This is used for Debug
    
    OIFS=$IFS
    IFS='.'
    ip=($ipaddress)
    IFS=$OIFS
    
    #VJN 9/9/2020 11:42am - This section verifies that the IP sections are 255 or less
    [[ ${ip[0]} -le 255 && ${ip[1]} -le 255 && ${ip[2]} -le 255 && ${ip[3]} -le 255 ]]
    ipstat=$?
    #echo "ipstatus:   $ipstat" #VJN 9/9/2020 11:42am - This is used for Debug
    
    #VJN 9/9/2020 11:42am - Seperates cidr from IP
    cidr=$(echo $host | awk -F'/' '{ print $2 }')

    echo "cidr:     $cidr" #VJN 9/9/2020 11:42am - This is used for Debug
    
    #VJN 9/9/2020 11:42am - This section verifies that the cidr is 32 or less
    if [ "$cidr" -le "32" ]; then
        cidrstat="0"
    else
        cidrstat="1"
    fi
    
    #echo "cidrstatus:   $cidrstat" #VJN 9/9/2020 11:42am - This is used for Debug 
    
    #VJN 9/9/2020 11:42am - This is to set the $stat variable with a combination of the $ipstat and $cidrstat
    if [ "$ipstat" -eq "0" ] && [ "$cidrstat" -eq "0" ]; then
        stat="0"
    elif [ "$ipstat" -eq "1" ] && [ "$cidrstat" -eq "0" ]; then
        stat="1"
    elif [ "$ipstat" -eq "0" ] && [ "$cidrstat" -eq "1" ]; then
        stat="2"
    else
        stat="3"
    fi
fi

echo "status options: 0 = IP & Cidr valid, 1 = IP invalid & cidr valid (or no cidr), 2 = IP valid & cidr invalid, 3 = IP invalid & cidr invalid, 4 = Hostname (not verified)" #VJN 9/9/2020 11:42am - This is for debug. description for the user of the status 

echo "status:   $stat" #VJN 9/9/2020 11:42am - This is for debug. 

echo "host:     $host" #VJN 9/7/2020 7:04pm - this is being used to debug. tells the host being scanned 


#BMM 9/9/2020 4:04pm - This will ensure that the stat information above is valid and then run an nmap on valid hosts and output to an XML file
    if [ "$stat" -eq "0" ]; then
        echo "Scanning many hosts can take a while. Would you like to perform a light scan? This can save time."

#BMM 9/10/2020 8:30am - The 'light scan' option is for having nmap scan only 100 ports versus 1000        

        read -p 'Run light scan? [y/n]: ' answer
            if [ "$answer" = "Y" ] || [ "$answer" = "y" ]; then
                echo "Starting scan, this could take a while depending on the number of devices Astrum scans."
                nmap -F -T4 $host -oX rawlogs/$host_$(date +"%Y-%m-%d").xml
            elif [ "$answer" = "N" ] || ["$answer" = "n" ]; then
                echo "Starting scan, this could take a while depending on the number of devices Astrum scans."
                nmap -T4 $host -oX rawlogs/$host_$(date +"%Y-%m-%d").xml 
            else
                echo "Error. Please try again."
            fi
    else
        echo "Sorry, something is wrong with that information. Please try again."
    fi

echo "Scan complete. It took <find time from XML file> minutes and <yeah> seconds." 

#BMM 9/10/2020 7:57am - BTW during the script you can press enter to see the status of the nmap. It does take a while on a deep scan, so we can try some things to make it faster. 

#!/bin/bash
#Astrum Created by Vincent Neiheisel, Brett Johnson, and Brenna Martz
#Created on 9/7/2020 at 6:33pm 
#This script will be used to scan a host and gather open ports, vulnerabilities, etc. 
#This will then be used to generate a report, generate a script to resolve issues, and meet compliance standards.

#VJN 9/21/2020 7:06pm - This checks and verifies that the required directories and files are present. If not it creates them. 
[ -d "temp" ] || mkdir temp 
[ -d "reports" ] || mkdir reports 
[ -d "rawlogs" ] || mkdir rawlogs 
[ -d "xml" ] || mkdir xml 
[ -e "vulnerabilities.txt" ] || curl https://isc.sans.edu/services.html >> vulnerabilities.txt

#VJN 9/7/2020 6:50pm - host will house the machine being scanned. This will either be a Hostname or an IP address. 
#read -p 'Enter Hostname or IP (with or without cidr): ' host

#VJN 9/28/2020 7:04pm - Setting passed variables to nothing
scantype=
host=
username=
password=

#VJN 9/28/2020 7:08pm - This section grabs the passed variables and assigns them to internal variables
while getopts "s:h:u:p:" opt; do
  case $opt in
    s) scantype=$OPTARG   ;;
    h) host=$OPTARG       ;;
    u) username=$OPTARG   ;;
    p) password=$OPTARG   ;;
    *) echo 'Error: Invalid argument.'
       exit 1
  esac
done

#VJN 9/28/2020 7:15pm - This section will be used to validate the scantype variable. The input has not been chosen as of now so this will be updated at a later date
if [[ $scantype =~ [a-zA-Z] ]]; then
    #TO BE EDITED WHEN WEB INTERFACE IS FURTHER ALONG
elif [[ $scantype =~ [a-zA-Z] ]]; then
    #TO BE EDITED WHEN WEB INTERFACE IS FURTHER ALONG
else 
    #TO BE EDITED WHEN WEB INTERFACE IS FURTHER ALONG
fi 

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

# echo "status options: 0 = IP & Cidr valid, 1 = IP invalid & cidr valid (or no cidr), 2 = IP valid & cidr invalid, 3 = IP invalid & cidr invalid, 4 = Hostname (not verified)" #VJN 9/9/2020 11:42am - This is for debug. description for the user of the status 
# echo "status:   $stat" #VJN 9/9/2020 11:42am - This is for debug. 
# echo "host:     $host" #VJN 9/7/2020 7:04pm - this is being used to debug. tells the host being scanned 

file="rawlogs/$host_$(date +"%Y-%m-%d--%H%M%S").xml"

#BMM 9/9/2020 4:04pm - This will ensure that the stat information above is valid and then run an nmap on valid hosts and output to an XML file
    if [ "$stat" -eq "0" ]; then
        #echo "Scanning many hosts will take a long time. Would you like to perform a light scan? This will save significant time but may provide less information."

        #BMM 9/10/2020 8:30am - The 'light scan' option is for having nmap scan only 100 ports versus 1000 
        #BMM 9/14/202 7:58pm - Added the option for OS scanning, the light option omits devices it deems "uninportant" 

        #read -p 'Run light scan? [y/n]: ' scantype
            if [ "$scantype" = "Y" ] || [ "$scantype" = "y" ]; then
                #echo "Starting scan, this could take a while depending on the number of devices Astrum scans."
                nmap -F -O --osscan-limit -T4 $host --stylesheet astrum.xsl -oX $file
            elif [ "$scantype" = "N" ] || [ "$scantype" = "n" ]; then
                #echo "Starting scan, this could take a while depending on the number of devices Astrum scans."
                nmap -O -T4 $host --stylesheet astrum.xsl -oX $file
                #echo "Error. Please try again."
            fi
    else
        echo "Sorry, something is wrong with that information. Please try again."
    fi

echo "Scan complete." 

#BMM 9/10/2020 7:57am - BTW during the script you can press enter to see the status of the nmap. It does take a while on a deep scan, so we can try some things to make it faster. 

#VJN 9/21/2020 7:17pm - vulnerabilities.txt is a database of ports and known uses / vulnerabilities 
vulnerabilityfile="vulnerabilities.txt"

#VJN 9/21/2020 7:18pm - select is used to grab only the useful information out of the raw nmap output. scanned grabs the section of the nmap output that shows what ports it scanned.
selected=$(cat $file | grep -ie "<hostname name=\|<address addr=\|<port protocol=\|<osmatch name=")
scanned=$(cat $file | grep -ia "<scaninfo type=" | awk -F'services="' '{ print $3 }' | awk -F'"' '{ print $1 }')

#VJN 9/21/2020 8:56pm - This section is used to consolidate all of the seperate lines into one line to be queried later
selected=($(echo $selected | tr " " "-"))
selected=($(echo $selected | tr "<" "\n"))

#VJN 9/21/2020 8:59pm - This section is used to break the selected variable into seperate temp files that contain each individual machine
j=0
for r in "${selected[@]}"; do
    if [[ "$r" == *"ipv4"* ]]; then
        j=$((j+1))
    fi
    
    if [[ "$r" == *"addr="* ]] || [[ "$r" == *"name="* ]] || [[ "$r" == *"portid="* ]] || [[ "$r" == *"state="* ]] || [[ "$r" == *"protocal="* ]] || [[ "$r" == *"osmatch"* ]]; then
        echo "$r" >> temp/machine$j.temp
    fi
done

#VJN 9/21/2020 9:00pm - This reads the temp files and puts them into an array
file=($(ls temp))

#VJN 9/21/2020 9:01pm - This iterates through each temp file and grabs imporant info
for f in "${file[@]}"; do

    #VJN 9/21/2020 9:02pm - This section identifies each data type and puts them into a array
    hostname=$(cat temp/$f | grep -ia "hostname-name=" | awk -F'hostname-name="' '{ print $2 }' | awk -F'"' '{ print $1 }')  
    addressip=$(cat temp/$f | grep -ia "ipv4" | awk -F'address-addr="' '{ print $2 }' | awk -F'"' '{ print $1 }')
    addressmac=$(cat temp/$f | grep -ia "mac" | awk -F'address-addr="' '{ print $2 }' | awk -F'"' '{ print $1 }')
    port=$(cat temp/$f | grep -ia "portid=" | awk -F'portid="' '{ print $2 }' | awk -F'"' '{ print $1 }')
    service=$(cat temp/$f | grep -ia "service-name=" | awk -F'service-name="' '{ print $2 }' | awk -F'"' '{ print $1 }')
    state=$(cat temp/$f | grep -ia "state-state=" | awk -F'state-state="' '{ print $2 }' | awk -F'"' '{ print $1 }')
    protocal=$(cat temp/$f | grep -ia "port-protocol=" | awk -F'port-protocol="' '{ print $2 }' | awk -F'"' '{ print $1 }')
    osmatch=$(cat temp/$f | grep -ia "osmatch-name=" | awk -F'osmatch-name="' '{ print $2 }' | awk -F'"' '{ print $1 }')
    accuracy=$(cat temp/$f | grep -ia "osmatch-name=" | awk -F'accuracy="' '{ print $2 }' | awk -F'"' '{ print $1 }')
       
    #VJN 9/21/2020 9:20pm - This section seperates the variables from one line into an array
    port=($(echo $port | tr "\n" "\n"))
    service=($(echo $service | tr "\n" "\n"))
    state=($(echo $state | tr "\n" "\n"))
    protocal=($(echo $protocal | tr "\n" "\n"))
    osmatch=($(echo $osmatch | tr "\n" "\n"))
    accuracy=($(echo $accuracy | tr "\n" "\n"))

    #VJN 9/22/2020 12:36pm - output specifies the file in which each report will be deposited in
    output="reports/$addressip.txt"

    #VJN 9/22/2020 12:38pm - This section is used to print the hostname and/or IP address and/or Mac address 
    if [ -z "$addressip" ] && [ -z "$addressmac" ] && [ -z "$hostname" ]; then
        echo "Host Machine: Nothing Found" >> $output
    elif [ -z "$addressip" ] && [ -z "$addressmac" ]; then
        echo "Host Machine: $hostname" >> $output
    elif [ -z "$addressip" ] && [ -z "$hostname" ]; then
        echo "Host Machine: $addressmac" >> $output
    elif [ -z "$addressmac" ] && [ -z "$hostname" ]; then
        echo "Host Machine: $addressip" >> $output
    elif [ -z "$addressip" ]; then
        echo "Host Machine: $hostname ($addressmac)" >> $output
    elif [ -z "$addressmac" ]; then
        echo "Host Machine: $hostname ($addressip)" >> $output
    else
        echo "Host Machine: $hostname ($addressip, $addressmac)" >> $output
    fi
    
    #VJN 9/22/2020 12:40pm - This section prints out the prots scanned by nmap 
    echo "Ports Scanned:" >> $output
    printf "\t$scanned\n" >> $output

    #VJN 9/22/2020 12:41pm - This section is used to print out the presumed Operating System of the host machine
    echo "Possible Operating System:" >> $output
    if [ -z "$osmatch" ]; then
        printf "\tNo Operating Sysem could be discerned.\n" >> $output
    else
        e=0
        for r in "${osmatch[@]}"
        do    
            printf "\t(${accuracy[$e]}%%)\t${osmatch[$e]}\n" >> $output
            e=$((e+1))
        done
    fi

    #VJN 9/22/2020 12:36pm - This section is used to print out the vulnerable ports 
    echo "Vulnerable Ports:" >> $output
    if [ -z "$port" ]; then
        printf "\tNo vulnerable ports found.\n" >> $output
    else
        t=0
        for g in "${port[@]}"
        do
            vulnerability=$(cat $vulnerabilityfile | grep -w "${port[$t]}" | grep -w "${protocal[$t]}" | awk '{$1=$2=$3=""; print $0}' | awk '{$1=$1};1' | sed -z 's/\n/, /g')
            if [ -z "$vulnerability" ]; then
                printf "\t(${state[$t]})\t${port[$t]}\t${protocal[$t]}\t[${service[$t]}]\tDescription: N/A\n" >> $output
            else
                printf "\t(${state[$t]})\t${port[$t]}\t${protocal[$t]}\t[${service[$t]}]\tDescription: ${vulnerability::-2}\n" >> $output
            fi 
            t=$((t+1))
        done
    fi

    #VJN 9/22/2020 12:44pm - This is used to remove the temp files 
    rm temp/$f
done

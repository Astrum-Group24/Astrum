#!/bin/bash
#Astrum Created by Vincent Neiheisel, Brett Johnson, and Brenna Martz
#Created on 9/7/2020 at 6:33pm 
#The Scan.sh script will be launched from the web interface and will scan the hosts passed to it and will launch Parse.sh

timeran=$(date +'%Y-%m-%d-%H-%M-%S')

#VJN 9/21/2020 7:06pm - This checks and verifies that the required directories and files are present. If not it creates them. 
[ -d "temp" ] || mkdir temp 
[ -d "reports" ] || mkdir reports
[ -d "reports/$timeran" ] || mkdir reports/$timeran
[ -d "reports/$timeran/html" ] || mkdir reports/$timeran/html
[ -d "reports/$timeran/json" ] || mkdir reports/$timeran/json
[ -d "reports/$timeran/ndjson" ] || mkdir reports/$timeran/ndjson 
[ -d "reports/$timeran/txt" ] || mkdir reports/$timeran/txt 
[ -d "reports/$timeran/xml" ] || mkdir reports/$timeran/xml
[ -d "rawlogs/" ] || mkdir rawlogs 
[ -d "xml" ] || mkdir xml 
[ -e "vulnerabilities.txt" ] || curl https://isc.sans.edu/services.html >> vulnerabilities.txt

#VJN 9/28/2020 7:04pm - Setting passed variables to nothing
scantype=
host=
username='root'
password='A5t7um'

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
#BRJ 10/06/2020 05:33 - Updated to an intermediate state, fast scans should work with this config
    
    #If fastscan/quickscan is selected, set $scantype equal to 'y'
if  [ $scantype = "fast" ]; then
    scantype="y"

    #If slow scan/deepscan is selected, set $scantype equal to 'n'
elif [ $scantype = "slow" ]; then
    scantype="n"

    #error exit on invalid $scantype
else 
    echo 'Error. Invalid scan type'
    exit 1
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
    
    OIFS=$IFS
    IFS='.'
    ip=($ipaddress)
    IFS=$OIFS
    
    #VJN 9/9/2020 11:42am - This section verifies that the IP sections are 255 or less
    [[ ${ip[0]} -le 255 && ${ip[1]} -le 255 && ${ip[2]} -le 255 && ${ip[3]} -le 255 ]]
    ipstat=$?
    
    #VJN 9/9/2020 11:42am - Seperates cidr from IP
    cidr=$(echo $host | awk -F'/' '{ print $2 }')
    
    #VJN 9/9/2020 11:42am - This section verifies that the cidr is 32 or less
    if [ "$cidr" -le "32" ]; then
        cidrstat="0"
    else
        cidrstat="1"
    fi
    
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

file="rawlogs/$host_$(date +"%Y-%m-%d--%H%M%S").xml"

#BMM 9/9/2020 4:04pm - This will ensure that the stat information above is valid and then run an nmap on valid hosts and output to an XML file
    if [ "$stat" -eq "0" ]; then
        #BMM 9/10/2020 8:30am - The 'light scan' option is for having nmap scan only 100 ports versus 1000 
        #BMM 9/14/202 7:58pm - Added the option for OS scanning, the light option omits devices it deems "uninportant" 
        if [ "$scantype" = "Y" ] || [ "$scantype" = "y" ]; then
            nmap -F -O --osscan-limit -T4 $host --stylesheet astrum.xsl -oX $file
        elif [ "$scantype" = "N" ] || [ "$scantype" = "n" ]; then
            nmap -O -T4 $host --stylesheet astrum.xsl -oX $file
        fi
    fi
#BMM 9/10/2020 7:57am - BTW during the script you can press enter to see the status of the nmap. It does take a while on a deep scan, so we can try some things to make it faster. 

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

#VJN 9/21/2020 9:01pm - This iterates through each temp file and launches Parse.sh
for f in "${file[@]}"; do
    source ./Parse.sh -t $timeran -h $f -u $username -p $password  #BRJ 11/9/2020 05:59 - added 'source' to run the commmond in current shell
done

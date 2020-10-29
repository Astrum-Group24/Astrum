#VJN 9/28/2020 7:04pm - Setting passed variables to nothing
timeran=
host=
username='root'
password='A5t7um'

#VJN 9/28/2020 7:08pm - This section grabs the passed variables and assigns them to internal variables
while getopts "t:h:u:p:" opt; do
  case $opt in
    t) timeran=$OPTARG   ;;
    h) host=$OPTARG       ;;
    u) username=$OPTARG   ;;
    p) password=$OPTARG   ;;
    *) echo 'Error: Invalid argument.'
       exit 1
  esac
done

#VJN 9/21/2020 7:17pm - vulnerabilities.txt is a database of ports and known uses / vulnerabilities 
vulnerabilityfile="vulnerabilities.txt"

#VJN 9/21/2020 9:02pm - This section identifies each data type and puts them into a array
hostname=$(cat temp/$host | grep -ia "hostname-name=" | awk -F'hostname-name="' '{ print $2 }' | awk -F'"' '{ print $1 }')  
addressip=$(cat temp/$host | grep -ia "ipv4" | awk -F'address-addr="' '{ print $2 }' | awk -F'"' '{ print $1 }')
addressmac=$(cat temp/$host | grep -ia "mac" | awk -F'address-addr="' '{ print $2 }' | awk -F'"' '{ print $1 }')
port=$(cat temp/$host | grep -ia "portid=" | awk -F'portid="' '{ print $2 }' | awk -F'"' '{ print $1 }')
service=$(cat temp/$host | grep -ia "service-name=" | awk -F'service-name="' '{ print $2 }' | awk -F'"' '{ print $1 }')
state=$(cat temp/$host | grep -ia "state-state=" | awk -F'state-state="' '{ print $2 }' | awk -F'"' '{ print $1 }')
protocal=$(cat temp/$host | grep -ia "port-protocol=" | awk -F'port-protocol="' '{ print $2 }' | awk -F'"' '{ print $1 }')
osmatch=$(cat temp/$host | grep -ia "osmatch-name=" | awk -F'osmatch-name="' '{ print $2 }' | awk -F'"' '{ print $1 }')
accuracy=$(cat temp/$host | grep -ia "osmatch-name=" | awk -F'accuracy="' '{ print $2 }' | awk -F'"' '{ print $1 }')
    
#VJN 9/21/2020 9:20pm - This section seperates the variables from one line into an array
port=($(echo $port | tr "\n" "\n"))
service=($(echo $service | tr "\n" "\n"))
state=($(echo $state | tr "\n" "\n"))
protocal=($(echo $protocal | tr "\n" "\n"))
osmatch=($(echo $osmatch | tr "\n" "\n"))
accuracy=($(echo $accuracy | tr "\n" "\n"))

#VJN 9/22/2020 12:36pm - outputtxt specifies the file in which each txt report will be deposited in
outputtxt="reports/$timeran/txt/$addressip.txt"
#VJN 9/29/2020 7:06pm - outputxml specifies the file in which each xml report will be deposited in
outputxml="reports/$timeran/xml/$addressip.xml"
#VJN 10/1/2020 12:30pm - outputhtml specifies the file in which each html report will be deposited in
outputhtml="reports/$timeran/html/$addressip.html"
#VJN 10/1/2020 5:30pm - outputjson specifies the file in which each json report will be deposited in
outputjson="reports/$timeran/json/$addressip.json"
#VJN 10/1/2020 5:30pm - outputndjson specifies the file in which each ndjson report will be deposited in
outputndjson="reports/$timeran/ndjson/$addressip.ndjson"

#VJN 10/19/2020 7:53pm - This section will determin if the machine being scan is windows or linux and will run the appropriate commands respectivly
if [[ "${osmatch[0]}" == *"Windows"* ]];then
    echo "Windows!"

    #windowscommandoutput="temp/$addressip.temp"
    windowscommandoutput="windowsoutput.txt" #VJN 10/26/2020 11:05pm - This is for debugging

    #sshpass -p $password ssh -o stricthostkeychecking=no $username@$ipaddress 'echo ^<usb^> && pnputil /enum-devices /connected && echo ^</usb^> && echo ^<drivespace^> && for /f "tokens=1-3" %a in ('\''WMIC LOGICALDISK GET FreeSpace^,Name^,Size ^|FINDSTR /I /V "Name"'\'') do @echo wsh.echo "%b" ^& " Free=" ^& FormatNumber^(cdbl^(%a^)/1024/1024/1024, 2^)^& " GB"^& " Total Space=" ^& FormatNumber^(cdbl^(%c^)/1024/1024/1024, 2^)^& " GB" > %temp%\tmp.vbs & @if not "%c"=="" @echo( & @cscript //nologo %temp%\tmp.vbs & del %temp%\tmp.vbs && echo ^</drivespace^> && echo ^<windefend^> && sc query WinDefend && echo ^</windefend^> && echo ^<mcafee^> && sc query mfemms && echo ^</mcafee^> && echo ^<norton^> && sc query navapsvc && echo ^</norton^> && echo ^<kapersky^> && sc query klnagent && echo ^</kapersky^> && echo ^<ciscoamp^> && sc query FireAMP && echo ^</ciscoamp^> && echo ^<users^> && net user && echo ^</users^> ' > $windowscommandoutput

    drivename=$(sed -n '/<drivespace/{n;:a;p;n;/<\/drivespace>/!ba}' $windowscommandoutput | awk -F' ' '{ print $1 }' | tr -d "\n")
    drivesize=$(sed -n '/<drivespace/{n;:a;p;n;/<\/drivespace>/!ba}' $windowscommandoutput | awk -F'=' '{ print $3 }' | awk -F' ' '{ print $1 }' | tr -d "\n")
    driveused=$(sed -n '/<drivespace/{n;:a;p;n;/<\/drivespace>/!ba}' $windowscommandoutput | awk -F'=' '{ print $2 }' | awk -F'Total' '{ print $1 }' | awk -F' ' '{ print $1 }' | tr -d "\n")
    driveavalible=$(echo "$drivesize $driveused" | awk '{print $1-$2}')
    driveusage=$(echo "$driveused $drivesize" | awk '{print $1/$2*100}' | awk '{print int($1)}')
    defenderstatus=$(sed -n '/<windefend/{n;:a;p;n;/<\/windefend>/!ba}' $windowscommandoutput | grep -ia "STATE" | awk -F' ' '{ print $4 }')
    users=$(sed -n '/<users/{n;:a;p;n;/<\/users>/!ba}' $windowscommandoutput | sed -n '/----------/{n;:a;p;n;/The command completed successfully./!ba}')
    users=($(echo $users | tr "\n" "\n"))
else
    echo "Linux!" #VJN 10/19/2020 - 8:42pm - This is for debug 
    #BMM 10/6/2020 6:10am this script portion is designed to remotley access a Linux machine and run the respective commands
    #BMM 10/6/2020 6:10am In order for the script to connect back to Astrum.sh it must have a clause for if the OS value equals Linux and the ability to repeat the commands for each device that it determines is Linux.
    #BMM 10/6/2020 6:40am SSHPASS MUST BE INSTALLED ON ASTRUM
    #BMM 10/7/2020 7:30am Variables from Astrum.sh can be passed as password, username, and hostname

    #linuxcommandoutput="temp/$addressip.temp"
    linuxcommandoutput="linuxoutput.txt" #VJN 10/22/2020 12:16pm - This is for debugging

    # sshpass -p $password ssh -o stricthostkeychecking=no $username@$ipaddress '
    # echo '\''<usb>'\''
    # for i in $(usb-devices | awk -F":" '\''{print $2}'\'' | grep Manufacturer | grep -v =Linux); do usb-devices | grep -B 3 -A 4 $i;done 
    # echo '\''</usb>'\''
    # echo '\''<drivespace>'\''
    # df -hP | grep -v Filesystem | awk '\''0+$5 >= 75  {print ;}'\''
    # echo '\''</drivespace>'\''
    # echo '\''<selinux>'\''
    # sestatus 
    # echo '\''</selinux>'\''
    # echo '\''<firewalld>'\''
    # firewall-cmd --state 
    # echo '\''</firewalld>'\''
    # echo '\''<iptables>'\''
    # service iptables status
    # echo '\''</iptables>'\''
    # echo '\''<users>'\''
    # awk -F: '\''{ print $1}'\'' /etc/passwd 
    # echo '\''</users>'\''
    # ' > $linuxcommandoutput

    selinuxstatus=$(sed -n '/<selinux/{n;:a;p;n;/<\/selinux>/!ba}' $linuxcommandoutput | awk -F' ' '{ print $3 }')
    drivename=$(sed -n '/<drivespace/{n;:a;p;n;/<\/drivespace>/!ba}' $linuxcommandoutput | awk -F' ' '{ print $1 }')
    drivesize=$(sed -n '/<drivespace/{n;:a;p;n;/<\/drivespace>/!ba}' $linuxcommandoutput | awk -F' ' '{ print $2 }')
    driveused=$(sed -n '/<drivespace/{n;:a;p;n;/<\/drivespace>/!ba}' $linuxcommandoutput | awk -F' ' '{ print $3 }')
    driveavalible=$(sed -n '/<drivespace/{n;:a;p;n;/<\/drivespace>/!ba}' $linuxcommandoutput | awk -F' ' '{ print $4 }')
    driveusage=$(sed -n '/<drivespace/{n;:a;p;n;/<\/drivespace>/!ba}' $linuxcommandoutput | awk -F' ' '{ print $5 }' | awk -F'%' '{ print $1 }')
    drivepath=$(sed -n '/<drivespace/{n;:a;p;n;/<\/drivespace>/!ba}' $linuxcommandoutput | awk -F' ' '{ print $6 }')
    firewalldstatus=$(sed -n '/<firewalld/{n;:a;p;n;/<\/firewalld>/!ba}' $linuxcommandoutput | awk -F' ' '{ print $1 }')
    iptablesstatustemp=$(sed -n '/<iptables/{n;:a;p;n;/<\/iptables>/!ba}' $linuxcommandoutput | awk -F' ' '{ print $2 }')
    iptablesstatustemp=($(echo $iptablesstatustemp | tr "\n" "\n"))
    iptablesstatus=${iptablesstatustemp[2]}
    users=$(sed -n '/<users/{n;:a;p;n;/<\/users>/!ba}' $linuxcommandoutput)
    users=($(echo $users | tr "\n" "\n"))
fi 

#VJN 9/29/2020 7:06pm - This specifies the type of xml we are exporting
echo '<?xml version="1.0" encoding="UTF-8"?>' >> $outputxml #VJN 9/29/2020 7:13pm - for xml report

#VJN 10/1/2020 12:30pm - This specifies the type of html we are exporting
echo "<!DOCTYPE html>" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
echo "<html lang=\"en\">" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
printf "\t<head>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
printf "\t\t<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
printf "\t\t<link href=\"astrum.css\" rel=\"stylesheet\">\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
printf "\t\t<link rel=\"icon\" href=\"../../../logos/aslt.ico\">\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
printf "\t\t<meta charset=\"utf-8\">\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
printf "\t\t<title>$addressip Vulnerability Report</title>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
printf "\t</head>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
printf "\t<body>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report

#VJN 10/2/2020 3:25pm - This specifies the type of json we are exporting
printf "{\n\t\"machine\":\n\t{\n" >> $outputjson #VJN 10/2/2020 10:48pm - for json report

#VJN 10/2/2020 3:25pm - This specifies the type of ndjson we are exporting
printf "{\"machine\": { " >> $outputndjson #VJN 10/2/2020 10:48pm - for ndjson report

#VJN 9/22/2020 12:38pm - This section is used to print the hostname and/or IP address and/or Mac address 
if [ -z "$addressmac" ] && [ -z "$hostname" ]; then
    echo "Host Machine: $addressip" >> $outputtxt #VJN 9/29/2020 7:08pm - for txt report
    
    echo "<machine ipaddress=\"$addressip\">" >> $outputxml #VJN 9/29/2020 7:13pm - for xml report
    
    printf "\t\t<h1>$addressip</h1>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report

    printf "\t\t\"ipaddress\": \"$addressip\",\n" >> $outputjson #VJN 10/2/2020 10:48pm - for json report

    printf "\"ipaddress\": \"$addressip\", " >> $outputndjson #VJN 10/2/2020 10:48pm - for ndjson report
elif [ -z "$hostname" ]; then
    echo "Host Machine: $addressip ($addressmac)" >> $outputtxt #VJN 9/29/2020 7:08pm - for txt report
    
    echo "<machine ipaddress=\"$addressip\" macaddress=\"$addressmac\">" >> $outputxml #VJN 9/29/2020 7:13pm - for xml report
    
    printf "\t\t<h1>$addressip ($addressmac)</h1>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report

    printf "\t\t\"ipaddress\": \"$addressip\",\n\t\t\"macaddress\": \"$addressmac\",\n" >> $outputjson #VJN 10/2/2020 10:48pm - for json report

    printf "\"ipaddress\": \"$addressip\", \"macaddress\": \"$addressmac\", " >> $outputndjson #VJN 10/2/2020 10:48pm - for ndjson report
elif [ -z "$addressmac" ]; then
    echo "Host Machine: $hostname ($addressip)" >> $outputtxt #VJN 9/29/2020 7:08pm - for txt report
    
    echo "<machine hostname=\"$hostname\" ipaddress=\"$addressip\">" >> $outputxml #VJN 9/29/2020 7:13pm - for xml report
    
    printf "\t\t<h1>$hostname ($addressip)</h1>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report

    printf "\t\t\"hostname\": \"$hostname\",\n\t\t\"ipaddress\": \"$addressip\",\n" >> $outputjson #VJN 10/2/2020 10:48pm - for json report

    printf "\"hostname\": \"$hostname\", \"ipaddress\": \"$addressip\", " >> $outputndjson #VJN 10/2/2020 10:48pm - for ndjson report
else
    echo "Host Machine: $hostname ($addressip, $addressmac)" >> $outputtxt #VJN 9/29/2020 7:08pm - for txt report
    
    echo "<machine hostname=\"$hostname\" ipaddress=\"$addressip\" macaddress=\"$addressmac\">" >> $outputxml #VJN 9/29/2020 7:13pm - for xml report            
    
    printf "\t\t<h1>$hostname ($addressip, $addressmac)</h1>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report

    printf "\t\t\"hostname\": \"$hostname\",\n\t\t\"ipaddress\": \"$addressip\",\n\t\t\"macaddress\": \"$addressmac\",\n" >> $outputjson #VJN 10/2/2020 10:48pm - for json report

    printf "\"hostname\": \"$hostname\", \"ipaddress\": \"$addressip\", \"macaddress\": \"$addressmac\", " >> $outputndjson #VJN 10/2/2020 10:48pm - for ndjson report
fi

#VJN 9/22/2020 12:40pm - This section prints out the prots scanned by nmap 
echo "Ports Scanned:" >> $outputtxt #VJN 9/29/2020 7:08pm - for txt report
printf "\t$scanned\n" >> $outputtxt #VJN 9/29/2020 7:08pm - for txt report

printf "\t<scanned ports=\"$scanned\"/>\n" >> $outputxml #VJN 9/29/2020 7:13pm - for xml report

printf "\t\t<h2>Ports Scanned</h2>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
printf "\t\t\t<p>$scanned</p>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report

printf "\t\t\"scannedports\": \"$scanned\",\n" >> $outputjson #VJN 10/2/2020 10:48pm - for json report

printf "\"scannedports\": \"$scanned\", " >> $outputndjson #VJN 10/2/2020 10:48pm - for ndjson report

#VJN 9/22/2020 12:41pm - This section is used to print out the presumed Operating System of the host machine
echo "Possible Operating System:" >> $outputtxt #VJN 9/29/2020 7:08pm - for txt report

printf "\t\t<h2>Possible Operating System</h2>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
if [ -z "$osmatch" ]; then    
    printf "\tNo Operating Sysem could be discerned\n" >> $outputtxt #VJN 9/29/2020 7:08pm - for txt report
            
    printf "\t\t\t<p>No Operating Sysem could be discerned</p>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
else
    e=0
    printf "\t\t\"osmatches\":\n\t\t[\n" >> $outputjson #VJN 10/2/2020 10:48pm - for json report

    printf "\"osmatches\": [ " >> $outputndjson #VJN 10/2/2020 10:48pm - for ndjson report

    printf "\t<osmatches>\n" >> $outputxml #VJN 9/29/2020 7:13pm - for xml report
    
    printf "\t\t\t<table>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
    printf "\t\t\t\t<tr>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
    printf "\t\t\t\t\t<td>Operating System Guess</td>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
    printf "\t\t\t\t\t<td>Accuracy</td>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
    printf "\t\t\t\t</tr>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
    
    for r in "${osmatch[@]}"
    do    
        printf "\t(${accuracy[$e]}%%)\t${osmatch[$e]}\n" >> $outputtxt #VJN 9/29/2020 7:08pm - for txt report
        
        printf "\t\t<osmatch name=\"${osmatch[$e]}\" accuracy=\"${accuracy[$e]}%%\"/>\n" >> $outputxml #VJN 9/29/2020 7:13pm - for xml report
        
        printf "\t\t\t\t<tr>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
        printf "\t\t\t\t\t<td>${osmatch[$e]}</td>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
        printf "\t\t\t\t\t<td>${accuracy[$e]}%%</td>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
        printf "\t\t\t\t</tr>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
        
        if [ "$e" -eq "$((${#osmatch[@]}-1))" ]; then
            printf "\t\t\t{\n\t\t\t\t\"name\": \"${osmatch[$e]}\",\n\t\t\t\t\"accuracy\": \"${accuracy[$e]}\"\n\t\t\t}\n" >> $outputjson #VJN 10/2/2020 10:48pm - for json report
            printf "{ \"name\": \"${osmatch[$e]}\", \"accuracy\": \"${accuracy[$e]}\" } " >> $outputndjson #VJN 10/2/2020 10:48pm - for ndjson report
        else 
            printf "\t\t\t{\n\t\t\t\t\"name\": \"${osmatch[$e]}\",\n\t\t\t\t\"accuracy\": \"${accuracy[$e]}\"\n\t\t\t},\n" >> $outputjson #VJN 10/2/2020 10:48pm - for json report
            printf "{ \"name\": \"${osmatch[$e]}\", \"accuracy\": \"${accuracy[$e]}\" }, " >> $outputndjson #VJN 10/2/2020 10:48pm - for ndjson report
        fi
        e=$((e+1))
    done
    printf "\t</osmatches>\n" >> $outputxml #VJN 9/29/2020 7:13pm - for xml report
    
    printf "\t\t\t</table>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report

    printf "\t\t],\n" >> $outputjson #VJN 10/2/2020 10:48pm - for json report

    printf "], " >> $outputndjson #VJN 10/2/2020 10:48pm - for ndjson report
fi

#VJN 9/22/2020 12:36pm - This section is used to print out the vulnerable ports 
echo "Vulnerable Ports:" >> $outputtxt #VJN 9/29/2020 7:08pm - for txt report

printf "\t\t<h2>Vulnerable Ports</h2>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
if [ -z "$port" ]; then
    printf "\tNo vulnerable ports found\n" >> $outputtxt #VJN 9/29/2020 7:08pm - for txt report
        
    printf "\t\t\t<p>No vulnerable ports found</p>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
else
    t=0
    printf "\t\t\"ports\":\n\t\t[\n" >> $outputjson #VJN 10/2/2020 10:48pm - for json report

    printf "\"ports\": [ " >> $outputndjson #VJN 10/2/2020 10:48pm - for ndjson report

    printf "\t<ports>\n" >> $outputxml #VJN 9/29/2020 7:13pm - for xml report
    
    printf "\t\t\t<table>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
    printf "\t\t\t\t<tr>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
    printf "\t\t\t\t\t<td>Port</td>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
    printf "\t\t\t\t\t<td>Protocal</td>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
    printf "\t\t\t\t\t<td>State</td>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
    printf "\t\t\t\t\t<td>Service</td>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
    printf "\t\t\t\t\t<td>Description</td>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
    printf "\t\t\t\t</tr>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report

    for g in "${port[@]}"
    do
        vulnerability=$(cat $vulnerabilityfile | grep -w "${port[$t]}" | grep -w "${protocal[$t]}" | awk '{$1=$2=$3=""; print $0}' | awk '{$1=$1};1' | sed -z 's/\n/, /g')
        if [ -z "$vulnerability" ]; then
            printf "\t(${state[$t]})\t${port[$t]}\t${protocal[$t]}\t[${service[$t]}]\tDescription: N/A\n" >> $outputtxt #VJN 9/29/2020 7:08pm - for txt report
            
            printf "\t\t<port number=\"${port[$t]}\" protocal=\"${protocal[$t]}\" state=\"${state[$t]}\" service=\"${service[$t]}\" description=\"N/A\"/>\n" >> $outputxml #VJN 9/29/2020 7:13pm - for xml report
            
            printf "\t\t\t\t<tr>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
            printf "\t\t\t\t\t<td>${port[$t]}</td>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
            printf "\t\t\t\t\t<td>${protocal[$t]}</td>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report 
            printf "\t\t\t\t\t<td>${state[$t]}</td>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
            printf "\t\t\t\t\t<td>${service[$t]}</td>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
            printf "\t\t\t\t\t<td>N/A</td>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
            printf "\t\t\t\t</tr>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
        
            if [ "$t" -eq "$((${#port[@]}-1))" ]; then
                printf "\t\t\t{\n\t\t\t\t\"number\": \"${port[$t]}\",\n\t\t\t\t\"protocal\": \"${protocal[$t]}\",\n\t\t\t\t\"state\": \"${state[$t]}\",\n\t\t\t\t\"service\": \"${service[$t]}\",\n\t\t\t\t\"description\": \"N/A\"\n\t\t\t}\n" >> $outputjson #VJN 10/2/2020 10:48pm - for json report
                printf "{ \"number\": \"${port[$t]}\", \"protocal\": \"${protocal[$t]}\", \"state\": \"${state[$t]}\", \"service\": \"${service[$t]}\", \"description\": \"N/A\" } " >> $outputndjson #VJN 10/2/2020 10:48pm - for ndjson report
            else 
                printf "\t\t\t{\n\t\t\t\t\"number\": \"${port[$t]}\",\n\t\t\t\t\"protocal\": \"${protocal[$t]}\",\n\t\t\t\t\"state\": \"${state[$t]}\",\n\t\t\t\t\"service\": \"${service[$t]}\",\n\t\t\t\t\"description\": \"N/A\"\n\t\t\t},\n" >> $outputjson #VJN 10/2/2020 10:48pm - for json report
                printf "{ \"number\": \"${port[$t]}\", \"protocal\": \"${protocal[$t]}\", \"state\": \"${state[$t]}\", \"service\": \"${service[$t]}\", \"description\": \"N/A\" }, " >> $outputndjson #VJN 10/2/2020 10:48pm - for ndjson report
            fi
        else
            printf "\t(${state[$t]})\t${port[$t]}\t${protocal[$t]}\t[${service[$t]}]\tDescription: ${vulnerability::-2}\n" >> $outputtxt #VJN 9/29/2020 7:08pm - for txt report
            
            printf "\t\t<port number=\"${port[$t]}\" protocal=\"${protocal[$t]}\" state=\"${state[$t]}\" service=\"${service[$t]}\" description=\"${vulnerability::-2}\"/>\n" >> $outputxml #VJN 9/29/2020 7:13pm - for xml report
        
            printf "\t\t\t\t<tr>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
            printf "\t\t\t\t\t<td>${port[$t]}</td>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
            printf "\t\t\t\t\t<td>${protocal[$t]}</td>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
            printf "\t\t\t\t\t<td>${state[$t]}</td>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
            printf "\t\t\t\t\t<td>${service[$t]}</td>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
            printf "\t\t\t\t\t<td>${vulnerability::-2}</td>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
            printf "\t\t\t\t</tr>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
        
            if [ "$t" -eq "$((${#port[@]}-1))" ]; then
                printf "\t\t\t{\n\t\t\t\t\"number\": \"${port[$t]}\",\n\t\t\t\t\"protocal\": \"${protocal[$t]}\",\n\t\t\t\t\"state\": \"${state[$t]}\",\n\t\t\t\t\"service\": \"${service[$t]}\",\n\t\t\t\t\"description\": \"${vulnerability::-2}\"\n\t\t\t}\n" >> $outputjson #VJN 10/2/2020 10:48pm - for json report
                printf "{ \"number\": \"${port[$t]}\", \"protocal\": \"${protocal[$t]}\", \"state\": \"${state[$t]}\", \"service\": \"${service[$t]}\", \"description\": \"${vulnerability::-2}\"} " >> $outputndjson #VJN 10/2/2020 10:48pm - for ndjson report
            else 
                printf "\t\t\t{\n\t\t\t\t\"number\": \"${port[$t]}\",\n\t\t\t\t\"protocal\": \"${protocal[$t]}\",\n\t\t\t\t\"state\": \"${state[$t]}\",\n\t\t\t\t\"service\": \"${service[$t]}\",\n\t\t\t\t\"description\": \"${vulnerability::-2}\"\n\t\t\t},\n" >> $outputjson #VJN 10/2/2020 10:48pm - for json report
                printf "{ \"number\": \"${port[$t]}\", \"protocal\": \"${protocal[$t]}\", \"state\": \"${state[$t]}\", \"service\": \"${service[$t]}\", \"description\": \"${vulnerability::-2}\"}, " >> $outputndjson #VJN 10/2/2020 10:48pm - for ndjson report
            fi
        fi 
        t=$((t+1))
    done
    printf "\t</ports>\n" >> $outputxml #VJN 9/29/2020 7:13pm - for xml report
    
    printf "\t\t\t</table>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
    
    printf "\t\t],\n" >> $outputjson #VJN 10/2/2020 10:48pm - for json report

    printf "], " >> $outputndjson #VJN 10/2/2020 10:48pm - for ndjson report
fi

#VJN 10/21/2020 3:22pm - This section is used to print the firewall status and determin which firewalls are running 
echo "Firewall Status:" >> $outputtxt #VJN 10/21/2020 3:22pm - for txt report

printf "\t\t<h2>Firewall Status</h2>\n" >> $outputhtml #VJN 10/21/2020 3:22pm - for html report
if [[ "${osmatch[0]}" == *"Windows"* ]];then
    if [ -z "$defenderstatus" ]; then
        printf "\tNo Firewall Detected!\n" >> $outputtxt #VJN 10/26/2020 11:18pm - for txt report
                
        printf "\t\t\t<h1>No Firewall Detected!</h1>\n" >> $outputhtml #VJN 10/26/2020 11:18pm - for html report
    else 
        printf "\tWindows Defender: $defenderstatus\n" >> $outputtxt #VJN 10/26/2020 11:18pm - for txt report
        
        printf "\t<firewall defender=\"$defenderstatus\"/>\n" >> $outputxml #VJN 10/26/2020 11:18pm - for xml report
        
        printf "\t\t\t<p>Windows Defender: $defenderstatus</p>\n" >> $outputhtml #VJN 10/26/2020 11:18pm - for html report
    
        printf "\t\t\"firewall\":\n\t\t[\n\t\t\t{\n\t\t\t\t\"defennder\": \"$defenderstatus\"\n\t\t\t}\n\t\t],\n" >> $outputjson #VJN 10/26/2020 11:18pm - for json report
    
        printf "\"firewall\": [ { \"defender\": \"$defenderstatus\" } ], " >> $outputndjson #VJN 10/26/2020 11:18pm - for ndjson report
    fi
else
    if [ -z "$selinuxstatus" ] && [ -z "$firewalldstatus" ] && [ -z "$iptablesstatus" ]; then
        printf "\tNo Firewall Detected!\n" >> $outputtxt #VJN 10/21/2020 5:39pm - for txt report
                
        printf "\t\t\t<h1>No Firewall Detected!</h1>\n" >> $outputhtml #VJN 10/21/2020 5:39pm - for html report
    elif [ -z "$firewalldstatus" ] && [ -z "$iptablesstatus" ]; then
        printf "\tSelinux: $selinuxstatus\n" >> $outputtxt #VJN 10/21/2020 5:39pm - for txt report
        
        printf "\t<firewall selinux=\"$selinuxstatus\"/>\n" >> $outputxml #VJN 10/21/2020 5:39pm - for xml report
        
        printf "\t\t\t<p>Selinux: $selinuxstatus</p>\n" >> $outputhtml #VJN 10/21/2020 5:39pm - for html report
    
        printf "\t\t\"firewall\":\n\t\t[\n\t\t\t{\n\t\t\t\t\"selinux\": \"$selinuxstatus\"\n\t\t\t}\n\t\t],\n" >> $outputjson #VJN 10/21/2020 5:39pm - for json report
    
        printf "\"firewall\": [ { \"selinux\": \"$selinuxstatus\" } ], " >> $outputndjson #VJN 10/21/2020 5:39pm - for ndjson report
    elif [ -z "$selinuxstatus" ] && [ -z "$firewalldstatus" ]; then
        printf "\tIptables: $iptablesstatus\n" >> $outputtxt #VJN 10/21/2020 5:39pm - for txt report
        
        printf "\t<firewall iptables=\"$iptablesstatus\"/>\n" >> $outputxml #VJN 10/21/2020 5:39pm - for xml report
        
        printf "\t\t\t<p>Iptables: $iptablesstatus</p>\n" >> $outputhtml #VJN 10/21/2020 5:39pm - for html report
    
        printf "\t\t\"firewall\":\n\t\t[\n\t\t\t{\n\t\t\t\t\"iptables\": \"$iptablesstatus\"\n\t\t\t}\n\t\t],\n" >> $outputjson #VJN 10/21/2020 5:39pm - for json report
    
        printf "\"firewall\": [ { \"iptables\": \"$iptablesstatus\" } ], " >> $outputndjson #VJN 10/21/2020 5:39pm - for ndjson report
    elif [ -z "$selinuxstatus" ] && [ -z "$iptablesstatus" ]; then
        printf "\tFirewalld: $firewalldstatus\n" >> $outputtxt #VJN 10/21/2020 5:39pm - for txt report
        
        printf "\t<firewall firewalld=\"$firewalldstatus\"/>\n" >> $outputxml #VJN 10/21/2020 5:39pm - for xml report
        
        printf "\t\t\t<p>Firewalld: $firewalldstatus</p>\n" >> $outputhtml #VJN 10/21/2020 5:39pm - for html report
    
        printf "\t\t\"firewall\":\n\t\t[\n\t\t\t{\n\t\t\t\t\"firewalld\": \"$firewalldstatus\"\n\t\t\t}\n\t\t],\n" >> $outputjson #VJN 10/21/2020 5:39pm - for json report
    
        printf "\"firewall\": [ { \"firewalld\": \"$firewalldstatus\" } ], " >> $outputndjson #VJN 10/21/2020 5:39pm - for ndjson report
    elif [ -z "$selinuxstatus" ]; then
        printf "\tFirewalld: $firewalldstatus\n\tIptables: $iptablesstatus\n" >> $outputtxt #VJN 10/21/2020 5:39pm - for txt report
        
        printf "\t<firewall firewalld=\"$firewalldstatus\" iptables=\"$iptablesstatus\"/>\n" >> $outputxml #VJN 10/21/2020 5:39pm - for xml report
        
        printf "\t\t\t<p>Firewalld: $firewalldstatus</p>\n\t\t\t<p>Iptables: $iptablesstatus</p>\n" >> $outputhtml #VJN 10/21/2020 5:39pm - for html report
    
        printf "\t\t\"firewall\":\n\t\t[\n\t\t\t{\n\t\t\t\t\"firewalld\": \"$firewalldstatus\",\n\t\t\t\t\"iptables\": \"$iptablesstatus\"\n\t\t\t}\n\t\t],\n" >> $outputjson #VJN 10/21/2020 5:39pm - for json report
    
        printf "\"firewall\": [ { \"firewalld\": \"$firewalldstatus\", \"iptables\": \"$iptablesstatus\" } ], " >> $outputndjson #VJN 10/21/2020 5:39pm - for ndjson report
    elif [ -z "$firewalldstatus" ]; then
        printf "\tSelinux: $selinuxstatus\n\tIptables: $iptablesstatus\n" >> $outputtxt #VJN 10/21/2020 5:39pm - for txt report
        
        printf "\t<firewall selinux=\"$selinuxstatus\" iptables=\"$iptablesstatus\"/>\n" >> $outputxml #VJN 10/21/2020 5:39pm - for xml report
        
        printf "\t\t\t<p>Selinux: $selinuxstatus</p>\n\t\t\t<p>Iptables: $iptablesstatus</p>\n" >> $outputhtml #VJN 10/21/2020 5:39pm - for html report
    
        printf "\t\t\"firewall\":\n\t\t[\n\t\t\t{\n\t\t\t\t\"selinux\": \"$selinuxstatus\",\n\t\t\t\t\"iptables\": \"$iptablesstatus\"\n\t\t\t}\n\t\t],\n" >> $outputjson #VJN 10/21/2020 5:39pm - for json report
    
        printf "\"firewall\": [ { \"selinux\": \"$selinuxstatus\", \"iptables\": \"$iptablesstatus\" } ], " >> $outputndjson #VJN 10/21/2020 5:39pm - for ndjson report
    elif [ -z "$iptablesstatus" ]; then
        printf "\tSelinux: $selinuxstatus\n\tFirewalld: $firewalldstatus\n" >> $outputtxt #VJN 10/21/2020 5:39pm - for txt report
        
        printf "\t<firewall selinux=\"$selinuxstatus\" firewalld=\"$firewalldstatus\"/>\n" >> $outputxml #VJN 10/21/2020 5:39pm - for xml report
        
        printf "\t\t\t<p>Selinux: $selinuxstatus</p>\n\t\t\t<p>Firewalld: $firewalldstatus</p>\n" >> $outputhtml #VJN 10/21/2020 5:39pm - for html report
    
        printf "\t\t\"firewall\":\n\t\t[\n\t\t\t{\n\t\t\t\t\"selinux\": \"$selinuxstatus\",\n\t\t\t\t\"firewalld\": \"$firewalldstatus\"\n\t\t\t}\n\t\t],\n" >> $outputjson #VJN 10/21/2020 5:39pm - for json report
    
        printf "\"firewall\": [ { \"selinux\": \"$selinuxstatus\", \"firewalld\": \"$firewalldstatus\" } ], " >> $outputndjson #VJN 10/21/2020 5:39pm - for ndjson report
    else
        printf "\tSelinux: $selinuxstatus\n\tFirewalld: $firewalldstatus\n\tIptables: $iptablesstatus\n" >> $outputtxt #VJN 10/21/2020 5:39pm - for txt report
        
        printf "\t<firewall selinux=\"$selinuxstatus\" firewalld=\"$firewalldstatus\" iptables=\"$iptablesstatus\"/>\n" >> $outputxml #VJN 10/21/2020 5:39pm - for xml report
        
        printf "\t\t\t<p>Selinux: $selinuxstatus</p>\n\t\t\t<p>Firewalld: $firewalldstatus</p>\n\t\t\t<p>Iptables: $iptablesstatus</p>\n" >> $outputhtml #VJN 10/21/2020 5:39pm - for html report
    
        printf "\t\t\"firewall\":\n\t\t[\n\t\t\t{\n\t\t\t\t\"selinux\": \"$selinuxstatus\",\n\t\t\t\t\"firewalld\": \"$firewalldstatus\",\n\t\t\t\t\"iptables\": \"$iptablesstatus\"\n\t\t\t}\n\t\t],\n" >> $outputjson #VJN 10/21/2020 5:39pm - for json report
    
        printf "\"firewall\": [ { \"selinux\": \"$selinuxstatus\", \"firewalld\": \"$firewalldstatus\", \"iptables\": \"$iptablesstatus\" } ], " >> $outputndjson #VJN 10/21/2020 5:39pm - for ndjson report
    fi
fi

#VJN 10/22/2020 9:03am - This section formats and prints out the Harddrive health of the system
if [[ "${osmatch[0]}" == *"Windows"* ]];then
    if [ -z "$drivesize" ]; then
        printf "Harddrive Health:\n\tNo issues found.\n" >> $outputtxt #VJN 10/26/2020 11:18pm - for txt report
                
        printf "\t\t\t<h2>Harddrive Health</h2>\n\t\t\t\t<p>No issues found</p>\n" >> $outputhtml #VJN 10/26/2020 11:18pm - for html report
    else 
        printf "Harddrive Health:\n\t$drivename has used $driveused GB/$drivesize GB ($driveusage%%) and still has $driveavalible GB left until full.\n" >> $outputtxt #VJN 10/26/2020 11:18pm - for txt report

        printf "\t<harddrive name=\"$drivename\" size=\"$drivesize GB\" used=\"$driveused GB\" avalible=\"$driveavalible GB\" usage=\"$driveusage\"/>\n" >> $outputxml #VJN 10/26/2020 11:18pm - for xml report

        printf "\t\t<h2>Harddrive Health</h2>\n\t\t\t<p>$drivename has used $driveused GB/$drivesize GB ($driveusage%%) and still has $driveavalible GB left until full.</p>\n" >> $outputhtml #VJN 10/26/2020 11:18pm - for html report

        printf "\t\t\"harddrive\":\n\t\t[\n\t\t\t{\n\t\t\t\t\"name\": \"$drivename\",\n\t\t\t\t\"size\": \"$drivesize GB\",\n\t\t\t\t\"used\": \"$driveused GB\",\n\t\t\t\t\"avalible\": \"$driveavalible GB\",\n\t\t\t\t\"usage\": \"$driveusage\"\n\t\t\t}\n\t\t],\n" >> $outputjson #VJN 10/26/2020 11:18pm - for json report
    
        printf "\"harddrive\": [ { \"name\": \"$drivename\", \"size\": \"$drivesize GB\", \"used\": \"$driveused GB\", \"avalible\": \"$driveavalible GB\", \"usage\": \"$driveusage\" } ], " >> $outputndjson #VJN 10/26/2020 11:18pm - for ndjson report
    fi 
else
    if [ -z "$drivesize" ]; then
        printf "Harddrive Health:\n\tNo issues found.\n" >> $outputtxt #VJN 10/22/2020 9:03am - for txt report
                
        printf "\t\t\t<h2>Harddrive Health</h2>\n\t\t\t\t<p>No issues found</p>\n" >> $outputhtml #VJN 10/22/2020 9:03am - for html report
    else 
        printf "Harddrive Health:\n\t$drivename ($drivepath) has used $driveused/$drivesize ($driveusage%%) and still has $driveavalible left until full.\n" >> $outputtxt #VJN 10/22/2020 9:03am - for txt report

        printf "\t<harddrive name=\"$drivename\" path=\"$drivepath\" size=\"$drivesize\" used=\"$driveused\" avalible=\"$driveavalible\" usage=\"$driveusage\"/>\n" >> $outputxml #VJN 10/22/2020 9:03am - for xml report

        printf "\t\t<h2>Harddrive Health</h2>\n\t\t\t<p>$drivename ($drivepath) has used $driveused/$drivesize ($driveusage%%) and still has $driveavalible left until full.</p>\n" >> $outputhtml #VJN 10/22/2020 9:03am - for html report

        printf "\t\t\"harddrive\":\n\t\t[\n\t\t\t{\n\t\t\t\t\"name\": \"$drivename\",\n\t\t\t\t\"path\": \"$drivepath\",\n\t\t\t\t\"size\": \"$drivesize\",\n\t\t\t\t\"used\": \"$driveused\",\n\t\t\t\t\"avalible\": \"$driveavalible\",\n\t\t\t\t\"usage\": \"$driveusage\"\n\t\t\t}\n\t\t],\n" >> $outputjson #VJN 10/22/2020 9:03am - for json report
    
        printf "\"harddrive\": [ { \"name\": \"$drivename\", \"path\": \"$drivepath\", \"size\": \"$drivesize\", \"used\": \"$driveused\", \"avalible\": \"$driveavalible\", \"usage\": \"$driveusage\" } ], " >> $outputndjson #VJN 10/22/2020 9:03am - for ndjson report
    fi 
fi

#VJN 10/22/2020 11:20am - This section formats and prints out usb status information
echo "USB Status:" >> $outputtxt #VJN 9/29/2020 7:08pm - for txt report

printf "\t\t<h2>USB Status</h2>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
if [[ "${osmatch[0]}" == *"Windows"* ]];then
    usbnumber=$(sed -n '/<usb/{n;:a;p;n;/<\/usb>/!ba}' $windowscommandoutput | grep -ia "Instance" | wc -l)
    if [ -z "$usbnumber" ]; then
        printf "\tNo USB information found.\n" >> $outputtxt #VJN 9/29/2020 7:08pm - for txt report

        printf "\t\t\tNo USB information found.\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
    else
        printf "\t<usbs>\n" >> $outputxml #VJN 9/29/2020 7:13pm - for xml report

        printf "\t\t\"usbs\":\n\t\t[\n" >> $outputjson #VJN 10/2/2020 10:48pm - for json report

        printf "\"usbs\": [ " >> $outputndjson #VJN 10/2/2020 10:48pm - for ndjson report
    
        printf "\t\t\t<table>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
        printf "\t\t\t\t<tr>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
        printf "\t\t\t\t\t<td>Manufacturer</td>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
        printf "\t\t\t\t\t<td>Product</td>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
        printf "\t\t\t\t\t<td>Description</td>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
        printf "\t\t\t\t\t<td>GUID</td>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
        printf "\t\t\t\t\t<td>Status</td>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
        printf "\t\t\t\t</tr>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
        for r in $(seq 1 $usbnumber)
        do 
            usb=$(sed -n '/<usb/{n;:a;p;n;/<\/usb>/!ba}' $windowscommandoutput | awk -F'Instance' "{ print $"$r" }")
            usbstatus=$(echo $usb | awk -F'Status: ' '{ print $2 }' | awk -F' ' '{ print $1 }')
            usbclass=$(echo $usb | awk -F'Class Name: ' '{ print $2 }' | awk -F'Class' '{ print $1 }')
            usbmanufacturer=$(echo $usb | awk -F'Manufacturer Name: ' '{ print $2 }' | awk -F'Status:' '{ print $1 }')
            usbdescription=$(echo $usb | awk -F'Device Description: ' '{ print $2 }' | awk -F'Class Name:' '{ print $1 }')
            usbguid=$(echo $usb | awk -F'Class GUID: ' '{ print $2 }' | awk -F'Manufacturer Name:' '{ print $1 }')

            if [ "$usbstatus" == "Started" ]; then
                if [[ "$usbclass" == *"Keyboard"* ]] || [[ "$usbclass" == *"Mouse"* ]] || [[ "$usbclass" == *"Monitor"* ]] || [[ "$usbclass" == *"USB"* ]] || [[ "$usbclass" == *"DiskDrive"* ]]; then
                    printf "\t$usbmanufacturer, $usbproduct \t Serial Number: $usbserialnumber\n" >> $outputtxt #VJN 10/22/2020 9:03am - for txt report

                    printf "\t\t<usb manufacturer=\"$usbmanufacturer\" product=\"$usbproduct\" serial=\"$usbserialnumber\"/>\n" >> $outputxml #VJN 10/22/2020 9:03am - for xml report

                    printf "\t\t\t\t<tr>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
                    printf "\t\t\t\t\t<td>$usbmanufacturer</td>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
                    printf "\t\t\t\t\t<td>$usbclass</td>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report 
                    printf "\t\t\t\t\t<td>$usbdescription</td>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
                    printf "\t\t\t\t\t<td>$usbguid</td>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
                    printf "\t\t\t\t\t<td>$usbstatus</td>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
                    printf "\t\t\t\t</tr>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report

                    if [ "$r" -eq "$usbnumber" ]; then
                        printf "\t\t\t{\n\t\t\t\t\"manufacturer\": \"$usbmanufacturer\",\n\t\t\t\t\"product\": \"$usbproduct\",\n\t\t\t\t\"serial\": \"$usbserialnumber\"\n\t\t\t}\n" >> $outputjson #VJN 10/22/2020 9:03am - for json report
                        printf "{ \"manufacturer\": \"$usbmanufacturer\", \"product\": \"$usbproduct\", \"serial\": \"$usbserialnumber\" } " >> $outputndjson #VJN 10/22/2020 9:03am - for ndjson report
                    else 
                        printf "\t\t\t{\n\t\t\t\t\"manufacturer\": \"$usbmanufacturer\",\n\t\t\t\t\"product\": \"$usbproduct\",\n\t\t\t\t\"serial\": \"$usbserialnumber\"\n\t\t\t},\n" >> $outputjson #VJN 10/22/2020 9:03am - for json report
                        printf "{ \"manufacturer\": \"$usbmanufacturer\", \"product\": \"$usbproduct\", \"serial\": \"$usbserialnumber\" },  " >> $outputndjson #VJN 10/22/2020 9:03am - for ndjson report
                    fi    
                fi
            fi
        done
        printf "\t\t\t</table>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
        
        printf "\t</usbs>\n" >> $outputxml #VJN 9/29/2020 7:13pm - for xml report

        printf "\t\t],\n" >> $outputjson #VJN 10/2/2020 10:48pm - for json report

        printf "], " >> $outputndjson #VJN 10/2/2020 10:48pm - for ndjson report
    fi
else
    usbnumber=$(sed -n '/<usb/{n;:a;p;n;/<\/usb>/!ba}' $linuxcommandoutput | grep -ia "T:" | wc -l)
    if [ -z "$usbnumber" ]; then
        printf "\tNo USB information found.\n" >> $outputtxt #VJN 9/29/2020 7:08pm - for txt report

        printf "\t\t\tNo USB information found.\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
    else
        printf "\t<usbs>\n" >> $outputxml #VJN 9/29/2020 7:13pm - for xml report

        printf "\t\t\"usbs\":\n\t\t[\n" >> $outputjson #VJN 10/2/2020 10:48pm - for json report

        printf "\"usbs\": [ " >> $outputndjson #VJN 10/2/2020 10:48pm - for ndjson report

        printf "\t\t\t<table>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
        printf "\t\t\t\t<tr>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
        printf "\t\t\t\t\t<td>Manufacturer</td>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
        printf "\t\t\t\t\t<td>Product</td>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
        printf "\t\t\t\t\t<td>Serial Number</td>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
        printf "\t\t\t\t</tr>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
        
        usbnumber=$((usbnumber+1))
        for r in $(seq 2 $usbnumber)
        do 
            usb=$(sed -n '/<usb/{n;:a;p;n;/<\/usb>/!ba}' $linuxcommandoutput) #| awk -F'T:' "{ print $"$r" }")
            t=$(echo $usb | awk -F'T:' "{ print $"$r" }")
            usbmanufacturer=$(echo $t | awk -F'Manufacturer=' '{ print $2 }' | awk -F'S:' '{ print $1 }' | sed 's/[[:blank:]]*$//')
            usbproduct=$(echo $t | awk -F'Product=' '{ print $2 }' | awk -F'S:|C:' '{ print $1 }' | sed 's/[[:blank:]]*$//')
            usbserialnumber=$(echo $t | awk -F'SerialNumber=' '{ print $2 }' | awk -F'C:' '{ print $1 }' | sed 's/[[:blank:]]*$//')

            printf "\t$usbmanufacturer, $usbproduct \t Serial Number: $usbserialnumber\n" >> $outputtxt #VJN 10/22/2020 9:03am - for txt report

            printf "\t\t<usb manufacturer=\"$usbmanufacturer\" product=\"$usbproduct\" serial=\"$usbserialnumber\"/>\n" >> $outputxml #VJN 10/22/2020 9:03am - for xml report

            printf "\t\t\t\t<tr>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
            printf "\t\t\t\t\t<td>$usbmanufacturer</td>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
            printf "\t\t\t\t\t<td>$usbproduct</td>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report 
            printf "\t\t\t\t\t<td>$usbserialnumber</td>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
            printf "\t\t\t\t</tr>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report

            if [ "$r" -eq "$usbnumber" ]; then
                printf "\t\t\t{\n\t\t\t\t\"manufacturer\": \"$usbmanufacturer\",\n\t\t\t\t\"product\": \"$usbproduct\",\n\t\t\t\t\"serial\": \"$usbserialnumber\"\n\t\t\t}\n" >> $outputjson #VJN 10/22/2020 9:03am - for json report
                printf "{ \"manufacturer\": \"$usbmanufacturer\", \"product\": \"$usbproduct\", \"serial\": \"$usbserialnumber\" } " >> $outputndjson #VJN 10/22/2020 9:03am - for ndjson report
            else 
                printf "\t\t\t{\n\t\t\t\t\"manufacturer\": \"$usbmanufacturer\",\n\t\t\t\t\"product\": \"$usbproduct\",\n\t\t\t\t\"serial\": \"$usbserialnumber\"\n\t\t\t},\n" >> $outputjson #VJN 10/22/2020 9:03am - for json report
                printf "{ \"manufacturer\": \"$usbmanufacturer\", \"product\": \"$usbproduct\", \"serial\": \"$usbserialnumber\" }, " >> $outputndjson #VJN 10/22/2020 9:03am - for ndjson report
            fi    
        done    
        printf "\t\t\t</table>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
        
        printf "\t</usbs>\n" >> $outputxml #VJN 9/29/2020 7:13pm - for xml report

        printf "\t\t],\n" >> $outputjson #VJN 10/2/2020 10:48pm - for json report

        printf "], " >> $outputndjson #VJN 10/2/2020 10:48pm - for ndjson report
    fi
fi

#VJN 10/22/2020 11:43am - This section formats and prints out active users on the machine
if [ -z "$users" ]; then
    printf "Users:\n\tNo User information found." >> $outputtxt #VJN 10/22/2020 12:16pm - for txt report
            
    printf "\t\t\t<h2>Users</h2>\n\t\t\t\t<p>No User information found</p>\n" >> $outputhtml #VJN 10/22/2020 12:16pm - for html report
else 
    printf "Users:\n" >> $outputtxt #VJN 10/22/2020 12:16pm - for txt report

    printf "\t<users>\n" >> $outputxml #VJN 10/22/2020 12:16pm - for xml report

    printf "\t\t<h2>Users</h2>\n" >> $outputhtml #VJN 10/22/2020 12:16pm - for html report

    printf "\t\t\"users\":\n\t\t[\n" >> $outputjson #VJN 10/22/2020 12:16pm - for json report

    printf "\"users\": [ " >> $outputndjson #VJN 10/22/2020 12:16pm - for ndjson report

    g=0
    for r in ${users[@]}
    do
        printf "\t$r\n" >> $outputtxt #VJN 10/22/2020 12:16pm - for txt report

        printf "\t\t<user name=\"$r\"/>\n" >> $outputxml #VJN 10/22/2020 12:16pm - for xml report

        printf "\t\t\t<p>$r</p>\n" >> $outputhtml #VJN 10/22/2020 12:16pm - for html report

        if [ "$g" -eq "$((${#users[@]}-1))" ]; then
            printf "\t\t\t{\n\t\t\t\t\"user\": \"$r\"\n\t\t\t}\n" >> $outputjson #VJN 10/22/2020 12:16pm - for json report
            printf "{ \"user\": \"$r\" } " >> $outputndjson #VJN 10/22/2020 12:16pm - for ndjson report
        else 
            printf "\t\t\t{\n\t\t\t\t\"user\": \"$r\"\n\t\t\t},\n" >> $outputjson #VJN 10/22/2020 12:16pm - for json report
            printf "{ \"user\": \"$r\" }, " >> $outputndjson #VJN 10/22/2020 12:16pm - for ndjson report
        fi

        g=$((g+1))
    done
    
    printf "\t</users>\n" >> $outputxml #VJN 10/22/2020 12:16pm - for xml report

    printf "\t\t]\n" >> $outputjson #VJN 10/22/2020 12:16pm - for json report

    printf "] " >> $outputndjson #VJN 10/22/2020 12:16pm - for ndjson report
fi 

#VJN 10/22/2020 9:03am - This section closes out the reports 
echo "</machine>" >> $outputxml #VJN 9/29/2020 7:13pm - for xml report

printf '\t</body>\n' >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
echo '</html>' >> $outputhtml #VJN 10/1/2020 2:55pm - for html report

printf "\t}\n}" >> $outputjson #VJN 10/2/2020 10:48pm - for json report

printf "} }" >> $outputndjson #VJN 10/2/2020 10:48pm - for ndjson report

#VJN 9/22/2020 12:44pm - This is used to remove the temp files 
rm temp/$host
#rm $linuxcommandoutput #VJN 10/21/2020 2:52pm - This is commented out for debugging
#rm $windowscommandoutput #VJN 10/26/2020 11:11pm - This is commented out for debugging
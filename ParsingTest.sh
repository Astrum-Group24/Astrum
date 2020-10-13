file="rawlogs/2020-09-21--191900.xml"
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

    #VJN 9/22/2020 12:36pm - outputtxt specifies the file in which each txt report will be deposited in
    outputtxt="reports/txt/$addressip.txt"
    #VJN 9/29/2020 7:06pm - outputxml specifies the file in which each xml report will be deposited in
    outputxml="reports/xml/$addressip.xml"
    #VJN 10/1/2020 12:30pm - outputhtml specifies the file in which each html report will be deposited in
    outputhtml="reports/html/$addressip.html"
    #VJN 10/1/2020 5:30pm - outputjson specifies the file in which each json report will be deposited in
    outputjson="reports/json/$addressip.json"
    #VJN 10/1/2020 5:30pm - outputndjson specifies the file in which each ndjson report will be deposited in
    outputndjson="reports/ndjson/$addressip.ndjson"

    #VJN 9/29/2020 7:06pm - This specifies the type of xml we are exporting
    echo '<?xml version="1.0" encoding="UTF-8"?>' >> $outputxml #VJN 9/29/2020 7:13pm - for xml report
    
    #VJN 10/1/2020 12:30pm - This specifies the type of html we are exporting
    echo "<!DOCTYPE html>" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
    echo "<html lang=\"en\">" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
    printf "\t<head>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
    printf "\t\t<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
    printf "\t\t<link href=\"astrum.css\" rel=\"stylesheet\">\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
    printf "\t\t<link rel=\"icon\" href=\"../../logos/aslt.ico\">\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
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
    
    printf "\t\t\"osmatches\":\n\t\t[\n" >> $outputjson #VJN 10/2/2020 10:48pm - for json report

    printf "\"osmatches\": [ " >> $outputndjson #VJN 10/2/2020 10:48pm - for ndjson report

    if [ -z "$osmatch" ]; then    
        printf "\tNo Operating Sysem could be discerned\n" >> $outputtxt #VJN 9/29/2020 7:08pm - for txt report
        
        printf "\t<osmatch name=\"N/A\"/>\n" >> $outputxml #VJN 9/29/2020 7:13pm - for xml report
        
        printf "\t\t<p>No Operating Sysem could be discerned</p>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
    
        printf "\t\t\t{\n\t\t\t\t\"name\": \"N/A\",\n\t\t\t\t\"accuracy\": \"N/A\"\n\t\t\t}\n" >> $outputjson #VJN 10/2/2020 10:48pm - for json report

        printf "{ \"name\": \"N/A\", \"accuracy\": \"N/A\" } " >> $outputndjson #VJN 10/2/2020 10:48pm - for ndjson report
    else
        e=0
        
        printf "\t<osmatches>\n" >> $outputxml #VJN 9/29/2020 7:13pm - for xml report
        
        printf "\t\t<table>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
        printf "\t\t\t<tr>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
        printf "\t\t\t\t<td>Operating System Guess</td>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
        printf "\t\t\t\t<td>Accuracy</td>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
        printf "\t\t\t</tr>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
        
        for r in "${osmatch[@]}"
        do    
            printf "\t(${accuracy[$e]}%%)\t${osmatch[$e]}\n" >> $outputtxt #VJN 9/29/2020 7:08pm - for txt report
            
            printf "\t\t<osmatch name=\"${osmatch[$e]}\" accuracy=\"${accuracy[$e]}%%\"/>\n" >> $outputxml #VJN 9/29/2020 7:13pm - for xml report
            
            printf "\t\t\t<tr>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
            printf "\t\t\t\t<td>${osmatch[$e]}</td>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
            printf "\t\t\t\t<td>${accuracy[$e]}%%</td>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
            printf "\t\t\t</tr>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
            
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
        
        printf "\t\t</table>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report

        printf "\t\t],\n" >> $outputjson #VJN 10/2/2020 10:48pm - for json report

        printf "], " >> $outputndjson #VJN 10/2/2020 10:48pm - for ndjson report
    fi

    #VJN 9/22/2020 12:36pm - This section is used to print out the vulnerable ports 
    echo "Vulnerable Ports:" >> $outputtxt #VJN 9/29/2020 7:08pm - for txt report
    
    printf "\t\t<h2>Vulnerable Ports</h2>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
    
    printf "\t\t\"ports\":\n\t\t[\n" >> $outputjson #VJN 10/2/2020 10:48pm - for json report

    printf "\"ports\": [ " >> $outputndjson #VJN 10/2/2020 10:48pm - for ndjson report

    if [ -z "$port" ]; then
        printf "\tNo vulnerable ports found\n" >> $outputtxt #VJN 9/29/2020 7:08pm - for txt report
        
        printf "\t<port number=\"N/A\"/>\n" >> $outputxml #VJN 9/29/2020 7:13pm - for xml report
        
        printf "\t\t<p>No vulnerable ports found</p>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
    
        printf "\t\t\t{\n\t\t\t\t\"number\": \"N/A\",\n\t\t\t\t\"protocal\": \"N/A\",\n\t\t\t\t\"state\": \"N/A\",\n\t\t\t\t\"service\": \"N/A\",\n\t\t\t\t\"description\": \"N/A\"\n\t\t\t}\n" >> $outputjson #VJN 10/2/2020 10:48pm - for json report

        printf "{ \"number\": \"N/A\", \"protocal\": \"N/A\", \"state\": \"N/A\", \"service\": \"N/A\", \"description\": \"N/A\" } " >> $outputndjson #VJN 10/2/2020 10:48pm - for ndjson report
    else
        t=0

        printf "\t<ports>\n" >> $outputxml #VJN 9/29/2020 7:13pm - for xml report
        
        printf "\t\t<table>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
        printf "\t\t\t<tr>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
        printf "\t\t\t\t<td>Port</td>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
        printf "\t\t\t\t<td>Protocal</td>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
        printf "\t\t\t\t<td>State</td>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
        printf "\t\t\t\t<td>Service</td>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
        printf "\t\t\t\t<td>Description</td>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
        printf "\t\t\t</tr>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report

        for g in "${port[@]}"
        do
            vulnerability=$(cat $vulnerabilityfile | grep -w "${port[$t]}" | grep -w "${protocal[$t]}" | awk '{$1=$2=$3=""; print $0}' | awk '{$1=$1};1' | sed -z 's/\n/, /g')
            if [ -z "$vulnerability" ]; then
                printf "\t(${state[$t]})\t${port[$t]}\t${protocal[$t]}\t[${service[$t]}]\tDescription: N/A\n" >> $outputtxt #VJN 9/29/2020 7:08pm - for txt report
                
                printf "\t\t<port number=\"${port[$t]}\" protocal=\"${protocal[$t]}\" state=\"${state[$t]}\" service=\"${service[$t]}\" description=\"N/A\"/>\n" >> $outputxml #VJN 9/29/2020 7:13pm - for xml report
                
                printf "\t\t\t<tr>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
                printf "\t\t\t\t<td>${port[$t]}</td>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
                printf "\t\t\t\t<td>${protocal[$t]}</td>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report 
                printf "\t\t\t\t<td>${state[$t]}</td>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
                printf "\t\t\t\t<td>${service[$t]}</td>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
                printf "\t\t\t\t<td>N/A</td>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
                printf "\t\t\t</tr>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
            
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
            
                printf "\t\t\t<tr>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
                printf "\t\t\t\t<td>${port[$t]}</td>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
                printf "\t\t\t\t<td>${protocal[$t]}</td>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
                printf "\t\t\t\t<td>${state[$t]}</td>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
                printf "\t\t\t\t<td>${service[$t]}</td>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
                printf "\t\t\t\t<td>${vulnerability::-2}</td>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
                printf "\t\t\t</tr>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
            
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

        printf "\t\t</table>\n" >> $outputhtml #VJN 10/1/2020 2:55pm - for html report

        printf "\t\t]\n" >> $outputjson #VJN 10/2/2020 10:48pm - for json report

        printf "] " >> $outputndjson #VJN 10/2/2020 10:48pm - for ndjson report
    fi

    echo "</machine>" >> $outputxml #VJN 9/29/2020 7:13pm - for xml report

    printf '\t</body>\n' >> $outputhtml #VJN 10/1/2020 2:55pm - for html report
    echo '</html>' >> $outputhtml #VJN 10/1/2020 2:55pm - for html report

    printf "\t}\n}" >> $outputjson #VJN 10/2/2020 10:48pm - for json report

    printf "} }" >> $outputndjson #VJN 10/2/2020 10:48pm - for ndjson report

    #VJN 9/22/2020 12:44pm - This is used to remove the temp files 
    rm temp/$f
done

#VJN 10/12/2020 8:41pm - This is used to test the Generator.sh Script. DEBUGGING
#file=($(ls reports/json))
#for f in "${file[@]}"; do
#    ./Generator.sh -f $f
#done 
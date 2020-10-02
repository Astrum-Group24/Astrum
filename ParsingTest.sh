file="rawlogs/2020-09-21--191900.xml"
vulnerabilityfile="vulnerabilities.txt"

selected=$(cat $file | grep -ie "<hostname name=\|<address addr=\|<port protocol=\|<osmatch name=")
scanned=$(cat $file | grep -ia "<scaninfo type=" | awk -F'services="' '{ print $3 }' | awk -F'"' '{ print $1 }')

selected=($(echo $selected | tr " " "-"))
selected=($(echo $selected | tr "<" "\n"))

j=0
for r in "${selected[@]}"; do
    if [[ "$r" == *"ipv4"* ]]; then
        j=$((j+1))
    fi
    
    if [[ "$r" == *"addr="* ]] || [[ "$r" == *"name="* ]] || [[ "$r" == *"portid="* ]] || [[ "$r" == *"state="* ]] || [[ "$r" == *"protocal="* ]] || [[ "$r" == *"osmatch"* ]]; then
        echo "$r" >> temp/machine$j.temp
    fi
done

file=($(ls temp))

for f in "${file[@]}"; do

    hostname=$(cat temp/$f | grep -ia "hostname-name=" | awk -F'hostname-name="' '{ print $2 }' | awk -F'"' '{ print $1 }')  
    addressip=$(cat temp/$f | grep -ia "ipv4" | awk -F'address-addr="' '{ print $2 }' | awk -F'"' '{ print $1 }')
    addressmac=$(cat temp/$f | grep -ia "mac" | awk -F'address-addr="' '{ print $2 }' | awk -F'"' '{ print $1 }')
    port=$(cat temp/$f | grep -ia "portid=" | awk -F'portid="' '{ print $2 }' | awk -F'"' '{ print $1 }')
    service=$(cat temp/$f | grep -ia "service-name=" | awk -F'service-name="' '{ print $2 }' | awk -F'"' '{ print $1 }')
    state=$(cat temp/$f | grep -ia "state-state=" | awk -F'state-state="' '{ print $2 }' | awk -F'"' '{ print $1 }')
    protocal=$(cat temp/$f | grep -ia "port-protocol=" | awk -F'port-protocol="' '{ print $2 }' | awk -F'"' '{ print $1 }')
    osmatch=$(cat temp/$f | grep -ia "osmatch-name=" | awk -F'osmatch-name="' '{ print $2 }' | awk -F'"' '{ print $1 }')
    accuracy=$(cat temp/$f | grep -ia "osmatch-name=" | awk -F'accuracy="' '{ print $2 }' | awk -F'"' '{ print $1 }')
       
    port=($(echo $port | tr "\n" "\n"))
    service=($(echo $service | tr "\n" "\n"))
    state=($(echo $state | tr "\n" "\n"))
    protocal=($(echo $protocal | tr "\n" "\n"))
    osmatch=($(echo $osmatch | tr "\n" "\n"))
    accuracy=($(echo $accuracy | tr "\n" "\n"))

    outputtxt="reports/$addressip.txt"
    outputxml="reports/$addressip.xml"
    outputhtml="reports/$addressip.html"
    
    echo '<?xml version="1.0" encoding="UTF-8"?>' >> $outputxml
    
    echo "<!DOCTYPE html>" >> $outputhtml
    echo "<html lang=\"en\">" >> $outputhtml
    echo "<head>" >> $outputhtml
    printf "\t<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n" >> $outputhtml
    printf "\t<link href=\"astrum.css\" rel=\"stylesheet\">\n" >> $outputhtml
    printf "\t<link rel=\"icon\" href=\"../logos/aslt.ico\">\n" >> $outputhtml
    printf "\t<meta charset=\"utf-8\">\n" >> $outputhtml
    printf "\t<title>$addressip Vulnerability Report</title>\n" >> $outputhtml
    echo "</head>" >> $outputhtml
    echo "<body>" >> $outputhtml

    if [ -z "$addressmac" ] && [ -z "$hostname" ]; then
        echo "Host Machine: $addressip" >> $outputtxt
        echo "<machine ipaddress=\"$addressip\">" >> $outputxml
        printf "\t<h1>$addressip</h1>\n" >> $outputhtml
    elif [ -z "$addressmac" ]; then
        echo "Host Machine: $hostname ($addressip)" >> $outputtxt
        echo "<machine hostname=\"$hostname\" ipaddress=\"$addressip\">" >> $outputxml
        printf "\t<h1>$hostname ($addressip)</h1>\n" >> $outputhtml
    elif [ -z "$hostname" ]; then
        echo "Host Machine: $addressip ($addressmac)" >> $outputtxt
        echo "<machine ipaddress=\"$addressip\" macaddress=\"$addressmac\">" >> $outputxml
        printf "\t<h1>$addressip ($addressmac)</h1>\n" >> $outputhtml
    else
        echo "Host Machine: $hostname ($addressip, $addressmac)" >> $outputtxt
        echo "<machine hostname=\"$hostname\" ipaddress=\"$addressip\" macaddress=\"$addressmac\">" >> $outputxml
        printf "\t<h1>$hostname ($addressip, $addressmac)</h1>\n" >> $outputhtml
    fi
    
    echo "Ports Scanned:" >> $outputtxt
    printf "\t$scanned\n" >> $outputtxt

    echo "<scanned ports=\"$scanned\"/>" >> $outputxml

    echo "<h2>Ports Scanned</h2>" >> $outputhtml
    printf "\t<p>$scanned</p>\n" >> $outputhtml

    echo "Possible Operating System:" >> $outputtxt
    echo "<h2>Possible Operating System</h2>" >> $outputhtml
    if [ -z "$osmatch" ]; then
        printf "\tNo Operating Sysem could be discerned\n" >> $outputtxt
        echo "<osmatch type=\"N/A\"/>" >> $outputxml
        printf "\t<p>No Operating Sysem could be discerned</p>\n" >> $outputhtml
    else
        e=0
        echo "<osmatchs>" >> $outputxml
        echo "<table>" >> $outputhtml
        printf "\t<tr>\n" >> $outputhtml
        printf "\t\t<td>Operating System Guess</td>\n" >> $outputhtml
        printf "\t\t<td>Accuracy</td>\n" >> $outputhtml
        printf "\t</tr>\n" >> $outputhtml
        for r in "${osmatch[@]}"
        do    
            printf "\t(${accuracy[$e]}%%)\t${osmatch[$e]}\n" >> $outputtxt
            echo "<osmatch type=\"${osmatch[$e]}\" accuracy=\"${accuracy[$e]}%\"/>" >> $outputxml
            printf "\t<tr>\n" >> $outputhtml
            printf "\t\t<td>${osmatch[$e]}</td>\n" >> $outputhtml
            printf "\t\t<td>${accuracy[$e]}%%</td>\n" >> $outputhtml
            printf "\t</tr>\n" >> $outputhtml
            e=$((e+1))
        done
        echo "</osmatchs>" >> $outputxml
        echo "</table>" >> $outputhtml
    fi

    echo "Vulnerable Ports:" >> $outputtxt
    echo "<h2>Vulnerable Ports</h2>" >> $outputhtml
    if [ -z "$port" ]; then
        printf "\tNo vulnerable ports found\n" >> $outputtxt
        echo "<port number=\"N/A\"/>" >> $outputxml
        printf "\t<p>No vulnerable ports found</p>\n" >> $outputhtml
    else
        t=0
        echo "<ports>" >> $outputxml
        echo "<table>" >> $outputhtml
        printf "\t<tr>\n" >> $outputhtml
        printf "\t\t<td>Port</td>\n" >> $outputhtml
        printf "\t\t<td>Protocal</td>\n" >> $outputhtml
        printf "\t\t<td>State</td>\n" >> $outputhtml
        printf "\t\t<td>Service</td>\n" >> $outputhtml
        printf "\t\t<td>Description</td>\n" >> $outputhtml
        printf "\t</tr>\n" >> $outputhtml   
        for g in "${port[@]}"
        do
            vulnerability=$(cat $vulnerabilityfile | grep -w "${port[$t]}" | grep -w "${protocal[$t]}" | awk '{$1=$2=$3=""; print $0}' | awk '{$1=$1};1' | sed -z 's/\n/, /g')
            if [ -z "$vulnerability" ]; then
                printf "\t(${state[$t]})\t${port[$t]}\t${protocal[$t]}\t[${service[$t]}]\tDescription: N/A\n" >> $outputtxt
                echo "<port number=\"${port[$t]}\" protocal=\"${protocal[$t]}\" state=\"${state[$t]}\" service=\"${service[$t]}\" description=\"N/A\"/>" >> $outputxml
                printf "\t<tr>\n" >> $outputhtml
                printf "\t\t<td>${port[$t]}</td>\n" >> $outputhtml
                printf "\t\t<td>${protocal[$t]}</td>\n" >> $outputhtml
                printf "\t\t<td>${state[$t]}</td>\n" >> $outputhtml
                printf "\t\t<td>${service[$t]}</td>\n" >> $outputhtml
                printf "\t</tr>\n" >> $outputhtml
            else
                printf "\t(${state[$t]})\t${port[$t]}\t${protocal[$t]}\t[${service[$t]}]\tDescription: ${vulnerability::-2}\n" >> $outputtxt
                echo "<port number=\"${port[$t]}\" protocal=\"${protocal[$t]}\" state=\"${state[$t]}\" service=\"${service[$t]}\" description=\"${vulnerability::-2}\"/>" >> $outputxml
                printf "\t<tr>\n" >> $outputhtml
                printf "\t\t<td>${port[$t]}</td>\n" >> $outputhtml
                printf "\t\t<td>${protocal[$t]}</td>\n" >> $outputhtml
                printf "\t\t<td>${state[$t]}</td>\n" >> $outputhtml
                printf "\t\t<td>${service[$t]}</td>\n" >> $outputhtml
                printf "\t\t<td>${vulnerability::-2}</td>\n" >> $outputhtml
                printf "\t</tr>\n" >> $outputhtml            
            fi 
            t=$((t+1))
        done
        echo "</ports>" >> $outputxml
        echo "</table>" >> $outputhtml
    fi

    echo "</machine>" >> $outputxml

    echo '</body>' >> $outputhtml
    echo '</html>' >> $outputhtml

    rm temp/$f

    # DEBUG SECTION
    # echo "# of entries in file: ${#file[@]}" #Debug checks size of array
    # echo "# of entries in hostname: ${#hostname[@]}" #Debug checks size of array
    # echo "# of entries in address: ${#address[@]}" #Debug checks size of array
    # echo "# of entries in port: ${#port[@]}" #Debug checks size of array
    # echo "# of entries in service: ${#service[@]}" #Debug checks size of array
    # echo "# of entries in state: ${#state[@]}" #Debug checks size of array
    # echo "# of entries in scanned: ${#scanned[@]}" #Debug checks size of array
    # echo "# of entries in accuracy: ${#accuracy[@]}" #Debug checks size of array
    # echo "# of entries in osmatch: ${#osmatch[@]}" #Debug checks size of array
done
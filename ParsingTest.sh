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

    output="reports/$addressip.txt"

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
    
    echo "Ports Scanned:" >> $output
    printf "\t$scanned\n" >> $output

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
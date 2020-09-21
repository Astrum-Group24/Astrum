#file="rawlogs/subnetoutput.xml"
#file="rawlogs/2020-09-10.xml"
file="rawlogs/longscan.xml"
vulnerabilityfile="vulnerabilities.txt"

selected=$(cat $file | grep -ie "<hostname name=\|<address addr=\|<port protocol=\|<osmatch name=")
scanned=$(cat $file | grep -ia "<scaninfo type=" | awk -F'services="' '{ print $3 }' | awk -F'"' '{ print $1 }')

scanned=($(echo $scanned | tr "," "\n"))
selected=($(echo $selected | tr " " "-"))
selected=($(echo $selected | tr "<" "\n"))

j=0
for r in "${selected[@]}"; do
    if [[ "$r" == *"address"* ]]; then
        j=$((j+1))
    fi
    
    if [[ "$r" == *"addr="* ]] || [[ "$r" == *"name="* ]] || [[ "$r" == *"portid="* ]] || [[ "$r" == *"state="* ]] || [[ "$r" == *"protocal="* ]] || [[ "$r" == *"osmatch"* ]]; then
        echo "$r" >> temp/machine$j.temp
    fi
done

file=($(ls temp))
# echo "# of entries in file: ${#file[@]}" #Debug checks size of array

#for i in "${scanned[@]}"; do echo "Scanned Port: $i"; done

for f in "${file[@]}"; do

    hostname=$(cat temp/$f | grep -ia "hostname-name=" | awk -F'hostname-name="' '{ print $2 }' | awk -F'"' '{ print $1 }')  
    address=$(cat temp/$f | grep -ia "address-addr=" | awk -F'address-addr="' '{ print $2 }' | awk -F'"' '{ print $1 }')
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

    # echo " " #This is for debug purposes 
    # echo "From File: temp/$f" #This is for debug purposes 

    echo "Host Machine: $hostname ($address)" >> reports/$address.txt
    echo "Possible Operating System:" >> reports/$address.txt
    
    if [ -z "$osmatch" ]; then
        printf "\tNo Operating Sysem could be discerned.\n" >> reports/$address.txt
    else
        e=0
        for r in "${osmatch[@]}"
        do    
            printf "\t(${accuracy[$e]}%%)\t${osmatch[$e]}\n" >> reports/$address.txt
            e=$((e+1))
        done
    fi

    echo "Vulnerable Ports:" >> reports/$address.txt

    if [ -z "$port" ]; then
        printf "\tNo vulnerable ports found.\n" >> reports/$address.txt
    else
        t=0
        for g in "${port[@]}"
        do
            vulnerability=$(cat $vulnerabilityfile | grep -w "${port[$t]}" | grep -w "${protocal[$t]}" | awk '{$1=$2=$3=""; print $0}' | awk '{$1=$1};1' | sed -z 's/\n/, /g')
            if [ -z "$vulnerability" ]; then
                printf "\t(${state[$t]})\t${port[$t]}\\${protocal[$t]}\t[${service[$t]}]\tDescription: N/A\n" >> reports/$address.txt
            else
                printf "\t(${state[$t]})\t${port[$t]}\\${protocal[$t]}\t[${service[$t]}]\tDescription: ${vulnerability::-2}\n" >> reports/$address.txt
            fi 
            t=$((t+1))
        done
    fi

    # echo "# of entries in hostname: ${#hostname[@]}" #Debug checks size of array
    # echo "# of entries in address: ${#address[@]}" #Debug checks size of array
    # echo "# of entries in port: ${#port[@]}" #Debug checks size of array
    # echo "# of entries in service: ${#service[@]}" #Debug checks size of array
    # echo "# of entries in state: ${#state[@]}" #Debug checks size of array
    # echo "# of entries in scanned: ${#scanned[@]}" #Debug checks size of array
    #echo "# of entries in scanned: ${#accuracy[@]}" #Debug checks size of array
    #echo "# of entries in scanned: ${#osmatch[@]}" #Debug checks size of array
    rm temp/$f

done
file="2020-09-15--05:33:28.xml"
#file="rawlogs/2020-09-10.xml"

selected=$(cat $file | grep -ie "<hostname name=\|<address addr=\|<port protocol=")
scanned=$(cat $file | grep -ia "<scaninfo type=" | awk -F'services="' '{ print $3 }' | awk -F'"' '{ print $1 }')

scanned=($(echo $scanned | tr "," "\n"))
selected=($(echo $selected | tr " " "-"))
selected=($(echo $selected | tr "<" "\n"))

j=0
for r in "${selected[@]}"; do
    if [[ "$r" == *"address"* ]]; then
        j=$((j+1))
    fi
    
    if [[ "$r" == *"addr="* ]] || [[ "$r" == *"name="* ]] || [[ "$r" == *"portid="* ]] || [[ "$r" == *"state="* ]] || [[ "$r" == *"protocal="* ]]; then
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
       
    port=($(echo $port | tr "\n" "\n"))
    service=($(echo $service | tr "\n" "\n"))
    state=($(echo $state | tr "\n" "\n"))
    protocal=($(echo $protocal | tr "\n" "\n"))

    echo " "

    echo "From File: temp/$f"

    echo "$hostname ($address)"

    t=0
    for g in "${port[@]}"
    do
        echo "Port: ${port[$t]} (${protocal[$t]}) (${service[$t]}) (${state[$t]})"
        t=$((t+1))
    done

    # echo "# of entries in hostname: ${#hostname[@]}" #Debug checks size of array
    # echo "# of entries in address: ${#address[@]}" #Debug checks size of array
    # echo "# of entries in port: ${#port[@]}" #Debug checks size of array
    # echo "# of entries in service: ${#service[@]}" #Debug checks size of array
    # echo "# of entries in state: ${#state[@]}" #Debug checks size of array
    # echo "# of entries in scanned: ${#scanned[@]}" #Debug checks size of array

done

rm temp/* 
file="2020-09-10.xml"
#file="subnetoutput.xml"

#Parses through xml log file and grabs hostname, ipaddress, ports, service, state, scanned ports
hostname=$(cat $file | grep -ia "<hostname name=" | awk -F'<hostname name="' '{ print $2 }' | awk -F'"' '{ print $1 }')  
address=$(cat $file | grep -ia "<address addr=" | awk -F'<address addr="' '{ print $2 }' | awk -F'"' '{ print $1 }')
port=$(cat $file | grep -ia "<port protocol=" | awk -F'portid="' '{ print $2 }' | awk -F'"' '{ print $1 }')
service=$(cat $file | grep -ia "<port protocol=" | awk -F'<service name="' '{ print $2 }' | awk -F'"' '{ print $1 }')
state=$(cat $file | grep -ia "<port protocol=" | awk -F'<state state="' '{ print $2 }' | awk -F'"' '{ print $1 }')
scanned=$(cat $file | grep -ia "<scaninfo type=" | awk -F'services="' '{ print $3 }' | awk -F'"' '{ print $1 }')

#makes variables into arrays 
hostname=($(echo $hostname | tr "\n" "\n"))
address=($(echo $address | tr "\n" "\n"))
port=($(echo $port | tr "\n" "\n"))
service=($(echo $service | tr "\n" "\n"))
state=($(echo $state | tr "\n" "\n"))
scanned=($(echo $scanned | tr "," "\n"))

j=0
t=0
for i in "${hostname[@]}"
do
    echo "${hostname[$j]} (${address[$j]})"
    
    j=$((j+1))
done

#for i in "${scanned[@]}"; do echo "Scanned Port: $i"; done

for r in "${port[@]}"
do
    echo "Port: ${port[$t]} (${service[$t]}) (${state[$t]})"
    t=$((t+1))
done

echo "# of entries in hostname: ${#hostname[@]}" #Debug checks size of array
echo "# of entries in address: ${#address[@]}" #Debug checks size of array
echo "# of entries in port: ${#port[@]}" #Debug checks size of array
echo "# of entries in service: ${#service[@]}" #Debug checks size of array
echo "# of entries in state: ${#state[@]}" #Debug checks size of array
echo "# of entries in scanned: ${#scanned[@]}" #Debug checks size of array
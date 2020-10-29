#file="rawlogs/2020-09-21--191900.xml"
file="rawlogs/longscan.xml"

timeran=$(date +'%Y-%m-%d-%H-%M-%S')
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
    ./Parse.sh -t $timeran -h $f
done

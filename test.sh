windowscommandoutput="windowsoutput.txt" #VJN 10/26/2020 11:05pm - This is for debugging

#VJN 10/22/2020 11:20am - This section formats and prints out usb status information
usbnumber=$(sed -n '/<usb/{n;:a;p;n;/<\/usb>/!ba}' $windowscommandoutput | grep -ia "Instance" | wc -l)
#echo "$usbnumber"
if [ -z "$usbnumber" ]; then
    printf "\tNo USB information found.\n" 

    printf "\t\t\tNo USB information found.\n" 
else 
    usb=$(sed -n '/<usb/{n;:a;p;n;/<\/usb>/!ba}' $windowscommandoutput )
    usbstatusnumber=8
    usbclassnumber=5
    usbmanufacturernumber=7
    usbdescriptionnumber=4
    usbguidnumber=6

    started=$(sed -n '/<usb/{n;:a;p;n;/<\/usb>/!ba}' $windowscommandoutput | grep -ian "Started" | awk -F':' '{ print $1 }')
    started=($(echo $started | tr "\n" "\n"))
    #echo "started: ${#started[@]}"
    class=$(sed -n '/<usb/{n;:a;p;n;/<\/usb>/!ba}' $windowscommandoutput | grep -ian "Keyboard\|Mouse\|Monitor\|USB\|DiskDrive" | awk -F':' '{ print $1 }')
    class=($(echo $class | tr "\n" "\n"))
    #echo "started: ${#class[@]}"
    for (( s=${#started[@]}-1 ; s>=0 ; s-- )) ; do
        #echo "started: ${started[s]}"
        for (( c=${#class[@]}-1 ; c>=0 ; c-- )) ; do
            #echo "class: ${class[c]}"
            if [[ ${class[c]} -eq $((${started[s]}-3)) ]]; then
                laststarted=${started[s]}
                lastclass=${class[c]}
                break 4
            fi
        done
    done

    # echo "laststarted: $laststarted"
    # echo "lastclass: $lastclass"
    laststarted=$(($laststarted+1))
    printf "\t\t\"usbs\":\n\t\t[\n" >> testoutput.txt
    for r in $(seq 1 $usbnumber)
    do 
        
        usbstatus=$(echo "$usb" | sed -n "$usbstatusnumber"p | awk -F':' '{ print $2 }' | tr -d '[:space:]')
        usbclass=$(echo "$usb" | sed -n "$usbclassnumber"p | awk -F':' '{ print $2 }' | tr -d '[:space:]')
        usbmanufacturer=$(echo "$usb" | sed -n "$usbmanufacturernumber"p | awk -F':' '{ print $2 }' | tr -d '[:space:]')
        usbdescription=$(echo "$usb" | sed -n "$usbdescriptionnumber"p | awk -F':' '{ print $2 }' | tr -d '[:space:]')
        usbguid=$(echo "$usb" | sed -n "$usbguidnumber"p | awk -F':' '{ print $2 }' | tr -d '[:space:]')
        
        # echo "r: $r"
        echo "usbstatus: -$usbstatus-"
        echo "usbclass: -$usbclass-"
        echo "usbmanufacturer: -$usbmanufacturer-"
        echo "usbdescription: -$usbdescription-"
        echo "usbguid: -$usbguid-"
        if [ "$usbstatus" == "Started" ]; then
            if [[ "$usbclass" == *"Keyboard"* ]] || [[ "$usbclass" == *"Mouse"* ]] || [[ "$usbclass" == *"Monitor"* ]] || [[ "$usbclass" == *"USB"* ]] || [[ "$usbclass" == *"DiskDrive"* ]]; then
                if [ "$usbstatusnumber" = "$laststarted" ]; then
                    printf "\t\t\t{\n\t\t\t\t\"manufacturer\": \"$usbmanufacturer\",\n\t\t\t\t\"class\": \"$usbclass\",\n\t\t\t\t\"description\": \"$usbdescription\",\n\t\t\t\t\"guid\": \"$usbguid\",\n\t\t\t\t\"status\": \"$usbstatus\"\n\t\t\t}\n" >> testoutput.txt
                else 
                    printf "\t\t\t{\n\t\t\t\t\"manufacturer\": \"$usbmanufacturer\",\n\t\t\t\t\"class\": \"$usbclass\",\n\t\t\t\t\"description\": \"$usbdescription\",\n\t\t\t\t\"guid\": \"$usbguid\",\n\t\t\t\t\"status\": \"$usbstatus\"\n\t\t\t},\n" >> testoutput.txt
                fi    
            fi
        fi
        # echo "r: $r"
        # echo "usbnumber: $usbnumber"
        echo "usbstatusnumber: -$usbstatusnumber-"
        echo "laststarted: -$laststarted-"
        usbstatusnumber=$((usbstatusnumber+8))
        usbclassnumber=$((usbclassnumber+8))
        usbmanufacturernumber=$((usbmanufacturernumber+8))
        usbdescriptionnumber=$((usbdescriptionnumber+8))
        usbguidnumber=$((usbguidnumber+8))
    done
    printf "\t\t],\n" >> testoutput.txt
fi
#!/bin/bash
#Astrum Created by Vincent Neiheisel, Brett Johnson, and Brenna Martz
#Created on 10/5/2020 at 8:03pm 
#This script will take the output of Astrum.sh and will generate a scriipt that the user can use to fix vulnerabilities. 

#VJN 10/5/2020 8:39pm - This checks and verifies that the required directories are present.  
[ -d "generatedscripts" ] || mkdir generatedscripts 

#VJN 10/5/2020 8:04pm - Setting passed variables to nothing
file=

#VJN 10/5/2020 8:04pm - This section grabs the passed variables and assigns them to internal variables
while getopts "f:" opt; do
  case $opt in
    f) file=$OPTARG   ;;
    *) echo 'Error: Invalid argument.'
       exit 1
  esac
done

#VJN 10/5/2020 8:34pm - This is the location of the generated script output 
output="generatedscripts/${file::-5}.sh"

ports=$(cat reports/json/$file | grep -ia "number" | awk -F'"number": "' '{ print $2 }' | awk -F'"' '{ print $1 }')
ports=($(echo $ports | tr "\n" "\n"))

f=0
for i in "${ports[@]}"; do
    #echo "port[$f]: $i" #VJN 10/5/2020 8:26pm - This is for debuging 
    echo "sudo ufw deny $i" >> $output
    f=$((f+1))
done

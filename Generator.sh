#!/bin/bash
#Astrum Created by Vincent Neiheisel, Brett Johnson, and Brenna Martz
#Created on 10/5/2020 at 8:03pm 
#This script will take the output of Astrum.sh and will generate a scriipt that the user can use to fix vulnerabilities. 

#VJN 10/5/2020 8:39pm - This checks and verifies that the required directories are present.  
[ -d "generatedscripts" ] || mkdir generatedscripts 

#VJN 10/5/2020 8:04pm - Setting passed variables to nothing
file=
whitelist=

#VJN 10/5/2020 8:04pm - This section grabs the passed variables and assigns them to internal variables
while getopts "f:w:" opt; do
  case $opt in
    f) file=$OPTARG   ;;
    w) whitelist=$OPTARG   ;;
    *) echo 'Error: Invalid argument.'
       exit 1
  esac
done

#VJN 10/12/2020 7:04pm - Takes the string whitelist variable and makes it an array
whitelist=($(echo $whitelist | tr "," "\n"))

#VJN 10/5/2020 8:34pm - This is the location of the generated script output 
output="generatedscripts/${file::-5}.sh"

ports=$(cat reports/json/$file | grep -ia "number" | awk -F'"number": "' '{ print $2 }' | awk -F'"' '{ print $1 }')
ports=($(echo $ports | tr "\n" "\n"))

#VJN 10/12/2020 7:58pm - This section will go through each vulnerable port and will cross reference it with the whitelist
for i in "${ports[@]}"; do
  if [ -z "$whitelist" ] && [[ "$i" != *"N"* ]]; then
    echo "sudo ufw deny $i" >> $output
  else 
  e=0
  f=0
    for g in "${whitelist[@]}"; do
      if [ "$i" -eq "$g" ] || [[ "$i" == *"N"* ]]; then
        e=$((e+1))
      fi
      f=$((f+1))
      if [ "$e" -eq "0" ] && [ "$f" -eq "${#whitelist[@]}" ]; then
        echo "sudo ufw deny $i" >> $output
      fi
    done
  fi
done

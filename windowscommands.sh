#!/bin/bash

#BMM 10/14/2020 2:06pm - This is the start of the script that will remote into Windows machines so long as they have OpenSSH server running on their computer.

#BMM 10/14/202 2:08pm - As with the Linux script, the username, password, and host varibles need to be passed down from the main astrum.sh script / user input.

#See Microsoft docs for more info regarding OpenSSH https://docs.microsoft.com/en-us/windows-server/administration/openssh/openssh_install_firstuse

sshpass -p 'A5t7um' ssh -o stricthostkeychecking=no Astrum@192.168.1.15 ' echo yep && ipconfig && wmic path CIM_LogicalDevice where "Description like 'USB%'" get /value ' > windows.txt

#For some reason it needs to be all on one line for Windows to like it. Will continue work as needed.

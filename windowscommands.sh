#!/bin/bash

#BMM 10/14/2020 2:06pm - This is the start of the script that will remote into Windows machines so long as they have OpenSSH server running on their computer.

#BMM 10/14/2020 2:08pm - As with the Linux script, the username, password, and host varibles need to be passed down from the main astrum.sh script / user input.

#See Microsoft docs for more info regarding OpenSSH https://docs.microsoft.com/en-us/windows-server/administration/openssh/openssh_install_firstuse

sshpass -p 'A5t7um' ssh -o stricthostkeychecking=no Astrum192.168.1.15 ' echo ^<usb^> && pnputil /enum-devices /connected && echo ^</usb^> && echo ^<drivespace^> && for /f "tokens=1-3" %a in ('\''WMIC LOGICALDISK GET FreeSpace^,Name^,Size ^|FINDSTR /I /V "Name"'\'') do @echo wsh.echo "%b" ^& " Free=" ^& FormatNumber^(cdbl^(%a^)/1024/1024/1024, 2^)^& " GB"^& " Total Space=" ^& FormatNumber^(cdbl^(%c^)/1024/1024/1024, 2^)^& " GB" > %temp%\tmp.vbs & @if not "%c"=="" @echo( & @cscript //nologo %temp%\tmp.vbs & del %temp%\tmp.vbs && echo ^</drivespace^> && echo ^<windefend^> && sc query WinDefend && echo ^</windefend^> && echo ^<mcafee^> && sc query mfemms && echo ^</mcafee^> && echo ^<norton^> && sc query navapsvc && echo ^</norton^> && echo ^<kapersky^> && sc query klnagent && echo ^</kapersky^> && echo ^<ciscoamp^> && sc query FireAMP && echo ^</ciscoamp^> && echo ^<users^> && net user && echo ^</users^> 
' > windowsdevice.txt

#BMM 10/20/2020 8:48am - For some reason it needs to be all on one line for Windows to like it. Regardless, it is able to pull nearly the same amount of information as the linuxcommands.sh script. Sample output in windowsoutput.txt

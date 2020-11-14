#!/bin/bash
#Astrum Created by Vincent Neiheisel, Brett Johnson, and Brenna Martz
#Created on 10/5/2020 at 8:03pm 
#This script will take the output of Astrum.sh and will generate a scriipt that the user can use to fix vulnerabilities. 

#VJN 10/19/2020 9:52pm - This section grabs the newest batch of reports and uses them to generate the script
timedirectory=($(ls reports | sort -nr | head -n1))

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

#VJN 10/5/2020 8:39pm - This checks and verifies that the required directories are present.  
[ -d "resolution" ] || mkdir resolution 
[ -d "resolution/${file::-5}" ] || mkdir resolution/${file::-5} 

#VJN 10/12/2020 7:04pm - Takes the string whitelist variable and makes it an array
whitelist=($(echo $whitelist | tr "," "\n"))

#VJN 10/5/2020 8:34pm - This is the location of the generated script output 
osmatch=$(cat reports/$timedirectory/json/$file | grep -ia '"name": ' | awk -F'"name": "' '{ print $2 }' | awk -F'"' '{ print $1 }' | head -1)
if [[ "${osmatch[0]}" == *"Windows"* ]]; then 
  scriptoutput="resolution/${file::-5}/ComplianceScript.bat"
else
  scriptoutput="resolution/${file::-5}/ComplianceScript.sh"
fi
sugestionoutput="resolution/${file::-5}/ComplianceSugestions.txt"

#VJN 11/13/2020 10:17 am - This section grabs information from the json report generated for the machine
ports=$(cat reports/$timedirectory/json/$file | grep -ia "number" | awk -F'"number": "' '{ print $2 }' | awk -F'"' '{ print $1 }')
ports=($(echo $ports | tr "\n" "\n"))
protocal=$(cat reports/$timedirectory/json/$file | grep -ia '"protocal": ' | awk -F'"protocal": "' '{ print $2 }' | awk -F'"' '{ print $1 }')
protocal=($(echo $protocal | tr "\n" "\n"))
defenderstatus=$(cat reports/$timedirectory/json/$file | grep -ia '"defender": ' | awk -F'"defender": "' '{ print $2 }' | awk -F'"' '{ print $1 }')
mcafeestatus=$(cat reports/$timedirectory/json/$file | grep -ia '"mcafee": ' | awk -F'"mcafee": "' '{ print $2 }' | awk -F'"' '{ print $1 }')
nortonstatus=$(cat reports/$timedirectory/json/$file | grep -ia '"norton": ' | awk -F'"norton": "' '{ print $2 }' | awk -F'"' '{ print $1 }')
kaperskystatus=$(cat reports/$timedirectory/json/$file | grep -ia '"kapersky": ' | awk -F'"kapersky": "' '{ print $2 }' | awk -F'"' '{ print $1 }')
ciscoampstatus=$(cat reports/$timedirectory/json/$file | grep -ia '"ciscoamp": ' | awk -F'"ciscoamp": "' '{ print $2 }' | awk -F'"' '{ print $1 }')
selinuxstatus=$(cat reports/$timedirectory/json/$file | grep -ia '"selinux": ' | awk -F'"selinux": "' '{ print $2 }' | awk -F'"' '{ print $1 }')
firewalldstatus=$(cat reports/$timedirectory/json/$file | grep -ia '"firewalld": ' | awk -F'"firewalld": "' '{ print $2 }' | awk -F'"' '{ print $1 }')
iptablesstatus=$(cat reports/$timedirectory/json/$file | grep -ia '"iptables": ' | awk -F'"iptables": "' '{ print $2 }' | awk -F'"' '{ print $1 }')
drivename=$(cat reports/$timedirectory/json/$file | grep -ia '"name": ' | awk -F'"name": "' '{ print $2 }' | awk -F'"' '{ print $1 }' | tail -1)
driveused=$(cat reports/$timedirectory/json/$file | grep -ia '"used": ' | awk -F'"used": "' '{ print $2 }' | awk -F'"' '{ print $1 }')
drivesize=$(cat reports/$timedirectory/json/$file | grep -ia '"size": ' | awk -F'"size": "' '{ print $2 }' | awk -F'"' '{ print $1 }')
driveusage=$(cat reports/$timedirectory/json/$file | grep -ia '"usage": ' | awk -F'"usage": "' '{ print $2 }' | awk -F'"' '{ print $1 }')
driveavalible=$(cat reports/$timedirectory/json/$file | grep -ia '"avalible": ' | awk -F'"avalible": "' '{ print $2 }' | awk -F'"' '{ print $1 }')
users=$(cat reports/$timedirectory/json/$file | grep -ia "user" | awk -F'"user": "' '{ print $2 }' | awk -F'"' '{ print $1 }')
users=($(echo $users | tr "\n" "\n"))

#VJN 11/13/2020 2:45pm - This section will enable firewalls if disabled 
if [[ "${osmatch[0]}" == *"Windows"* ]]; then
  if [ "$driveusage" -gt 69 ]; then
    echo "*************************************************************************************" >> $sugestionoutput
    echo "*                             Low Drive Space Remedies                              *" >> $sugestionoutput
    echo "*************************************************************************************" >> $sugestionoutput
    echo "The drive $drivename has used $driveused/$drivesize ($driveusage%) and still has $driveavalible left until full." >> $sugestionoutput    
    echo '1) Run this command "forfiles /S /M * /C “cmd /c if @fsize GEQ 1073741824 echo @path > largefiles.txt" to check all files over 1GB on the machine.' >> $sugestionoutput 
    echo "2) Verify which files can be compressed, offloaded, or deleted." >> $sugestionoutput
    echo "Reference Link: https://helpdeskgeek.com/how-to/find-the-largest-files-on-your-computer/" >> $sugestionoutput
    echo "" >> $sugestionoutput
  fi
else
  if [ "$driveusage" -gt 69 ]; then
    echo "*************************************************************************************" >> $sugestionoutput
    echo "*                             Low Drive Space Remedies                              *" >> $sugestionoutput
    echo "*************************************************************************************" >> $sugestionoutput
    echo "The drive $drivename has used $driveused/$drivesize ($driveusage%) and still has $driveavalible left until full." >> $sugestionoutput
    echo '1) Run this commmand "du -ahx | sort -rh | head -50" to check the 50 largest files on the machine.' >> $sugestionoutput 
    echo "2) Verify which files can be compressed, offloaded, or deleted." >> $sugestionoutput
    echo "Reference Link: https://www.cyberciti.biz/faq/linux-find-largest-file-in-directory-recursively-using-find-du/" >> $sugestionoutput
    echo "" >> $sugestionoutput
  fi
fi

#VJN 11/13/2020 2:45pm - This section will enable firewalls if disabled 
if [[ "${osmatch[0]}" == *"Windows"* ]]; then 
  case $defenderstatus in
    RUNNING|running|active|enabled|"") ;;
    *) 
      echo "::These commands will activate Defender and will set it to start automatically after reboot." >> $scriptoutput
      echo "sc config WinDefend start= auto" >> $scriptoutput
      echo "sc start WinDefend" >> $scriptoutput
    ;;
  esac
  case $mcafeestatus in
    RUNNING|running|active|enabled|"") ;;
    *) 
      echo "::This command will launch the Mcafee program." >> $scriptoutput
      echo '"C:\Program Files\Common Files\McAfee\Platform\McUICnt.exe"' >> $scriptoutput 
    ;;
  esac
  case $nortonstatus in
    RUNNING|running|active|enabled|"") ;;
    *) 
      echo "::This command will launch the Norton program." >> $scriptoutput
      echo '"C:\Program Files\Norton Security\Engine\22.20.2.57\NortonSecurity.exe"' >> $scriptoutput 
    ;;
  esac
  case $kaperskystatus in
    RUNNING|running|active|enabled|"") ;;
    *) 
      echo "::This command will launch the Kapersky program." >> $scriptoutput
      echo '"C:\Program Files\Kaspersky Lab\Kaspersky Internet Security 21.1\avpui.exe"' >> $scriptoutput
    ;;
  esac
  case $ciscoampstatus in
    RUNNING|running|active|enabled|"") ;;
    *) 
      echo "::This command will launch the Cisco AMP program." >> $scriptoutput
      echo '"C:\Program Files\Cisco\AMP\6.1.7\sfc.exe"' >> $scriptoutput
    ;;
  esac
else
  case $selinuxstatus in
    RUNNING|running|active|enabled|"") ;;
    *) 
      echo "#These commands will activate Selinux and will set it to enforcing. A reboot will need to occure." >> $scriptoutput
      echo "sudo selinux-activate" >> $scriptoutput
      echo "sudo selinux-config-enforcing" >> $scriptoutput
    ;;
  esac
  case $firewalldstatus in
    RUNNING|running|active|enabled|"") ;;
    *) 
      echo "#These commands will activate firewalld and set it to start automatically at start up." >> $scriptoutput
      echo "sudo systemctl start firewalld" >> $scriptoutput
      echo "sudo systemctl enable firewalld" >> $scriptoutput
    ;;
  esac
  case $iptablesstatus in
    RUNNING|running|active|enabled|"") ;;
    *) 
      echo "#These commands will start Iptables and restart the ufw firewall." >> $scriptoutput
      echo "sudo ufw enable" >> $scriptoutput
      echo "sudo ufw reload" >> $scriptoutput
    ;;
  esac
fi

x=0
nummcafee=0
numnorton=0
numkapersky=0
#VJN 10/12/2020 7:58pm - This section will go through each vulnerable port and will cross reference it with the whitelist
for i in "${ports[@]}"; do
  if [ -z "$whitelist" ] && [[ "$i" != *"N"* ]]; then
    case $defenderstatus in
      RUNNING|running|active|enabled) 
        echo "::This command will close port $i for the Windows Defender Firewall." >> $scriptoutput
        echo 'netsh advfirewall firewall add rule name="Open Remote Desktop" protocol=TCP dir=in localport='"$i"' action=deny' >> $scriptoutput 
      ;;
      *) ;;
    esac
    case $mcafeestatus in
      RUNNING|running|active|enabled) 
        case $nummcafee in
          0)
            echo "*************************************************************************************" >> $sugestionoutput
            echo "*                          How to block ports using McAfee                          *" >> $sugestionoutput
            echo "*************************************************************************************" >> $sugestionoutput
            echo "1) Open the interface by double-clickng the icon by the system clock or via a short cut or the Start Menu item." >> $sugestionoutput 
            echo "2) Click Web and Email Protection then click Firewall" >> $sugestionoutput
            echo "3) Scroll down.  Click Ports and System Services" >> $sugestionoutput
            echo "4) Click Add then enter a Service Name, then a Category & Description as you wish." >> $sugestionoutput
            echo "5) Then the Port numbers, separated by commas in the UDP category. e.g. 5060,5061,5062,5063" >> $sugestionoutput
            echo "6) Click Save." >> $sugestionoutput
            echo "7) Then go back to that item and deselect it, click Save & that will then block it." >> $sugestionoutput
            echo "Reference Link: https://community.mcafee.com/t5/Personal-Firewall/How-do-I-block-ports-specifically-UDP-5060-5063/td-p/444768#:~:text=You%20can%20indeed%20block%20(or,or%20the%20Start%20Menu%20item.&text=Click%20Add%20then%20enter%20a,Category%20%26%20Description%20as%20you%20wish.&text=Click%20Save" >> $sugestionoutput
            echo "************************" >> $sugestionoutput
            echo "*    Ports To Block    *" >> $sugestionoutput
            echo "************************" >> $sugestionoutput
            for p in ${ports[@]}; do
              echo "$p" >> $sugestionoutput
            done
            nummcafee=$((nummcafee+1))
          ;;
          *) ;;
        esac
      ;;
      *) ;;
    esac
    case $nortonstatus in
      RUNNING|running|active|enabled) 
        case $numnorton in
          0)
            echo "*************************************************************************************" >> $sugestionoutput
            echo "*                          How to block ports using Norton                          *" >> $sugestionoutput
            echo "*************************************************************************************" >> $sugestionoutput
            echo "1) Go to Settings > Internet Settings > General Rules." >> $sugestionoutput 
            echo '2) Click the "Add" button' >> $sugestionoutput
            echo '3) Tick "Block do not allow connections that match this rule". Then click Next.' >> $sugestionoutput
            echo '4) Tick " Connections from other computers". Then click Next.'>> $sugestionoutput
            echo '5) Verify that "Any computer" is ticked. Then click Next.' >> $sugestionoutput
            echo '6) Tick "Only communications that match all types of ports listed below". Click Add.' >> $sugestionoutput
            echo '7) Then click "Next", then "Next", and finally "Finish".' >> $sugestionoutput
            echo '8) It will now show up as a "Firewall Rule" at the bottom of the list off General Rule.' >> $sugestionoutput
            echo '9) Click mofift to change any thing for that rule.' >> $sugestionoutput
            echo "Reference Link: https://community.norton.com/en/forums/block-port" >> $sugestionoutput
            echo "************************" >> $sugestionoutput
            echo "*    Ports To Block    *" >> $sugestionoutput
            echo "************************" >> $sugestionoutput
            for p in ${ports[@]}; do
              echo "$p" >> $sugestionoutput
            done
            numnorton=$((numnorton+1))
          ;;
          *) ;;
        esac 
      ;;
      *) ;;
    esac
    case $kaperskystatus in
      RUNNING|running|active|enabled) 
        case $numkapersky in
          0)
            echo "*************************************************************************************" >> $sugestionoutput
            echo "*                         How to block ports using Kapersky                         *" >> $sugestionoutput
            echo "*************************************************************************************" >> $sugestionoutput
            echo "1) Open Kaspersky Internet Security." >> $sugestionoutput 
            echo '2) Click "Settings"s.' >> $sugestionoutput
            echo '3) Click "Additional" and select "Network" in the right frame.' >> $sugestionoutput
            echo '4) Click "Select..." to the right of Monitor selected ports only.'>> $sugestionoutput
            echo '5) Find the port you want and Right-click the port and choose Disable.' >> $sugestionoutput
            echo '6) Close the Network ports window.' >> $sugestionoutput
            echo '7) Restart the computer.' >> $sugestionoutput
            echo "Reference Link: https://support.kaspersky.com/us/11589" >> $sugestionoutput
            echo "************************" >> $sugestionoutput
            echo "*    Ports To Block    *" >> $sugestionoutput
            echo "************************" >> $sugestionoutput
            for p in ${ports[@]}; do
              echo "$p" >> $sugestionoutput
            done
            numkapersky=$((numkapersky+1))
          ;;
          *) ;;
        esac 
      ;;
      *) ;;
    esac
    case $selinuxstatus in
      RUNNING|running|active|enabled) 
        echo "#This command will close port $i for the Selinux Firewall." >> $scriptoutput
        echo "sudo semanage port -d -p ${protocal[$x]} $i" >> $scriptoutput 
      ;;
      *) ;;
    esac
    case $firewalldstatus in
      RUNNING|running|active|enabled) 
        echo "#This command will close port $i for the Firewalld Firewall." >> $scriptoutput
        echo "sudo firewall-cmd --zone=public --permanent --remove-port=$i/${protocal[$x]}" >> $scriptoutput 
        echo "sudo firewall-cmd --reload" >> $scriptoutput 
      ;;
      *) ;;
    esac
    case $iptablesstatus in
      RUNNING|running|active|enabled) 
        echo "#This command will close port $i for the Iptables Firewall." >> $scriptoutput
        echo "iptables -I INPUT -p ${protocal[$x]} –-dport $i -j REJECT" >> $scriptoutput 
        echo "service iptables save" >> $scriptoutput 
      ;;
      *) ;;
    esac
  else 
    e=0
    f=0
    for g in "${whitelist[@]}"; do
      if [ "$i" -eq "$g" ] || [[ "$i" == *"N"* ]]; then
        e=$((e+1))
      fi
      f=$((f+1))
      if [ "$e" -eq "0" ] && [ "$f" -eq "${#whitelist[@]}" ]; then
        case $defenderstatus in
          RUNNING|running|active|enabled) 
            echo "::This command will close port $i for the Windows Defender Firewall." >> $scriptoutput
            echo 'netsh advfirewall firewall add rule name="Open Remote Desktop" protocol=TCP dir=in localport='"$i"' action=deny' >> $scriptoutput 
          ;;
          *) ;;
        esac
        case $mcafeestatus in
          RUNNING|running|active|enabled) 
            case $nummcafee in
              0)
                echo "*************************************************************************************" >> $sugestionoutput
                echo "*                          How to block ports using McAfee                          *" >> $sugestionoutput
                echo "*************************************************************************************" >> $sugestionoutput
                echo "1) Open the interface by double-clickng the icon by the system clock or via a short cut or the Start Menu item." >> $sugestionoutput 
                echo "2) Click Web and Email Protection then click Firewall" >> $sugestionoutput
                echo "3) Scroll down.  Click Ports and System Services" >> $sugestionoutput
                echo "4) Click Add then enter a Service Name, then a Category & Description as you wish." >> $sugestionoutput
                echo "5) Then the Port numbers, separated by commas in the UDP category. e.g. 5060,5061,5062,5063" >> $sugestionoutput
                echo "6) Click Save." >> $sugestionoutput
                echo "7) Then go back to that item and deselect it, click Save & that will then block it." >> $sugestionoutput
                echo "Reference Link: https://community.mcafee.com/t5/Personal-Firewall/How-do-I-block-ports-specifically-UDP-5060-5063/td-p/444768#:~:text=You%20can%20indeed%20block%20(or,or%20the%20Start%20Menu%20item.&text=Click%20Add%20then%20enter%20a,Category%20%26%20Description%20as%20you%20wish.&text=Click%20Save" >> $sugestionoutput
                echo "************************" >> $sugestionoutput
                echo "*    Ports To Block    *" >> $sugestionoutput
                echo "************************" >> $sugestionoutput
                for a in "${ports[@]}"; do
                  b=0
                  c=0
                  for d in "${whitelist[@]}"; do
                    if [ "$a" -eq "$d" ] || [[ "$a" == *"N"* ]]; then
                      b=$((b+1))
                    fi
                    c=$((c+1))
                    if [ "$b" -eq "0" ] && [ "$c" -eq "${#whitelist[@]}" ]; then
                      echo "$a" >> $sugestionoutput
                    fi
                  done
                done
                nummcafee=$((nummcafee+1))
              ;;
              *) ;;
            esac
          ;;
          *) ;;
        esac
        case $nortonstatus in
          RUNNING|running|active|enabled) 
            case $numnorton in
              0)
                echo "*************************************************************************************" >> $sugestionoutput
                echo "*                          How to block ports using Norton                          *" >> $sugestionoutput
                echo "*************************************************************************************" >> $sugestionoutput
                echo "1) Go to Settings > Internet Settings > General Rules." >> $sugestionoutput 
                echo '2) Click the "Add" button' >> $sugestionoutput
                echo '3) Tick "Block do not allow connections that match this rule". Then click Next.' >> $sugestionoutput
                echo '4) Tick " Connections from other computers". Then click Next.'>> $sugestionoutput
                echo '5) Verify that "Any computer" is ticked. Then click Next.' >> $sugestionoutput
                echo '6) Tick "Only communications that match all types of ports listed below". Click Add.' >> $sugestionoutput
                echo '7) Then click "Next", then "Next", and finally "Finish".' >> $sugestionoutput
                echo '8) It will now show up as a "Firewall Rule" at the bottom of the list off General Rule.' >> $sugestionoutput
                echo '9) Click mofift to change any thing for that rule.' >> $sugestionoutput
                echo "Reference Link: https://community.norton.com/en/forums/block-port" >> $sugestionoutput
                echo "************************" >> $sugestionoutput
                echo "*    Ports To Block    *" >> $sugestionoutput
                echo "************************" >> $sugestionoutput
                for a in "${ports[@]}"; do
                  b=0
                  c=0
                  for d in "${whitelist[@]}"; do
                    if [ "$a" -eq "$d" ] || [[ "$a" == *"N"* ]]; then
                      b=$((b+1))
                    fi
                    c=$((c+1))
                    if [ "$b" -eq "0" ] && [ "$c" -eq "${#whitelist[@]}" ]; then
                      echo "$a" >> $sugestionoutput
                    fi
                  done
                done
                numnorton=$((numnorton+1))
              ;;
              *) ;;
            esac 
          ;;
          *) ;;
        esac
        case $kaperskystatus in
          RUNNING|running|active|enabled) 
            case $numkapersky in
              0)
                echo "*************************************************************************************" >> $sugestionoutput
                echo "*                         How to block ports using Kapersky                         *" >> $sugestionoutput
                echo "*************************************************************************************" >> $sugestionoutput
                echo "1) Open Kaspersky Internet Security." >> $sugestionoutput 
                echo '2) Click "Settings"s.' >> $sugestionoutput
                echo '3) Click "Additional" and select "Network" in the right frame.' >> $sugestionoutput
                echo '4) Click "Select..." to the right of Monitor selected ports only.'>> $sugestionoutput
                echo '5) Find the port you want and Right-click the port and choose Disable.' >> $sugestionoutput
                echo '6) Close the Network ports window.' >> $sugestionoutput
                echo '7) Restart the computer.' >> $sugestionoutput
                echo "Reference Link: https://support.kaspersky.com/us/11589" >> $sugestionoutput
                echo "************************" >> $sugestionoutput
                echo "*    Ports To Block    *" >> $sugestionoutput
                echo "************************" >> $sugestionoutput
                for a in "${ports[@]}"; do
                  b=0
                  c=0
                  for d in "${whitelist[@]}"; do
                    if [ "$a" -eq "$d" ] || [[ "$a" == *"N"* ]]; then
                      b=$((b+1))
                    fi
                    c=$((c+1))
                    if [ "$b" -eq "0" ] && [ "$c" -eq "${#whitelist[@]}" ]; then
                      echo "$a" >> $sugestionoutput
                    fi
                  done
                done
                numkapersky=$((numkapersky+1))
              ;;
              *) ;;
            esac 
          ;;
          *) ;;
        esac
        case $selinuxstatus in
          RUNNING|running|active|enabled) 
            echo "#This command will close port $i for the Selinux Firewall." >> $scriptoutput
            echo "sudo semanage port -d -p ${protocal[$x]} $i" >> $scriptoutput 
          ;;
          *) ;;
        esac
        case $firewalldstatus in
          RUNNING|running|active|enabled) 
            echo "#This command will close port $i for the Firewalld Firewall." >> $scriptoutput
            echo "sudo firewall-cmd --zone=public --permanent --remove-port=$i/${protocal[$x]}" >> $scriptoutput 
            echo "sudo firewall-cmd --reload" >> $scriptoutput 
          ;;
          *) ;;
        esac
        case $iptablesstatus in
          RUNNING|running|active|enabled) 
            echo "#This command will close port $i for the Iptables Firewall." >> $scriptoutput
            echo "iptables -I INPUT -p ${protocal[$x]} –-dport $i -j REJECT" >> $scriptoutput 
            echo "service iptables save" >> $scriptoutput 
          ;;
          *) ;;
        esac
      fi
    done
  fi
  x=$((x+1))
done

#VJN 11/14/2020 4:58pm - This section will disable defualt user accounts on the machine
for i in "${users[@]}";do
  if [[ "${osmatch[0]}" == *"Windows"* ]]; then 
    case $i in
      Guest|guest|Administrator|administrator) 
        echo "::This command will disable the $i account." >> $scriptoutput
        echo "net user $i /active:no" >> $scriptoutput 
      ;;
      *) ;;
    esac
  else 
    case $i in
      Guest|guest|Administrator|administrator) 
        echo "#This command will disable the $i account." >> $scriptoutput
        echo "usermod -L $i" >> $scriptoutput 
      ;;
      *) ;;
    esac
  fi
done

#VIN 11/14/2020 5:13pm - This section will disable USB ports on the machine
if [[ "${osmatch[0]}" == *"Windows"* ]]; then 
  echo "::This section will disable all usb ports on the machine." >> $scriptoutput
  echo 'reg add HKLM\SYSTEM\CurrentControlSet\Services\UsbStor /v "Start" /t REG_DWORD /d "4" /f' >> $scriptoutput
else 

fi
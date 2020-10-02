Astrum
======

This is where we will describe what Astrum is, what it is used for, why it was an issue, and why it is the best tool for the job. 

# Components:

    This is where we will list out all the components of Astrum, Reports, Genereated Script, Helpful Links, etc.

# Prerequisites for running the script:

	This is where we will explain what the user needs to do / have accomplished before running the script.

# Usage:

    This is where we will explain how to run the script.

# Example Output:

    This is where we will show what a successful and non-successful output of the script would be.

# F.A.Q:

    This is where we will answere Frequently Asked Questions.

# Variable Reference Sheet:

### Global Variables:

- scantype: This will specify a full scan or a quick scan. 
- host: The raw input that the user types into the CLI. This will either be an IP by itself, an IP with cidr, or a hostname.
- username: Username used to scan each machine. 
- password: password used to scan each machine.
- ipaddress: The IP will be stored here if an IP and cidr are entered into host.
- cidr: The cidr will be stored here if an IP and cidr ar entered into host.
- stat: The verified status of the input. 

    | Number | Meaning |
    | ------ | ------ |
    | 0 | IP & Cidr valid |
    | 1 | IP invalid & cidr valid (or no cidr) |
    | 2 | IP valid & cidr invalid |
    | 3 | IP invalid & cidr invalid |
    | 4 | Hostname (not verified) |

- file: This variable specifies the file and location of the nmap scan.
- vulnerabilityfile: This specifies the file and location of vulnerabilities.txt. 
- selected: This variable selects all the useful information from the file variable. 
- scanned: This contains all the scanned ports by nmap. 
- hostname: This grabs the hostname of the machine.
- addressip: This grabs the IP address of the machine.
- addressmac: This grabs the Mac Address of the machine.
- port: This grabs the vulnerable ports 
- service: This grabs the service running on each port.
- state: This tells you if the port is open or closed.
- protocal: This tells you if the port is TCP or UDP.
- osmatch: This will list out the possible Operating Systems the machine could be. 
- accuracy: This tells how accurate the osmatch is. 
- outputtxt: This is the location and name of the .txt report files. 
- outputxml: This is the location and name of the .xml report files. 
- outputhtml: This is the location and name of the .html report files.

## Local Variables:
- ipstat: The verified status of the IP.
    | Number | Meaning |
    | ------ | ------ |
    | 0 | Valid |
    | 1 | Invalid |
- cidrstat: The verified status of the cidr. 
    | Number | Meaning |
    | ------ | ------ |
    | 0 | Valid |
    | 1 | Invalid |
- OIFS: This is used to verify the IP address. Used to seperate IP by "."
- IFS: This is used to verify the IP address. Used to seperate IP by "."
- ip: This is used to verify the IP address. This is the individual blocks of the IP.

# Tech:

    * NodeJS
    * Bash
    * Curl
    * Nmap

# Credits: 

Vincent Neiheisel – UX Designer 
- Designing the frontend / user interface  
- Assisting with script development 

Brenna Martz – Bug Tester (QA) / Network Admin 
- Assisting with script development, server set up and deployment 
- Reviewing script and scenarios to test for bugs 
- Designing the report that is generated from the scanner 

Brett Johnson – Hardware Architect  
- Set up the web server 
- Assisting with script development  

Ryan Moore - Technical Practicum Advisor 
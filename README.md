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

##### Global Variables:

- host: The raw input that the user types into the CLI. This will either be an IP by itself, an IP with cidr, or a hostname.
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

#### Local Variables:
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
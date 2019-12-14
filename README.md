# Gh0stHunt
Gh0stHunt is an Incident Response Investigative Framework written in PowerShell that computer network defenders, hunt teams and forensic analysts can use to retrieve and analyze information, baseline, hunt for Indicators of Compromise (IOCs) and mitigate IOCs across remote Windows systems. All functions are driven by input from the operator and provides output throughout each function so the operator understands what actions are being taken. 

Ghosthunt allows an operator to take a list of IOCs and hunt across remote systems for those IOCs. GhostHunt will baseline and enumerate systems and domains and allow you to view results in the console or send them to a CSV file. You can then use the framework to rerun the commands and compare the current results against the baseline for changes. Gh0stHunt also parses a number Windows Event Logs types by parsing the xml of Windows Event Log message blocks and turning those xml values into PowerShell objects.  

Once your hunt has found IOCs on remote workstations, you can use Gh0stHunt to take action on those IOCs on one or multiple hosts. Gh0sthunt will kill malicious processes, delete registry keys, stop and delete services, unregister and delete scheduled tasks, blackhole malicious domains and block malicious IP addresses at the Windows Firewall.

Gh0sthunt uses a text-based user interface to allow any operator to be able run the functions regardless of their experience level. WinRM and PSRemoting must be enabled on the operators system and you should run it from Administrative PowerShell session in order to get full functionality from the program. Gh0sthunt will require administrative rights and WinRM on the remote systems, as well as the WinRM port to be allowed thru the Windows Firewall. I recommend locking down PowerShell execution at the remote hosts by both setting the trusted hosts registry key to only those systems that approved system administrators use and also set the Windows Firewall to allow "Windows Remote Management" from only those approved systems administrative users and only from their approved workstations on the inbound interface.

# Getting Started  
You don't need to install anything to run Gh0stHunt.  
Open up an administrative PowerShell Session.  
Depending on your environment, you may need to change the execution policy:    
&nbsp;&nbsp;&nbsp;&nbsp;**Set-ExecutionPolicy -ExecutionPolicy Bypass -Force**   
Navigate to your Gh0sthunt working directory and run **.\Gh0stHunt**.  

For more information, please reference the Gh0stHunt Wiki!

# To-Do
Log Parser Menu needs expanded and some of the functions need updated.  
Create Modules instead of using the long script.  
Documentation in the Wiki needs completed with screenshots added.  

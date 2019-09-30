# Gh0stHunt
Gh0stHunt is an Incident Repsonse Investigative Framework written in PowerShell that computer network defenders, hunt teams and forensic analysts can use to retrieve and analyze information from remote Windows systems. The framework will allow you to take a list of IOCs and hunt across remote systems for those IOCs.

GhostHunt will baseline and enumerate systems and domains and allow you to view results in the console or send them to a CSV file. You can then use the framework to rerun the commands and compare the current results against the baseline. Gh0stHunt parses a number Windows Event Logs types by parsing the xml of Windows Event Log message blocks and turning those xml values into PowerShell objects.  

Once your hunt has found IOCs on remote workstation, you can use Gh0stHunt to take action on those IOCs. Gh0sthunt will kill malicious processes, delete registry keys, stop and delete services, unregister and delete scheduled tasks, blackhole malicious domains and block malicious IP addresses at the Windows Firewall. 

The framework uses a text-based user interface to allow any operator to be able run the functions regardless of their experience level. The framework will require administrative rights and WinRM on the remote systems, as well as the WinRM port to be allowed thru the Windows Firewall. WinRM and PSRemoting must be enabled on the operators system. I recommend locking down PowerShell execution at the remote hosts by both setting the trusted hosts registry key to only those systems that approved system administrators use and also set the Windows Firewall to allow "Windows Remote Management" from only those approved systems administrative users and only from their approved workstations on the inbound interface.


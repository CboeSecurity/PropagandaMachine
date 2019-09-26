# PropagandaMachine
Project for disseminating disinformation IOCs and very weak port banners for ransomware/novice red team attackers on Windows.

The purpose of this tool is to provide indicators of compromise (IOCs) that can be used for:
1. Preventing infection/installation of malware/ransomware when such a tool uses one of the types of install checks listed here to check whether to install or not.
2. Confusing the anti-reverse engineering (RE) of some malware to think that you are examining it (i.e. files/regkeys pointing to VM environment with RE debuggers installed).
3. Drop documents and files of interest that are meant to be honeytokens to monitor for potential perpetrator access (e.g. using sysmon).
4. Test your SIEM for alerting on known IOCs

- Note: In order for this to work in any of the ways above, it requires a JSON configuration file to be web hosted or preferably dynamically generated somewhere in your environment.  Not hosting your own file is a bad idea(r).  Though there may be an example configuration file provided at a later time, it is NOT safe, as this tool might overwrite your files if they have the same name!  

This is an academic example, and not intended for production or in-use environments!  

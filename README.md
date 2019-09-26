# PropagandaMachine
Project for disseminating disinformation IOCs and very weak port banners for ransomware/novice red team attackers on Windows.

The purpose of this tool is to provide indicators of compromise (IOCs) that can be used for:
1. Preventing infection/installation of malware/ransomware when such a tool uses one of the types of install checks listed here to check whether to install or not.
2. Confusing the anti-reverse engineering (RE) of some malware to think that you are examining it (i.e. files/regkeys pointing to VM environment with RE debuggers installed).
3. Drop documents and files of interest that are meant to be honeytokens to monitor for potential perpetrator access (e.g. using sysmon).
4. Test your SIEM for alerting on known IOCs

## Now / Planned / Possible
1. Currently the code supports:
 * Named Pipes
 * Mutices
 * Mailslots
 * Registry Keys
 * Files (Zero-filled, with abitrary sizes)
2. Stub support exists for:
 * TCP/UDP bound listening ports, simulating immediate responses (like SSH) or after receiving *any* input (more like HTTP)
 * Start up a dummy process... e.g. windbg.exe or avp.exe <- Hey look mom, I've got Kaspersky running here!
3. Planned support for:
 * Dropping files with arbitrary content (either from a URL or from within the JSON file)
 * Honey AuthToken creation - given a set of credentials, create an authtoken. <- this can be dangerous, should be used *very* carefully if this feature is ever created... but it could be interesting for testing SIEMs and/or seeing if someone gets a PTH that shouldn't ever be touched
4. Possible support may include:
 * Alerting / Killing if processes with any of the IOC types provided in the grabbed JSON file are found (currently we just ignore the exceptions, keep on truckin').
 * Support non-default option of overwriting regkeys/files if they already exist <- we try to behave nicely and prevent this right now, but there are no warranties...
 

- Note: In order for this to work in any of the ways above, it requires a JSON configuration file to be web hosted or preferably dynamically generated somewhere in your environment.  Not hosting your own file is a bad idea(r).  Though there may be an example configuration file provided at a later time, it is NOT safe, as this tool might overwrite your files if they have the same name!  

This is an academic example, and not intended for production or in-use environments!  

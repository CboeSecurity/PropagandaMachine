# PropagandaMachine
Project for disseminating disinformation IOCs and very weak port banners for ransomware/novice red team attackers on Windows.

The purpose of this tool is to provide indicators of compromise (IOCs) that can be used for:
1. Preventing infection/installation of malware/ransomware when such a tool uses one of the types of install checks listed here to check whether to install or not.
2. Confusing the anti-reverse engineering (RE) of some malware to think that you are examining it (i.e. files/regkeys pointing to VM environment with RE debuggers installed).
3. Drop documents and files of interest that are meant to be honeytokens to monitor for potential perpetrator access (e.g. using sysmon).
4. Test your SIEM for alerting on known IOCs

## Configuring
1. Modify the url/timer value to your preference in the ConfigurationResources.resx file.
2. Compile the Binary/Install it.
3. Configure a web server with the url provided in step 1 with json file(s) using the example_config.json as a template.

## Now / Planned / Possible
1. Currently the code supports:
 * Named Pipes
 * Mutices
 * Mailslots
 * Registry Keys
 * Files (Zero-filled, with abitrary sizes)
 * TCP/UDP bound listening ports, simulating immediate responses (like SSH) or after receiving *any* input (more like HTTP)
 * Dropping files with arbitrary content (either from a URL or from within the JSON file)
 * Honey AuthToken creation - given a set of credentials, create an authtoken. <- this can be dangerous, should be used *very* carefully if this feature is ever created... but it could be interesting for testing SIEMs and/or seeing if someone gets a PTH that shouldn't ever be touched
2. Stub support exists for:
 * Start up a dummy process... e.g. windbg.exe or avp.exe <- Hey look mom, I've got Kaspersky running here!
3. Possible support may include:
 * Alerting / Killing if processes with any of the IOC types provided in the grabbed JSON file are found (currently we just ignore the exceptions, keep on truckin').
 * Support non-default option of overwriting regkeys/files if they already exist <- we try to behave nicely and prevent this right now, but there are no warranties...
 

- Note: In order for this to work in any of the ways above, it requires a JSON configuration file to be web hosted or preferably dynamically generated somewhere in your environment.  Not hosting your own file is a bad idea(r).  Though there may be an example configuration file provided at a later time, it is NOT safe, as this tool might overwrite your files if they have the same name!  

This is an academic example, and not intended for production or in-use environments!  

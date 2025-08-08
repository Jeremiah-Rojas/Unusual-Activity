# Unusual-Activity
Through a social engineering attack, a user was able to gain access to a certain part of the facility. During this time he accessed one of the company computers and was seen interacting with the machine. The security administrators have tasked you to figure out what this individual was doing and if the computer's integrity was compromised in anyway.

## Tools Utilized
- Powershell
- Microsoft Defender (KQL)

## Step 1: Setting up the Alert in Microsoft Defender
Rule 1:
I created a detection rule in Defender that would detect the existence of a file on the system named `AutoIt3.exe` which in this case is the script executor. The rule also checks if any commands run on the system that contain the values `.au3` or `calc.au3`, then the alert is triggered.
I created the detection rule using the following query:
```kql
DeviceProcessEvents
| where DeviceName == "rojas-mde"
| where FileName =~ "AutoIt3.exe"
| where ProcessCommandLine has_any (".au3", "calc.au3")
| where FolderPath has_any ("Users", "Temp", "Downloads")
```
Rule 2:
This detection rule is triggered when `AutoIt.exe` launches `calc.exe`. The way I know to search with these parameters is because these processes are common given the attack scenario.
I created the detection rule using the following query:
```kql
DeviceProcessEvents
| where DeviceName == "rojas-mde"
| where InitiatingProcessFileName =~ "AutoIt3.exe"
| where FileName =~ "calc.exe"
```
Rule 3:
This rule was designed to trigger an alert when Powershell is used to download content from the internet; this is done using the `Invoke-WebRequest`.
I created the detection rule using the following query:
```kql
DeviceProcessEvents
| where DeviceName == "rojas-mde"
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any ("Invoke-WebRequest", "wget", "curl")
| where ProcessCommandLine has "autoit" "getfile.pl"
```
Rule 4:
The last rule triggers an alert when Powershell is being used to install `AutoIt.exe`. Powershell is not a common method of installing programs like these in normal day-to-day activities therefore this activity is considered suspicious.
I created the detection rule using the following query:
```kql
DeviceFileEvents
| where DeviceName == "rojas-mde"
| where FileName has "autoit" and FileName endswith ".exe"
| where InitiatingProcessFileName =~ "powershell.exe"
```
## Step 2: Running the Attack (Steps taken by the Attacker/Victim)
This series of commands would have been taken by the victim or attacker depending on the circumstances in the real-world.

This downloads the full library of Atomic Red simulated attacks into the VM, including the script that will be run. 
```powershell
git clone https://github.com/redcanaryco/atomic-red-team.git
```
This command moves the user to the folder where the scripts are loaded.
```powershell
cd C:\Users\ceh2025\atomic-red-team
```
This command makes sure that the atomic script is being pulled from the correct folder (Atomics) that was created when the user cloned the Atomic Red database of attacks.
```powershell
$env:PathToAtomicsFolder = "C:\Users\YourUser\atomic-red-team\atomics\"
```
This prepares the VM for running the attacks by downloading the right module to do so. “-AllowClobber” also allows the user to override any existing modules that could get in the way.
```powershell
Install-Module -Name Invoke-AtomicRedTeam -Force -AllowClobber
```
This pulls up the needed module to run the script for the current Powershell session. The user will see it install in powershell.
```powershell
Import-Module Invoke-AtomicRedTeam
```
This prepares the VM for the attacks by creating the right permissions so that no security controls interfere.
```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
```
This command downloads and installs all the prerequisites needed to run the script.
```powershell
Invoke-AtomicTest T1059 -GetPrereqs -PathToAtomicsFolder "C:\Users\YourUser\atomic-red-team\atomics\"
```
Runs and detonates the malicious script in the VM. The calculator should launch after running this; in a real-world scenario, the end result would be much more concerning.
```powershell
Invoke-AtomicTest T1059 -PathToAtomicsFolder "C:\Users\YourUser\atomic-red-team\atomics\"
```
![image](https://github.com/user-attachments/assets/6db2f87a-4951-4020-bde6-366ef5f1e45f)

## Step 3: Analyze the Indicators of Compromise
Using Microsoft Defender, I was able to view the steps the malicious attacker took to facilitate the attack. Within this page, is it also useful to make note of the timestamps.
![image](https://github.com/user-attachments/assets/05ecd3d7-301a-467b-a9dc-5a1e7745c945)

According to the NIST 800-61 guidelines, there are certain tasks necessary to perform in order to determine if the alert is a true or false positive:
1. **_Find the attack vector used to initiate the attack._** The attack vector is the means by which the attack was intiated; things like a malicious link or a USB drive etc. But because this a simulated lab, there is no attack vector per se.
2. **_Finding precursors or indicators of a security incident._** Because this is a lab and the attack was done my myself, there are no IoCs leading up to the attack. 
3. **_Analyze the potential security Incident and determine if it is a true or false positive._** After reviewing the alerts in Defender, I verified the the script was indeed downloaded and run.
4. **_Document all findings and activities of investigation if it is a true positive._** The feature to downlaod a investigation package is currently avaliable in Microsoft Defender.
5. **_Report the confirmed security incident to management team._** Of course, because this is a simluated lab, there is no management team, but in the real-world, this step would be performed by emailing or presenting findings during a briefing.

## Step 4: NIST 800-61 Incident Response
**Preparation**

- The proper preparation to prevent an attack like this would be to ensure the the system was fully updated, its firewall properly configured, implementing a back-up of data/system configurations, and other such activities; in this case, I turned off the firewalls so that nothing would prevent the attack from executing.

**Detection and Analysis**

- The IoCs in this case would be the downloading of the AutoIt.exe file and the fact that the user disabled multiple security configurations in order for the program to run smoothly.

**Containment, Eradication, and Recovery**

- The proper steps to be taken would be to isolate the device, remove all malicious files/programs, and restore the system back to a secure state using a back-up. Before removing all the malicious files, its important to retain all relevant data for future purpose and legal reasons. Microsoft Defender has a built-in feature that automatically collects the evidence of the attack.

**Post-Incident Activity**

- This would include the lessons learned and the retention of the data collected. The lessons learned would be to prevent any user from altering the security confirguations of their system and to implement a secure baseline for all endpoints. The data collected from the attack should be saved according to the organization's policies.

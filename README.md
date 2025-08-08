# Unusual-Activity
## Example Scenario
Through a social engineering attack, a user was able to gain access to a certain part of the facility. During this time he accessed one of the company computers and was seen interacting with the machine. The security administrators have tasked you to figure out what this individual was doing and if the computer's integrity was compromised in anyway.

## Tools Utilized
- Powershell
- Microsoft Defender (KQL)

---

## IoC Discovery Plan:
1. Check DeviceLogonEvents for any signs of brute force attempts
2. Check DeviceFileEvents for any new files or deleted files
3. Check DeviceProcessEvents to view any commands run

---
## Steps Taken by Bad Actor
1. Logon successfully into machine (credentials compromised via social engineering)
2. Run series of commands to gain informaiton about host machine and network
3. Restart the machine in a futile attempt to erase anything that may have been logged
---

## Steps Taken

1. First look for logon events using the following query (I narrowed down the results by entering in the DeviceName):
```kql
DeviceLogonEvents
| where DeviceName == "rojas-mde"
| order by Timestamp desc
```
The following events results were displayed:
<img width="1639" height="328" alt="image" src="https://github.com/user-attachments/assets/82d87d6e-ab4b-4f89-a6f8-fde2e76fffd2" />
Interestingly, there were no failed logon attempts which means that somehow this individual was able to gain valid credentials without having to brute force them.


2. I checked individually for new files, modified files, and deleted files. :
</br>New Files
```kql
DeviceFileEvents
| where DeviceName == "rojas-mde"
| where ActionType == "FileCreated"
| order by Timestamp desc
```
</br>Modified Files
```kql
DeviceFileEvents
| where DeviceName == "rojas-mde"
| where ActionType == "FileCreated"
| order by Timestamp desc
```
</br>Deleted Files
```kql
DeviceFileEvents
| where DeviceName == "rojas-mde"
| where ActionType == "FileCreated"
| order by Timestamp desc
```

The following results were displayed:
<img width="1405" height="256" alt="image" src="https://github.com/user-attachments/assets/c8ec9aed-8c05-4fc1-b995-6bb21cca29f6" />
The ".Ink" extension indicates powershell activity so I looked for that next.

5. Although the administor claimed he saw no scripts on the system, I decided to check you powershell events using the following query:
```kql
DeviceProcessEvents
| where DeviceName == "rojas-admin"
| where ActionType == "ProcessCreated"
| where InitiatingProcessCommandLine contains "powershell"
```
The following events were displayed:
<img width="1408" height="289" alt="image" src="https://github.com/user-attachments/assets/9b293d53-4534-43f7-8b27-aad2cc3c4ec7" />
Since I was looking specifically for powershell events, I click on the powershell event:
</br><img width="314" height="500" alt="image" src="https://github.com/user-attachments/assets/61b41644-a787-45ef-856c-6eb1c308f41c" />
</br>This event tells me that the user used Powershell ISE to run the this command: 
</br>```"powershell.exe" -EncodedCommand VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIABoAGUAbABsAG8AIAB3AG8AcgBsAGQ=```
</br>Based on the last character of the string "=", this is a base64 encoded message that is displayed to the screen when the command runs. The following command prints to the screen "hello world." However, I still had not found an evidence of a script, so I ran the following query:
```kql
DeviceFileEvents
| where DeviceName == "rojas-admin"
| where FileName endswith ".ps1"
```
I found the script in the results named "IT-testing" and clicked on it:
</br><img width="1391" height="229" alt="image" src="https://github.com/user-attachments/assets/00978991-034e-4183-991e-2c5ccc0c93be" />
</br>Collectively from the data, I concluded that the image was downloaded from the powershell script and the command to print "hello world" was printed to the screen. To prevent this infected system from damaging other systems on the network, I isolated the administrator's computer, "rojas-admin". (For some odd reasons, I could not verify that the script was deleted because the logs weren't showing up.)

---

## Chronological Events

1. The user brute forced the admin password and logged in
2. The user used powershell ISE to write and run the script
3. The script downloaded an image and printed text to the screen

---

## Summary

The administrator's device was compromised via brute force, ```rojas-admin``` and a script ```IT-testing.ps1``` was run. This script downloaded an image and printed text to the screen but did not implement permanent damage. This attack, although simple, stresses the importance having strong passwords and avoiding the reuse of old passwords since they can be easily compromised.

---

## Response Taken
The administrator's device was compromised via brute force, ```rojas-admin```. The device was isolated and the administrator was notified. All malicous files were deleted and a anti-malware scan was peformed.

---

## Created By:
- **Author Name**: Jeremiah Rojas
- **Author Contact**: https://www.linkedin.com/in/jeremiah-rojas-2425532b3
- **Date**: July 12, 2025

---

## Revision History:
| **Version** | **Changes**                   | **Date**         | **Modified By**   |
|-------------|-------------------------------|------------------|-------------------|
| 1.0         | Initial draft                  | `July  14, 2025`  | `Jeremiah Rojas`   

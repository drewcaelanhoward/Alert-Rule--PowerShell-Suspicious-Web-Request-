# Threat Hunt Report: Unauthorized TOR Usage Project
- [Scenario Creation](https://github.com/drewcaelanhoward/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor" in it and discovered what looks like the user "employee" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `2025-10-22T17:28:59.883726Z` These events began at `2025-10-22T17:28:59.883726Z`.

**Query used to locate events:**

```kql
DeviceFileEvents  
| where DeviceName == "dh-test-vuln"
| where InitiatingProcessAccountName == "dh"
| where FileName contains "tor"
| where Timestamp >= datetime(2025-10-22T17:28:59.883726Z)
| order by Timestamp desc  
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="1364" height="437" alt="image" src="https://github.com/user-attachments/assets/ba85f3d0-b420-4dd2-b407-3721a201b232" />

---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-14.0.1.exe". Based on the logs returned, at `2025-10-22T17:28:59.1193171Z`, an employee on the "dh-test-vuln" device ran the file `tor-browser-windows-x86_64-portable-14.5.8.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents  
| where DeviceName == "dh-test-vuln"  
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.8.exe"  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1333" height="439" alt="image" src="https://github.com/user-attachments/assets/97f846a0-8727-4e9d-9763-5109ec641986" />

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "dh" actually opened the TOR browser. There was evidence that they did open it at `2025-10-22T17:29:48.0836423Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
|where DeviceName == "dh-test-vuln"
| where InitiatingProcessAccountName == "dh"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| where Timestamp >= datetime(2025-10-22T17:01:41.5417889Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, InitiatingProcessAccountName, ProcessCommandLine
```
<img width="1324" height="493" alt="image" src="https://github.com/user-attachments/assets/f9f92ba1-1a68-418f-bd35-98e11dfd4c63" />



---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2025-10-22T17:30:05.2782042Z`, an employee on the "threat-hunt-lab" device successfully established a connection to the remote IP address `185.219.84.166` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\dh\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where InitiatingProcessFileName  has_any ("tor.exe", "firefox.exe")
| where DeviceName == "dh-test-vuln"
| where RemotePort in ("9030", "9001", "9040", "9050", "9051", "9150", "80", "443")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFolderPath
| order by Timestamp desc
```
<img width="1340" height="439" alt="image" src="https://github.com/user-attachments/assets/029e2173-92f4-4e29-9857-8e5b3ffa2170" />


---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2025-10-22T17:01:41.5417889Z`
- **Event:** The user "dh" downloaded a file named `tor-browser-windows-x86_64-portable-14.5.8.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\DH\Downloads\tor-browser-windows-x86_64-portable-14.5.8.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2025-10-22T17:28:59.1193171Z`
- **Event:** The user "employee" executed the file `tor-browser-windows-x86_64-portable-14.5.8.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.5.8.exe /S`
- **File Path:** `C:\Users\DH\Downloads\tor-browser-windows-x86_64-portable-14.5.8.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2025-10-22T17:29:53.7615676Z`
- **Event:** User "dh" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\DH\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2025-10-22T17:30:05.2782042Z`
- **Event:** A network connection to IP `185.219.84.166` on port `9001` by user "employee" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\DH\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2025-10-22T17:30:01.1475237Z` - Connected to `162.55.48.243` on port `443`.
  - `2025-10-22T17:30:15.7604651Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "dh" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2025-10-22T18:50:29.60246Z`
- **Event:** The user "employee" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\DH\Desktop\tor-shopping-list.txt`

---

## Summary

The user "dh" on the "dh-test-vuln" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `dh-test-vuln` by the user `dh`. The device was isolated, and the user's direct manager was notified.

---

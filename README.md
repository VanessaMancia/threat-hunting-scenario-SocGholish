<img width="400" src="https://github.com/user-attachments/assets/bb4dc9ef-c418-467b-ac7a-2c6385e5ec21" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: SocGholish Malware 
- [Scenario Creation](https://github.com/VanessaMancia/threat-hunt-scenario-for-SocGholish-event-creation)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Fake SocGholish download 

##  Scenario

Management has received threat intelligence reports warning that multiple partner organizations in the same industry were recently compromised via SocGholish malware delivered through fake browser update pop-ups on legitimate but compromised websites. Additionally, the organization’s web proxy logs show that some employees recently visited websites flagged by threat feeds as having served SocGholish payloads.

The goal of this threat hunt is to proactively detect any possible SocGholish infections that may have occurred through these fake update lures, to identify any PowerShell loader execution, and to validate whether any systems have established C2 communications with known SocGholish infrastructure. If any SocGholish activity is identified, please immediately isolate affected endpoints and notify management.


### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `chrome_update_fake.exe` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections to a C2 server.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Confirming that the alert was a true positive, we searched the DeviceFileEvents table for the workstation nessa-windows. This revealed a suspicious pattern involving the renamed file. Originally, a legitimate VLC installer from a trusted source (get.videolan.org) was renamed to chrome_update_fake.exe in the Downloads folder, which is consistent with SocGholish infection techniques that disguise payloads as browser updates.

**Query used to locate events:**

```kql
DeviceFileEvents  
| where DeviceName == "nessa-windows"   
| where FileName contains "fake"  
| where ActionType contains "rename"
| project Timestamp, DeviceName, ActionType, FileName, FileOriginReferrerUrl, InitiatingProcessAccountName, InitiatingProcessRemoteSessionIP
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/55850959-2ba4-41ff-88d5-15131ef66b19">

---

### 2. Searched the `DeviceFileEvents` Table continued...

Shortly after renaming, multiple FileDeleted events were captured for this file. This may indicate that the user or malware attempted to remove forensic artifacts after execution. The repeated deletion pattern aligns with known anti-forensics or cleanup behavior to hide traces of a malicious loader. All events were initiated from an internal session using IP 192.168.0.140, suggesting local or remote session activity on the device.

Given these findings, additional hunting was performed to search for encoded PowerShell activity and any outbound network connections potentially associated with this suspicious file execution.

**Query used to locate event:**

```kql

DeviceFileEvents  
| where FileName contains "chrome_update_fake"
| order by Timestamp desc   
| project Timestamp, DeviceName, ActionType, FileName, FileOriginUrl, FileOriginReferrerUrl, InitiatingProcessRemoteSessionIP
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/93052198-0793-49d4-97e0-ceb616ecdd9d">

---

### 3. Searched the `DeviceProcessEvents` Table for encoded PowerShell commands executed

During the hunt, analysis of DeviceProcessEvents on nessa-windows showed three encoded PowerShell commands executed under the same user account. This suggests that the suspicious file may have launched hidden scripts as part of a potential malware infection. Encoded PowerShell is rarely used by typical users, so this activity should be investigated further to confirm its purpose and assess potential malicious behavior.

**Query used to locate events:**

```kql
DeviceProcessEvents  
| where DeviceName == "nessa-windows"
| where ProcessCommandLine has "-enc"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, ProcessCommandLine, AccountName, AccountDomain
| order by Timestamp desc
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/4ac3e8e0-27e7-475b-b617-1c25378c35dc">

---

### 4. Searched the `DeviceNetworkEvents` Table for PowerShell-based network Connections

It was confirmed that the simulated fake update scenario successfully triggered a PowerShell-based network connection to example.com over port 80. This behavior matches what would be expected of a SocGholish loader attempting a command-and-control check-in. No additional suspicious C2 traffic was detected beyond this controlled test event. Two other outbound HTTPS connections from the system account were identified as related to lab infrastructure and are not considered suspicious.

**Query used to locate events:**

```kql
DeviceNetworkEvents  
| where DeviceName == "nessa-windows"  
| where InitiatingProcessFileName =~ "powershell.exe"
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessAccountName, RemoteIP, RemotePort, RemoteUrl
| order by Timestamp desc
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/62bfcc0d-5a76-4316-a410-72a7c9008a70">

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2024-11-08T22:14:48.6065231Z`
- **Event:** The user "employee" downloaded a file named `tor-browser-windows-x86_64-portable-14.0.1.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2024-11-08T22:16:47.4484567Z`
- **Event:** The user "employee" executed the file `tor-browser-windows-x86_64-portable-14.0.1.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.0.1.exe /S`
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2024-11-08T22:17:21.6357935Z`
- **Event:** User "employee" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\employee\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2024-11-08T22:18:01.1246358Z`
- **Event:** A network connection to IP `176.198.159.33` on port `9001` by user "employee" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2024-11-08T22:18:08Z` - Connected to `194.164.169.85` on port `443`.
  - `2024-11-08T22:18:16Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "employee" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2024-11-08T22:27:19.7259964Z`
- **Event:** The user "employee" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\employee\Desktop\tor-shopping-list.txt`

---

## Summary

The user "employee" on the "threat-hunt-lab" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `threat-hunt-lab` by the user `employee`. The device was isolated, and the user's direct manager was notified.

---

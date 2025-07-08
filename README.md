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
| take 10
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/98b7fd32-877d-42f4-b89c-1a4a9b330b8a">

---

## Chronological Event Timeline 

### 1. File Renaming - Disguised Payload

- **Timestamp:** `2025-06-30T17:19:42Z`
- **Event:** The legitimate VLC installer `vlc-3.0.21-win64.exe` was renamed to `chrome_update_fake.exe` on the workstation nessa-windows. This mirrors SocGholish techniques, where a fake browser update is used to lure users.
- **Action:** File renamed
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 2. File Deletion - Cleanup Activity

- **Timestamps:**
- `2025-06-30T17:20:18Z`
- `2025-06-30T17:20:21Z`
- `2025-06-30T17:27:30Z`

- **Event:** The file `chrome_update_fake.exe` was deleted multiple times from the same Downloads folder. This pattern suggests the user or malware may have attempted to remove forensic evidence after execution.
- **Action:** FileDeleted event detected (3 occurrences).
- **Command:** `tor-browser-windows-x86_64-portable-14.0.1.exe /S`
- **File Path:** `C:\Users\BigMOMMA\Downloads\chrome_update_fake.exe`

### 3. PowerShell Execution - Encoded Commands

- **Timestamp:** 
- `2025-06-30T17:22:00Z`
- `2025-06-30T17:23:09Z`
- `2025-06-30T17:23:36Z`
- **Event:** Encoded PowerShell commands were executed by the user bigmomma on device nessa-windows. This is commonly seen in SocGholish, where initial loaders drop encoded scripts to evade detection.
- **Action:** Process creation detected (Base64-encoded PowerShell).
- **Command Example:
- `powershell.exe' -enc UwBlAGMAdQByAGU=`
- **File Path:** `C:\Windows\System32\WindowsPowerShell\v1.0`

### 4. Outbound Network Connection - Simulated C2 Callback

- **Timestamp:** `2025-06-30T17:26:46Z`
- **Event:** PowerShell initiated an outbound HTTP connection to example.com over port 80. This simulated a command-and-control (C2) check-in, mimicking real SocGholish behavior.
- **Action:** Network connection to external IP 23.192.228.80 established.
- **Process:** `powershell.exe`
- **Remote URL:** `wxample.com`

---

## Summary

On June 30, 2025, a simulated SocGholish infection was successfully emulated on the device nessa-windows. The chain began with the renaming of a legitimate VLC installer to chrome_update_fake.exe, consistent with real-world SocGholish delivery mechanisms that impersonate browser updates.

Shortly after, the file was deleted multiple times—an indicator of anti-forensic behavior. The user bigmomma also ran three encoded PowerShell commands, suggesting post-download execution of hidden scripts.

The simulation included a test outbound connection from powershell.exe to example.com, replicating the callback behavior of SocGholish malware attempting to reach a C2 server. No further suspicious network behavior was identified beyond this controlled scenario.

---

## Response Taken

SocGholish-like activity was confirmed on the endpoint `nessa-windows.` The device was isolated, and management was notified.

---

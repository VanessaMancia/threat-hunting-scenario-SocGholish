# Threat Event (SocGholish Fake Browser Update)
**Unauthorized SocGholish Loader Emulation**

## Steps the "Bad Actor" took to Create Logs and IoCs:
1. Visit a compromised website (simulated)
2. Downloads a fake Chrome update installer named: `chrome_update_fake.exe`
3. Executes the fake installer 
4. The "installer" then runs an obfuscated PowerShell encoded command: `powershell -enc UwBlAGMAdQByAGU=` (base64 for "secure", harmless)
5. PowerShell sends a simulated C2 check-in to a benign site: `Invoke-WebRequest -Uri "http://example.com/collect"`
6. Deletes the fake installer to mimic attacker cleanup: `Remove-Item C:\Users\<username>\Downloads\chrome_update_fake.exe`

---

## Tables Used to Detect IoCs:
| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceFileEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table|
| **Purpose**| Used to detect fake update file creation, execution, and deletion. |

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceProcessEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table|
| **Purpose**| 	Used to detect the encoded PowerShell loader simulation.|

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceNetworkEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table|
| **Purpose**| Used to detect PowerShell network activity to the simulated C2.|

---

## Related Queries:
```kql
// Detect the fake update download 
DeviceFileEvents
| where FileName contains "chrome_update_fake"
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FileOriginUrl, FileOriginReferrerUrl, InitiatingProcessRemoteSessionIP

// Detect suspicious PowerShell with encoded command
DeviceProcessEvents
| where DeviceName == "nessa-windows"
| where ProcessCommandLine has "-enc"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, ProcessCommandLine, AccountName, AccountDomain
| order by Timestamp desc

// Detect PowerShell making outbound network request
DeviceNetworkEvents
| where DeviceName == "nessa-windows"
| where InitiatingProcessFileName =~ "powershell.exe"
| project Timestamp, DeviceName, InitiatingProcessAccountName, RemoteIP, RemotePort, RemoteUrl
| order by Timestamp desc

// Detect deletion of the fake update file
DeviceFileEvents
| where FileName contains "chrome_update_fake" and ActionType == "FileDeleted"

```

---

## Created By:
- **Author Name**: Vanessa Mancia 
- **Author Contact**: https://www.linkedin.com/in/VanessaMancia/
- **Date**: June 30, 2025

## Validated By:
- **Reviewer Name**: 
- **Reviewer Contact**: 
- **Validation Date**: 

---

## Additional Notes:
- **None**

---

## Revision History:
| **Version** | **Changes**                   | **Date**         | **Modified By**   |
|-------------|-------------------------------|------------------|-------------------|
| 1.0         | Initial draft                  | `September  6, 2024`  | `Josh Madakor`   

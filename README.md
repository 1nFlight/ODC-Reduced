# Collect-IntuneLogs

A PowerShell log collector for Intune / MDM endpoint troubleshooting. Produces a single ZIP file containing all relevant diagnostic artifacts. Drop-in replacement for `IntuneODCStandAlone.ps1` + `Intune.xml`.

## Quick Start

Run as **Administrator** on the target device:

```
irm https://raw.githubusercontent.com/1nFlight/ODC-Reduced/main/Collect-IntuneLogs.ps1 | iex
```

With parameters:

```
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/1nFlight/ODC-Reduced/main/Collect-IntuneLogs.ps1))) -Deep -DaysBack 14
```

Or download and run locally:

```
.\Collect-IntuneLogs.ps1
```

The ZIP is saved to your Desktop and Explorer opens to it automatically.

## What It Collects

| Category | Contents | Scope |
| --- | --- | --- |
| **IME Sidecar Logs** | Full `%ProgramData%\Microsoft\IntuneManagementExtension\Logs` | All rolled files |
| **MDM Logs** | SYSTEM profile + current user `mdm\*.log` | Both contexts |
| **Autopilot** | `AutoPilotConfigurationFile.json`, `ServiceState\Autopilot\*.json`, AP event dump | Last 200 events per channel |
| **Enrollment / Policy Registry** | Enrollments, EnterpriseDesktopAppManagement, PolicyManager, Provisioning, MDMWins, OnlineManagement, DeclaredConfiguration, CSPs | 35 keys |
| **Narrow Event Log Channels** | AAD, DeviceManagement-Enterprise-Diagnostics-Provider (Admin/Operational/Debug/Autopilot), User Device Registration, ModernDeployment, Provisioning, Shell-Core, AppxDeployment-Server, PushNotification, HelloForBusiness, BitLocker, Defender, AppLocker, etc. | Full export (time not filtered — channels are small) |
| **Big Event Logs** | Application, System | Time-filtered by `-DaysBack` |
| **Company Portal Logs** | `DiagOutputDir` + `LocalCache\*.log` + `TempState\*.log` | Every user profile on the device |
| **MDMDiagnosticsTool** | Official Microsoft enrollment+provisioning+autopilot ZIP | Always |
| **Commands** | `dsregcmd /status`, `whoami /all`, `ipconfig /all`, proxy (WinHTTP+WinINet+.NET), service status, certs (LM\My + CU\My + EKU), installed programs (registry, not WMI), MP status, TPM/BitLocker/OS version | Always |
| **User-context commands** | `dsregcmd /status`, `whoami /all`, and `certutil -user -store My` are executed in the **interactive console user's context** via scheduled task (LogonType=Interactive, no password). Ensures `UserState` fields in `dsregcmd` reflect the affected end user, not the helpdesk admin who elevated PowerShell. Falls back to elevated context with a header note if no interactive user is detected. | Automatic |
| **Panther / Setup** | `%SystemRoot%\Panther\*.log/xml`, `inf\setup*.log` | OOBE-scoped |
| **MSI Install Logs** | `%SystemRoot%\temp\*MSI*.log` | Recent |
| **DiagnosticLogCSP** | `%ProgramData%\microsoft\diagnosticlogcsp\collectors\*` | Historical CSP-collected bundles |
| **WinGet DiagOutputDir** | Per-user WinGet diagnostics | All users |

## Optional artifacts (`-Deep`)

| Artifact | Why optional |
| --- | --- |
| `msinfo32 /nfo` | 2–5 min runtime, large output, rarely changes diagnosis |
| `dsregcmd /debug` | Scheduled-task-as-SYSTEM, 120s wait, only useful for WPJ/HAADJ deep dives |
| `gpresult /H` | Slow on domain-joined devices |
| `Get-DeliveryOptimizationLog` | Verbose, relevant only for Win32 app / update distribution issues |
| `Security.evtx` (time-filtered) | Can be gigabytes; auth-failure investigations only |

## Parameters

| Parameter | Default | Description |
| --- | --- | --- |
| `-DaysBack` | `7` | Days of history for Application / System / Security event log exports |
| `-OutputRoot` | Desktop | Folder where the ZIP is created |
| `-Deep` | off | Include heavy artifacts (msinfo32, dsregcmd /debug, gpresult, Security.evtx, DO log) |
| `-IncludeNDES` | off | NDES Connector logs + IIS W3SVC1 (only if `NDESConnectorSvc` present) |
| `-IncludeConfigMgr` | off | ConfigMgr client logs (only if `CcmExec` present) |
| `-NoZip` | off | Keep staging folder, skip ZIP creation |
| `-NoOpen` | off | Don't open Explorer after completion |

### Examples

```
# Default — last 7 days, save ZIP to Desktop
.\Collect-IntuneLogs.ps1

# Last 14 days + deep collection
.\Collect-IntuneLogs.ps1 -DaysBack 14 -Deep

# NDES server collection
.\Collect-IntuneLogs.ps1 -IncludeNDES

# Co-managed device with ConfigMgr client
.\Collect-IntuneLogs.ps1 -IncludeConfigMgr

# Custom output location, skip auto-open
.\Collect-IntuneLogs.ps1 -OutputRoot C:\Temp -NoOpen
```

## Output

```
COMPUTERNAME_IntuneLogs_20260421-143022.zip
├── _Collector.log              (per-step pass/fail, timestamped)
├── _Summary.txt                (run metadata, elapsed time, size)
├── Commands\
│   ├── dsregcmd_status.txt
│   ├── whoami.txt
│   ├── ipconfig_all.txt
│   ├── proxy_settings.txt
│   ├── services_status.txt
│   ├── mp_computer_status.txt
│   ├── certs_localmachine_my.txt
│   ├── certs_currentuser_my.txt
│   ├── installed_programs.txt  (from registry — no Win32_Product MSI repair)
│   ├── basic_system_info.txt
│   ├── bitlocker_status.txt
│   ├── autopilot_events_summary.txt
│   ├── MDMDiagReport.zip
│   └── (-Deep) msinfo32.nfo, dsregcmd_debug.txt, gpresult.html, delivery_optimization.log
├── Files\
│   ├── IME\                    (IntuneManagementExtension\Logs contents)
│   ├── MDM\SYSTEM\             (systemprofile mdm logs)
│   ├── MDM\CurrentUser\        (user-context mdm logs)
│   ├── Autopilot\              (JSON files)
│   ├── CompanyPortal\<user>\DiagOutputDir\   (per-user logs)
│   ├── DeviceInventory\
│   ├── EPM\
│   ├── PolicyClient\
│   ├── MSI\
│   ├── DiagnosticLogCSP\
│   ├── MDMDiagnostics_Historical\
│   ├── WinGet\<user>\
│   ├── WPM\
│   ├── Panther\
│   └── (-IncludeNDES) NDES\
│       └── (-IncludeConfigMgr) ConfigMgr\
├── Registry\                   (35 .reg exports)
└── EventLogs\                  (40+ .evtx channels)
```

## What Was Removed from the Original IntuneODC

This collector intentionally drops the following categories that the original collected unconditionally:

* **Dead Windows paths**: HomeGroup (removed in 1803), DirSync (deprecated 2014), System Center Advisor, SCO (scoconnector.etl), Teams classic / Squirrel
* **Legacy Intune paths**: OnlineManagement PolicyAgent GUID `3DA21691-E39D-4DA6-8A4B-B43877BCB1B7` (pre-2022 client agent), legacy clientui.log hunting across 4 locations
* **Legacy registry keys**: POSReady, WEPOS, WindowsEmbedded, ProductSuite, CSDVersion, Microsoft Operations Manager, SystemCenterAdvisor, HVSICSP
* **Duplicates**: IME logs collected under both Intune and Sidecar teams; MDM systemprofile path duplicated under EPM and Sidecar; Windows Update registry keys collected under both `..\Commands` and `..\RegistryKeys`; `HKLM\...\Installer\UserData\S-1-5-18` listed twice
* **Expensive-by-default commands**: `Win32_Product` (triggers MSI self-repair on every installed package — don't use), `Win32_PnPSignedDriver` (slow WMI, rarely relevant), `msinfo32 /report` (the `.txt` is a degraded view of the `.nfo`)
* **NDES server paths on client machines**: `%ProgramFiles%\Microsoft Configuration Manager\logs\ndes*`, `C:\inetpub\logs\LogFiles\W3SVC1` — now gated behind `-IncludeNDES` with service detection

## Requirements

* Windows 10 1809+ / Windows 11
* PowerShell 5.1 or 7+
* **Administrator elevation required** (event log export, SYSTEM-context scheduled task, registry `reg export`, certificate store reads)

## License

MIT

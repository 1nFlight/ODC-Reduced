#Requires -Version 5.1
<#
.SYNOPSIS
    Intune / MDM diagnostic log collector. Single-file replacement for IntuneODC.

.DESCRIPTION
    Self-contained, parameterized, one-ZIP-to-Desktop collector for Intune endpoint
    troubleshooting. No external XML manifest. No external downloads. Zero dependencies.

    Collects (always):
      - IME Sidecar logs (full, all rolled files)
      - MDM systemprofile + user MDM logs
      - Registry exports for enrollment, policy, provisioning, IME, Autopilot
      - Event logs (time-filtered for big channels, full for narrow Intune channels)
      - dsregcmd /status, whoami, certs, proxy, services, MDE status
      - MDMDiagnosticsTool output for DeviceEnrollment/DeviceProvisioning/Autopilot
      - Autopilot JSON from Provisioning + ServiceState
      - Company Portal DiagOutputDir for every user profile (not just current)
      - Installed programs via registry Uninstall keys (no Win32_Product MSI repair)

    Collects (switched):
      -Deep              : msinfo32, dsregcmd /debug (as SYSTEM), gpresult /H,
                           Get-DeliveryOptimizationLog, Security.evtx (time-filtered)
      -IncludeNDES       : NDES connector logs + IIS W3SVC1 (if service detected)
      -IncludeConfigMgr  : SCCM client logs (if CcmExec detected)

.PARAMETER DaysBack
    Days of event log history to include for the three big channels
    (Application/System/Security). Narrow Intune channels are taken in full.
    Default: 7.

.PARAMETER OutputRoot
    Folder where the final ZIP is written. Default: current user's Desktop.

.PARAMETER Deep
    Include heavyweight artifacts (msinfo32, dsregcmd /debug, gpresult /H,
    Security.evtx, DO log). Adds 2-5 minutes to runtime.

.PARAMETER IncludeNDES
    Collect NDES Connector logs + IIS W3SVC1 logs. Only runs if
    NDESConnectorSvc is detected on the machine.

.PARAMETER IncludeConfigMgr
    Collect ConfigMgr client logs (co-managed devices). Only runs if
    CcmExec is detected.

.PARAMETER NoZip
    Keep the staging folder, skip ZIP creation. Useful for debugging the collector.

.PARAMETER NoOpen
    Do not open Explorer to the output location when finished.

.EXAMPLE
    .\Collect-IntuneLogs.ps1

.EXAMPLE
    .\Collect-IntuneLogs.ps1 -Deep -DaysBack 14

.EXAMPLE
    # One-liner (defaults only)
    irm https://raw.githubusercontent.com/<user>/<repo>/main/Collect-IntuneLogs.ps1 | iex

.EXAMPLE
    # One-liner with parameters
    & ([scriptblock]::Create((irm https://raw.githubusercontent.com/<user>/<repo>/main/Collect-IntuneLogs.ps1))) -Deep

.NOTES
    Requires administrator elevation.
    Changelog:
        1.1.0  2026-04-21  Interactive-user context for user-scoped commands.
                           - dsregcmd /status, whoami /all, and CurrentUser\My
                             cert enumeration now run in the interactive
                             console user's context via scheduled task
                             (LogonType=Interactive, no password required).
                           - Fixes the "helpdesk admin elevated the PS session,
                             so UserState in dsregcmd reflects the admin not
                             the affected user" trap.
                           - Falls back to elevated context with a header note
                             if no interactive user is detected (e.g. when run
                             from SYSTEM / Intune remediation).
        1.0.0  2026-04-21  Initial release. Rewrite of IntuneODC.
                           - Fixed: dup IME/Sidecar file entries, dup registry keys
                             under Commands\Windows Update + RegistryKeys sections
                           - Fixed: Company Portal collection now walks all user
                             profiles and targets DiagOutputDir (not whole LocalState)
                           - Fixed: event log collection time-filters big channels
                             via wevtutil /q XPath instead of copying full evtx
                           - Fixed: removed WMI Win32_Product (MSI repair trigger)
                             in favor of registry Uninstall-key enumeration
                           - Fixed: removed HomeGroup, DirSync, Advisor, SCO,
                             legacy PolicyAgent GUID paths, Teams classic, SCOM,
                             WEPOS/POSReady/WindowsEmbedded registry keys
                           - Fixed: gated NDES and ConfigMgr on service presence
                           - Fixed: proxy-detect assignment vs comparison bug
                           - Fixed: zip cleanup filter glob vs regex mismatch
                           - Fixed: timestamp format (%m month vs %M minutes)
                           - Fixed: duplicate Initialize() call
                           - Fixed: repeated CSV header in stdout.log
                           - Fixed: unnecessary zip-then-copy-uncompressed double IO
                           - Added: parameterized interface matching Collect-Win32Logs
                           - Added: per-step logging with pass/fail status to
                             _Collector.log for DFM escalation evidence
#>

[CmdletBinding()]
param(
    [ValidateRange(1, 90)]
    [int]$DaysBack = 7,

    [string]$OutputRoot = [Environment]::GetFolderPath('Desktop'),

    [switch]$Deep,
    [switch]$IncludeNDES,
    [switch]$IncludeConfigMgr,
    [switch]$NoZip,
    [switch]$NoOpen
)

#region Constants

$APP_VERSION = '1.1.0'
$APP_BUILD   = '2026-04-21'

$script:Timestamp  = Get-Date -Format 'yyyyMMdd-HHmmss'
$script:Computer   = $env:COMPUTERNAME
$script:StageRoot  = Join-Path $env:TEMP ("Collect-IntuneLogs_{0}_{1}" -f $script:Computer, $script:Timestamp)
$script:ZipName    = "{0}_IntuneLogs_{1}.zip" -f $script:Computer, $script:Timestamp
$script:ZipPath    = Join-Path $OutputRoot $script:ZipName
$script:LogFile    = Join-Path $script:StageRoot '_Collector.log'
$script:SummaryFile= Join-Path $script:StageRoot '_Summary.txt'
$script:StartTime  = Get-Date

#endregion

#region Helpers

function Write-CLog {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('INFO','WARN','ERROR','OK','SKIP')][string]$Level = 'INFO'
    )
    $line = '{0}  {1,-5}  {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    $color = switch ($Level) {
        'OK'    { 'Green' }
        'WARN'  { 'Yellow' }
        'ERROR' { 'Red' }
        'SKIP'  { 'DarkGray' }
        default { 'Gray' }
    }
    Write-Host $line -ForegroundColor $color
    try { Add-Content -Path $script:LogFile -Value $line -Encoding UTF8 -ErrorAction Stop } catch {}
}

function Invoke-Safe {
    <#
    .SYNOPSIS
        Wraps a collection step. Logs OK/ERROR/SKIP and never lets one step kill the run.
    #>
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][scriptblock]$Action,
        [switch]$ContinueOnError
    )
    Write-CLog "BEGIN  $Name"
    try {
        & $Action
        Write-CLog "OK     $Name" -Level OK
        return $true
    }
    catch {
        Write-CLog "ERROR  $Name :: $($_.Exception.Message)" -Level ERROR
        return $false
    }
}

function Ensure-Dir { param([string]$Path) if (-not (Test-Path -LiteralPath $Path)) { New-Item -ItemType Directory -Path $Path -Force | Out-Null } }

function Test-IsAdmin {
    ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-InteractiveUser {
    <#
    .SYNOPSIS
        Returns "DOMAIN\User" of the active console user, or $null if none.
    .DESCRIPTION
        Tries multiple detection methods. Used to distinguish the helpdesk
        admin who elevated PowerShell from the affected end user whose
        Intune state we actually want to inspect.
    #>

    # Method 1: Win32_ComputerSystem.UserName — reliable for console sessions
    try {
        $u = (Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).UserName
        if ($u) { return $u }
    } catch {}

    # Method 2: explorer.exe owner — covers cases where #1 returns null but
    # a user has an interactive shell running
    try {
        $proc = Get-CimInstance Win32_Process -Filter "Name='explorer.exe'" -ErrorAction Stop |
                Select-Object -First 1
        if ($proc) {
            $owner = Invoke-CimMethod -InputObject $proc -MethodName GetOwner -ErrorAction Stop
            if ($owner.User) {
                if ($owner.Domain) { return "$($owner.Domain)\$($owner.User)" }
                return $owner.User
            }
        }
    } catch {}

    # Method 3: query user (quser.exe) — fallback, parses "Active" session
    try {
        $q = & quser.exe 2>$null
        if ($LASTEXITCODE -eq 0 -and $q) {
            foreach ($line in ($q | Select-Object -Skip 1)) {
                if ($line -match '\s+Active\s+') {
                    $name = (($line -replace '^\s*>', '') -split '\s+')[0]
                    if ($name) { return $name }
                }
            }
        }
    } catch {}

    return $null
}

function Invoke-AsInteractiveUser {
    <#
    .SYNOPSIS
        Runs a cmd.exe command line in the interactive user's context via
        a short-lived scheduled task, captures output, writes to $OutputFile.
    .DESCRIPTION
        If no interactive user is detected, or if the elevated admin and the
        interactive user are the same account, runs the command directly
        and annotates the output with context info.

        Uses LogonType=Interactive so no password is required — the task
        simply fails if the specified user is not logged on.
    .PARAMETER Command
        Full cmd.exe argument string. Stdout+stderr are captured.
    .PARAMETER OutputFile
        Final destination in the staging tree.
    .PARAMETER TimeoutSeconds
        Max wait for the task to complete. Default 60.
    #>
    param(
        [Parameter(Mandatory)][string]$Command,
        [Parameter(Mandatory)][string]$OutputFile,
        [int]$TimeoutSeconds = 60
    )

    $elevated    = "$env:USERDOMAIN\$env:USERNAME"
    $interactive = Get-InteractiveUser
    Ensure-Dir (Split-Path $OutputFile -Parent)

    # Case A: no interactive user detected — run directly, mark context
    if (-not $interactive) {
        "# Context: elevated ($elevated). No interactive user detected." | Out-File $OutputFile -Encoding UTF8
        "# UserState fields in dsregcmd reflect the elevated account, not an end user." | Out-File $OutputFile -Encoding UTF8 -Append
        '' | Out-File $OutputFile -Encoding UTF8 -Append
        $raw = & cmd.exe /c $Command 2>&1 | Out-String
        $raw | Out-File $OutputFile -Encoding UTF8 -Append
        return 'direct-no-interactive'
    }

    # Case B: elevated admin == interactive user (self-service scenario)
    if ($interactive -ieq $elevated) {
        "# Context: $elevated (elevated == interactive, direct execution)." | Out-File $OutputFile -Encoding UTF8
        '' | Out-File $OutputFile -Encoding UTF8 -Append
        $raw = & cmd.exe /c $Command 2>&1 | Out-String
        $raw | Out-File $OutputFile -Encoding UTF8 -Append
        return 'direct-same-user'
    }

    # Case C: different users — impersonate via scheduled task
    "# Context: interactive user = $interactive" | Out-File $OutputFile -Encoding UTF8
    "# Command executed via scheduled task (LogonType=Interactive)." | Out-File $OutputFile -Encoding UTF8 -Append
    "# Elevated PS session was running as $elevated (not used for this command)." | Out-File $OutputFile -Encoding UTF8 -Append
    '' | Out-File $OutputFile -Encoding UTF8 -Append

    $guid     = [guid]::NewGuid().ToString('N')
    $tempFile = "C:\Windows\Temp\CollectIntuneLogs_usercmd_$guid.txt"
    $taskName = "CollectIntuneLogs_$($guid.Substring(0,12))"

    try {
        # cmd.exe redirects to a path writable by standard users (C:\Windows\Temp
        # default ACL grants BUILTIN\Users "Create files / write data").
        $argLine  = "/c $Command > `"$tempFile`" 2>&1"
        $action   = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument $argLine
        $trigger  = New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(3)
        $principal= New-ScheduledTaskPrincipal -UserId $interactive -LogonType Interactive -RunLevel Limited
        $settings = New-ScheduledTaskSettingsSet `
                        -ExecutionTimeLimit (New-TimeSpan -Seconds $TimeoutSeconds) `
                        -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
        $task = New-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -Settings $settings
        Register-ScheduledTask -TaskName $taskName -InputObject $task -Force -ErrorAction Stop | Out-Null
        Start-ScheduledTask -TaskName $taskName -ErrorAction Stop

        $elapsed = 0
        do {
            Start-Sleep -Seconds 2
            $elapsed += 2
            $state = (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue).State
        } while ($state -ne 'Ready' -and $elapsed -lt $TimeoutSeconds)

        if (Test-Path -LiteralPath $tempFile) {
            Get-Content -LiteralPath $tempFile -Raw | Out-File $OutputFile -Encoding UTF8 -Append
            return 'task-impersonated'
        } else {
            "# WARNING: task produced no output. User may not be logged on interactively, or" | Out-File $OutputFile -Encoding UTF8 -Append
            "#          the account cannot satisfy LogonType=Interactive on this session." | Out-File $OutputFile -Encoding UTF8 -Append
            "# Falling back to elevated-context execution below." | Out-File $OutputFile -Encoding UTF8 -Append
            '' | Out-File $OutputFile -Encoding UTF8 -Append
            $raw = & cmd.exe /c $Command 2>&1 | Out-String
            $raw | Out-File $OutputFile -Encoding UTF8 -Append
            return 'task-fallback'
        }
    }
    finally {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $tempFile -Force -ErrorAction SilentlyContinue
    }
}

function Copy-IfExists {
    param(
        [string]$Source,
        [string]$Destination,
        [string]$Filter = '*'
    )
    # Resolves env vars, silently skips missing paths, preserves structure
    $resolved = [Environment]::ExpandEnvironmentVariables($Source)
    if (-not (Test-Path -LiteralPath $resolved)) { return 0 }
    Ensure-Dir $Destination
    $items = Get-ChildItem -LiteralPath $resolved -Filter $Filter -Recurse -Force -ErrorAction SilentlyContinue -File
    $count = 0
    foreach ($i in $items) {
        $rel = $i.FullName.Substring($resolved.TrimEnd('\').Length).TrimStart('\')
        $dst = Join-Path $Destination $rel
        Ensure-Dir (Split-Path $dst -Parent)
        try {
            Copy-Item -LiteralPath $i.FullName -Destination $dst -Force -ErrorAction Stop
            $count++
        } catch {}
    }
    return $count
}

function Export-RegKey {
    param(
        [Parameter(Mandatory)][string]$Key,
        [Parameter(Mandatory)][string]$OutDir
    )
    # Accepts HKLM\... or HKEY_LOCAL_MACHINE\...
    $keyPath = $Key -replace '^HKLM\\', 'HKEY_LOCAL_MACHINE\' -replace '^HKCU\\', 'HKEY_CURRENT_USER\'
    $hiveRoot = ($keyPath -split '\\')[0]
    if ($hiveRoot -notin @('HKEY_LOCAL_MACHINE','HKEY_CURRENT_USER','HKEY_USERS','HKEY_CLASSES_ROOT')) { return }
    $flat = ($keyPath -replace '[\\:/*?"<>|]', '_') + '.reg'
    $out  = Join-Path $OutDir $flat
    $null = & reg.exe export $keyPath "$out" /y 2>$null
}

function New-EventLogExport {
    param(
        [Parameter(Mandatory)][string]$Channel,
        [Parameter(Mandatory)][string]$OutDir,
        [int]$DaysFilter = 0   # 0 = full export, >0 = time-filter XPath
    )
    $safe = $Channel -replace '[\\/:*?"<>|]', '_'
    $out  = Join-Path $OutDir ($safe + '.evtx')
    $args = @('epl', $Channel, $out, '/ow:true')
    if ($DaysFilter -gt 0) {
        $ms = [long]($DaysFilter * 86400 * 1000)
        $xp = "*[System[TimeCreated[timediff(@SystemTime) <= $ms]]]"
        $args += @('/q:' + $xp)
    }
    $null = & wevtutil.exe @args 2>$null
    return (Test-Path -LiteralPath $out)
}

#endregion

#region Preflight

if (-not (Test-IsAdmin)) {
    Write-Host ''
    Write-Host 'ERROR: Collect-IntuneLogs must be run as Administrator.' -ForegroundColor Red
    Write-Host 'Right-click PowerShell and choose "Run as administrator", then re-run.' -ForegroundColor Yellow
    Write-Host ''
    return
}

if (-not (Test-Path -LiteralPath $OutputRoot)) {
    try { New-Item -ItemType Directory -Path $OutputRoot -Force | Out-Null }
    catch {
        Write-Host "ERROR: Cannot create OutputRoot '$OutputRoot'." -ForegroundColor Red
        return
    }
}

Ensure-Dir $script:StageRoot
'' | Out-File -FilePath $script:LogFile -Encoding UTF8

Write-CLog ("Collect-IntuneLogs v{0} ({1})" -f $APP_VERSION, $APP_BUILD)
Write-CLog ("Computer: {0}  |  User: {1}" -f $script:Computer, "$env:USERDOMAIN\$env:USERNAME")
Write-CLog ("Staging : {0}" -f $script:StageRoot)
Write-CLog ("Output  : {0}" -f $script:ZipPath)
Write-CLog ("DaysBack: {0}  Deep: {1}  NDES: {2}  ConfigMgr: {3}" -f $DaysBack, $Deep.IsPresent, $IncludeNDES.IsPresent, $IncludeConfigMgr.IsPresent)

#endregion

#region Collection :: Commands

$cmdDir = Join-Path $script:StageRoot 'Commands'
Ensure-Dir $cmdDir

Invoke-Safe 'dsregcmd /status (interactive user context)' {
    $mode = Invoke-AsInteractiveUser `
                -Command 'dsregcmd.exe /status' `
                -OutputFile (Join-Path $cmdDir 'dsregcmd_status.txt') `
                -TimeoutSeconds 30
    Write-CLog "       mode: $mode"
}

Invoke-Safe 'whoami (interactive user context)' {
    $mode = Invoke-AsInteractiveUser `
                -Command 'whoami.exe /upn & echo. & echo === whoami /all === & whoami.exe /all' `
                -OutputFile (Join-Path $cmdDir 'whoami.txt') `
                -TimeoutSeconds 30
    Write-CLog "       mode: $mode"
}

Invoke-Safe 'ipconfig /all' {
    & ipconfig.exe /all 2>&1 | Out-File (Join-Path $cmdDir 'ipconfig_all.txt') -Encoding UTF8
}

Invoke-Safe 'proxy settings' {
    $out = Join-Path $cmdDir 'proxy_settings.txt'
    '=== netsh winhttp show proxy ===' | Out-File $out -Encoding UTF8
    & netsh.exe winhttp show proxy 2>&1 | Out-File $out -Encoding UTF8 -Append
    '' | Out-File $out -Encoding UTF8 -Append
    '=== WinINet (user) proxy ===' | Out-File $out -Encoding UTF8 -Append
    try {
        Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction Stop |
            Select-Object ProxyEnable, ProxyServer, ProxyOverride, AutoConfigURL |
            Format-List | Out-String | Out-File $out -Encoding UTF8 -Append
    } catch {}
    '' | Out-File $out -Encoding UTF8 -Append
    '=== System default web proxy (PS) ===' | Out-File $out -Encoding UTF8 -Append
    try { [System.Net.WebRequest]::DefaultWebProxy.Address | Out-File $out -Encoding UTF8 -Append } catch {}
}

Invoke-Safe 'service status' {
    $svcs = 'IntuneManagementExtension','dmwappushservice','DmEnrollmentSvc','DeviceInventoryAgent',
            'EPMAgentSvc','DiagTrack','CryptSvc','CertPropSvc','TPM','SCardSvr','CcmExec',
            'NDESConnectorSvc','WinDefend','WdNisSvc','Sense','bthserv','wuauserv'
    Get-Service -Name $svcs -ErrorAction SilentlyContinue |
        Select-Object Status, StartType, Name, DisplayName |
        Format-Table -AutoSize | Out-String -Width 300 |
        Out-File (Join-Path $cmdDir 'services_status.txt') -Encoding UTF8
}

Invoke-Safe 'Get-MpComputerStatus' {
    try {
        Get-MpComputerStatus -ErrorAction Stop | Format-List * |
            Out-File (Join-Path $cmdDir 'mp_computer_status.txt') -Encoding UTF8
    } catch {
        "Get-MpComputerStatus not available: $($_.Exception.Message)" |
            Out-File (Join-Path $cmdDir 'mp_computer_status.txt') -Encoding UTF8
    }
}

Invoke-Safe 'certificates (LocalMachine\My)' {
    $out = Join-Path $cmdDir 'certs_localmachine_my.txt'
    Get-ChildItem 'Cert:\LocalMachine\My' -ErrorAction SilentlyContinue |
        Select-Object Subject, Issuer, NotBefore, NotAfter, Thumbprint, HasPrivateKey,
                      @{n='EKU';e={($_.EnhancedKeyUsageList | ForEach-Object FriendlyName) -join '; '}} |
        Format-List | Out-String | Out-File $out -Encoding UTF8
}

Invoke-Safe 'certificates (CurrentUser\My) - interactive user context' {
    # certutil -user -store My enumerates the interactive user's personal certs;
    # running it in the user's context (not the elevated admin's) ensures we see
    # user-issued device compliance / Hello / SCEP certs for the affected user.
    $mode = Invoke-AsInteractiveUser `
                -Command 'certutil.exe -user -store My' `
                -OutputFile (Join-Path $cmdDir 'certs_currentuser_my.txt') `
                -TimeoutSeconds 30
    Write-CLog "       mode: $mode"
}

Invoke-Safe 'installed programs (registry)' {
    $keys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    $apps = foreach ($k in $keys) {
        Get-ItemProperty $k -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName } |
            Select-Object @{n='Scope';e={ if ($k -like 'HKCU:*') {'User'} elseif ($k -like '*WOW6432Node*') {'MachineX86'} else {'Machine'} }},
                          DisplayName, DisplayVersion, Publisher, InstallDate, UninstallString
    }
    $apps | Sort-Object DisplayName | Format-Table -AutoSize | Out-String -Width 400 |
        Out-File (Join-Path $cmdDir 'installed_programs.txt') -Encoding UTF8
}

Invoke-Safe 'basic system info' {
    $out = Join-Path $cmdDir 'basic_system_info.txt'
    $lines = @()
    $lines += '=== OS ==='
    $os = Get-CimInstance Win32_OperatingSystem
    $lines += "Caption     : $($os.Caption)"
    $lines += "Version     : $($os.Version)"
    $lines += "BuildNumber : $($os.BuildNumber)"
    $lines += "OSArch      : $($os.OSArchitecture)"
    $lines += "InstallDate : $($os.InstallDate)"
    $lines += "LastBoot    : $($os.LastBootUpTime)"
    $lines += ''
    $lines += '=== UBR (Update Build Revision) ==='
    try {
        $ubr = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop).UBR
        $dispVer = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop).DisplayVersion
        $lines += "DisplayVersion: $dispVer"
        $lines += "UBR           : $ubr"
    } catch { $lines += "UBR lookup failed: $($_.Exception.Message)" }
    $lines += ''
    $lines += '=== Computer ==='
    $cs = Get-CimInstance Win32_ComputerSystem
    $lines += "Manufacturer: $($cs.Manufacturer)"
    $lines += "Model       : $($cs.Model)"
    $lines += "Domain      : $($cs.Domain)"
    $lines += "PartOfDomain: $($cs.PartOfDomain)"
    $lines += "TotalMemGB  : {0:N2}" -f ($cs.TotalPhysicalMemory/1GB)
    $lines += ''
    $lines += '=== BIOS ==='
    $bios = Get-CimInstance Win32_BIOS
    $lines += "Vendor      : $($bios.Manufacturer)"
    $lines += "Version     : $($bios.SMBIOSBIOSVersion)"
    $lines += "Serial      : $($bios.SerialNumber)"
    $lines += ''
    $lines += '=== TPM ==='
    try {
        $t = Get-Tpm -ErrorAction Stop
        $lines += "Present : $($t.TpmPresent)"
        $lines += "Ready   : $($t.TpmReady)"
        $lines += "Enabled : $($t.TpmEnabled)"
        $lines += "Activated: $($t.TpmActivated)"
        $lines += "Owned   : $($t.TpmOwned)"
        $lines += "ManuVer : $($t.ManufacturerVersion)"
    } catch { $lines += "Get-Tpm failed: $($_.Exception.Message)" }
    $lines | Out-File $out -Encoding UTF8
}

Invoke-Safe 'BitLocker status' {
    try {
        Get-BitLockerVolume -ErrorAction Stop |
            Select-Object MountPoint, VolumeType, ProtectionStatus, LockStatus, EncryptionMethod,
                          EncryptionPercentage, VolumeStatus, AutoUnlockEnabled, KeyProtector |
            Format-List | Out-String |
            Out-File (Join-Path $cmdDir 'bitlocker_status.txt') -Encoding UTF8
    } catch {
        "Get-BitLockerVolume unavailable: $($_.Exception.Message)" |
            Out-File (Join-Path $cmdDir 'bitlocker_status.txt') -Encoding UTF8
    }
}

Invoke-Safe 'MDMDiagnosticsTool (Enrollment+Provisioning+Autopilot)' {
    $mdmZip = Join-Path $cmdDir 'MDMDiagReport.zip'
    $null = & mdmdiagnosticstool.exe -area 'DeviceEnrollment;DeviceProvisioning;Autopilot' -zip "$mdmZip" 2>&1
    if (-not (Test-Path -LiteralPath $mdmZip)) { throw 'MDMDiagnosticsTool did not produce a ZIP.' }
}

Invoke-Safe 'Autopilot diagnostic events' {
    # Lightweight AP provisioning event dump (substitute for Get-AutopilotDiagnostics)
    $out = Join-Path $cmdDir 'autopilot_events_summary.txt'
    $channels = @(
        'Microsoft-Windows-ModernDeployment-Diagnostics-Provider/Autopilot',
        'Microsoft-Windows-Provisioning-Diagnostics-Provider/Admin',
        'Microsoft-Windows-Shell-Core/Operational'
    )
    foreach ($ch in $channels) {
        try {
            "=== $ch ===" | Out-File $out -Encoding UTF8 -Append
            Get-WinEvent -LogName $ch -MaxEvents 200 -ErrorAction Stop |
                Select-Object TimeCreated, Id, LevelDisplayName, Message |
                Format-Table -AutoSize | Out-String -Width 400 | Out-File $out -Encoding UTF8 -Append
        } catch {
            "($ch not available: $($_.Exception.Message))" | Out-File $out -Encoding UTF8 -Append
        }
    }
}

# --- Deep-only commands ---
if ($Deep) {
    Invoke-Safe 'dsregcmd /debug (as SYSTEM, via scheduled task)' {
        $task  = "CollectIntuneLogs_dsregdebug_$script:Timestamp"
        $outFi = Join-Path $cmdDir 'dsregcmd_debug.txt'
        '' | Out-File $outFi -Encoding ASCII -Force
        $action  = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument "/c dsregcmd /debug >> `"$outFi`""
        $trigger = New-ScheduledTaskTrigger -At (Get-Date).AddSeconds(3) -Once
        Register-ScheduledTask -TaskName $task -Action $action -Trigger $trigger `
            -User 'NT AUTHORITY\SYSTEM' -RunLevel Highest -Force | Out-Null
        Start-ScheduledTask -TaskName $task
        Start-Sleep -Seconds 5
        $elapsed = 0
        while (((Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue).State -ne 'Ready') -and ($elapsed -lt 120)) {
            Start-Sleep -Seconds 3; $elapsed += 3
        }
        Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction SilentlyContinue
    }

    Invoke-Safe 'msinfo32 /nfo' {
        & msinfo32.exe /nfo (Join-Path $cmdDir 'msinfo32.nfo') | Out-Null
        # wait up to 5 min (msinfo32 runs async)
        $t = 0
        while ((Get-Process -Name msinfo32 -ErrorAction SilentlyContinue) -and ($t -lt 300)) {
            Start-Sleep 10; $t += 10
        }
    }

    Invoke-Safe 'gpresult /H' {
        & gpresult.exe /H (Join-Path $cmdDir 'gpresult.html') /F 2>$null
    }

    Invoke-Safe 'Get-DeliveryOptimizationLog' {
        try {
            Get-DeliveryOptimizationLog -ErrorAction Stop |
                Out-File (Join-Path $cmdDir 'delivery_optimization.log') -Encoding UTF8
        } catch {
            "Get-DeliveryOptimizationLog unavailable: $($_.Exception.Message)" |
                Out-File (Join-Path $cmdDir 'delivery_optimization.log') -Encoding UTF8
        }
    }
}

#endregion

#region Collection :: Files

$filesDir = Join-Path $script:StageRoot 'Files'
Ensure-Dir $filesDir

# IME logs (single source of truth — no duplicate entries)
Invoke-Safe 'IME Sidecar logs' {
    $n = Copy-IfExists '%ProgramData%\Microsoft\IntuneManagementExtension\Logs' (Join-Path $filesDir 'IME')
    Write-CLog "       copied $n IME log files"
}

# MDM logs under SYSTEM profile (IME SYSTEM-context) + any user profile MDM
Invoke-Safe 'MDM logs (SYSTEM + user)' {
    $n1 = Copy-IfExists '%SystemRoot%\system32\config\systemprofile\AppData\Local\mdm' (Join-Path $filesDir 'MDM\SYSTEM') '*.log'
    $n2 = Copy-IfExists '%LocalAppData%\mdm' (Join-Path $filesDir 'MDM\CurrentUser') '*.log'
    Write-CLog "       SYSTEM: $n1  |  user: $n2"
}

Invoke-Safe 'DiagnosticLogCSP collectors' {
    $null = Copy-IfExists '%ProgramData%\microsoft\diagnosticlogcsp\collectors' (Join-Path $filesDir 'DiagnosticLogCSP')
}

Invoke-Safe 'MDMDiagnostics public reports (historical)' {
    $null = Copy-IfExists '%public%\Documents\MDMDiagnostics' (Join-Path $filesDir 'MDMDiagnostics_Historical')
}

Invoke-Safe 'Autopilot JSON' {
    $apDir = Join-Path $filesDir 'Autopilot'
    Ensure-Dir $apDir
    $p1 = [Environment]::ExpandEnvironmentVariables('%SystemRoot%\Provisioning\AutoPilot\AutoPilotConfigurationFile.json')
    if (Test-Path -LiteralPath $p1) { Copy-Item -LiteralPath $p1 -Destination $apDir -Force -ErrorAction SilentlyContinue }
    $null = Copy-IfExists '%SystemRoot%\ServiceState\Autopilot' $apDir '*.json'
}

Invoke-Safe 'Device Inventory Agent logs' {
    $null = Copy-IfExists '%ProgramFiles%\Microsoft Device Inventory Agent\Logs' (Join-Path $filesDir 'DeviceInventory')
}

Invoke-Safe 'EPM Agent logs' {
    $null = Copy-IfExists '%ProgramFiles%\Microsoft EPM Agent\Logs' (Join-Path $filesDir 'EPM')
}

Invoke-Safe 'PolicyClient logs' {
    $n = 0
    Get-ChildItem -Path $env:SystemRoot -Filter 'PolicyClient*.log' -ErrorAction SilentlyContinue | ForEach-Object {
        Ensure-Dir (Join-Path $filesDir 'PolicyClient')
        Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $filesDir 'PolicyClient') -Force -ErrorAction SilentlyContinue
        $n++
    }
    Write-CLog "       copied $n PolicyClient files"
}

Invoke-Safe 'MSI install logs (windows\temp)' {
    $n = 0
    Get-ChildItem -Path (Join-Path $env:SystemRoot 'temp') -Filter '*MSI*.log' -ErrorAction SilentlyContinue -File | ForEach-Object {
        Ensure-Dir (Join-Path $filesDir 'MSI')
        Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $filesDir 'MSI') -Force -ErrorAction SilentlyContinue
        $n++
    }
    Write-CLog "       copied $n MSI log files"
}

Invoke-Safe 'WinGet DiagOutputDir' {
    # DesktopAppInstaller diag output for app install troubleshooting
    $usersRoot = 'C:\Users'
    if (Test-Path $usersRoot) {
        Get-ChildItem $usersRoot -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            $src = Join-Path $_.FullName 'AppData\Local\Packages\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe\LocalState\DiagOutputDir'
            if (Test-Path -LiteralPath $src) {
                $dst = Join-Path $filesDir ("WinGet\" + $_.Name)
                Ensure-Dir $dst
                Copy-Item -LiteralPath $src -Destination $dst -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }
}

Invoke-Safe 'WPM (winget managed package) logs' {
    $null = Copy-IfExists '%TEMP%\winget\defaultState' (Join-Path $filesDir 'WPM') 'WPM-*.txt'
}

# Panther / Setup — relevant for OOBE/Autopilot failures; keep narrow
Invoke-Safe 'Panther + setup logs' {
    $null = Copy-IfExists '%SystemRoot%\Panther' (Join-Path $filesDir 'Panther') '*.log'
    $null = Copy-IfExists '%SystemRoot%\Panther' (Join-Path $filesDir 'Panther') '*.xml'
    $null = Copy-IfExists '%SystemRoot%\inf' (Join-Path $filesDir 'Panther\inf') 'setup*.log'
}

#endregion

#region Collection :: Registry

$regDir = Join-Path $script:StageRoot 'Registry'
Ensure-Dir $regDir

$mdmRegKeys = @(
    'HKLM\SOFTWARE\Microsoft\Enrollments',
    'HKLM\SOFTWARE\Microsoft\EnterpriseDesktopAppManagement',
    'HKLM\SOFTWARE\Microsoft\IntuneManagementExtension',
    'HKLM\SOFTWARE\Microsoft\MicrosoftIntune',
    'HKLM\SOFTWARE\Microsoft\PolicyManager',
    'HKLM\SOFTWARE\Microsoft\PolicyPlatform',
    'HKLM\SOFTWARE\Microsoft\Provisioning',
    'HKLM\SOFTWARE\Microsoft\Windows\Autopilot',
    'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\MDM',
    'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication',
    'HKLM\SOFTWARE\Microsoft\MDMWins',
    'HKLM\SOFTWARE\Microsoft\OnlineManagement',
    'HKLM\SOFTWARE\Microsoft\DeclaredConfiguration\HostOS',
    'HKLM\SOFTWARE\Microsoft\DeviceInventory',
    'HKLM\SOFTWARE\Microsoft\EPMAgent',
    'HKLM\SOFTWARE\Microsoft\DeviceManageabilityCSP',
    'HKLM\SOFTWARE\Microsoft\DiagnosticLogCSP',
    'HKLM\SOFTWARE\Microsoft\BitLockerCsp',
    'HKLM\SOFTWARE\Microsoft\Provisioning\Diagnostics\AutoPilot',
    'HKLM\SOFTWARE\Microsoft\Provisioning\NodeCache\CSP',
    'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies',
    'HKLM\SOFTWARE\Policies',
    'HKLM\SOFTWARE\WOW6432Node\Policies',
    'HKLM\SOFTWARE\Microsoft\Cryptography\MSCEP',
    'HKLM\SOFTWARE\Microsoft\Windows Defender',
    'HKLM\SYSTEM\CurrentControlSet\Control\CloudDomainJoin',
    'HKLM\SYSTEM\CurrentControlSet\Services\TPM',
    'HKLM\SYSTEM\CurrentControlSet\Services\CertPropSvc',
    'HKLM\SYSTEM\CurrentControlSet\Services\CryptSvc',
    'HKLM\SYSTEM\CurrentControlSet\Services\SCPolicySvc',
    'HKLM\SYSTEM\CurrentControlSet\Services\SCardSvr',
    'HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\Mdm',
    'HKCU\Software\Microsoft\SCEP',
    'HKCU\Software\Policies',
    'HKCU\Volatile Environment'
)

Invoke-Safe 'registry exports (MDM/enrollment scope)' {
    foreach ($k in $mdmRegKeys) {
        Export-RegKey -Key $k -OutDir $regDir
    }
    $count = (Get-ChildItem -LiteralPath $regDir -File -ErrorAction SilentlyContinue).Count
    Write-CLog "       exported $count reg files"
}

#endregion

#region Collection :: Event Logs

$evtDir = Join-Path $script:StageRoot 'EventLogs'
Ensure-Dir $evtDir

# Narrow Intune-relevant channels (full export — these are small)
$narrowChannels = @(
    'Microsoft-Windows-AAD/Operational',
    'Microsoft-Windows-AAD/Analytic',
    'Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin',
    'Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Operational',
    'Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Debug',
    'Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Autopilot',
    'Microsoft-Windows-User Device Registration/Admin',
    'Microsoft-Windows-User Device Registration/Debug',
    'Microsoft-Windows-ModernDeployment-Diagnostics-Provider/Admin',
    'Microsoft-Windows-ModernDeployment-Diagnostics-Provider/Autopilot',
    'Microsoft-Windows-ModernDeployment-Diagnostics-Provider/Diagnostics',
    'Microsoft-Windows-ModernDeployment-Diagnostics-Provider/ManagementService',
    'Microsoft-Windows-Provisioning-Diagnostics-Provider/Admin',
    'Microsoft-Windows-Shell-Core/Operational',
    'Microsoft-Windows-AppxDeployment-Server/Operational',
    'Microsoft-Windows-AppxDeploymentServer/Operational',
    'Microsoft-Windows-AppxPackaging/Operational',
    'Microsoft-Windows-PushNotification-Platform/Operational',
    'Microsoft-Windows-PushNotifications-Developer/Operational',
    'Microsoft-Windows-HelloForBusiness/Operational',
    'Microsoft-Windows-Store/Operational',
    'Microsoft-Windows-BitLocker/BitLocker Management',
    'Microsoft-Windows-BitLocker-DrivePreparationTool/Operational',
    'Microsoft-Windows-Windows Defender/Operational',
    'Microsoft-Windows-CodeIntegrity/Operational',
    'Microsoft-Windows-DeviceGuard/Operational',
    'Microsoft-Windows-NetworkProfile/Operational',
    'Microsoft-Windows-Bits-Client/Operational',
    'Microsoft-Windows-WindowsUpdateClient/Operational',
    'Microsoft-Windows-LAPS/Operational',
    'Microsoft-Windows-SENSE/Operational',
    'Microsoft-Windows-AppLocker/EXE and DLL',
    'Microsoft-Windows-AppLocker/MSI and Script',
    'Microsoft-Windows-AssignedAccess/Admin',
    'Microsoft-Windows-AssignedAccess/Operational',
    'Microsoft-Windows-AssignedAccessBroker/Admin',
    'Microsoft-Windows-AssignedAccessBroker/Operational',
    'Microsoft-Windows-Kernel-Boot/Operational',
    'Microsoft-Windows-Authentication User Interface/Operational',
    'Microsoft-Windows-RemoteHelp/Diagnostic',
    'Microsoft-Windows-RemoteHelp/Operational',
    'Microsoft-Windows-TaskScheduler/Operational',
    'Setup'
)

Invoke-Safe 'narrow event log channels (full)' {
    $ok = 0; $skip = 0
    foreach ($ch in $narrowChannels) {
        if (New-EventLogExport -Channel $ch -OutDir $evtDir) { $ok++ } else { $skip++ }
    }
    Write-CLog "       exported $ok  /  unavailable $skip"
}

# Big channels: time-filtered
Invoke-Safe "Application.evtx (last $DaysBack days)" {
    $null = New-EventLogExport -Channel 'Application' -OutDir $evtDir -DaysFilter $DaysBack
}
Invoke-Safe "System.evtx (last $DaysBack days)" {
    $null = New-EventLogExport -Channel 'System' -OutDir $evtDir -DaysFilter $DaysBack
}

if ($Deep) {
    Invoke-Safe "Security.evtx (last $DaysBack days, -Deep)" {
        $null = New-EventLogExport -Channel 'Security' -OutDir $evtDir -DaysFilter $DaysBack
    }
}

#endregion

#region Collection :: Company Portal (all users)

Invoke-Safe 'Company Portal logs (all user profiles)' {
    $cpRoot = Join-Path $filesDir 'CompanyPortal'
    $usersRoot = 'C:\Users'
    $totalFiles = 0
    $userCount  = 0
    if (Test-Path $usersRoot) {
        Get-ChildItem $usersRoot -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            $userName = $_.Name
            $pkgRoot  = Join-Path $_.FullName 'AppData\Local\Packages\Microsoft.CompanyPortal_8wekyb3d8bbwe'
            if (-not (Test-Path -LiteralPath $pkgRoot)) { return }
            $userCount++
            $userDst  = Join-Path $cpRoot $userName
            Ensure-Dir $userDst

            # Primary: DiagOutputDir (the actual logs)
            $diag = Join-Path $pkgRoot 'LocalState\DiagOutputDir'
            if (Test-Path -LiteralPath $diag) {
                $dst = Join-Path $userDst 'DiagOutputDir'
                Ensure-Dir $dst
                Get-ChildItem -LiteralPath $diag -File -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
                    Copy-Item -LiteralPath $_.FullName -Destination $dst -Force -ErrorAction SilentlyContinue
                    $totalFiles++
                }
            }
            # Secondary: *.log files under LocalCache and TempState
            foreach ($sub in @('LocalCache','TempState','RoamingState')) {
                $p = Join-Path $pkgRoot $sub
                if (Test-Path -LiteralPath $p) {
                    $dst = Join-Path $userDst $sub
                    Get-ChildItem -LiteralPath $p -Filter '*.log' -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
                        Ensure-Dir $dst
                        Copy-Item -LiteralPath $_.FullName -Destination $dst -Force -ErrorAction SilentlyContinue
                        $totalFiles++
                    }
                }
            }
        }
    }
    Write-CLog "       users with CP package: $userCount  |  files copied: $totalFiles"
}

#endregion

#region Collection :: NDES (conditional)

if ($IncludeNDES) {
    $ndesSvc = Get-Service -Name NDESConnectorSvc -ErrorAction SilentlyContinue
    if (-not $ndesSvc) {
        Write-CLog 'NDES: NDESConnectorSvc not installed — skipping' -Level SKIP
    } else {
        $ndesDir = Join-Path $filesDir 'NDES'
        Ensure-Dir $ndesDir
        Invoke-Safe 'NDES Connector logs' {
            $null = Copy-IfExists '%ProgramFiles%\Microsoft Intune\NDESConnectorSvc\Logs' (Join-Path $ndesDir 'NDESConnectorSvc')
            $null = Copy-IfExists '%ProgramFiles%\Microsoft Intune\NDESPolicyModule\Logs' (Join-Path $ndesDir 'NDESPolicyModule')
            $cfg = [Environment]::ExpandEnvironmentVariables('%ProgramFiles%\Microsoft Intune\NDESConnectorSvc\NDESConnector.exe.config')
            if (Test-Path -LiteralPath $cfg) { Copy-Item -LiteralPath $cfg -Destination $ndesDir -Force -ErrorAction SilentlyContinue }
            $ui  = [Environment]::ExpandEnvironmentVariables('%ProgramFiles%\Microsoft Intune\NDESConnectorUI\NDESConnectorUI.log')
            if (Test-Path -LiteralPath $ui) { Copy-Item -LiteralPath $ui -Destination $ndesDir -Force -ErrorAction SilentlyContinue }
        }
        Invoke-Safe 'NDES IIS W3SVC1 (last 7 days)' {
            $iisDir = Join-Path $ndesDir 'IIS_W3SVC1'
            Ensure-Dir $iisDir
            $cut = (Get-Date).AddDays(-7)
            Get-ChildItem 'C:\inetpub\logs\LogFiles\W3SVC1' -Filter 'u_ex*.log' -ErrorAction SilentlyContinue |
                Where-Object { $_.LastWriteTime -ge $cut } |
                ForEach-Object { Copy-Item -LiteralPath $_.FullName -Destination $iisDir -Force -ErrorAction SilentlyContinue }
        }
        Invoke-Safe 'certutil -template' {
            & certutil.exe -v -template 2>&1 | Out-File (Join-Path $ndesDir 'certificate_templates.txt') -Encoding UTF8
        }
    }
}

#endregion

#region Collection :: ConfigMgr (conditional)

if ($IncludeConfigMgr) {
    $ccm = Get-Service -Name CcmExec -ErrorAction SilentlyContinue
    if (-not $ccm) {
        Write-CLog 'ConfigMgr: CcmExec not installed — skipping' -Level SKIP
    } else {
        $cmDir = Join-Path $filesDir 'ConfigMgr'
        Invoke-Safe 'ConfigMgr client logs' {
            $null = Copy-IfExists '%SMS_LOG_PATH%' (Join-Path $cmDir 'Client')
            $null = Copy-IfExists '%SystemRoot%\ccmsetup\Logs' (Join-Path $cmDir 'CCMSetup')
        }
    }
}

#endregion

#region Summary + Compress

Invoke-Safe 'write _Summary.txt' {
    $elapsed = (Get-Date) - $script:StartTime
    $sz = 0
    Get-ChildItem -LiteralPath $script:StageRoot -Recurse -File -ErrorAction SilentlyContinue |
        ForEach-Object { $sz += $_.Length }
    $lines = @()
    $lines += "Collect-IntuneLogs v$APP_VERSION  ($APP_BUILD)"
    $lines += "Run start   : $($script:StartTime.ToString('yyyy-MM-dd HH:mm:ss'))"
    $lines += "Run end     : $((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))"
    $lines += "Elapsed     : {0:N0} seconds" -f $elapsed.TotalSeconds
    $lines += "Computer    : $script:Computer"
    $lines += "User        : $env:USERDOMAIN\$env:USERNAME"
    $lines += "DaysBack    : $DaysBack"
    $lines += "Deep        : $($Deep.IsPresent)"
    $lines += "IncludeNDES : $($IncludeNDES.IsPresent)"
    $lines += "IncludeCM   : $($IncludeConfigMgr.IsPresent)"
    $lines += "Staging     : $script:StageRoot"
    $lines += "Zip output  : $script:ZipPath"
    $lines += "Staging size: {0:N2} MB" -f ($sz/1MB)
    $lines | Out-File -FilePath $script:SummaryFile -Encoding UTF8
}

if ($NoZip) {
    Write-CLog "NoZip specified — staging left at $script:StageRoot" -Level WARN
    if (-not $NoOpen) { Start-Process -FilePath explorer.exe -ArgumentList $script:StageRoot }
    return
}

Invoke-Safe 'compress to ZIP' {
    # give msinfo32 one last chance to exit
    $t = 0
    while ((Get-Process -Name msinfo32 -ErrorAction SilentlyContinue) -and ($t -lt 60)) {
        Start-Sleep 5; $t += 5
    }
    if (Test-Path -LiteralPath $script:ZipPath) { Remove-Item -LiteralPath $script:ZipPath -Force -ErrorAction SilentlyContinue }
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::CreateFromDirectory(
        $script:StageRoot,
        $script:ZipPath,
        [System.IO.Compression.CompressionLevel]::Optimal,
        $false
    )
}

if (Test-Path -LiteralPath $script:ZipPath) {
    # Clean staging
    Remove-Item -LiteralPath $script:StageRoot -Recurse -Force -ErrorAction SilentlyContinue
    $zipSize = (Get-Item -LiteralPath $script:ZipPath).Length
    Write-Host ''
    Write-Host ('ZIP created: {0} ({1:N2} MB)' -f $script:ZipPath, ($zipSize/1MB)) -ForegroundColor Green
    Write-Host ''
    if (-not $NoOpen) {
        Start-Process -FilePath explorer.exe -ArgumentList "/select,`"$script:ZipPath`""
    }
} else {
    Write-Host ''
    Write-Host "ZIP creation failed. Staging retained at: $script:StageRoot" -ForegroundColor Red
    Write-Host ''
}

#endregion

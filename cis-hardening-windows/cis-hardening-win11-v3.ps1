<#
.SYNOPSIS
  CIS Windows 11 hardening for Windows 11, v3. Same settings as v2 EXCEPT the
  audit subcategory "Removable Storage", plus a backup of every value it touches and a
  matching undo script (cis-hardening-win11-v3-undo.ps1).

.NOTES
  Root cause of the v1/v2 BSOD (dump analysed 2026-09-19): null dereference in Windows
  ks.sys (ks!DispatchQuerySecurity+0x2a) while "Bongiovi DPS.exe" opened a kernel
  streaming device; the kernel queried the security descriptor of that handle. Which
  hardening setting makes the kernel take that path is NOT confirmed. Leading suspect:
  audit subcategory "Removable Storage" (Object Access). That one is left out here and
  should be re-tested ALONE afterwards.

  BEFORE running: the Bongiovi DPS startup shortcut must be moved out of
  C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup so a repeat crash cannot
  turn into a boot loop.

  Backup goes to the cis-v3-backup folder next to this script. It is written only once;
  re-running the script never overwrites the original backup.
  Undo works from an admin PowerShell in Safe Mode too (no restore point needed).
  ASCII only on purpose. Run as Administrator.
#>

#Requires -RunAsAdministrator
$ErrorActionPreference = "Stop"
$backupDir = Join-Path $PSScriptRoot "cis-v3-backup"
$stateFile = Join-Path $backupDir "state.json"
$auditFile = Join-Path $backupDir "audit-backup.csv"

Write-Host "=== CIS hardening v3 - Windows 11 (Removable Storage audit excluded) ===" -ForegroundColor Cyan

# Registry values touched by this script: path, name
$regTargets = @(
    @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "DontDisplayLastUserName"),
    @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "DisableLockScreenAppNotifications"),
    @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "InactivityTimeoutSecs"),
    @("HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters", "EnableSecuritySignature"),
    @("HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters", "RequireSecuritySignature"),
    @("HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "EnableSecuritySignature"),
    @("HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "RequireSecuritySignature"),
    @("HKLM:\SYSTEM\CurrentControlSet\Control\Lsa", "RestrictAnonymous"),
    @("HKLM:\SYSTEM\CurrentControlSet\Control\Lsa", "RestrictAnonymousSAM"),
    @("HKLM:\SYSTEM\CurrentControlSet\Control\Lsa", "NoLMHash"),
    @("HKLM:\SYSTEM\CurrentControlSet\Control\Lsa", "LmCompatibilityLevel"),
    @("HKLM:\SYSTEM\CurrentControlSet\Control\Lsa", "LimitBlankPasswordUse")
)

$servicesToDisable = @(
    "XblAuthManager", "XblGameSave", "XboxNetApiSvc", "XboxGipSvc",
    "RetailDemo", "PhoneSvc", "WMPNetworkSvc", "Fax", "TapiSrv",
    "dmwappushservice", "PcaSvc", "WalletService", "WerSvc"
)

# -- 0. Backup (only if none exists yet) ---------------------------------------
Write-Host "`n[0/7] Backup of current values..." -ForegroundColor Yellow
if (Test-Path $stateFile) {
    Write-Host "  Backup already exists at $backupDir - keeping the ORIGINAL, not overwriting." -ForegroundColor DarkYellow
} else {
    New-Item -ItemType Directory -Force $backupDir | Out-Null

    # Account policy via secedit (locale independent keys)
    $cfg = Join-Path $backupDir "secpol.cfg"
    secedit /export /cfg $cfg /areas SECURITYPOLICY | Out-Null
    $sec = @{}
    foreach ($line in Get-Content $cfg) {
        if ($line -match '^\s*(\w+)\s*=\s*(-?\d+)\s*$') { $sec[$Matches[1]] = [int]$Matches[2] }
    }
    function Get-Sec($key, $default) { if ($sec.ContainsKey($key)) { $sec[$key] } else { $default } }
    $account = [ordered]@{
        MinPwLen   = Get-Sec "MinimumPasswordLength" 0
        MaxPwAge   = Get-Sec "MaximumPasswordAge" 42
        MinPwAge   = Get-Sec "MinimumPasswordAge" 0
        UniquePw   = Get-Sec "PasswordHistorySize" 0
        LockThresh = Get-Sec "LockoutBadCount" 0
        LockWindow = Get-Sec "ResetLockoutCount" 30
        LockDur    = Get-Sec "LockoutDuration" 30
    }

    $reg = @()
    foreach ($t in $regTargets) {
        $existing = (Get-ItemProperty -Path $t[0] -Name $t[1] -ErrorAction SilentlyContinue)
        $val = $null
        if ($existing -and ($existing.PSObject.Properties.Name -contains $t[1])) { $val = $existing.$($t[1]) }
        $reg += [pscustomobject]@{ Path = $t[0]; Name = $t[1]; Value = $val }
    }

    $svcState = @()
    foreach ($n in $servicesToDisable) {
        $s = Get-Service -Name $n -ErrorAction SilentlyContinue
        if ($s) { $svcState += [pscustomobject]@{ Name = $n; StartType = [string]$s.StartType; WasRunning = ($s.Status -eq "Running") } }
    }

    $guest = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
    auditpol /backup /file:$auditFile | Out-Null

    [pscustomobject]@{
        Taken        = (Get-Date).ToString("s")
        Account      = $account
        Registry     = $reg
        Services     = $svcState
        GuestEnabled = [bool]($guest -and $guest.Enabled)
    } | ConvertTo-Json -Depth 5 | Set-Content -Path $stateFile -Encoding ASCII
    Write-Host "  Backup written to $backupDir"
}

# -- 1. Password policy --------------------------------------------------------
Write-Host "`n[1/7] Password policy..." -ForegroundColor Yellow
net accounts /minpwlen:14
net accounts /maxpwage:60
net accounts /minpwage:1
net accounts /uniquepw:24

# -- 2. Account lockout policy -------------------------------------------------
Write-Host "`n[2/7] Account lockout policy..." -ForegroundColor Yellow
net accounts /lockoutthreshold:5
net accounts /lockoutwindow:15
net accounts /lockoutduration:15

# -- 3. Privacy / lock screen / notifications ----------------------------------
Write-Host "`n[3/7] Privacy and lock-screen notifications..." -ForegroundColor Yellow
$sys = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
if (-not (Test-Path $sys)) { New-Item -Path $sys -Force | Out-Null }
Set-ItemProperty -Path $sys -Name "DontDisplayLastUserName" -Value 1 -Type DWord
Set-ItemProperty -Path $sys -Name "DisableLockScreenAppNotifications" -Value 1 -Type DWord
Set-ItemProperty -Path $sys -Name "InactivityTimeoutSecs" -Value 900 -Type DWord

# -- 4. SMB signing (client + server) ------------------------------------------
Write-Host "`n[4/7] SMB signing..." -ForegroundColor Yellow
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "EnableSecuritySignature" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "RequireSecuritySignature" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "EnableSecuritySignature" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RequireSecuritySignature" -Value 1 -Type DWord

# -- 5. Audit policy (CIS Level 1 baseline subcategories) ----------------------
# "Removable Storage" {0CCE9245-...} is DELIBERATELY NOT in this list (see NOTES).
Write-Host "`n[5/7] Audit policy (21 subcategories, Removable Storage excluded)..." -ForegroundColor Yellow
$auditSubcategories = [ordered]@{
    "Credential Validation"           = "{0CCE923F-69AE-11D9-BED3-505054503030}"
    "Security Group Management"       = "{0CCE9237-69AE-11D9-BED3-505054503030}"
    "User Account Management"         = "{0CCE9235-69AE-11D9-BED3-505054503030}"
    "PNP Activity"                    = "{0CCE9248-69AE-11D9-BED3-505054503030}"
    "Process Creation"                = "{0CCE922B-69AE-11D9-BED3-505054503030}"
    "Account Lockout"                 = "{0CCE9217-69AE-11D9-BED3-505054503030}"
    "Group Membership"                = "{0CCE9249-69AE-11D9-BED3-505054503030}"
    "Logoff"                          = "{0CCE9216-69AE-11D9-BED3-505054503030}"
    "Logon"                           = "{0CCE9215-69AE-11D9-BED3-505054503030}"
    "Other Logon/Logoff Events"       = "{0CCE921C-69AE-11D9-BED3-505054503030}"
    "Special Logon"                   = "{0CCE921B-69AE-11D9-BED3-505054503030}"
    "Audit Policy Change"             = "{0CCE922F-69AE-11D9-BED3-505054503030}"
    "Authentication Policy Change"    = "{0CCE9230-69AE-11D9-BED3-505054503030}"
    "Authorization Policy Change"     = "{0CCE9231-69AE-11D9-BED3-505054503030}"
    "MPSSVC Rule-Level Policy Change" = "{0CCE9232-69AE-11D9-BED3-505054503030}"
    "Sensitive Privilege Use"         = "{0CCE9228-69AE-11D9-BED3-505054503030}"
    "IPsec Driver"                    = "{0CCE9213-69AE-11D9-BED3-505054503030}"
    "Other System Events"             = "{0CCE9214-69AE-11D9-BED3-505054503030}"
    "Security State Change"           = "{0CCE9210-69AE-11D9-BED3-505054503030}"
    "Security System Extension"       = "{0CCE9211-69AE-11D9-BED3-505054503030}"
    "System Integrity"                = "{0CCE9212-69AE-11D9-BED3-505054503030}"
}
$auditOk = 0
foreach ($name in $auditSubcategories.Keys) {
    auditpol /set /subcategory:"$($auditSubcategories[$name])" /success:enable /failure:enable | Out-Null
    if ($LASTEXITCODE -eq 0) { $auditOk++ } else { Write-Host "  FAILED: $name" -ForegroundColor Red }
}
Write-Host "  $auditOk/$($auditSubcategories.Count) subcategories set to Success+Failure."

# -- 6. General security options -----------------------------------------------
Write-Host "`n[6/7] General security options..." -ForegroundColor Yellow
$lsa = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
Set-ItemProperty -Path $lsa -Name "RestrictAnonymous" -Value 1 -Type DWord
Set-ItemProperty -Path $lsa -Name "RestrictAnonymousSAM" -Value 1 -Type DWord
Set-ItemProperty -Path $lsa -Name "NoLMHash" -Value 1 -Type DWord
Set-ItemProperty -Path $lsa -Name "LmCompatibilityLevel" -Value 5 -Type DWord
Set-ItemProperty -Path $lsa -Name "LimitBlankPasswordUse" -Value 1 -Type DWord
net user Guest /active:no

# -- 7. Unnecessary consumer/legacy services -> Disabled ------------------------
Write-Host "`n[7/7] Disabling unnecessary services..." -ForegroundColor Yellow
foreach ($svcName in $servicesToDisable) {
    $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
    if ($svc) {
        if ($svc.Status -eq "Running") { Stop-Service -Name $svcName -Force }
        Set-Service -Name $svcName -StartupType Disabled
        Write-Host "  $svcName -> Disabled"
    } else {
        Write-Host "  $svcName -> not present, skipped"
    }
}

Write-Host "`n=== Done. Reboot, then start Bongiovi DPS by hand and wait ~10 minutes. ===" -ForegroundColor Cyan
Write-Host "If it crashes: copy C:\Windows\Minidump from Safe Mode, then run cis-hardening-win11-v3-undo.ps1 (no System Restore needed)." -ForegroundColor DarkYellow
Write-Host "Skipped on purpose: BitLocker, Windows Firewall, RDP, audit 'Removable Storage' (isolated re-test pending)." -ForegroundColor DarkYellow

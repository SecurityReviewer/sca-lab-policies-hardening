<#
.SYNOPSIS
  Undo for cis-hardening-win11-v3.ps1 - restores the values saved in
  the cis-v3-backup folder next to this script . Works from Safe Mode (admin PowerShell).
  ASCII only on purpose. Reboot afterwards (SMB signing / LSA values apply at boot).
#>

#Requires -RunAsAdministrator
$ErrorActionPreference = "Continue"
$backupDir = Join-Path $PSScriptRoot "cis-v3-backup"
$stateFile = Join-Path $backupDir "state.json"
$auditFile = Join-Path $backupDir "audit-backup.csv"

if (-not (Test-Path $stateFile)) { Write-Host "No backup found at $stateFile - nothing to undo." -ForegroundColor Red; return }
$state = Get-Content $stateFile -Raw | ConvertFrom-Json
Write-Host "=== Undo CIS hardening v3 (backup taken $($state.Taken)) ===" -ForegroundColor Cyan

Write-Host "`n[1/5] Password + lockout policy..." -ForegroundColor Yellow
$a = $state.Account
net accounts /minpwlen:$($a.MinPwLen)
net accounts /maxpwage:$($a.MaxPwAge)
net accounts /minpwage:$($a.MinPwAge)
net accounts /uniquepw:$($a.UniquePw)
net accounts /lockoutthreshold:$($a.LockThresh)
net accounts /lockoutwindow:$($a.LockWindow)
net accounts /lockoutduration:$($a.LockDur)

Write-Host "`n[2/5] Registry values..." -ForegroundColor Yellow
foreach ($r in $state.Registry) {
    if ($null -eq $r.Value) {
        Remove-ItemProperty -Path $r.Path -Name $r.Name -ErrorAction SilentlyContinue
        Write-Host "  removed  $($r.Name)"
    } else {
        Set-ItemProperty -Path $r.Path -Name $r.Name -Value $r.Value -Type DWord
        Write-Host "  restored $($r.Name) = $($r.Value)"
    }
}

Write-Host "`n[3/5] Audit policy..." -ForegroundColor Yellow
if (Test-Path $auditFile) { auditpol /restore /file:$auditFile } else { Write-Host "  audit backup missing" -ForegroundColor Red }

Write-Host "`n[4/5] Guest account..." -ForegroundColor Yellow
if ($state.GuestEnabled) { net user Guest /active:yes } else { Write-Host "  was disabled, left as is" }

Write-Host "`n[5/5] Services..." -ForegroundColor Yellow
foreach ($s in $state.Services) {
    $type = if ($s.StartType -eq "Automatic") { "Automatic" } elseif ($s.StartType -eq "Disabled") { "Disabled" } else { "Manual" }
    Set-Service -Name $s.Name -StartupType $type -ErrorAction SilentlyContinue
    Write-Host "  $($s.Name) -> $type"
}

Write-Host "`n=== Undo done. Reboot. ===" -ForegroundColor Cyan

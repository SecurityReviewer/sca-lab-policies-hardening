<#
.SYNOPSIS
  Undo for cis-hardening-win11-v3-audit-addon.ps1: restores the audit policy
  snapshot taken just before the add-on (v3 state, without the 5 extra subcategories).
  ASCII only on purpose. Run as Administrator.
#>

#Requires -RunAsAdministrator
$snapshot = Join-Path $PSScriptRoot "cis-v3-backup\audit-before-addon.csv"
if (-not (Test-Path $snapshot)) { Write-Host "No snapshot at $snapshot - nothing to undo." -ForegroundColor Red; return }
auditpol /restore /file:$snapshot
Write-Host "Audit policy restored from $snapshot" -ForegroundColor Cyan

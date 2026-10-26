<#
.SYNOPSIS
  Adds the 5 CIS Level 1 audit subcategories that v3 did not set, so the matching SCA
  checks can pass. Takes a snapshot of the whole audit policy first; undo with
  cis-hardening-win11-v3-audit-addon-undo.ps1 (auditpol /restore of that snapshot).

    Application Group Management   Success and Failure
    Detailed File Share            Failure
    File Share                     Success and Failure
    Other Object Access Events     Success and Failure
    Other Policy Change Events     Failure

  Takes effect immediately, no reboot. ASCII only on purpose. Run as Administrator.
#>

#Requires -RunAsAdministrator
$ErrorActionPreference = "Stop"
$backupDir = Join-Path $PSScriptRoot "cis-v3-backup"
$snapshot = Join-Path $backupDir "audit-before-addon.csv"

Write-Host "=== CIS audit add-on: 5 missing subcategories ===" -ForegroundColor Cyan
New-Item -ItemType Directory -Force $backupDir | Out-Null
if (Test-Path $snapshot) {
    Write-Host "Snapshot already exists - keeping the original: $snapshot" -ForegroundColor DarkYellow
} else {
    auditpol /backup /file:$snapshot | Out-Null
    Write-Host "Snapshot written: $snapshot"
}

# GUIDs are locale independent (Italian/Spanish/German Windows localize the names)
$settings = @(
    @{ Name = "Application Group Management"; Guid = "{0CCE9239-69AE-11D9-BED3-505054503030}"; Args = @("/success:enable", "/failure:enable") },
    @{ Name = "Detailed File Share";          Guid = "{0CCE9244-69AE-11D9-BED3-505054503030}"; Args = @("/failure:enable") },
    @{ Name = "File Share";                   Guid = "{0CCE9224-69AE-11D9-BED3-505054503030}"; Args = @("/success:enable", "/failure:enable") },
    @{ Name = "Other Object Access Events";   Guid = "{0CCE9227-69AE-11D9-BED3-505054503030}"; Args = @("/success:enable", "/failure:enable") },
    @{ Name = "Other Policy Change Events";   Guid = "{0CCE9234-69AE-11D9-BED3-505054503030}"; Args = @("/failure:enable") }
)
$ok = 0
foreach ($s in $settings) {
    auditpol /set /subcategory:"$($s.Guid)" @($s.Args) | Out-Null
    if ($LASTEXITCODE -eq 0) { $ok++; Write-Host "  OK: $($s.Name)" } else { Write-Host "  FAILED: $($s.Name)" -ForegroundColor Red }
}
Write-Host "$ok/$($settings.Count) subcategories set."

Write-Host "`nResulting values (0 none, 1 success, 2 failure, 3 both):" -ForegroundColor Yellow
$tmp = Join-Path $env:TEMP "audit-check.csv"
auditpol /backup /file:$tmp | Out-Null
foreach ($s in $settings) {
    $line = Select-String -Path $tmp -SimpleMatch $s.Guid | Select-Object -First 1
    "  {0,-32} {1}" -f $s.Name, ($line.Line.Split(',')[-1].Trim())
}
Remove-Item $tmp -Force
Write-Host "`nDone. Undo: cis-hardening-win11-v3-audit-addon-undo.ps1" -ForegroundColor Cyan

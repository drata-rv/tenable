<#
.SYNOPSIS
  Unregisters the Drata Nessus CIS Collector Windows Scheduled Task.
  Run from an elevated PowerShell prompt.

.PARAMETER TaskName
  Name of the scheduled task to remove (must match the name used at
  install time in install_task.ps1).
#>
param(
    [string]$TaskName = "Drata Nessus CIS Collector"
)

$ErrorActionPreference = "Stop"

if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    Write-Host "Unregistered scheduled task '$TaskName'."
} else {
    Write-Host "No scheduled task named '$TaskName' found -- nothing to do."
}

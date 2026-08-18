<#
.SYNOPSIS
  Registers the Drata Nessus CIS Collector as a Windows Scheduled Task.
  Run from an elevated PowerShell prompt (spec Section 9.4).

.DESCRIPTION
  Task settings mirror spec Section 9.4 exactly:
    - ExecutionTimeLimit 2 hours (bounds a hung export)
    - MultipleInstances IgnoreNew (belt-and-braces alongside the collector's
      own state/collector.lock file)
    - StartWhenAvailable (the host is a workstation, may be off at trigger time)
    - RestartCount 2 / RestartInterval 15 minutes
    - Runs on battery, does not stop if going on battery
    - RunLevel Limited -- no elevation required. If the collector ever
      appears to need admin rights, the directory permission model in
      spec Section 9.1 is wrong; do not "fix" that by elevating this task.

.PARAMETER RunAsUser
  Domain\username of the dedicated service account the task runs as (spec
  Section 14 assumed default: svc-drata-nessus). The account must already
  exist; this script does not create it.

.PARAMETER Password
  The service account's password, as a SecureString (prompt interactively,
  never pass as a plaintext command-line argument).

.PARAMETER StartTime
  Daily trigger time (spec Section 14 assumed default: 06:00 local).

.PARAMETER InstallDir
  Path to the collector's Program Files installation.

.EXAMPLE
  $cred = Get-Credential -UserName 'CONTOSO\svc-drata-nessus' -Message 'Service account password'
  .\install_task.ps1 -RunAsUser $cred.UserName -Password $cred.Password
#>
param(
    [Parameter(Mandatory = $true)]
    [string]$RunAsUser,

    [Parameter(Mandatory = $true)]
    [securestring]$Password,

    [string]$StartTime = "06:00",

    [string]$InstallDir = "C:\Program Files\NessusDrataCollector",

    [string]$TaskName = "Drata Nessus CIS Collector"
)

$ErrorActionPreference = "Stop"

$scriptPath = Join-Path $InstallDir "windows\run_collector.cmd"
if (-not (Test-Path $scriptPath)) {
    throw "run_collector.cmd not found at $scriptPath -- check -InstallDir"
}

$action = New-ScheduledTaskAction -Execute $scriptPath
$trigger = New-ScheduledTaskTrigger -Daily -At $StartTime
$settings = New-ScheduledTaskSettingsSet `
    -ExecutionTimeLimit (New-TimeSpan -Hours 2) `
    -MultipleInstances IgnoreNew `
    -StartWhenAvailable `
    -RestartCount 2 `
    -RestartInterval (New-TimeSpan -Minutes 15) `
    -DontStopIfGoingOnBatteries `
    -AllowStartIfOnBatteries

$bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
$plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
[System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)

try {
    Register-ScheduledTask -TaskName $TaskName `
        -Action $action -Trigger $trigger -Settings $settings `
        -User $RunAsUser -Password $plainPassword -RunLevel Limited | Out-Null
}
finally {
    Remove-Variable plainPassword -ErrorAction SilentlyContinue
}

Write-Host "Registered scheduled task '$TaskName' running as $RunAsUser daily at $StartTime."
Write-Host "Force one manual run now with:"
Write-Host "  Start-ScheduledTask -TaskName '$TaskName'"
Write-Host "Then confirm Last Result is 0 with:"
Write-Host "  (Get-ScheduledTaskInfo -TaskName '$TaskName').LastTaskResult"
